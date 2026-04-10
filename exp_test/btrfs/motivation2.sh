#!/usr/bin/env bash
set -euo pipefail

DEV="${1:-/dev/nvme1n1}"          # 会被格式化
MNT="${2:-/mnt/btrfs_gran_eval}"
OUT="${3:-./results_btrfs_gran}"

PROTECTED_SIZE="${PROTECTED_SIZE:-2G}"
HOT_SIZE="${HOT_SIZE:-4G}"
STEP_BYTES="${STEP_BYTES:-256M}"
ROUNDS="${ROUNDS:-12}"

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "missing command: $1" >&2
    exit 1
  }
}

for c in mkfs.btrfs btrfs mount umount fio sync df tail awk; do
  need_cmd "$c"
done

mkdir -p "$MNT" "$OUT"

maybe_blkdiscard() {
  if command -v blkdiscard >/dev/null 2>&1; then
    blkdiscard -f "$DEV" || true
  fi
}

reset_fs() {
  sync || true
  umount "$MNT" 2>/dev/null || true
  mkdir -p "$MNT"

  maybe_blkdiscard
  mkfs.btrfs -f "$DEV" >/dev/null
  mount "$DEV" "$MNT"
}

get_used_bytes() {
  df -B1 --output=used "$MNT" | tail -1 | tr -d ' '
}

seed_file() {
  local path="$1"
  local size="$2"

  fio --name=seed \
      --filename="$path" \
      --size="$size" \
      --rw=write \
      --bs=1M \
      --direct=1 \
      --iodepth=32 \
      --ioengine=libaio \
      --fallocate=none >/dev/null
  sync
}

mutate_hot_window() {
  local path="$1"
  local round="$2"

  local step_bytes
  step_bytes=$(numfmt --from=iec "$STEP_BYTES")
  local offset_bytes=$(( (round - 1) * step_bytes ))

  fio --name=mut \
      --filename="$path" \
      --rw=write \
      --bs=4k \
      --offset="$offset_bytes" \
      --io_size="$STEP_BYTES" \
      --size="$HOT_SIZE" \
      --direct=1 \
      --ioengine=psync \
      --end_fsync=1 >/dev/null

  sync
}

run_single_subvol_case() {
  local csv="$OUT/single_subvol.csv"

  echo "round,cumulative_hot_overwrite_bytes,used_bytes" > "$csv"

  reset_fs
  btrfs subvolume create "$MNT/live" >/dev/null
  mkdir -p "$MNT/live/protected" "$MNT/live/hot"

  seed_file "$MNT/live/protected/coldfile" "$PROTECTED_SIZE"
  seed_file "$MNT/live/hot/hotfile" "$HOT_SIZE"

  # 只能 snapshot 整个 live，因为 protected 不是 subvolume
  btrfs subvolume snapshot -r "$MNT/live" "$MNT/live_snap" >/dev/null
  sync

  echo "0,0,$(get_used_bytes)" >> "$csv"

  local cumulative=0
  for r in $(seq 1 "$ROUNDS"); do
    mutate_hot_window "$MNT/live/hot/hotfile" "$r"
    cumulative=$(( cumulative + $(numfmt --from=iec "$STEP_BYTES") ))
    echo "$r,$cumulative,$(get_used_bytes)" >> "$csv"
  done

  umount "$MNT"
}

run_split_subvol_case() {
  local csv="$OUT/split_subvol.csv"

  echo "round,cumulative_hot_overwrite_bytes,used_bytes" > "$csv"

  reset_fs
  btrfs subvolume create "$MNT/protected_sv" >/dev/null
  btrfs subvolume create "$MNT/hot_sv" >/dev/null

  seed_file "$MNT/protected_sv/coldfile" "$PROTECTED_SIZE"
  seed_file "$MNT/hot_sv/hotfile" "$HOT_SIZE"

  # 只 snapshot protected_sv，hot_sv 不进版本域
  btrfs subvolume snapshot -r "$MNT/protected_sv" "$MNT/protected_snap" >/dev/null
  sync

  echo "0,0,$(get_used_bytes)" >> "$csv"

  local cumulative=0
  for r in $(seq 1 "$ROUNDS"); do
    mutate_hot_window "$MNT/live/hot/hotfile" "$r"
    cumulative=$(( cumulative + $(numfmt --from=iec "$STEP_BYTES") ))
    echo "$r,$cumulative,$(get_used_bytes)" >> "$csv"
  done

  umount "$MNT"
}

run_single_subvol_case
run_split_subvol_case

echo "done. results in $OUT"