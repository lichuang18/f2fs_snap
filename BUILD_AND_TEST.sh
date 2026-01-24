#!/bin/bash
# Complete build and test script for F2FS_IOC_DELETE_SNAPSHOT

set -e

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${GREEN}=== F2FS_IOC_DELETE_SNAPSHOT - Build and Test ===${NC}\n"

# Step 1: Clean
echo -e "${YELLOW}[1/5]${NC} Cleaning..."
make clean
cd test_ioctl && make clean && cd ..

# Step 2: Build kernel module
echo -e "${YELLOW}[2/5]${NC} Building kernel module..."
make
if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓${NC} Kernel module built successfully"
else
    echo "✗ Build failed"
    exit 1
fi

# Step 3: Build test tools
echo -e "${YELLOW}[3/5]${NC} Building test tools..."
cd test_ioctl && make && cd ..
if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓${NC} Test tools built successfully"
else
    echo "✗ Build failed"
    exit 1
fi

# Step 4: Verify implementation
echo -e "${YELLOW}[4/5]${NC} Verifying implementation..."
./verify_implementation.sh > /dev/null 2>&1
if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓${NC} Implementation verified"
else
    echo "✗ Verification failed"
    exit 1
fi

# Step 5: Show summary
echo -e "${YELLOW}[5/5]${NC} Build summary:"
echo "  - Kernel module: snapfs.ko ($(ls -lh snapfs.ko | awk '{print $5}'))"
echo "  - Test tool: test_ioctl/test_delete"
echo "  - Documentation: 5 files"
echo ""

echo -e "${GREEN}=== Build Complete ===${NC}\n"
echo "Next steps:"
echo "  1. Load module: sudo insmod snapfs.ko"
echo "  2. Run tests: sudo ./test_delete_snapshot.sh"
echo "  3. Read docs: cat QUICKSTART.md"
echo ""
