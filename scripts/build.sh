#!/bin/bash
#
# DEPRECATED: This script is no longer maintained.
# Please use CMake instead for building BG3SE-macOS.
#

echo "=============================================="
echo "ERROR: build.sh is deprecated"
echo "=============================================="
echo ""
echo "Please use CMake instead:"
echo ""
echo "  cd $(dirname "$0")/.."
echo "  mkdir -p build && cd build"
echo "  cmake .."
echo "  cmake --build ."
echo ""
echo "The built library will be at: build/lib/libbg3se.dylib"
echo ""
echo "For more information, see the README.md"
echo "=============================================="
exit 1
