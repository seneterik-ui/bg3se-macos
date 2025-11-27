#!/bin/bash
#
# BG3SE-macOS Launcher Script
#
# This script launches Baldur's Gate 3 with the Script Extender dylib injected.
# Usage: ./launch_bg3.sh [path_to_dylib]
#

set -e

# Configuration
BG3_APP="/Users/tomdimino/Library/Application Support/Steam/steamapps/common/Baldurs Gate 3/Baldur's Gate 3.app"
BG3_EXEC="${BG3_APP}/Contents/MacOS/Baldur's Gate 3"

# Find the dylib
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# Check for dylib in order of preference
if [[ -n "$1" ]]; then
    DYLIB="$1"
elif [[ -f "${PROJECT_ROOT}/build/lib/libbg3se.dylib" ]]; then
    DYLIB="${PROJECT_ROOT}/build/lib/libbg3se.dylib"
elif [[ -f "${PROJECT_ROOT}/lib/libbg3se.dylib" ]]; then
    DYLIB="${PROJECT_ROOT}/lib/libbg3se.dylib"
else
    echo "Error: Cannot find libbg3se.dylib"
    echo "Build it first with: cd build && cmake .. && make"
    exit 1
fi

# Verify paths exist
if [[ ! -f "$BG3_EXEC" ]]; then
    echo "Error: Baldur's Gate 3 not found at:"
    echo "  $BG3_EXEC"
    exit 1
fi

if [[ ! -f "$DYLIB" ]]; then
    echo "Error: Dylib not found at:"
    echo "  $DYLIB"
    exit 1
fi

# Clean up old logs
rm -f /tmp/bg3se_loaded.txt
rm -f /tmp/bg3se_macos.log

echo "=========================================="
echo "BG3SE-macOS Launcher"
echo "=========================================="
echo "Game:   $BG3_EXEC"
echo "Dylib:  $DYLIB"
echo ""

# Check if dylib is universal binary
echo "Dylib architecture:"
file "$DYLIB"
echo ""

# Launch with DYLD injection
echo "Launching Baldur's Gate 3 with Script Extender..."
echo "(Check /tmp/bg3se_macos.log for detailed output)"
echo ""

# Set the environment variable and launch
DYLD_INSERT_LIBRARIES="$DYLIB" "$BG3_EXEC" &

# Give it a moment to start
sleep 3

# Check if injection worked
if [[ -f /tmp/bg3se_loaded.txt ]]; then
    echo "SUCCESS: BG3SE-macOS loaded!"
    echo ""
    echo "=== Injection Log ==="
    cat /tmp/bg3se_loaded.txt
    echo ""
    echo "=== Full Log ==="
    cat /tmp/bg3se_macos.log 2>/dev/null || echo "(No detailed log yet)"
else
    echo "WARNING: Injection marker not found."
    echo "The game may still be starting, or injection failed."
    echo "Check /tmp/bg3se_macos.log for details."
fi

echo ""
echo "Game is running in background (PID: $!)"
echo "Press Ctrl+C to continue (game will keep running)"
