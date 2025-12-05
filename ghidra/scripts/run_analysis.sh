#!/bin/bash
# Wrapper script that ensures optimize_analysis.py is always used
# This prevents accidentally running full (slow) analysis
#
# Usage: ./run_analysis.sh <postscript.py> [additional args...]
# Example: ./run_analysis.sh find_modifierlist_offsets.py
#
# Monitor progress: tail -f /tmp/ghidra_progress.log

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
POSTSCRIPT="$1"

if [ -z "$POSTSCRIPT" ]; then
    echo "Usage: $0 <postscript.py> [additional args...]"
    echo ""
    echo "Available scripts:"
    ls -1 "$SCRIPT_DIR"/*.py 2>/dev/null | xargs -n1 basename | grep -v "^_" | grep -v "utils" | sort
    echo ""
    echo "Example: $0 find_modifierlist_offsets.py"
    exit 1
fi

shift  # Remove first arg, pass rest through

# Clear progress log
> /tmp/ghidra_progress.log

echo "=============================================="
echo "Ghidra Analysis with Optimized Settings"
echo "=============================================="
echo "Script: $POSTSCRIPT"
echo "Progress: tail -f /tmp/ghidra_progress.log"
echo ""

JAVA_HOME="/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home" \
  ~/ghidra/support/analyzeHeadless ~/ghidra_projects BG3Analysis \
  -process BG3_arm64_thin \
  -scriptPath "$SCRIPT_DIR" \
  -preScript optimize_analysis.py \
  -postScript "$POSTSCRIPT" \
  "$@" \
  2>&1 | tee /tmp/ghidra_output.log

echo ""
echo "=============================================="
echo "Analysis complete"
echo "Output: /tmp/ghidra_output.log"
echo "Progress: /tmp/ghidra_progress.log"
echo "=============================================="
