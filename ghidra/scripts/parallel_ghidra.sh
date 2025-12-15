#!/bin/bash
# Parallel Ghidra Analysis Runner
#
# Runs multiple Ghidra headless scripts simultaneously for faster offset discovery.
# Each script runs as a separate analyzeHeadless process.
#
# Usage: ./parallel_ghidra.sh script1.py script2.py script3.py ...
#        ./parallel_ghidra.sh --max-jobs 2 script1.py script2.py  # Limit concurrency
#        ./parallel_ghidra.sh --all-init  # Run all *_init.py scripts
#
# WARNING: Each Ghidra instance loads the full BG3 binary (~500MB).
#          With 4 concurrent jobs, expect ~8GB RAM usage.
#          Default max jobs is 2 to avoid OOM on 16GB machines.
#
# Output: /tmp/ghidra_parallel/<script_name>.log per script
#         /tmp/ghidra_parallel/summary.txt for final report

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
LOG_DIR="/tmp/ghidra_parallel"
MAX_JOBS=2  # Default: 2 concurrent jobs (safe for 16GB RAM)
SCRIPTS=()

# Parse arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        --max-jobs)
            MAX_JOBS="$2"
            shift 2
            ;;
        --all-init)
            # Find all *_init.py scripts
            mapfile -t SCRIPTS < <(find "$SCRIPT_DIR" -maxdepth 1 -name "*_init*.py" -type f | xargs -n1 basename 2>/dev/null | sort)
            shift
            ;;
        -h|--help)
            echo "Parallel Ghidra Analysis Runner"
            echo ""
            echo "Usage: $0 [options] script1.py script2.py ..."
            echo ""
            echo "Options:"
            echo "  --max-jobs N    Maximum concurrent Ghidra processes (default: 2)"
            echo "  --all-init      Run all *_init*.py scripts in parallel"
            echo "  -h, --help      Show this help"
            echo ""
            echo "Available scripts:"
            ls -1 "$SCRIPT_DIR"/*.py 2>/dev/null | xargs -n1 basename | grep -v "^_" | grep -v "utils" | sort
            echo ""
            echo "Examples:"
            echo "  $0 find_status_init.py find_passive_init.py"
            echo "  $0 --max-jobs 4 script1.py script2.py script3.py script4.py"
            echo "  $0 --all-init"
            exit 0
            ;;
        *.py)
            SCRIPTS+=("$1")
            shift
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

if [ ${#SCRIPTS[@]} -eq 0 ]; then
    echo "Error: No scripts specified."
    echo "Usage: $0 [--max-jobs N] script1.py script2.py ..."
    echo "       $0 --all-init"
    echo ""
    echo "Run '$0 --help' for more options."
    exit 1
fi

# Setup logging directory
rm -rf "$LOG_DIR"
mkdir -p "$LOG_DIR"

echo "=============================================="
echo "Parallel Ghidra Analysis"
echo "=============================================="
echo "Scripts: ${#SCRIPTS[@]}"
echo "Max concurrent jobs: $MAX_JOBS"
echo "Log directory: $LOG_DIR"
echo ""
echo "Scripts to run:"
for script in "${SCRIPTS[@]}"; do
    echo "  - $script"
done
echo ""
echo "Starting parallel analysis at $(date '+%Y-%m-%d %H:%M:%S')..."
echo ""

# Track PIDs and their associated scripts
declare -A pid_to_script
declare -a pids=()
active_jobs=0
total_scripts=${#SCRIPTS[@]}
started=0
completed=0
failed=0

# Function to run a single Ghidra script
run_ghidra_script() {
    local script="$1"
    local log_file="$LOG_DIR/$(basename "$script" .py).log"

    JAVA_HOME="/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home" \
      ~/ghidra/support/analyzeHeadless ~/ghidra_projects BG3Analysis \
      -process BG3_arm64_thin \
      -noanalysis \
      -scriptPath "$SCRIPT_DIR" \
      -postScript "$script" \
      > "$log_file" 2>&1
}

# Function to check and handle completed jobs
check_completed_jobs() {
    local -a still_running=()
    for pid in "${pids[@]}"; do
        if kill -0 "$pid" 2>/dev/null; then
            still_running+=("$pid")
        else
            # Job completed - check exit status
            if wait "$pid" 2>/dev/null; then
                local script="${pid_to_script[$pid]}"
                echo "[$(date '+%H:%M:%S')] DONE: $script"
                ((completed++))
            else
                local script="${pid_to_script[$pid]}"
                echo "[$(date '+%H:%M:%S')] FAIL: $script (check $LOG_DIR/$(basename "$script" .py).log)"
                ((failed++))
            fi
            ((active_jobs--))
            unset "pid_to_script[$pid]"
        fi
    done
    pids=("${still_running[@]}")
}

# Main execution loop
for script in "${SCRIPTS[@]}"; do
    # Wait if at job limit
    while (( active_jobs >= MAX_JOBS )); do
        sleep 2
        check_completed_jobs
    done

    # Start new job
    ((started++))
    echo "[$(date '+%H:%M:%S')] START ($started/$total_scripts): $script"

    run_ghidra_script "$script" &
    local pid=$!
    pids+=("$pid")
    pid_to_script[$pid]="$script"
    ((active_jobs++))
done

# Wait for remaining jobs
echo ""
echo "All scripts launched. Waiting for completion..."
while (( ${#pids[@]} > 0 )); do
    sleep 2
    check_completed_jobs
done

# Generate summary
echo ""
echo "=============================================="
echo "Analysis Complete"
echo "=============================================="
echo "Total scripts: $total_scripts"
echo "Completed: $completed"
echo "Failed: $failed"
echo "Finished at: $(date '+%Y-%m-%d %H:%M:%S')"
echo ""

# Write summary file
{
    echo "Parallel Ghidra Analysis Summary"
    echo "================================"
    echo "Date: $(date '+%Y-%m-%d %H:%M:%S')"
    echo "Total: $total_scripts | Completed: $completed | Failed: $failed"
    echo ""
    echo "Individual Results:"
    for script in "${SCRIPTS[@]}"; do
        log_file="$LOG_DIR/$(basename "$script" .py).log"
        if [ -f "$log_file" ]; then
            if grep -q "ERROR\|Exception\|FAILED" "$log_file"; then
                echo "  FAIL: $script"
            else
                echo "  OK:   $script"
            fi
        else
            echo "  ???:  $script (no log file)"
        fi
    done
} > "$LOG_DIR/summary.txt"

echo "Logs: $LOG_DIR/"
echo "Summary: $LOG_DIR/summary.txt"

# Show quick results from each log
echo ""
echo "Quick Results (last 5 lines per script):"
echo "----------------------------------------"
for script in "${SCRIPTS[@]}"; do
    log_file="$LOG_DIR/$(basename "$script" .py).log"
    if [ -f "$log_file" ]; then
        echo ""
        echo "--- $script ---"
        tail -5 "$log_file"
    fi
done

# Exit with failure if any scripts failed
if (( failed > 0 )); then
    exit 1
fi
