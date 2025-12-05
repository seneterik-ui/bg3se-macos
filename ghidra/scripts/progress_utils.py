# Shared progress tracking utilities for Ghidra scripts
# Usage: from progress_utils import init_progress, progress, finish_progress

import time

PROGRESS_FILE = "/tmp/ghidra_progress.log"

def init_progress(script_name=None):
    """Clear progress log at script start.

    Args:
        script_name: Optional name to display in the log header
    """
    header = "=== Ghidra Script Started"
    if script_name:
        header += ": %s" % script_name
    header += " ==="

    with open(PROGRESS_FILE, "w") as f:
        f.write("[%s] %s\n" % (time.strftime("%H:%M:%S"), header))

def progress(msg, pct=None):
    """Log progress to file and console for real-time monitoring.

    File-based logging is essential because stdout is buffered in headless mode
    and only appears after script completion.

    Args:
        msg: Status message to display
        pct: Optional percentage (0-100)
    """
    line = "[%s] %s" % (time.strftime("%H:%M:%S"), msg)
    if pct is not None:
        line += " (%d%%)" % pct
        try:
            monitor.setMaximum(100)
            monitor.setProgress(int(pct))
        except:
            pass  # monitor may not be available in all contexts
    try:
        monitor.setMessage(str(msg))
    except:
        pass
    print(line)
    with open(PROGRESS_FILE, "a") as f:
        f.write(line + "\n")

def finish_progress():
    """Mark script completion."""
    progress("=== Script Complete ===", 100)
