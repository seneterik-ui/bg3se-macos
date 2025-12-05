/**
 * BG3SE-macOS - Logging Implementation
 */

#include "logging.h"
#include "version.h"

#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <syslog.h>
#include <sys/stat.h>
#include <pthread.h>

// Static buffers for paths
static char g_DataDir[512] = {0};
static char g_DataPath[512] = {0};
static pthread_once_t g_DataDirOnce = PTHREAD_ONCE_INIT;

static void init_data_dir(void) {
    const char *home = getenv("HOME");

    // Try to create in ~/Library/Application Support/BG3SE/
    if (home && home[0] != '\0') {
        snprintf(g_DataDir, sizeof(g_DataDir),
                 "%s/Library/Application Support/%s",
                 home, BG3SE_DATA_DIR_NAME);

        // Create directory hierarchy
        char path[512];
        snprintf(path, sizeof(path), "%s/Library", home);
        mkdir(path, 0755);

        snprintf(path, sizeof(path), "%s/Library/Application Support", home);
        mkdir(path, 0755);

        if (mkdir(g_DataDir, 0755) == 0 || errno == EEXIST) {
            // Success - directory exists or was created
            return;
        }
    }

    // Fallback to /tmp/BG3SE/ if home directory fails
    snprintf(g_DataDir, sizeof(g_DataDir), "/tmp/%s", BG3SE_DATA_DIR_NAME);
    mkdir(g_DataDir, 0755);
}

const char *bg3se_get_data_dir(void) {
    pthread_once(&g_DataDirOnce, init_data_dir);
    return g_DataDir;
}

const char *bg3se_get_data_path(const char *filename) {
    pthread_once(&g_DataDirOnce, init_data_dir);
    snprintf(g_DataPath, sizeof(g_DataPath), "%s/%s", g_DataDir, filename);
    return g_DataPath;
}

void log_init(void) {
    const char *log_path = bg3se_get_data_path(BG3SE_LOG_FILENAME);

    // Use append mode to preserve logs from crashed sessions
    FILE *f = fopen(log_path, "a");
    if (f) {
        fprintf(f, "\n\n========================================\n");
        fprintf(f, "=== %s v%s ===\n", BG3SE_NAME, BG3SE_VERSION);
        fprintf(f, "Log file: %s\n", log_path);
        fprintf(f, "Injection timestamp: %ld\n", (long)time(NULL));
        fprintf(f, "========================================\n");
        fclose(f);
    }
}

void log_message(const char *format, ...) {
    va_list args;
    char buffer[1024];

    va_start(args, format);
    vsnprintf(buffer, sizeof(buffer), format, args);
    va_end(args);

    // Write to syslog
    syslog(LOG_ERR, "[%s] %s", BG3SE_NAME, buffer);

    // Write to log file
    const char *log_path = bg3se_get_data_path(BG3SE_LOG_FILENAME);
    FILE *f = fopen(log_path, "a");
    if (f) {
        time_t now = time(NULL);
        struct tm *t = localtime(&now);
        fprintf(f, "[%04d-%02d-%02d %02d:%02d:%02d] %s\n",
                t->tm_year + 1900, t->tm_mon + 1, t->tm_mday,
                t->tm_hour, t->tm_min, t->tm_sec, buffer);
        fclose(f);
    }
}
