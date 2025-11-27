/**
 * BG3SE-macOS - Baldur's Gate 3 Script Extender for macOS
 *
 * This dylib is loaded via DYLD_INSERT_LIBRARIES before the game starts.
 * The constructor runs automatically when the library is loaded.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <syslog.h>
#include <dlfcn.h>
#include <time.h>
#include <unistd.h>
#include <mach-o/dyld.h>

// Dobby hooking framework
#include "Dobby/include/dobby.h"

// Version info
#define BG3SE_VERSION "0.4.0"
#define BG3SE_NAME "BG3SE-macOS"

// Log file for debugging
#define LOG_FILE "/tmp/bg3se_macos.log"

// Enable hooks (set to 0 to disable for testing)
#define ENABLE_HOOKS 1

// Forward declarations
static void log_message(const char *format, ...);
static void enumerate_loaded_images(void);
static void check_osiris_library(void);
static void install_hooks(void);

// Original function pointers (filled by Dobby)
static void *orig_InitGame = NULL;
static void *orig_Load = NULL;

// Hook call counters
static int initGame_call_count = 0;
static int load_call_count = 0;

// Track if hooks are already installed
static int hooks_installed = 0;

/**
 * Write to both syslog and our log file
 */
static void log_message(const char *format, ...) {
    va_list args;
    char buffer[1024];

    va_start(args, format);
    vsnprintf(buffer, sizeof(buffer), format, args);
    va_end(args);

    // Write to syslog
    syslog(LOG_ERR, "[%s] %s", BG3SE_NAME, buffer);

    // Write to log file
    FILE *f = fopen(LOG_FILE, "a");
    if (f) {
        time_t now = time(NULL);
        struct tm *t = localtime(&now);
        fprintf(f, "[%04d-%02d-%02d %02d:%02d:%02d] %s\n",
                t->tm_year + 1900, t->tm_mon + 1, t->tm_mday,
                t->tm_hour, t->tm_min, t->tm_sec, buffer);
        fclose(f);
    }
}

/**
 * Hooked COsiris::InitGame - called when game initializes Osiris
 * Mangled name: _ZN7COsiris8InitGameEv
 * This is a member function, so 'this' pointer is first arg
 */
static void fake_InitGame(void *thisPtr) {
    initGame_call_count++;
    log_message(">>> COsiris::InitGame called! (count: %d, this: %p)", initGame_call_count, thisPtr);

    // Call original
    if (orig_InitGame) {
        ((void (*)(void*))orig_InitGame)(thisPtr);
    }

    log_message(">>> COsiris::InitGame returned");
}

/**
 * Hooked COsiris::Load - called when loading save/story data
 * Mangled name: _ZN7COsiris4LoadER12COsiSmartBuf
 * Signature: bool COsiris::Load(COsiSmartBuf&)
 * This is a member function with a reference parameter, returns bool
 */
static int fake_Load(void *thisPtr, void *smartBuf) {
    load_call_count++;
    log_message(">>> COsiris::Load called! (count: %d, this: %p, buf: %p)", load_call_count, thisPtr, smartBuf);

    // Call original and preserve return value
    int result = 0;
    if (orig_Load) {
        result = ((int (*)(void*, void*))orig_Load)(thisPtr, smartBuf);
    }

    log_message(">>> COsiris::Load returned: %d", result);
    return result;
}

/**
 * Enumerate all loaded dynamic libraries
 * This helps us understand what's loaded and find libOsiris.dylib
 */
static void enumerate_loaded_images(void) {
    uint32_t count = _dyld_image_count();
    log_message("Loaded images: %u", count);

    int interesting_count = 0;
    for (uint32_t i = 0; i < count && interesting_count < 15; i++) {
        const char *name = _dyld_get_image_name(i);
        if (name) {
            // Only log interesting ones (not system frameworks)
            if (strstr(name, "Baldur") || strstr(name, "Osiris") ||
                strstr(name, "steam") || strstr(name, "Steam") ||
                strstr(name, "BG3") || strstr(name, "bg3se") ||
                strstr(name, "Larian") || strstr(name, "discord") ||
                strstr(name, "Bink") || strstr(name, "PlayFab") ||
                strstr(name, "Http")) {
                log_message("  [%u] %s", i, name);
                interesting_count++;
            }
        }
    }
}

/**
 * Install Dobby hooks on Osiris functions
 */
static void install_hooks(void) {
#if ENABLE_HOOKS
    // Only install hooks once
    if (hooks_installed) {
        log_message("Hooks already installed, skipping");
        return;
    }

    log_message("Installing Dobby hooks...");

    // Get libOsiris handle - try various paths
    void *osiris = dlopen("@rpath/libOsiris.dylib", RTLD_NOLOAD);
    if (!osiris) {
        // Try @executable_path relative (works when injected into BG3)
        osiris = dlopen("@executable_path/../Frameworks/libOsiris.dylib", RTLD_NOW);
    }

    if (!osiris) {
        log_message("ERROR: Could not get libOsiris handle for hooking");
        return;
    }

    // Get function addresses (C++ mangled names)
    void *initGameAddr = dlsym(osiris, "_ZN7COsiris8InitGameEv");
    void *loadAddr = dlsym(osiris, "_ZN7COsiris4LoadER12COsiSmartBuf");

    int hook_count = 0;

    // Hook COsiris::InitGame
    if (initGameAddr) {
        int result = DobbyHook(initGameAddr, (void *)fake_InitGame, &orig_InitGame);
        if (result == 0) {
            log_message("  COsiris::InitGame hooked successfully (orig: %p)", orig_InitGame);
            hook_count++;
        } else {
            log_message("  ERROR: Failed to hook COsiris::InitGame (error: %d)", result);
        }
    } else {
        log_message("  COsiris::InitGame not found, skipping");
    }

    // Hook COsiris::Load
    if (loadAddr) {
        int result = DobbyHook(loadAddr, (void *)fake_Load, &orig_Load);
        if (result == 0) {
            log_message("  COsiris::Load hooked successfully (orig: %p)", orig_Load);
            hook_count++;
        } else {
            log_message("  ERROR: Failed to hook COsiris::Load (error: %d)", result);
        }
    } else {
        log_message("  COsiris::Load not found, skipping");
    }

    log_message("Hooks installed: %d/2", hook_count);
    hooks_installed = 1;
#else
    log_message("Hooks DISABLED (ENABLE_HOOKS=0)");
#endif
}

/**
 * Check if libOsiris.dylib is loaded and examine its exports
 */
static void check_osiris_library(void) {
    // Try to find libOsiris.dylib
    void *osiris = dlopen("@rpath/libOsiris.dylib", RTLD_NOLOAD);

    if (!osiris) {
        // Try @executable_path relative (works when injected into BG3)
        osiris = dlopen("@executable_path/../Frameworks/libOsiris.dylib", RTLD_NOW);
    }

    if (osiris) {
        log_message("libOsiris.dylib handle obtained!");

        // Look up key exported C symbols
        void *debugHook = dlsym(osiris, "DebugHook");
        void *createRule = dlsym(osiris, "CreateRule");
        void *defineFunction = dlsym(osiris, "DefineFunction");
        void *setInitSection = dlsym(osiris, "SetInitSection");

        // Try C++ mangled names for COsiris methods
        void *initGame = dlsym(osiris, "_ZN7COsiris8InitGameEv");
        void *load = dlsym(osiris, "_ZN7COsiris4LoadER12COsiSmartBuf");

        log_message("Osiris symbol addresses:");
        log_message("  DebugHook: %p", debugHook);
        log_message("  CreateRule: %p", createRule);
        log_message("  DefineFunction: %p", defineFunction);
        log_message("  SetInitSection: %p", setInitSection);
        log_message("  COsiris::InitGame: %p", initGame);
        log_message("  COsiris::Load: %p", load);

        // Count how many we found
        int found = 0;
        if (debugHook) found++;
        if (createRule) found++;
        if (defineFunction) found++;
        if (setInitSection) found++;
        if (initGame) found++;
        if (load) found++;

        log_message("Found %d/6 key Osiris symbols", found);

        // Don't close - we need this handle for hooks
        // dlclose(osiris);
    } else {
        log_message("libOsiris.dylib not yet loaded");
        log_message("  dlerror: %s", dlerror());
    }
}

/**
 * Callback for when new images are loaded
 * This lets us know when libOsiris.dylib becomes available
 */
static void image_added_callback(const struct mach_header *mh, intptr_t slide) {
    // Find the name of this image
    uint32_t count = _dyld_image_count();
    for (uint32_t i = 0; i < count; i++) {
        if (_dyld_get_image_header(i) == mh) {
            const char *name = _dyld_get_image_name(i);
            if (name && strstr(name, "libOsiris")) {
                log_message(">>> libOsiris.dylib loaded dynamically! Slide: 0x%lx", (long)slide);
                check_osiris_library();
                // Install hooks when Osiris loads
                install_hooks();
            }
            break;
        }
    }
}

/**
 * Main constructor - runs when dylib is loaded
 */
__attribute__((constructor))
static void bg3se_init(void) {
    // Clear log file
    FILE *f = fopen(LOG_FILE, "w");
    if (f) {
        fprintf(f, "=== %s v%s ===\n", BG3SE_NAME, BG3SE_VERSION);
        fprintf(f, "Injection timestamp: %ld\n", (long)time(NULL));
        fprintf(f, "Process ID: %d\n", getpid());
        fclose(f);
    }

    log_message("=== %s v%s initialized ===", BG3SE_NAME, BG3SE_VERSION);
    log_message("Running in process: %s (PID: %d)", getprogname(), getpid());

    // Get architecture
#if defined(__arm64__)
    log_message("Architecture: ARM64 (Apple Silicon)");
#elif defined(__x86_64__)
    log_message("Architecture: x86_64 (Rosetta/Intel)");
#else
    log_message("Architecture: Unknown");
#endif

    // Log Dobby availability
    log_message("Dobby inline hooking: enabled");

    // Enumerate loaded images
    enumerate_loaded_images();

    // Check for Osiris library
    check_osiris_library();

    // Try to install hooks now (in case Osiris is already loaded)
    install_hooks();

    // Register callback for when new images load
    _dyld_register_func_for_add_image(image_added_callback);

    log_message("Image load callback registered");
    log_message("=== Initialization complete ===");
}

/**
 * Destructor - runs when dylib is unloaded (usually at process exit)
 */
__attribute__((destructor))
static void bg3se_cleanup(void) {
    log_message("=== %s shutting down ===", BG3SE_NAME);
    log_message("Final hook call counts:");
    log_message("  COsiris::InitGame: %d calls", initGame_call_count);
    log_message("  COsiris::Load: %d calls", load_call_count);
}
