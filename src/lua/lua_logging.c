/**
 * BG3SE-macOS - Lua Logging API Implementation
 *
 * Exposes the C logging system to Lua scripts.
 */

#include "lua_logging.h"
#include "../core/logging.h"
#include <string.h>
#include <stdio.h>

// ============================================================================
// Helper: Log at specified level
// ============================================================================

static int log_at_level(lua_State *L, LogLevel level) {
    const char *module_name = luaL_checkstring(L, 1);
    const char *message = luaL_checkstring(L, 2);

    LogModule module = log_module_from_string(module_name);

    // Check if this message would be logged (lazy check)
    if (!log_should_write(level, module)) {
        return 0;
    }

    // Write the log message (use "Lua" as file for Lua-originated logs)
    log_write(level, module, "Lua", 0, "%s", message);

    return 0;
}

// ============================================================================
// Ext.Log.Debug/Info/Warn/Error (module-aware versions)
// ============================================================================

int lua_log_debug(lua_State *L) {
    return log_at_level(L, LOG_LEVEL_DEBUG);
}

// ============================================================================
// Ext.Log.Print/PrintWarning/PrintError (convenience versions - no module arg)
// These match Windows BG3SE's simple print API
// ============================================================================

/**
 * Helper: Concatenate all Lua arguments into a single message string.
 * Mimics Lua's print() behavior of space-separated tostring() of each arg.
 */
static const char *concat_args_to_message(lua_State *L, int start_arg) {
    static char buffer[4096];
    buffer[0] = '\0';
    int pos = 0;
    int nargs = lua_gettop(L);

    for (int i = start_arg; i <= nargs && pos < (int)sizeof(buffer) - 1; i++) {
        // Convert argument to string
        const char *s = luaL_tolstring(L, i, NULL);
        if (s) {
            if (i > start_arg && pos < (int)sizeof(buffer) - 1) {
                buffer[pos++] = ' ';
            }
            while (*s && pos < (int)sizeof(buffer) - 1) {
                buffer[pos++] = *s++;
            }
        }
        lua_pop(L, 1);  // Pop the tostring result
    }
    buffer[pos] = '\0';
    return buffer;
}

/**
 * Ext.Log.Print(...) - Log info message to console (varargs, no module required)
 * Matches Windows BG3SE's Ext.Log.Print() API
 */
int lua_log_print(lua_State *L) {
    const char *message = concat_args_to_message(L, 1);

    if (!log_should_write(LOG_LEVEL_INFO, LOG_MODULE_LUA)) {
        return 0;
    }

    log_write(LOG_LEVEL_INFO, LOG_MODULE_LUA, "Lua", 0, "%s", message);
    return 0;
}

/**
 * Ext.Log.PrintWarning(...) - Log warning message (varargs, no module required)
 */
int lua_log_print_warning(lua_State *L) {
    const char *message = concat_args_to_message(L, 1);

    if (!log_should_write(LOG_LEVEL_WARN, LOG_MODULE_LUA)) {
        return 0;
    }

    log_write(LOG_LEVEL_WARN, LOG_MODULE_LUA, "Lua", 0, "%s", message);
    return 0;
}

/**
 * Ext.Log.PrintError(...) - Log error message (varargs, no module required)
 */
int lua_log_print_error(lua_State *L) {
    const char *message = concat_args_to_message(L, 1);

    if (!log_should_write(LOG_LEVEL_ERROR, LOG_MODULE_LUA)) {
        return 0;
    }

    log_write(LOG_LEVEL_ERROR, LOG_MODULE_LUA, "Lua", 0, "%s", message);
    return 0;
}

int lua_log_info(lua_State *L) {
    return log_at_level(L, LOG_LEVEL_INFO);
}

int lua_log_warn(lua_State *L) {
    return log_at_level(L, LOG_LEVEL_WARN);
}

int lua_log_error(lua_State *L) {
    return log_at_level(L, LOG_LEVEL_ERROR);
}

// ============================================================================
// Ext.Log.GetLevel / SetLevel
// ============================================================================

int lua_log_get_level(lua_State *L) {
    const char *module_name = luaL_checkstring(L, 1);
    LogModule module = log_module_from_string(module_name);
    LogLevel level = log_get_module_level(module);

    lua_pushstring(L, log_level_name(level));
    return 1;
}

int lua_log_set_level(lua_State *L) {
    const char *module_name = luaL_checkstring(L, 1);
    const char *level_name = luaL_checkstring(L, 2);

    LogModule module = log_module_from_string(module_name);
    LogLevel level = log_level_from_string(level_name);

    log_set_module_level(module, level);

    LOG_LUA_INFO("Set log level for %s to %s",
                 log_module_name(module), log_level_name(level));

    return 0;
}

// ============================================================================
// Ext.Log.GetGlobalLevel / SetGlobalLevel
// ============================================================================

int lua_log_get_global_level(lua_State *L) {
    LogLevel level = log_get_global_level();
    lua_pushstring(L, log_level_name(level));
    return 1;
}

int lua_log_set_global_level(lua_State *L) {
    const char *level_name = luaL_checkstring(L, 1);
    LogLevel level = log_level_from_string(level_name);

    log_set_global_level(level);

    LOG_LUA_INFO("Set global log level to %s", log_level_name(level));

    return 0;
}

// ============================================================================
// Ext.Log.GetModules
// ============================================================================

int lua_log_get_modules(lua_State *L) {
    lua_newtable(L);

    for (int i = 0; i < LOG_MODULE_MAX; i++) {
        lua_pushstring(L, log_module_name((LogModule)i));
        lua_rawseti(L, -2, i + 1);
    }

    return 1;
}

// ============================================================================
// Registration
// ============================================================================

void lua_ext_register_log(lua_State *L, int ext_table_index) {
    // Convert negative index to absolute
    if (ext_table_index < 0) {
        ext_table_index = lua_gettop(L) + ext_table_index + 1;
    }

    // Create Ext.Log table
    lua_newtable(L);

    // Register logging functions
    lua_pushcfunction(L, lua_log_debug);
    lua_setfield(L, -2, "Debug");

    lua_pushcfunction(L, lua_log_info);
    lua_setfield(L, -2, "Info");

    lua_pushcfunction(L, lua_log_warn);
    lua_setfield(L, -2, "Warn");

    lua_pushcfunction(L, lua_log_error);
    lua_setfield(L, -2, "Error");

    // Register level query/set functions
    lua_pushcfunction(L, lua_log_get_level);
    lua_setfield(L, -2, "GetLevel");

    lua_pushcfunction(L, lua_log_set_level);
    lua_setfield(L, -2, "SetLevel");

    lua_pushcfunction(L, lua_log_get_global_level);
    lua_setfield(L, -2, "GetGlobalLevel");

    lua_pushcfunction(L, lua_log_set_global_level);
    lua_setfield(L, -2, "SetGlobalLevel");

    // Register module listing
    lua_pushcfunction(L, lua_log_get_modules);
    lua_setfield(L, -2, "GetModules");

    // Register convenience print functions (Windows BG3SE parity)
    lua_pushcfunction(L, lua_log_print);
    lua_setfield(L, -2, "Print");

    lua_pushcfunction(L, lua_log_print_warning);
    lua_setfield(L, -2, "PrintWarning");

    lua_pushcfunction(L, lua_log_print_error);
    lua_setfield(L, -2, "PrintError");

    // Set Ext.Log = table
    lua_setfield(L, ext_table_index, "Log");

    LOG_LUA_INFO("Registered Ext.Log namespace (12 functions)");
}
