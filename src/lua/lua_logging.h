/**
 * BG3SE-macOS - Lua Logging API
 *
 * Exposes the C logging system to Lua scripts via Ext.Log namespace.
 *
 * API (Module-aware - requires module name):
 *   Ext.Log.Debug(module, message) - Log debug message
 *   Ext.Log.Info(module, message)  - Log info message
 *   Ext.Log.Warn(module, message)  - Log warning message
 *   Ext.Log.Error(module, message) - Log error message
 *
 * API (Convenience - no module required, Windows BG3SE compatible):
 *   Ext.Log.Print(...)         - Log info message (varargs like print())
 *   Ext.Log.PrintWarning(...)  - Log warning message
 *   Ext.Log.PrintError(...)    - Log error message
 *
 * API (Configuration):
 *   Ext.Log.GetLevel(module)       - Get current log level for module
 *   Ext.Log.SetLevel(module, level) - Set log level for module
 *   Ext.Log.GetGlobalLevel()       - Get global log level
 *   Ext.Log.SetGlobalLevel(level)  - Set global log level
 *   Ext.Log.GetModules()           - Get list of available module names
 *
 * Module names: "Core", "Console", "Lua", "Osiris", "Entity", "Events",
 *               "Stats", "Timer", "Hooks", "Mod", "Memory", "Persist",
 *               "Game", "Input"
 *
 * Level names: "DEBUG", "INFO", "WARN", "ERROR", "NONE"
 */

#ifndef BG3SE_LUA_LOGGING_H
#define BG3SE_LUA_LOGGING_H

#include <lua.h>
#include <lauxlib.h>

#ifdef __cplusplus
extern "C" {
#endif

// ============================================================================
// Lua C API Functions
// ============================================================================

/**
 * Ext.Log.Debug(module, message) - Log debug message
 * @param module Module name as string (e.g., "Lua", "Stats")
 * @param message Message to log
 */
int lua_log_debug(lua_State *L);

/**
 * Ext.Log.Info(module, message) - Log info message
 */
int lua_log_info(lua_State *L);

/**
 * Ext.Log.Warn(module, message) - Log warning message
 */
int lua_log_warn(lua_State *L);

/**
 * Ext.Log.Error(module, message) - Log error message
 */
int lua_log_error(lua_State *L);

/**
 * Ext.Log.GetLevel(module) - Get log level for module
 * @param module Module name
 * @return Level name ("DEBUG", "INFO", "WARN", "ERROR")
 */
int lua_log_get_level(lua_State *L);

/**
 * Ext.Log.SetLevel(module, level) - Set log level for module
 * @param module Module name
 * @param level Level name
 */
int lua_log_set_level(lua_State *L);

/**
 * Ext.Log.GetGlobalLevel() - Get global log level
 * @return Level name
 */
int lua_log_get_global_level(lua_State *L);

/**
 * Ext.Log.SetGlobalLevel(level) - Set global log level
 * @param level Level name
 */
int lua_log_set_global_level(lua_State *L);

/**
 * Ext.Log.GetModules() - Get list of available module names
 * @return Table of module names
 */
int lua_log_get_modules(lua_State *L);

// ============================================================================
// Convenience Print Functions (non-static for use by Ext.Utils aliases)
// ============================================================================

/**
 * Ext.Log.Print(...) / Ext.Utils.Print(...) - Log info message (varargs)
 */
int lua_log_print(lua_State *L);

/**
 * Ext.Log.PrintWarning(...) / Ext.Utils.PrintWarning(...) - Log warning
 */
int lua_log_print_warning(lua_State *L);

/**
 * Ext.Log.PrintError(...) / Ext.Utils.PrintError(...) - Log error
 */
int lua_log_print_error(lua_State *L);

// ============================================================================
// Registration
// ============================================================================

/**
 * Register Ext.Log namespace functions
 * @param L Lua state
 * @param ext_table_index Stack index of Ext table
 */
void lua_ext_register_log(lua_State *L, int ext_table_index);

#ifdef __cplusplus
}
#endif

#endif // BG3SE_LUA_LOGGING_H
