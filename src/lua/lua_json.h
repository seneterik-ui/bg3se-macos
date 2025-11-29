/**
 * BG3SE-macOS - Lua JSON Module
 *
 * Provides JSON parsing and stringification for Lua integration.
 * Implements Ext.Json.Parse and Ext.Json.Stringify API.
 */

#ifndef BG3SE_LUA_JSON_H
#define BG3SE_LUA_JSON_H

#include <lua.h>
#include <lauxlib.h>

#ifdef __cplusplus
extern "C" {
#endif

// ============================================================================
// Lua C API Functions (for Ext.Json namespace)
// ============================================================================

/**
 * Ext.Json.Parse - Parse JSON string into Lua value
 * @param L Lua state (expects string on stack)
 * @return 1 (parsed value or nil on failure)
 */
int lua_ext_json_parse(lua_State *L);

/**
 * Ext.Json.Stringify - Convert Lua value to JSON string
 * @param L Lua state (expects value on stack)
 * @return 1 (JSON string)
 */
int lua_ext_json_stringify(lua_State *L);

// ============================================================================
// Low-level JSON Functions (for internal use)
// ============================================================================

/**
 * Stringify a Lua value at given stack index into a luaL_Buffer.
 * Used internally and by other modules that need JSON output.
 * @param L Lua state
 * @param index Stack index of value to stringify
 * @param b luaL_Buffer to append to (must be initialized)
 */
void json_stringify_value(lua_State *L, int index, luaL_Buffer *b);

/**
 * Parse a JSON value and push it onto the Lua stack.
 * @param L Lua state
 * @param json JSON string to parse
 * @return Pointer to next character after parsed value, or NULL on error
 */
const char *json_parse_value(lua_State *L, const char *json);

/**
 * Register Ext.Json namespace functions in a table.
 * @param L Lua state
 * @param ext_table_index Stack index of Ext table
 */
void lua_json_register(lua_State *L, int ext_table_index);

#ifdef __cplusplus
}
#endif

#endif // BG3SE_LUA_JSON_H
