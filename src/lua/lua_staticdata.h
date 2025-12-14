/**
 * lua_staticdata.h - Lua bindings for Ext.StaticData API
 *
 * Provides Lua access to immutable game data like Feats, Races, Backgrounds, etc.
 */

#ifndef LUA_STATICDATA_H
#define LUA_STATICDATA_H

#include <lua.h>

/**
 * Register Ext.StaticData API with the Lua state.
 *
 * @param L Lua state
 * @param ext_table_idx Stack index of Ext table
 */
void lua_staticdata_register(lua_State *L, int ext_table_idx);

#endif // LUA_STATICDATA_H
