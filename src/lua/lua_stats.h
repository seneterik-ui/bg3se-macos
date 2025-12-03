/**
 * lua_stats.h - Lua bindings for Ext.Stats API
 *
 * Provides Lua access to the game's stats system for reading and modifying
 * game statistics (weapons, armor, spells, statuses, passives, etc.)
 *
 * Lua API:
 *   Ext.Stats.Get(name) -> StatsObject or nil
 *   Ext.Stats.GetAll(type?) -> array of names
 *   Ext.Stats.Sync(name) -> bool
 *   Ext.Stats.Create(name, type, template?) -> StatsObject or nil
 *   Ext.Stats.IsReady() -> bool
 *   Ext.Stats.DumpTypes() -> void
 *
 * StatsObject methods:
 *   obj.Name -> string
 *   obj.Type -> string
 *   obj.Level -> int
 *   obj.Using -> string or nil
 *   obj:GetProperty(name) -> value
 *   obj:SetProperty(name, value) -> bool
 */

#ifndef LUA_STATS_H
#define LUA_STATS_H

#include "../../lib/lua/src/lua.h"

/**
 * Register Ext.Stats API functions.
 *
 * @param L Lua state
 * @param ext_table_index Stack index of Ext table
 */
void lua_stats_register(lua_State *L, int ext_table_index);

#endif // LUA_STATS_H
