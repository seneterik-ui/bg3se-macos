/**
 * lua_ui.h - Lua Bindings for Ext.UI (Noesis Stub API)
 *
 * MCM (Mod Configuration Menu) uses Ext.UI for ESC menu button injection.
 * These stubs allow MCM to gracefully degrade without crashing.
 * MCM checks for nil returns and falls back to IMGUI-only mode.
 *
 * Stubs:
 *   Ext.UI.GetRoot() -> nil
 *   Ext.UI.RegisterType(name) -> nil (no-op)
 *   Ext.UI.Instantiate(name) -> nil
 *   Ext.UI.IsReady() -> false
 *   Ext.UI.SetValue(path, value) -> nil (no-op)
 */

#ifndef LUA_UI_H
#define LUA_UI_H

#include "../../lib/lua/src/lua.h"

/**
 * Register Ext.UI namespace functions.
 * @param L Lua state
 * @param ext_table_idx Index of the Ext table on the stack
 */
void lua_ext_register_ui(lua_State *L, int ext_table_idx);

#endif // LUA_UI_H
