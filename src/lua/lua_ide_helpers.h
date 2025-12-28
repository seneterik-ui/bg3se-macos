/**
 * BG3SE-macOS - IDE Type Helper Generation
 *
 * Generates LuaLS-compatible type annotation files for VS Code IntelliSense.
 * Provides Ext.Types.GenerateIdeHelpers() API function.
 */

#ifndef LUA_IDE_HELPERS_H
#define LUA_IDE_HELPERS_H

#include <lua.h>

/**
 * Ext.Types.GenerateIdeHelpers(filename?) -> string
 *
 * Generates LuaLS type annotations and returns the content as a string.
 * If filename is provided, also saves to ~/Library/Application Support/BG3SE/<filename>
 *
 * Output includes:
 * - Basic types (EntityHandle, vec3, vec4)
 * - All enum types as @alias
 * - All component types as @class with @field annotations
 * - Ext.* namespace function signatures
 * - Osi and Mods global stubs
 *
 * @param L Lua state
 * @return 1 (returns string content)
 */
int lua_ide_helpers_generate(lua_State *L);

#endif // LUA_IDE_HELPERS_H
