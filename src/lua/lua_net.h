/**
 * BG3SE-macOS - Ext.Net Lua Bindings
 *
 * Network messaging API for multiplayer mod synchronization.
 *
 * API:
 *   Ext.Net.PostMessageToServer(channel, payload, module, handler, replyId, binary)
 *   Ext.Net.PostMessageToUser(userId, channel, payload, module, handler, replyId, binary)
 *   Ext.Net.PostMessageToClient(guid, channel, payload, module, handler, replyId, binary)
 *   Ext.Net.BroadcastMessage(channel, payload, excludeChar, module, handler, replyId, binary)
 *   Ext.Net.Version() -> int
 *   Ext.Net.IsHost() -> boolean
 *
 * Issue #6: NetChannel API
 */

#ifndef LUA_NET_H
#define LUA_NET_H

#include <lua.h>

/**
 * Register the Ext.Net namespace.
 *
 * @param L               Lua state
 * @param ext_table_index Stack index of Ext table
 * @param is_server       Whether this is the server context
 */
void lua_net_register(lua_State *L, int ext_table_index, bool is_server);

/**
 * Process pending network messages.
 * Should be called once per tick from both server and client contexts.
 *
 * @param server_L Server Lua state (or NULL)
 * @param client_L Client Lua state (or NULL)
 */
void lua_net_process_messages(lua_State *server_L, lua_State *client_L);

/**
 * Initialize the network subsystem.
 * Called during BG3SE initialization.
 */
void lua_net_init(void);

/**
 * Load the embedded Net library Lua scripts.
 * MUST be called AFTER Ext is set as a global (lua_setglobal(L, "Ext")).
 * Creates the global Net table with Net.CreateChannel.
 *
 * @param L Lua state
 */
void lua_net_load_scripts(lua_State *L);

#endif /* LUA_NET_H */
