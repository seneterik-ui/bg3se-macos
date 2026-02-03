# Plan: Issue #6 - NetChannel API (Multiplayer Networking)

## Goal

Implement the NetChannel API for multiplayer mod state synchronization, enabling mods to communicate between server and clients.

## Research Summary

### What We Already Have ✅
| Component | Status | Location |
|-----------|--------|----------|
| `Ext.Json.Parse/Stringify` | ✅ Working | `src/lua/lua_json.c` |
| `Ext.IsServer/IsClient` | ✅ Working | `src/lua/lua_context.c` |
| `Ext.Events` subscription | ✅ Working | `src/lua/lua_events.c` |
| UserID component infra | ✅ Working | `src/entity/component_offsets.h` |

### Portable Lua Layer (Copy from Windows)
| File | Lines | Purpose |
|------|-------|---------|
| `NetChannel.lua` | ~110 | Channel class: SetHandler, SendToServer, RequestToClient, etc. |
| `NetworkManager.lua` | ~70 | Channel registry, routes NetModMessage events to channels |

These are **100% pure Lua** - no C++ dependencies, just wrap `Ext.Net.*` functions.

### New C Code Required
```c
// Ext.Net namespace - 6 core functions
Ext.Net.PostMessageToServer(channel, payload, module, handler, replyId, binary)
Ext.Net.PostMessageToUser(userId, channel, payload, module, handler, replyId, binary)
Ext.Net.PostMessageToClient(guid, channel, payload, module, handler, replyId, binary)
Ext.Net.BroadcastMessage(channel, payload, excludeChar, module, handler, replyId, binary)
Ext.Net.Version()      // Returns protocol version (2 for binary support)
Ext.Net.IsHost()       // Returns true if this peer is the host
```

### Network Hook Requirements (Reverse Engineering)
From Windows BG3SE reference:
1. **NetMessageFactory** - Register custom `NETMSG_SCRIPT_EXTENDER` message type
2. **Message dispatch hook** - Intercept incoming messages to fire `NetModMessage` event
3. **Message send hook** - Inject outgoing messages into game's network layer

## Implementation Approach

### Phase 1: Lua Layer + Stubs (Get API Working)
**Goal:** Make the Lua API functional for single-player/local testing.

1. **Port Lua files:**
   - Copy `NetChannel.lua` → `src/lua/scripts/NetChannel.lua`
   - Copy `NetworkManager.lua` → `src/lua/scripts/NetworkManager.lua`
   - Load during Lua state initialization

2. **Create `src/lua/lua_net.c`:**
   - Implement stub functions that work locally (same-process calls)
   - For single-player: messages route directly without network
   - Fire `NetModMessage` event immediately for local messages

3. **Add `NetModMessage` event:**
   - Event fields: `Channel`, `Payload`, `Module`, `UserID`, `RequestId`, `ReplyId`, `Binary`
   - Subscribe in NetworkManager.lua to dispatch to channels

### Phase 2: Reverse Engineer Network Hooks
**Goal:** Find macOS equivalents of Windows network hooks.

**Ghidra targets:**
- Search for `NetMessageFactory` or `MessageFactory` strings
- Find `NETMSG_` enum values
- Look for protobuf-related functions (`.pb.h` patterns)
- Analyze `ClientConnectMessage` handling

**Frida probing:**
- Hook known network-related components (`esv::NetComponent`)
- Trace message serialization calls

### Phase 3: Full Multiplayer Implementation
**Goal:** Real network message transmission.

1. Hook `NetMessageFactory::Register` to add our message type
2. Hook message processing to intercept incoming extender messages
3. Implement `PostMessage*` functions to send via game's network layer
4. Handle request/reply correlation with callback IDs

## File Changes

### New Files
| File | Purpose |
|------|---------|
| `src/lua/lua_net.c` | Ext.Net.* C implementations |
| `src/lua/lua_net.h` | Header with function declarations |
| `src/lua/scripts/NetChannel.lua` | Portable channel class |
| `src/lua/scripts/NetworkManager.lua` | Channel registry |
| `src/net/net_message.c` | Network message infrastructure (Phase 3) |
| `ghidra/offsets/NETWORK.md` | Discovered network offsets |

### Modified Files
| File | Change |
|------|--------|
| `src/injector/main.c` | Register Ext.Net namespace, load Lua scripts |
| `src/lua/lua_events.c` | Add NetModMessage event type |
| `CMakeLists.txt` | Add new source files |

## API Surface (Target)

```lua
-- Channel creation
local channel = Net.CreateChannel(ModuleUUID, "MyChannel")

-- Fire-and-forget handler
channel:SetHandler(function(data, user)
    Osi.TemplateAddTo(data.Template, data.Target, data.Amount)
end)

-- Request/reply handler
channel:SetRequestHandler(function(data, user)
    return { Result = CheckSomething(data) }
end)

-- Client → Server
channel:SendToServer(data)
channel:RequestToServer(data, function(response) ... end)

-- Server → Client
channel:SendToClient(data, userOrGuid)
channel:Broadcast(data)
channel:RequestToClient(data, user, function(response) ... end)

-- Utility
Ext.Net.IsHost()  -- Returns true if host
```

## Verification Plan

### Phase 1 Testing (Local)
```lua
-- Test 1: Channel creation
local ch = Net.CreateChannel(ModuleUUID, "TestChannel")
assert(ch ~= nil, "Channel created")

-- Test 2: Local message round-trip
ch:SetHandler(function(data, user)
    _P("Received: " .. Ext.Json.Stringify(data))
end)
ch:SendToServer({test = "hello"})  -- Should fire immediately in single-player

-- Test 3: Request/reply
ch:SetRequestHandler(function(data, user)
    return { echo = data.message }
end)
ch:RequestToServer({message = "ping"}, function(response)
    assert(response.echo == "ping", "Reply received")
end)
```

### Phase 3 Testing (Multiplayer)
- Host + client in same LAN
- Verify messages transmit between peers
- Test request/reply latency
- Verify UserID tracking

## Dependencies

- **Ext.Json** ✅ (already implemented)
- **Ext.Events** ✅ (already implemented)
- **Ext.IsServer/IsClient** ✅ (already implemented)
- **Ext.Mod.IsModLoaded** ❌ (needs implementation - NetworkManager.lua uses this)

## Risk Assessment

| Risk | Mitigation |
|------|------------|
| Network hooks hard to find | Phase 1 works without them (local-only) |
| Protocol format unknown | Start with JSON, add binary later |
| Multiplayer testing difficult | Focus on local first, add multi-peer later |

## Estimated Effort

| Phase | Scope | Effort |
|-------|-------|--------|
| Phase 1 | Lua layer + local stubs | 1-2 sessions |
| Phase 2 | Ghidra RE for hooks | 2-3 sessions |
| Phase 3 | Full multiplayer | 2-3 sessions |

**Total:** ~6-8 sessions for full implementation

## Scope Decision

**Full Implementation** - All 3 phases:
- Phase 1: Lua layer + local stubs
- Phase 2: Ghidra RE for network hooks
- Phase 3: Complete multiplayer support

## Implementation Order

1. **First:** Implement `Ext.Mod.IsModLoaded` (dependency)
2. **Then:** Phase 1 - Port Lua files, create `lua_net.c` with local stubs
3. **Then:** Phase 2 - Ghidra RE to find NetMessageFactory, message hooks
4. **Finally:** Phase 3 - Wire up real network transmission
