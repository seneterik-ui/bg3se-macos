# Issue #4: Custom Osiris Function Registration

## Goal
Implement `Ext.Osiris.NewQuery()`, `Ext.Osiris.NewCall()`, and `Ext.Osiris.NewEvent()` to allow Lua mods to register custom Osiris functions callable from story scripts.

## Target API (from Windows BG3SE)

```lua
-- Register a custom query (returns values via OUT params)
Ext.Osiris.NewQuery(name, signature, handler)
-- Example:
Ext.Osiris.NewQuery("MyMod_GetPlayerHealth", "[in](GUIDSTRING)_Target,[out](INTEGER)_Health", function(target)
    local entity = Ext.Entity.Get(target)
    return entity.Health.CurrentHP  -- Returned as OUT param
end)

-- Register a custom call (no return value)
Ext.Osiris.NewCall(name, signature, handler)
-- Example:
Ext.Osiris.NewCall("MyMod_SpawnEffect", "(GUIDSTRING)_Target,(STRING)_Effect", function(target, effect)
    -- Spawn visual effect at target
end)

-- Register a custom event (can be raised from Lua)
Ext.Osiris.NewEvent(name, signature)
-- Example:
Ext.Osiris.NewEvent("MyMod_OnItemUsed", "(GUIDSTRING)_Item,(GUIDSTRING)_User")
```

## Architecture Overview

### Windows BG3SE Implementation

The Windows implementation uses a multi-layered approach:

1. **CustomFunctionManager** - Stores registered custom functions (calls, queries, events)
2. **CustomFunctionInjector** - Hooks into Osiris dispatch to intercept custom function calls
3. **CustomLuaCall/CustomLuaQuery** - Lua-specific wrappers that invoke Lua callbacks
4. **Header Injection** - Appends custom function declarations to `story_header.div`

Key flow:
```
Story Script calls custom function
    ↓
Osiris dispatches via Call/Query function pointer
    ↓
CustomFunctionInjector::CallWrapper/QueryWrapper
    ↓
Check osiToDivMappings_ (Osiris ID → Custom handle)
    ↓
If custom: CustomFunctionManager::Call/Query
    ↓
CustomLuaCall/Query::Call/Query → Invoke Lua handler
```

### Simplified macOS Approach

Since we already hook `InternalQuery` and `InternalCall` in main.c, we can:

1. **Intercept at the hook level** - Check if function ID matches a custom function
2. **Custom function registry** - Map custom function names → handlers
3. **Header generation** - NOT needed for runtime (only for story compilation)

## Implementation Phases

### Phase 1: Custom Function Registry Module

**New File: `src/osiris/custom_functions.h`**
```c
#ifndef BG3SE_CUSTOM_FUNCTIONS_H
#define BG3SE_CUSTOM_FUNCTIONS_H

#include <stdint.h>
#include <lua.h>

// Custom function types
typedef enum {
    CUSTOM_FUNC_CALL = 1,
    CUSTOM_FUNC_QUERY = 2,
    CUSTOM_FUNC_EVENT = 3
} CustomFuncType;

// Parameter direction
typedef enum {
    PARAM_DIR_IN = 0,
    PARAM_DIR_OUT = 1
} ParamDirection;

// Parameter definition
typedef struct {
    char name[64];
    uint8_t type;        // OsiValueType
    uint8_t direction;   // ParamDirection
} CustomFuncParam;

// Custom function definition
typedef struct {
    char name[128];
    CustomFuncType type;
    int callback_ref;    // Lua registry reference
    uint32_t arity;
    uint32_t num_in_params;
    uint32_t num_out_params;
    CustomFuncParam params[16];  // Max 16 params
    uint32_t assigned_id;        // Osiris function ID (assigned at registration)
} CustomFunction;

// Initialize custom function system
void custom_func_init(void);

// Register a custom function
// Returns function handle, or 0 on failure
uint32_t custom_func_register(const char *name, CustomFuncType type,
                              int callback_ref, const char *signature);

// Look up custom function by Osiris ID
CustomFunction *custom_func_get_by_id(uint32_t funcId);

// Look up custom function by name
CustomFunction *custom_func_get_by_name(const char *name);

// Check if ID is a custom function
int custom_func_is_custom(uint32_t funcId);

// Call a custom function (invoke Lua callback)
int custom_func_call(lua_State *L, uint32_t funcId, OsiArgumentDesc *args);

// Query a custom function (invoke Lua callback, fill OUT params)
int custom_func_query(lua_State *L, uint32_t funcId, OsiArgumentDesc *args);

// Clear all custom functions (on session reset)
void custom_func_clear(void);

#endif
```

**New File: `src/osiris/custom_functions.c`**
```c
// Implementation details:
// - Use a simple array + hash map for O(1) lookup
// - Custom function IDs start at 0x80000000 | CUSTOM_FUNC_BASE
// - Parse signature string: "[in](TYPE)_Name,[out](TYPE)_Name"
// - Store Lua callback via luaL_ref()
```

### Phase 2: Signature Parsing

Parse Windows-style signatures:
```
"[in](GUIDSTRING)_Target,[out](INTEGER)_Health"
  ↓
params[0] = { name="Target", type=GUIDSTRING, dir=IN }
params[1] = { name="Health", type=INTEGER, dir=OUT }
```

Type mapping:
- `INTEGER` → OSI_TYPE_INTEGER
- `INTEGER64` → OSI_TYPE_INTEGER64
- `REAL` → OSI_TYPE_REAL
- `STRING` → OSI_TYPE_STRING
- `GUIDSTRING` → OSI_TYPE_GUIDSTRING

### Phase 3: Hook Integration

**Modify: `src/injector/main.c`**

In the existing `lua_osi_call()` function, add custom function check:

```c
// At the start of lua_osi_call()
if (custom_func_is_custom(funcId)) {
    // Dispatch to custom function handler
    return custom_func_call_dispatch(L, funcId, args);
}
```

For InternalQuery hook:
```c
// Wrap InternalQuery to intercept custom queries
bool hooked_internal_query(uint32_t funcId, OsiArgumentDesc *args) {
    if (custom_func_is_custom(funcId)) {
        return custom_func_query(g_LuaState, funcId, args);
    }
    return pfn_InternalQuery(funcId, args);
}
```

### Phase 4: Lua Bindings

**Modify: `src/lua/lua_osiris.c`**

```c
// Ext.Osiris.NewCall(name, signature, handler)
static int lua_ext_osiris_newcall(lua_State *L) {
    const char *name = luaL_checkstring(L, 1);
    const char *signature = luaL_checkstring(L, 2);
    luaL_checktype(L, 3, LUA_TFUNCTION);

    // Store callback
    lua_pushvalue(L, 3);
    int callback_ref = luaL_ref(L, LUA_REGISTRYINDEX);

    // Register custom function
    uint32_t handle = custom_func_register(name, CUSTOM_FUNC_CALL,
                                           callback_ref, signature);
    if (handle == 0) {
        luaL_unref(L, LUA_REGISTRYINDEX, callback_ref);
        return luaL_error(L, "Failed to register custom call '%s'", name);
    }

    lua_pushinteger(L, handle);
    return 1;
}

// Ext.Osiris.NewQuery(name, signature, handler)
static int lua_ext_osiris_newquery(lua_State *L) {
    // Similar to NewCall but type = CUSTOM_FUNC_QUERY
}

// Ext.Osiris.NewEvent(name, signature)
static int lua_ext_osiris_newevent(lua_State *L) {
    // No callback for events - they're raised from Lua
}

// Register in lua_osiris_register()
lua_pushcfunction(L, lua_ext_osiris_newcall);
lua_setfield(L, -2, "NewCall");
lua_pushcfunction(L, lua_ext_osiris_newquery);
lua_setfield(L, -2, "NewQuery");
lua_pushcfunction(L, lua_ext_osiris_newevent);
lua_setfield(L, -2, "NewEvent");
```

### Phase 5: ID Assignment Strategy

**Option A: Virtual IDs (Simple)**
- Assign IDs in range 0xF0000000+ (unlikely to collide with game)
- Custom functions only callable from Lua, not story scripts
- Simpler implementation, no header injection needed

**Option B: Full Integration (Complex)**
- Hook `GetFunctionMappings` to inject custom function mappings
- Generate and append headers to `story_header.div`
- Requires finding/hooking additional Osiris functions
- Enables calling custom functions from story scripts

**Recommended: Start with Option A**, iterate to Option B if needed.

## Key Challenges

### 1. ID Collision
Custom function IDs must not collide with game's Osiris IDs.
- Game IDs: 0x00000000 - 0x7FFFFFFF (observed max ~2M)
- Custom IDs: 0xF0000000+ (4B+ range, safe)

### 2. Session Lifecycle
Custom functions must be cleared on session reset:
- Hook `SessionReset` or `DeleteAllData` event
- Call `custom_func_clear()` to unregister all
- Lua callbacks may already be invalid after state reset

### 3. OUT Parameter Handling
For queries, Lua handler returns values that must fill OUT params:
```lua
function handler(in1, in2)
    return out1, out2  -- Returned values fill OUT params
end
```

### 4. Type Marshalling
Convert between Lua types and Osiris types:
- INTEGER: lua_tointeger ↔ int32_t
- REAL: lua_tonumber ↔ float
- STRING: lua_tostring ↔ const char*
- GUIDSTRING: lua_tostring ↔ const char* (validate GUID format)

## Files to Modify/Create

| File | Action | Description |
|------|--------|-------------|
| `src/osiris/custom_functions.h` | Create | Custom function registry header |
| `src/osiris/custom_functions.c` | Create | Custom function registry implementation |
| `src/lua/lua_osiris.c` | Modify | Add NewCall/NewQuery/NewEvent bindings |
| `src/lua/lua_osiris.h` | Modify | Add function declarations |
| `src/injector/main.c` | Modify | Hook integration for dispatch |
| `CMakeLists.txt` | Modify | Add new source files |

## Testing

### Basic Registration Test
```lua
-- Register a simple query
Ext.Osiris.NewQuery("TestMod_GetValue", "[out](INTEGER)_Value", function()
    return 42
end)

-- Test via Osi namespace
local result = Osi.TestMod_GetValue()
_P("Result: " .. tostring(result))  -- Should print 42
```

### Multi-Parameter Test
```lua
Ext.Osiris.NewQuery("TestMod_Add", "[in](INTEGER)_A,[in](INTEGER)_B,[out](INTEGER)_Sum",
    function(a, b)
        return a + b
    end)

local sum = Osi.TestMod_Add(10, 20)
_P("Sum: " .. tostring(sum))  -- Should print 30
```

### Call Test (No Return)
```lua
Ext.Osiris.NewCall("TestMod_Log", "(STRING)_Message", function(msg)
    _P("Custom call: " .. msg)
end)

Osi.TestMod_Log("Hello from custom call!")
```

## Execution Order

1. Create `custom_functions.h` with data structures
2. Implement `custom_functions.c`:
   - Registry initialization
   - Signature parsing
   - Function registration
   - ID assignment
   - Lookup functions
3. Add Lua bindings in `lua_osiris.c`
4. Integrate with main.c dispatch:
   - Intercept in `lua_osi_call()`
   - Add custom function check before InternalQuery/Call
5. Test with simple query/call
6. Add session lifecycle management (clear on reset)
7. Document in ROADMAP.md

## Future Enhancements (Phase 2)

- **Header Injection**: Hook `GetFunctionMappings` to enable story script calls
- **Event Raising**: `Ext.Osiris.RaiseEvent(name, args...)` to trigger custom events
- **Function Listing**: `Ext.Osiris.GetCustomFunctions()` for debugging
- **Hot Reload**: Re-register functions without session restart
