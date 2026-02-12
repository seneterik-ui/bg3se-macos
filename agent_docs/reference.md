# Reference Implementation

**Local clone:** `/Users/tomdimino/Desktop/Programming/game-modding/bg3/bg3se` (Norbyte's Windows BG3SE)
**GitHub:** https://github.com/Norbyte/bg3se

## Key Directories
- `BG3Extender/Osiris/` - Osiris binding patterns, function lookups
- `BG3Extender/Lua/` - Lua API design, Ext.* implementations
- `BG3Extender/Lua/Libs/Entity.inl` - Entity Lua bindings
- `BG3Extender/GameDefinitions/` - Entity/component structures
- `BG3Extender/GameDefinitions/EntitySystem.cpp` - EntitySystemHelpers
- `BG3Extender/GameDefinitions/Components/Components.h` - Component structs
- `CoreLib/` - Core utilities, memory patterns

## Searching with RLAMA

**Prefer RLAMA** for semantic search over the reference implementation.

```bash
# Semantic queries against Windows BG3SE reference
rlama run bg3se-windows --query "how does entity component access work?"
rlama run bg3se-windows --query "GUID to entity handle lookup"
rlama run bg3se-windows --query "Lua component binding pattern"
rlama run bg3se-windows --query "Osiris query output parameters and OutParamList"

# Compare with macOS port
rlama run bg3se-macos --query "how does Osiris dispatch work?"
```

## Technical Patterns from Reference

### Pattern Scanning
When dlsym fails (symbols stripped):
```c
static const FunctionPattern g_osirisPatterns[] = {
    {"InternalQuery", "_Z13InternalQueryjP16COsiArgumentDesc", "FD 43...", 28},
};
void *addr = resolve_by_pattern("libOsiris.dylib", &pattern);
```

### Osiris Function Calls
```c
// Query (returns values)
OsiArgumentDesc *args = alloc_args(2);
set_arg_string(&args[0], guid, 1);  // isGuid=1
int result = osiris_query_by_id(funcId, args);

// Call (no return)
osiris_call_by_id(funcId, args);
```

### Lua API Registration
```c
void lua_ext_register_basic(lua_State *L, int ext_table_index) {
    lua_pushcfunction(L, lua_ext_print);
    lua_setfield(L, ext_table_index, "Print");
}
```
