# Signal Integration RE Notes

## Goal
Find the `ComponentCallbackRegistry` offset within EntityWorld on ARM64 macOS,
then hook `Signal::Add` to automatically fire entity events on component create/destroy.

## Windows BG3SE Struct Layouts (from source)

### EntityWorld (EntitySystem.h:799-804)
```
EntityWorld {
    ...
    Array<EntityCommandBuffer> CommandBuffers;     // +?? (16 bytes)
    ComponentCallbackRegistry ComponentCallbacks;  // +?? ← TARGET
    bool RegisterPhaseEnded;
    bool Active;
    bool NeedsOptimize;
    bool PerformingECSUpdate;
    ...
}
```

### ComponentCallbackRegistry (EntitySystem.h:609-614)
```
struct ComponentCallbackRegistry {
    Array<ComponentCallbacks*> Callbacks;   // ptr(8) + capacity(4) + size(4) = 16 bytes total
};
```
- `Get(ComponentTypeIndex)` returns `Callbacks[index]`

### ComponentCallbacks (EntitySystem.h:602-607)
```
struct ComponentCallbacks {
    void* VMT;                    // +0x00 (8 bytes)
    Signal OnConstruct;           // +0x08 (24 bytes)
    Signal OnDestroy;             // +0x20 (24 bytes)
};
// Total: 56 bytes (0x38)
```

### Signal<EntityRef*, void*> (BaseFunction.h:407-477)
```
struct Signal {
    uint64_t NextRegistrantId;    // +0x00 (8 bytes), starts at 1
    Array<Connection> Connections; // +0x08 (16 bytes: ptr(8) + capacity(4) + size(4))
};
// Total: 24 bytes (0x18)
```

### Connection (BaseFunction.h:411-440)
```
struct Connection {
    Function Handler;             // +0x00 (64 bytes)
    uint64_t RegistrantIndex;     // +0x40 (8 bytes)
};
// Total: 72 bytes (0x48)
```

### Function<void(EntityRef*, void*)> (BaseFunction.h:116-191)
```
class Function {
    FunctionStorage* pStorage_;   // +0x00 (8 bytes, points to storage_ below)
    FunctionStorage storage_;     // +0x08 (56 bytes)
};
// Total: 64 bytes (0x40)

struct FunctionStorage {
    CallProc*  call_;             // +0x00 (8 bytes) — the invoke function pointer
    CopyProc*  copy_;             // +0x08 (8 bytes)
    MoveProc*  move_;             // +0x10 (8 bytes)
    uintptr_t  data_[4];         // +0x18 (32 bytes) — inline context data
};
// Total: 56 bytes (0x38)
```

## RE Strategy

### Approach A: Runtime Probing (preferred)
With game running and EntityWorld* known, scan for the pattern:
1. Find an `Array<ptr>` field where:
   - Each element points to a 56-byte struct
   - First 8 bytes of each struct look like a VMT (valid pointer)
   - Bytes at +0x08 contain a uint64_t >= 1 (NextRegistrantId)
   - The array size matches the number of component types (~2000)
   - Array layout: buf_(8B ptr) + capacity_(4B uint32) + size_(4B uint32)

```lua
-- Probe for ComponentCallbackRegistry
local world = Ext.Entity.GetWorldAddress()
local probeRange = 0x400  -- scan 1024 bytes from known fields
for offset = 0, probeRange, 8 do
    local ptr = Ext.Debug.ReadPtr(world + offset)
    if ptr and Ext.Debug.IsValidPointer(ptr) then
        local cap = Ext.Debug.ReadU32(world + offset + 8)
        local sz  = Ext.Debug.ReadU32(world + offset + 12)
        if sz > 1000 and sz < 3000 and cap >= sz then
            -- Possible Array<ComponentCallbacks*>
            local first = Ext.Debug.ReadPtr(ptr)
            if first and Ext.Debug.IsValidPointer(first) then
                local vmt = Ext.Debug.ReadPtr(first)
                local nextId = Ext.Debug.ReadU64(first + 8)
                if nextId >= 1 and nextId < 1000000 then
                    _P(string.format("Candidate CCR at +0x%x: size=%d, cap=%d, vmt=%s, nextId=%d",
                        offset, sz, cap, _H(vmt), nextId))
                end
            end
        end
    end
end
```

### Approach B: Ghidra Static Analysis
1. Search for `AddComponent<T>` template instantiations
2. Find where they access `EntityWorld->ComponentCallbacks`
3. The decompiled code will show the offset as a constant

### Approach C: Offset from Known Fields
Since we know `CommandBuffers` comes immediately before `ComponentCallbackRegistry`:
1. Find `CommandBuffers` field in EntityWorld (it's an Array<EntityCommandBuffer>)
2. ComponentCallbackRegistry starts at `CommandBuffers_offset + 16`

## Signal Hooking Strategy

Once we have the ComponentCallbackRegistry offset:

### Option 1: Direct Signal Manipulation
- Read `ComponentCallbacks*` for the target component type
- Read `OnConstruct.NextRegistrantId` at callbacks+0x08
- Construct a `Connection` with our C function handler
- Append to `OnConstruct.Connections` array
- Challenge: Must construct a valid `Function<>` object (64 bytes)

### Option 2: VMT Hooking
- Patch the VMT of individual `ComponentCallbacks` objects
- Replace OnConstruct/OnDestroy virtual methods
- Simpler but less compatible across game versions

### Option 3: Dobby Hook on Signal::Invoke
- Find the `Signal::Invoke` template instantiation address
- Hook it with Dobby
- Filter by Signal pointer to identify which component type fired
- Most robust but requires finding the function address

## Discovered Offsets (Runtime Verified 2026-02-07)

### EntityWorld → CCR
- **EntityWorld + 0x240** = `ComponentCallbackRegistry` (inline `Array<ComponentCallbacks*>`)
  - `+0x240`: `buf_` (ptr to array of ComponentCallbacks*)
  - `+0x248`: `capacity_` (uint32)
  - `+0x24C`: `size_` (uint32) — observed value: 2709

### ImmediateWorldCache → CCR chain
- **EntityWorld + 0x3F0** = `ImmediateWorldCache*`
- **ImmediateWorldCache + 0x240** = `ComponentCallbackRegistry**` (pointer to &EntityWorld.CCR.buf_)
- **ImmediateWorldCache + 0x250** = `EntityWorld*` (back-pointer)

### ComponentCallbacks Layout (Runtime Verified)
```
+0x00: VMT              (8B)  - valid code pointer (e.g., 0x10d4de098)
+0x08: OnConstruct.NextRegistrantId (8B uint64) - starts at 1
+0x10: OnConstruct.Connections.buf_ (8B ptr)
+0x18: OnConstruct.Connections.capacity_ (4B uint32)
+0x1C: OnConstruct.Connections.size_ (4B uint32)
+0x20: OnDestroy.NextRegistrantId (8B uint64) - starts at 1
+0x28: OnDestroy.Connections.buf_ (8B ptr)
+0x30: OnDestroy.Connections.capacity_ (4B uint32)
+0x34: OnDestroy.Connections.size_ (4B uint32)
Total: 0x38 = 56 bytes ✓
```

### Connection Layout (Runtime Verified)
```
+0x00: Handler.pStorage_       (8B ptr, self-referential → +0x08)
+0x08: Handler.storage_.call_  (8B function ptr)
+0x10: Handler.storage_.copy_  (8B function ptr)
+0x18: Handler.storage_.move_  (8B function ptr)
+0x20: Handler.storage_.data_[0] (8B)
+0x28: Handler.storage_.data_[1] (8B)
+0x30: Handler.storage_.data_[2] (8B)
+0x38: Handler.storage_.data_[3] (8B)
+0x40: RegistrantIndex         (8B uint64)
Total: 0x48 = 72 bytes ✓
```

### Observations
- Many component types have exactly 1 OnConstruct and 1 OnDestroy handler (game's own)
- Some have NextRegistrantId=0 with no Connections (uninitialized / tag components)
- Entry indices match component TypeIndex values (e.g., index 468 = a specific component)
- First non-null entries start around index 463

## Status
- [x] Find ComponentCallbackRegistry offset in macOS EntityWorld → **+0x240**
- [x] Verify ComponentCallbacks struct layout on ARM64 → **56 bytes, confirmed**
- [x] Verify Signal struct layout on ARM64 → **24 bytes, confirmed**
- [x] Implement Signal hooking → **Connection injection (v0.36.46)**
- [ ] Test with actual component create/destroy events

## Signal Hooking Implementation (v0.36.46)

**Approach:** Direct Connection injection into CCR Signal arrays.

Since `Signal::Invoke` is inlined into every AddComponent/RemoveComponent template (no standalone
function to Dobby-hook), we inject our own `Connection` objects into each subscribed type's
`OnConstruct.Connections` and `OnDestroy.Connections` arrays. The game's inlined Signal::Invoke
loop naturally calls our handler during component creation/destruction.

**Key design decisions:**
- Lazy installation: signal hooks installed on first subscription for each type (not all ~2709)
- Connection includes `copy_`/`move_` procs so the game can safely reallocate the array
- `data_[0]` stores `type_index` so our handler knows which component type fired
- macOS BG3 uses system malloc, so our `calloc`'d buffers are compatible with game's realloc/free
- Cleanup removes all injected Connections before Lua state shutdown (prevents stale callbacks)
