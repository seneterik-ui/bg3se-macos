# ARM64 Hooking Prevention Strategies & Best Practices

**Document Version:** 1.0
**Last Updated:** December 2025
**Scope:** BG3SE-macOS reverse engineering on ARM64 Apple Silicon
**Status:** Production-tested patterns and prevention techniques

## Overview

This document consolidates hard-won lessons from BG3SE-macOS reverse engineering on ARM64. The key learnings are the result of crashes, data corruption, and weeks of debugging. These strategies prevent the most common ARM64 hooking failures.

## Key Learnings from BG3SE-macOS Development

### 1. Dobby Inline Hooks Corrupt PC-Relative ARM64 Instructions

**The Problem:**

Dobby's inline hooking can corrupt PC-relative addressing patterns on ARM64, specifically the `ADRP+LDR` (Load Register) sequences used for global variable access.

**Why it happens:**

- ARM64 uses 4KB-page-granularity PC-relative addressing
- `ADRP xN, #0x1234567000` loads the page address (aligned to 4KB boundary)
- `LDR xN, [xN, #0xABC]` adds the page offset to access the global
- Dobby's hook trampoline can corrupt the page offset calculation if not careful

**Example of the issue:**

```asm
; Original code accessing RPGStats singleton
0x101234567: ADRP x8, #0x1089b0000    ; Load page
0x10123456B: LDR  x8, [x8, #0xac80]   ; Load singleton from page offset
0x10123456F: LDR  x9, [x8, #0x348]    ; Access member

; After corrupt Dobby hook, the ADRP address or LDR offset may be corrupted
0x101234567: ADRP x8, #0x1089d0000    ; WRONG page!
0x10123456B: LDR  x8, [x8, #0xac80]   ; Offset doesn't match new page
```

### 2. TypeContext Metadata != Actual Manager Data

**The Problem:**

C++ type metadata (RTTI, TypeContext) doesn't necessarily match the actual runtime memory layout. The struct definition in headers is not always what's in memory, especially for:

- Complex STL containers (std::vector, std::map) with different alignment on ARM64
- Template instantiations with implicit padding
- Singletons with conditional initialization

**Example from BG3SE-macOS:**

```c
// Windows x64 layout (from headers):
struct RPGStats {
    void* VMT;              // 0x00
    CNamedElementManager Objects;  // 0x08
    // ...
};

// ARM64 actual layout (verified via runtime probing):
// Objects is at +0xC0, not +0x08!
// Reason: ARM64 aligns std::vector differently
```

**Why it matters for hooking:**

- Hooking a function to capture struct field values? Use runtime probing first
- The field offset in the struct layout may not match the offset the function uses
- Always verify with `Ext.Debug.ProbeStruct()` before assuming Windows layout

### 3. const& Parameters on ARM64 Are Passed as Pointers

**The Problem:**

C++ `const&` (const reference) parameters are passed differently on ARM64 vs x86_64:

- **x86_64**: Reference passed directly in register or stack (value semantics in calling convention)
- **ARM64**: Reference passed as **pointer** (x0, x1, x2, etc.)

**Critical for hooking:**

When you hook a function with `const&` parameters and try to read them:

```c
// WRONG - will crash or read garbage
void fake_Init(const uint32_t& spell_name_fs) {
    uint32_t value = spell_name_fs;  // Reading from register, not memory!
}

// CORRECT - read from the pointer
void fake_Init(const uint32_t* spell_name_fs) {
    uint32_t value = *spell_name_fs;  // Dereference pointer first
}
```

**Example from BG3SE-macOS:**

```c
// Real function signature
void eoc::SpellPrototype::Init(ls::FixedString const& spellName);

// ARM64 calling convention converts to:
// x0 = this (SpellPrototype*)
// x1 = pointer to FixedString (NOT the value itself!)

// Correct hook implementation:
void fake_SpellPrototype_Init(void* this, const uint32_t* spell_name_fs) {
    uint32_t fs_value = *spell_name_fs;  // Must dereference!
    // ... use fs_value
}
```

## Prevention Strategies

### Strategy 1: Use Frida Interceptor with onEnter-Only

**Principle:** Non-invasive hooking that doesn't modify code

**Why it's safer:**

- Frida Interceptor patches the code minimally
- `onEnter` hooks only (no return value capture) avoid x8 issues
- Runs in a sandboxed JS context, doesn't corrupt ARM64 addressing

**Pattern:**

```javascript
// Good: onEnter-only, capture arguments only
Interceptor.attach(Module.findExportByName(null, "SpellPrototype_Init"), {
    onEnter: function(args) {
        var this_ptr = args[0];
        var fs_ptr = args[1];  // Already a pointer on ARM64!
        var fs_value = Memory.readU32(fs_ptr);  // Dereference to get value
        send({
            type: "call",
            timestamp: Date.now(),
            fs: fs_value.toString(16)
        });
    }
    // NO onLeave - avoids x8 corruption
});
```

**When to use:**

- Discovering singleton values at runtime
- Capturing function arguments
- Building mappings (component name → type index)
- Any situation where you only need to **observe** behavior

**When NOT to use:**

- You need to modify return values
- You need to change control flow (skip calls, redirect to different function)
- You need to prevent the function from running

### Strategy 2: Always Verify Offset Assumptions with Runtime Probing

**Principle:** Trust the binary, not the source code headers

**Why it's critical:**

- Headers are documentation, not truth
- ARM64 uses different alignment rules than x86_64
- Template instantiations may have different layouts
- Singletons might use conditional initialization with different memory sizes

**Pattern using Lua Debug API:**

```lua
-- Before hooking, probe the actual offsets
function probe_rpgstats_offsets()
    local rpg_ptr = Ext.Memory.Read(
        Ext.Memory.GetModuleBase("Baldur") + 0x89c5730, 8)
    if rpg_ptr == 0 then
        Ext.Print("RPGStats not initialized yet")
        return
    end

    -- Probe in 8-byte increments
    for offset = 0, 256, 8 do
        local value = Ext.Memory.Read(rpg_ptr + offset, 8)
        if value > 0x100000000 then  -- Likely a pointer
            Ext.Print(string.format("+0x%X: pointer=%p", offset, value))
        end
    end
end

probe_rpgstats_offsets()
```

**Pattern using Frida ProbeStruct:**

```javascript
function probeStruct(addr, name) {
    var base = ptr(addr);
    var results = {};

    for (var i = 0; i < 256; i += 8) {
        var val = base.add(i).readPointer();
        if (val.compare(ptr("0")) > 0) {
            results['+0x' + i.toString(16)] = val.toString();
        }
    }
    return results;
}

var findings = probeStruct(rpgStatsAddr, "RPGStats");
Object.keys(findings).forEach(k => console.log(k + ": " + findings[k]));
```

**Before and after probing:**

```
BEFORE (assumed from Windows headers):
  Objects manager at +0x08

AFTER (probed on actual binary):
  Objects manager at +0xC0

Result: Hook using +0xC0, not +0x08
```

### Strategy 3: Document the Distinction Between Metadata and Data Structures

**Principle:** Separate compilation-time knowledge from runtime reality

**Why it matters:**

- Code that works on Windows fails on macOS ARM64
- The same code works on different game versions if structures changed
- Future developers won't understand mysterious offset hardcoding

**Pattern - Create separate header files:**

```c
// component_definitions.h - From Windows source code (documentation)
struct SpellPrototype_Windows {
    uint32_t StatsObjectIndex;      // From Windows BG3SE headers
    uint32_t SpellTypeId;
    // ... windows layout ...
};

// component_offsets_arm64.h - Runtime-verified ARM64 layout
#define SPELLPROTOTYPE_STATSINDEX_OFFSET 0x00  // Verified via probe
#define SPELLPROTOTYPE_TYPEID_OFFSET 0x04      // Verified via probe
#define SPELLPROTOTYPE_SPELLID_OFFSET 0x08     // Verified via Ghidra disassembly

// component_offsets_arm64.c - Add VERIFICATION comments
const ComponentLayout SpellPrototypeLayout = {
    .name = "SpellPrototype",
    .size = 0x1A8,  // Verified: GetSpellPrototype creates (capacity*0x1A8)
    .fields = {
        {.offset = 0x00, .type = "uint32", .name = "StatsObjectIndex"},
        // Verified via: Ghidra disassembly of SpellPrototype::Init
        // which does: [x0 + 0x00] = stats_index
        // Status: VERIFIED_GHIDRA
    }
};
```

**Pattern - Comment every offset with verification method:**

```c
// From STATS.md, verified Dec 5, 2025:
// - Ghidra decompilation of StatsObject::GetFixedStringValue
// - Shows LDR [x22, #0x348] accessing FixedStrings buffer
// - Confirmed via runtime probe on WPN_Longsword stat object
#define RPGSTATS_FIXEDSTRINGS_OFFSET 0x348

// From empirical runtime probing (probe_spell_refmap.lua):
// - Loaded spell prototype manager
// - Inspected RefMap structure at manager+0x08
// - Found capacity=12289, size=1847 (matches known spell count)
#define SPELLPROTOTYPEMANAGER_REFMAP_OFFSET 0x08
```

### Strategy 4: Test Hooks on Non-Critical Functions First

**Principle:** Sandbox your hooking experiments

**Why it prevents crashes:**

- Non-critical functions can be called repeatedly
- If your hook crashes, it only affects that function
- Game doesn't crash if non-critical function has issues
- Easier to debug hook issues in isolation

**Pattern - Test hierarchy:**

```
1. START: Very simple read-only hook
   Interceptor.attach(simple_function, {
       onEnter: function(args) {
           console.log("Called with " + args[0]);
       }
   });

2. NEXT: Capture and send data (no modification)
   Interceptor.attach(function_with_args, {
       onEnter: function(args) {
           send({type: "call", arg0: args[0]});
       }
   });

3. THEN: Hook non-critical business logic
   Interceptor.attach(helper_function, {...});

4. FINALLY: Hook critical path
   Interceptor.attach(init_or_update_function, {...});
```

**Example - BG3SE-macOS pattern:**

```
✅ TESTED FIRST:  Frida hooks on TryGetSingleton (read-only)
✅ TESTED NEXT:   EntityStorage::TryGet (observer only)
✅ TESTED THEN:   GetRawComponent (map discovery)
⚠️  PROBLEMATIC:  Dobby hooks on SpellPrototype::Init (code modification)
❌ NEVER TRIED:   Dobby hooks on Entity::Create (would corrupt entity system)
```

## Best Practices by Task

### When Discovering Singletons

**Use:** Frida Interceptor onEnter-only
**Don't use:** Dobby hooking

```javascript
// GOOD: Discover EntityWorld singleton via IsInCombat hook
Interceptor.attach(ptr("0x10124f92c"), {
    onEnter: function(args) {
        // x0 = EntityWorld* (first argument on ARM64)
        var world_ptr = args[0];
        console.log("EntityWorld = " + world_ptr);
        send({type: "singleton", ptr: world_ptr.toString()});
    }
});
```

**Why:**
- Frida doesn't modify code, can't corrupt ADRP+LDR
- Captures pointers directly from registers
- Can run indefinitely without degradation

### When Capturing Component Type Indices

**Use:** Runtime memory reads + Frida observation
**Don't use:** Dobby hooks on critical ECS functions

```javascript
// GOOD: Hook GetRawComponent to learn type indices
Interceptor.attach(Module.findExportByName("libOsiris", "GetRawComponent"), {
    onEnter: function(args) {
        // x2 = typeIndex (16-bit, zero-extended to 32-bit)
        var type_index = args[2].toInt32() & 0xFFFF;
        var component_name = lookupComponentName(type_index);
        send({type: "component", index: type_index, name: component_name});
    }
});
```

**Why:**
- Observing doesn't modify behavior
- No return values = no x8 issues
- Works with Frida's safe interceptor model

### When Mapping Stats Objects

**Use:** Probe RPGStats directly, no hooking needed
**Don't use:** Dobby hooks on RPGStats manager functions

```c
// GOOD: Read RPGStats directly
void* get_stats_object_by_name(const char* name) {
    void* rpg_stats = *((void**)dlsym(RTLD_DEFAULT, "__ZN8RPGStats5m_ptrE"));
    if (!rpg_stats) return NULL;

    // Use runtime probing to find Objects manager
    void* objects_mgr = (void*)rpg_stats + RPGSTATS_OBJECTS_OFFSET;

    // Look up by name in the manager's HashMap
    // (no hooking required)
    return stats_object_lookup_by_name(objects_mgr, name);
}
```

**Why:**
- RPGStats::m_ptr is exported, can be dlsym'd
- No need to hook anything - read the data directly
- Avoids all hooking issues entirely

### When Modifying Function Behavior

**Use:** Lua or scripting layer modifications
**Fallback:** Dobby only if necessary, on libOsiris functions only

```c
// GOOD: Register custom Osiris function (Lua layer)
bool custom_GetSpellData(uint16_t stats_id, void* output_ptr) {
    // Lua wrapper that calls our code
    // Game doesn't even know we hooked anything
}

// OK: Hook libOsiris function (has different protections)
void* orig_Query = NULL;
void* fake_Query(uint16_t func_id, void* args) {
    // Custom logic here
    // ...
    // Call original
    return orig_Query(func_id, args);
}
// In init: DobbyHook(query_addr, fake_Query, &orig_Query);

// BAD: Never do this!
// DobbyHook(main_binary_function, fake, &orig);  // ❌ Crashes on macOS
```

**Why:**
- Lua layer modifications are safe (no code patching)
- libOsiris.dylib is loaded at runtime, writable (Dobby can modify)
- Main binary is signed and immutable

### When Verifying Offset Accuracy

**Workflow:**

```
1. Hypothesis: "FixedStrings pool is at RPGStats+0x348"

2. Verify with Ghidra:
   - Decompile StatsObject::GetFixedStringValue
   - Find: [x22, #0x348] instruction
   - Confirm offset in disassembly

3. Verify with runtime probe:
   - Capture RPGStats pointer
   - Read +0x348 as pointer
   - Verify it points to valid memory with FixedString data

4. Use offset in code:
   // VERIFIED_GHIDRA + VERIFIED_RUNTIME
   #define RPGSTATS_FIXEDSTRINGS_OFFSET 0x348
```

**Never assume Windows layout matches ARM64 layout.**

## ARM64-Specific Pitfalls and Solutions

### Pitfall 1: const& Semantics

**Problem:**

```c
// Windows x86_64:
void Init(const std::vector<int>& items);  // Reference fits in register

// ARM64:
void Init(const std::vector<int>& items);  // Pointer to the vector!
```

**Solution:**

When reading arguments in a hook:

```javascript
// ARM64 Interceptor.onEnter(args):
// args[0], args[1], args[2]... are the actual parameters
// For const&, args[N] is a POINTER

var vector_ptr = args[0];      // This is a pointer
var vector_size = Memory.readU32(vector_ptr.add(16));  // Read size field
```

### Pitfall 2: Alignment Differences

**Problem:**

Structs on ARM64 use different alignment than x86_64:

```c
struct Example {
    uint32_t a;     // 4 bytes
    uint64_t b;     // 8 bytes (aligned to 8-byte boundary)
    uint32_t c;     // 4 bytes
};

// x86_64: a=0x00, b=0x04, c=0x0C
// ARM64:  a=0x00, b=0x08, c=0x10  (padding inserted before b)
```

**Solution:**

Never assume contiguous offsets. Always verify:

```lua
-- Probe to find actual offsets
for offset = 0, 64, 4 do
    local val = Ext.Memory.ReadU32(struct_ptr + offset)
    if val == expected_field_value then
        Ext.Print(string.format("Field found at +0x%X", offset))
    end
end
```

### Pitfall 3: ADRP+LDR Pattern Assumptions

**Problem:**

Code like this may not work after Dobby patches it:

```asm
ADRP x8, #0x108900000      ; Load page
LDR  x8, [x8, #0xac80]     ; Load offset

; After Dobby hook: addresses can be corrupted
```

**Solution:**

- Avoid hooking functions that use ADRP+LDR patterns
- Use dlsym or direct memory reads instead
- If you must hook, test thoroughly on non-critical functions first

### Pitfall 4: x8 Indirect Return Buffer

**Problem:**

Functions returning >16 bytes expect x8 to contain a buffer pointer:

```c
// Function that returns 64-byte struct
ls::Result TryGetSingleton<T>(EntityWorld* world);

// If you call this incorrectly:
call_function(world);  // ❌ x8 uninitialized, will crash

// Must be:
LsResult buf = {0};
call_function_with_x8_buffer(world, &buf);  // ✅ x8 = &buf
```

**Solution:**

Use the provided `call_try_get_singleton_with_x8()` wrapper:

```c
// From arm64_call.c
void* world = get_entity_world();
void* singleton = call_try_get_singleton_with_x8(
    (TryGetSingletonFn)function_ptr,
    world
);
```

## Frida vs Dobby: Decision Tree

```
Are you DISCOVERING information (reading, not modifying)?
├─ YES: Use Frida Interceptor (safe, non-invasive)
└─ NO: Are you modifying libOsiris.dylib behavior?
    ├─ YES: Use Dobby (hook libOsiris functions)
    └─ NO: Are you absolutely sure you need hooking?
        ├─ YES: Use Lua layer modifications
        └─ NO: Read the data directly (dlsym, memory reads)
```

## Testing and Validation Checklist

Before deploying any hook:

- [ ] **Memory safety**: Can the hooked function still access its data?
- [ ] **ARM64 ABI**: Did I handle const&, x8, alignment correctly?
- [ ] **Non-critical first**: Did I test on a helper function before critical path?
- [ ] **Runtime probe**: Did I verify offsets on the actual binary, not from headers?
- [ ] **ADRP+LDR**: Does the function use PC-relative addressing? (If yes, use Frida only)
- [ ] **Code modification**: Is this Dobby hook modifying code in the main binary? (If yes, ❌ don't)
- [ ] **Fallback path**: What happens if this hook fails silently?
- [ ] **Log coverage**: Can I tell from logs that the hook ran and what it captured?

## Production Patterns

### Singleton Discovery Pattern

```javascript
// tools/frida/discover_singleton.js
// Safe, verified pattern from BG3SE-macOS

Interceptor.attach(ptr("0x10124f92c"), {  // IsInCombat
    onEnter: function(args) {
        var entityWorld = args[0];
        console.log("Captured EntityWorld: " + entityWorld);

        // Store for later use
        send({
            type: "singleton_found",
            name: "EntityWorld",
            address: entityWorld.toString(),
            timestamp: new Date()
        });
    }
    // NOTE: No onLeave! Avoids return value issues
});
```

### Component Type Mapping Pattern

```javascript
// tools/frida/discover_components.js
// Observable approach - never modifies behavior

var component_map = {};

Interceptor.attach(Module.findExportByName(null, "GetRawComponent"), {
    onEnter: function(args) {
        var typeIndex = args[2].toInt32() & 0xFFFF;
        var size = args[3].toInt32();

        if (component_map[typeIndex] === undefined) {
            console.log(`Found component type ${typeIndex}, size=${size}`);
            component_map[typeIndex] = size;

            send({
                type: "component_discovered",
                index: typeIndex,
                size: size
            });
        }
    }
});
```

### Offset Verification Pattern

```lua
-- scripts/library/verify_offsets.lua
-- Runtime verification before using offsets

function verify_offset(base_ptr, offset, expected_marker)
    if base_ptr == 0 then
        return false, "base_ptr is NULL"
    end

    local value = Ext.Memory.Read(base_ptr + offset, 8)
    if value == 0 then
        return false, string.format("offset %d reads as NULL", offset)
    end

    if expected_marker and value ~= expected_marker then
        return false, string.format("expected %p, got %p", expected_marker, value)
    end

    return true, string.format("verified: +0x%X -> %p", offset, value)
end

-- Usage:
local rpg_ptr = Ext.Memory.Read(
    Ext.Memory.GetModuleBase("Baldur") + 0x89c5730, 8)

local ok, msg = verify_offset(rpg_ptr, 0x348, nil)
if ok then
    Ext.Print("FixedStrings offset: " .. msg)
else
    Ext.Print("ERROR: " .. msg)
end
```

## Related Documentation

- **ARM64 Patterns Reference**: `/tools/skills/bg3se-macos-ghidra/references/arm64-patterns.md`
- **Frida Tools**: `/tools/frida/README.md`
- **Ghidra Workflow**: `/agent_docs/ghidra.md`
- **Architecture**: `/agent_docs/architecture.md`

## Summary of Prevention Strategies

| Strategy | Prevents | Cost | When to Use |
|----------|----------|------|------------|
| **Frida onEnter-only** | ADRP corruption, x8 issues, code modification problems | Low | Discovery, observation |
| **Runtime probing** | TypeContext mismatches, ARM64 alignment issues | Low | Before any hooking |
| **Offset documentation** | Silent failures, future regressions | Very low | Always |
| **Non-critical testing** | Cascading failures, hard-to-debug crashes | Medium | Before critical hooks |
| **Direct memory reads** | ALL hooking issues | Low-medium | When possible |
| **Lua layer modifications** | Code patching issues entirely | Low | When behavior modification needed |

## Conclusion

The core principle is simple: **observe first, modify last**. Use Frida to learn the system, use runtime probing to verify offsets, and only use Dobby for the minimal modifications necessary on libOsiris functions. Never modify the main binary with Dobby, never assume Windows layouts, and always test non-critical paths first.

The 3000+ lines of ARM64-aware code in BG3SE-macOS exist because these lessons were learned the hard way through crashes, data corruption, and weeks of debugging. By following these patterns, future reverse engineering efforts can avoid the same pitfalls.
