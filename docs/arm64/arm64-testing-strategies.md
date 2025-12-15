# ARM64 Testing Strategies for Game Reverse Engineering

**Document Version:** 1.0
**Last Updated:** December 2025
**Scope:** BG3SE-macOS testing approaches for ARM64-specific issues
**Status:** Production-tested techniques

## Overview

This document provides practical testing strategies for validating ARM64 reverse engineering work. Game reverse engineering has unique constraints:

- You cannot simply crash and restart; the test involves a 1GB+ binary
- Memory layouts vary by build; offsets change between game versions
- The environment (with mods, saves, game state) affects reproducibility
- You need to validate complex runtime behavior without full symbolic debugging

This guide covers the techniques that work specifically for BG3SE-macOS on ARM64.

## Testing Hierarchy

```
Tier 1: Memory Safety (Does my code crash?)
    ↓
Tier 2: Correctness (Does it return correct values?)
    ↓
Tier 3: Robustness (Does it work across game states?)
    ↓
Tier 4: Integration (Does it work with other systems?)
```

### Tier 1: Memory Safety Testing

**Goal:** Ensure your code doesn't cause crashes, segfaults, or memory corruption.

#### Technique 1.1: Null Pointer Validation

Every pointer must be checked:

```c
// ALWAYS check before dereferencing
void* ptr = get_some_pointer();
if (ptr == NULL) {
    log_message("Pointer is NULL, returning gracefully");
    return false;
}

// NEVER do this:
void* ptr = get_some_pointer();
void* value = *(void**)ptr;  // ❌ Crash if ptr is NULL
```

#### Technique 1.2: Bounds Checking for Array Access

```c
// VERIFY index before access
void* get_stat(uint32_t index) {
    void* objects_array = get_stats_objects_array();
    uint32_t count = get_stats_count();

    if (index >= count) {
        log_message("Index %u out of bounds (count=%u)", index, count);
        return NULL;
    }

    // Safe to access
    return objects_array[index];
}
```

#### Technique 1.3: Memory Range Validation

Before reading a struct, verify the pointer points to valid memory:

```lua
-- Lua equivalent: Use Ext.Debug.IsValidPointer
function read_struct_safely(addr, size)
    -- Check if memory is readable
    if not Ext.Debug.IsValidPointer(addr) then
        return nil, "Invalid pointer: " .. Ext.Debug.ClassifyPointer(addr)
    end

    -- Check bounds if we're in a known region
    local module_base = Ext.Memory.GetModuleBase("Baldur")
    if addr >= module_base and addr < module_base + 0x100000000 then
        -- In module range, likely valid
        local data = {}
        for i = 0, size-1, 8 do
            data[i] = Ext.Memory.Read(addr + i, 8)
        end
        return data
    end

    return nil, "Pointer outside module range"
end
```

#### Technique 1.4: Logging Every Hook Entry/Exit

```c
// Minimal overhead, catches crashes
void fake_function(void *arg1, uint32_t arg2) {
    log_message("ENTER fake_function: arg1=%p, arg2=%u", arg1, arg2);

    // Your logic here
    if (!arg1) {
        log_message("ERROR: NULL arg1 in fake_function");
        return;
    }

    log_message("EXIT fake_function success");
}
```

**Why:** If the game crashes with a cryptic message, the last log line tells you exactly where it failed.

### Tier 2: Correctness Testing

**Goal:** Verify the returned values are correct.

#### Technique 2.1: Known-Good Reference Values

```lua
-- Before deploying a hook, capture baseline values
function test_spell_prototype_init()
    -- Load a spell we know exists and have tested
    local spell = Ext.Stats.Get("Projectile_FireBolt")
    assert(spell ~= nil, "FireBolt should exist")
    assert(spell.Name == "Projectile_FireBolt", "Name mismatch")

    -- Log the known-good values
    local expected = {
        Damage = spell.Damage,
        SpellType = spell.SpellType,
        School = spell.School,
    }

    Ext.Print("BASELINE: " .. Ext.JSON.Stringify(expected))

    -- After your change:
    -- Compare actual values to baseline
    if actual.Damage ~= expected.Damage then
        error("Damage mismatch: expected " .. expected.Damage
            .. ", got " .. actual.Damage)
    end
end
```

#### Technique 2.2: Round-Trip Verification

```lua
-- Test: Create, read, verify
function test_create_and_verify()
    -- 1. Create a stat
    local stat = Ext.Stats.Create("TestSpell_Verify", "SpellData", "Projectile_FireBolt")

    -- 2. Set properties
    stat.Damage = "3d6"

    -- 3. Retrieve and verify
    local retrieved = Ext.Stats.Get("TestSpell_Verify")
    assert(retrieved ~= nil, "Should be able to retrieve created stat")
    assert(retrieved.Damage == "3d6", "Damage should be 3d6")

    Ext.Print("✅ Round-trip verification passed")
end
```

#### Technique 2.3: Consistency Checks

```c
// After reading a struct, verify internal consistency
bool verify_rpgstats_structure(void *rpg_stats) {
    // Read the Objects manager
    void* objects_mgr = (void*)rpg_stats + RPGSTATS_OBJECTS_OFFSET;

    // Verify the manager has valid-looking values
    uint32_t size = read_u32(objects_mgr + OBJECTS_MGR_SIZE_OFFSET);
    uint32_t capacity = read_u32(objects_mgr + OBJECTS_MGR_CAPACITY_OFFSET);

    // Sanity check: size should be <= capacity
    if (size > capacity) {
        log_message("CONSISTENCY FAIL: Objects size (%u) > capacity (%u)",
                    size, capacity);
        return false;
    }

    // Sanity check: size should be in reasonable range (not 0, not millions)
    if (size == 0 || size > 100000) {
        log_message("CONSISTENCY FAIL: Objects size (%u) out of range", size);
        return false;
    }

    return true;
}
```

### Tier 3: Robustness Testing

**Goal:** Verify your code works across different game states.

#### Technique 3.1: State Transition Testing

Test your code at different game phases:

```lua
-- File: test_across_states.lua
function test_in_different_states()
    local states = {
        "main_menu",
        "loading",
        "in_game",
        "in_combat",
        "inventory_open",
        "spell_selection",
    }

    for _, state in ipairs(states) do
        Ext.Print("Testing in state: " .. state)

        -- Call your function
        local result = Ext.Stats.Get("WPN_Longsword")

        if result == nil then
            Ext.Print("  ⚠️  NULL in " .. state)
        else
            Ext.Print("  ✅ OK: " .. result.Name)
        end
    end
end

-- Manual testing steps:
-- 1. Start game, stay in main menu, run test_in_different_states()
-- 2. Load a save, run test in game
-- 3. Start combat, run test while fighting
-- 4. Open inventory, run test
```

#### Technique 3.2: Edge Case Testing

```lua
-- Test boundary conditions
function test_edge_cases()
    -- Test 1: Empty string
    local empty = Ext.Stats.Get("")
    if empty ~= nil then
        Ext.Print("⚠️  Empty stat name returned non-nil: " .. empty.Name)
    else
        Ext.Print("✅ Empty stat name correctly returns nil")
    end

    -- Test 2: Very long name
    local long_name = string.rep("A", 1000)
    local result = Ext.Stats.Get(long_name)
    if result == nil then
        Ext.Print("✅ Long stat name returns nil as expected")
    end

    -- Test 3: Special characters
    local special = "Test<>Name|:?*"
    result = Ext.Stats.Get(special)
    if result == nil then
        Ext.Print("✅ Special characters handled")
    end

    -- Test 4: Unicode
    local unicode = "Test_名前_Имя"
    result = Ext.Stats.Get(unicode)
    Ext.Print("Unicode handling: " .. tostring(result))
end
```

#### Technique 3.3: Resource Allocation Testing

```c
// Track allocations to catch leaks
static int g_probe_calls = 0;
static int g_probe_errors = 0;

void* probe_with_tracking(void *base, uint32_t offset) {
    g_probe_calls++;

    void *ptr = (void*)base + offset;
    if (!is_valid_pointer(ptr)) {
        g_probe_errors++;
        log_message("Probe error count: %d/%d", g_probe_errors, g_probe_calls);
        return NULL;
    }

    return ptr;
}

// Periodic health check
void check_probe_health() {
    double error_rate = (double)g_probe_errors / g_probe_calls;
    if (error_rate > 0.1) {
        log_message("WARNING: High probe error rate: %.1f%%", error_rate * 100);
    }
}
```

### Tier 4: Integration Testing

**Goal:** Verify your code plays nicely with other systems.

#### Technique 4.1: API Contract Testing

```lua
-- Ensure your API behaves like other similar APIs
function test_api_consistency()
    -- Test 1: Ext.Stats should behave like other Ext.* APIs
    local stat = Ext.Stats.Get("WPN_Longsword")

    -- Verify required fields exist
    assert(stat.Name ~= nil, "stat.Name missing")
    assert(type(stat.Name) == "string", "stat.Name should be string")

    -- Test 2: Error handling consistency
    local missing = Ext.Stats.Get("NONEXISTENT_STAT")
    assert(missing == nil, "Missing stat should return nil, not error")

    -- Test 3: Iteration consistency
    local count = 0
    for name, _ in pairs(stat) do
        count = count + 1
    end
    assert(count > 0, "Stat should have properties")

    Ext.Print("✅ API consistency checks passed")
end
```

#### Technique 4.2: Hook Ordering Testing

```javascript
// If multiple hooks on the same function, test ordering
var call_order = [];

Interceptor.attach(ptr("0x123"), {
    onEnter: function(args) {
        call_order.push("hook1_enter");
    },
    onLeave: function(retval) {
        call_order.push("hook1_exit");
    }
});

Interceptor.attach(ptr("0x123"), {
    onEnter: function(args) {
        call_order.push("hook2_enter");
    }
});

// Later verify order
if (call_order[0] != "hook1_enter" || call_order[1] != "hook2_enter") {
    console.log("WARNING: Hook order unexpected: " + JSON.stringify(call_order));
}
```

#### Technique 4.3: Mod Compatibility Testing

```lua
-- Test that your changes don't break known mods
function test_mod_compatibility()
    -- Load stats that mods commonly use
    local mod_stats = {
        "DAIP_LevelUpAbility",     -- Artifice mod
        "CUSTOM_JUMP",              -- Jump extension
        "MOD_BARBARIAN_SPELL",      -- Class expansion
    }

    for _, stat_name in ipairs(mod_stats) do
        local stat = Ext.Stats.Get(stat_name)
        if stat then
            Ext.Print("✅ Mod stat available: " .. stat_name)
        else
            Ext.Print("⚠️  Mod stat missing: " .. stat_name)
        end
    end
end
```

## Testing at Scale

### Automated Testing Framework

```lua
-- test_framework.lua
local tests = {}
local passed = 0
local failed = 0

function register_test(name, fn)
    tests[name] = fn
end

function run_all_tests()
    Ext.Print("=== BG3SE Test Suite ===")
    for name, test_fn in pairs(tests) do
        local ok, err = pcall(test_fn)
        if ok then
            Ext.Print("✅ " .. name)
            passed = passed + 1
        else
            Ext.Print("❌ " .. name .. ": " .. err)
            failed = failed + 1
        end
    end

    local total = passed + failed
    Ext.Print(string.format("\nResults: %d/%d passed", passed, total))
    return failed == 0
end

-- Register tests
register_test("Stats.Get with valid name", function()
    local stat = Ext.Stats.Get("WPN_Longsword")
    assert(stat ~= nil, "Should find weapon")
end)

register_test("Stats.Get with invalid name", function()
    local stat = Ext.Stats.Get("INVALID_STAT_NAME_SURELY_DOESNT_EXIST")
    assert(stat == nil, "Should return nil for missing stat")
end)

-- Run all tests
-- run_all_tests()
```

### Performance Baseline Testing

```lua
-- test_performance.lua
function benchmark_stats_lookup()
    local iterations = 1000
    local names = {"WPN_Longsword", "ARM_Plate", "Projectile_FireBolt"}

    Ext.Debug.PrintTime("Starting benchmark")
    local start = Ext.Debug.Timestamp()

    for i = 1, iterations do
        for _, name in ipairs(names) do
            local stat = Ext.Stats.Get(name)
            assert(stat ~= nil, "Lookup should succeed")
        end
    end

    local elapsed = Ext.Debug.Timestamp() - start
    local avg_micros = (elapsed * 1000000) / (iterations * #names)

    Ext.Print(string.format(
        "Benchmark: %d lookups in %.3f seconds (%.1f µs per lookup)",
        iterations * #names, elapsed, avg_micros))

    -- Warn if performance degraded
    if avg_micros > 1000 then
        Ext.Print("⚠️  Performance warning: Lookup took > 1ms")
    end
end
```

## Testing Hooks on ARM64

### Hook Validation Checklist

Before using a Dobby hook, test all of these:

```c
static int test_hook(void) {
    // 1. Can we hook it?
    void* orig = NULL;
    int result = DobbyHook(function_addr, fake_function, &orig);
    if (result != DOBBY_SUCCESS) {
        log_message("FAIL: Could not hook (error %d)", result);
        return 0;
    }

    // 2. Does original function still work?
    void *test_arg = get_test_argument();
    void *orig_result = ((typedef_t)orig)(test_arg);
    if (orig_result == NULL) {
        log_message("FAIL: Original function returned NULL");
        return 0;
    }

    // 3. Does fake function get called?
    reset_hook_call_count();
    test_arg = get_test_argument();
    void *fake_result = ((typedef_t)function_addr)(test_arg);
    if (get_hook_call_count() == 0) {
        log_message("FAIL: Hook was not called");
        return 0;
    }

    // 4. Does fake function return correct values?
    if (fake_result != orig_result) {
        log_message("FAIL: fake returned %p, orig returned %p",
                    fake_result, orig_result);
        return 0;
    }

    // 5. Can we call it repeatedly without degradation?
    for (int i = 0; i < 100; i++) {
        test_arg = get_test_argument();
        void *repeat_result = ((typedef_t)function_addr)(test_arg);
        if (repeat_result == NULL) {
            log_message("FAIL: Hook failed on iteration %d", i);
            return 0;
        }
    }

    log_message("SUCCESS: Hook validation passed all checks");
    return 1;
}
```

## Testing with Frida

### Hook Testing Pattern

```javascript
// test_frida_hook.js
// Run with: frida -U -n "Baldur's Gate 3" -l test_frida_hook.js

var hook_hits = 0;
var hook_errors = 0;

function test_frida_hook() {
    console.log("Installing test hook...");

    Interceptor.attach(Module.findExportByName(null, "GetRawComponent"), {
        onEnter: function(args) {
            hook_hits++;

            try {
                var entity_world = args[0];
                var entity_handle = args[1];
                var type_index = args[2].toInt32() & 0xFFFF;
                var size = args[3].toInt32();

                if (hook_hits % 100 == 0) {
                    console.log(`[Hook] Hit ${hook_hits}: type=${type_index}, size=${size}`);
                }
            } catch (e) {
                hook_errors++;
                console.log("Hook error: " + e);
            }
        }
    });

    console.log("Hook installed, move around in game...");

    // Report every 5 seconds
    setInterval(function() {
        var error_rate = hook_errors / hook_hits * 100;
        console.log(`Stats: ${hook_hits} hits, ${hook_errors} errors (${error_rate.toFixed(1)}%)`);
    }, 5000);
}

test_frida_hook();
```

## Debugging Failed Tests

### The Debug Checklist

When a test fails:

1. **Enable verbose logging**
   ```c
   #define LOG_LEVEL DEBUG
   #define LOG_COMPONENT "TEST"
   ```

2. **Add memory validation**
   ```c
   if (!is_valid_pointer(ptr)) {
       log_message("FAIL: Invalid pointer at test step X");
       return;
   }
   ```

3. **Check game state**
   ```lua
   -- Is the game actually loaded?
   if Ext.Events.CanLoadModule() == false then
       Ext.Print("Game not fully loaded yet")
       return
   end
   ```

4. **Isolate the component**
   ```lua
   -- Test just the offset, not the whole chain
   local offset = 0x348
   local raw_value = Ext.Memory.Read(base_ptr + offset, 8)
   Ext.Print("Raw value at +0x348: " .. Ext.Debug.HexDump(raw_value, 1))
   ```

5. **Compare with working reference**
   ```lua
   -- We know this works from previous testing
   local known_good = Ext.Stats.Get("WPN_Longsword")

   -- Our new code
   local our_result = our_new_get_stat("WPN_Longsword")

   if our_result.Name ~= known_good.Name then
       Ext.Print("Name mismatch!")
       Ext.Print("  Expected: " .. known_good.Name)
       Ext.Print("  Got:      " .. our_result.Name)
   end
   ```

## Summary: Testing Strategy by Complexity

| Complexity | Testing Approach | Effort | Confidence |
|------------|------------------|--------|------------|
| **Simple read** (1 function) | Tier 1 + Tier 2 | 30 min | High |
| **Complex read** (struct parsing) | Tier 1-3 | 2-4 hours | Medium-High |
| **Hook + capture** (Frida) | Tier 1-2 + Frida pattern | 1-2 hours | High |
| **Hook + modify** (Dobby) | All 4 tiers + full suite | 4-8 hours | Medium |
| **Cross-system integration** | All 4 tiers + mod testing | 8-16 hours | Medium-Low |

## Related Documentation

- **ARM64 Hooking Prevention**: `/docs/arm64-hooking-prevention.md`
- **Development Workflow**: `/agent_docs/development.md`
- **Ghidra Analysis**: `/agent_docs/ghidra.md`

## Conclusion

Testing game reverse engineering code is fundamentally different from application testing because:

1. **You can't easily isolate issues** - The game is a massive system
2. **Crashes are expensive** - Each crash requires restarting the 1GB binary
3. **State matters** - The same code may work in main menu but fail in combat
4. **Offsets change** - Different game versions have different layouts

Therefore, testing must be:
- **Incremental** - Verify each layer before moving to the next
- **Observable** - Extensive logging to diagnose failures
- **Defensive** - Null checks and bounds checking everywhere
- **Reproducible** - Use known-good reference values to validate

Following this strategy, you can confidently deploy reverse engineering code knowing it won't crash the game or corrupt memory.
