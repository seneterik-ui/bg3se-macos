# ARM64 Troubleshooting Guide

**Document Version:** 1.0
**Last Updated:** December 2025
**Scope:** Diagnosing and fixing ARM64-specific issues in BG3SE-macOS
**Status:** Field-tested solutions

## Quick Diagnosis Reference

### Symptom: Game Crashes After Hooking

**Most likely cause: Dobby hook on main binary**

```
Dobby on main binary → Code patching fails → Instruction corruption
```

**Quick fix:**
1. Remove Dobby hooks on main binary functions
2. Use Frida or direct memory reads instead
3. If you must hook, use libOsiris functions (writable at runtime)

**Verification:**
```bash
# Check which functions are being hooked
grep -n "DobbyHook" src/injector/main.c

# Identify if hook is on main binary or libOsiris
nm -gU /Applications/Baldur\'s\ Gate\ 3.app/Contents/MacOS/Baldur\'s\ Gate\ 3 \
    | c++filt | grep <function_name>
# If found: it's in main binary - don't use Dobby!
```

### Symptom: Return Value is Wrong/Corrupted

**Most likely cause: x8 indirect return not handled**

```
Function returns > 16 bytes
  ↓
ARM64 ABI requires x8 = pointer to buffer
  ↓
You didn't set x8 before calling
  ↓
Function writes result to invalid memory
```

**Quick fix:**

```c
// WRONG:
ls::Result result = call_function(arg);

// CORRECT:
ls::Result result = {0};
call_function_with_x8_buffer(arg, &result);
```

**Verification:**
```c
// Check struct size
if (sizeof(return_struct) > 16) {
    log_message("WARNING: Return struct is %zu bytes, needs x8",
                sizeof(return_struct));
}
```

### Symptom: Function Called but Hook Handler Never Runs

**Most likely cause: Wrong address or protection**

1. **Address is wrong**
   ```c
   // Get from Ghidra, verify with dlsym
   void* addr = dlsym(handle, "function_name");
   if (addr == NULL) {
       log_message("Symbol not exported, might be wrong address");
   }
   ```

2. **Function address is in read-only segment**
   ```c
   // Check memory protections
   vm_address_t addr = (vm_address_t)function_ptr;
   mach_msg_type_number_t region_size = 0;
   vm_region_basic_info_data_t region_info;

   kern_return_t result = vm_region(mach_task_self(), &addr,
       &region_size, VM_REGION_BASIC_INFO,
       (vm_region_info_t)&region_info, &region_size);

   if (!(region_info.protection & VM_PROT_WRITE)) {
       log_message("ERROR: Function is in read-only memory, Dobby cannot hook");
       return;
   }
   ```

3. **Hook is on a template instantiation that was inlined**
   ```c
   // Ghidra shows the function exists but it's marked as "inlined"
   // This means the code was compiled inline, no hook point exists
   // Solution: Hook the caller instead
   ```

### Symptom: Offset Reads as Zero or Garbage

**Most likely cause: TypeContext metadata != actual data structure**

**Quick fix:**

```lua
-- Don't trust header offsets, probe the actual data
function find_correct_offset(base_ptr, expected_marker)
    for offset = 0, 256, 8 do
        local value = Ext.Memory.Read(base_ptr + offset, 8)
        if value == expected_marker then
            Ext.Print(string.format("Found marker at +0x%X", offset))
            return offset
        end
    end
    return nil
end

-- Usage:
local offset = find_correct_offset(rpg_stats_ptr, RPGSTATS_OBJECTS_CAPACITY)
if offset then
    Ext.Print("Correct offset: +0x" .. string.format("%X", offset))
else
    Ext.Print("Could not find offset")
end
```

### Symptom: Memory Reads Return Sporadic Errors

**Most likely cause: Pointer is not always valid (timing issue)**

```
Singleton might not be initialized yet
  ↓
Code tries to dereference it
  ↓
Sometimes it's NULL, sometimes it's valid
  ↓
Intermittent failures
```

**Quick fix:**

```c
// Add initialization check
void* get_rpgstats(void) {
    void* ptr = *((void**)dlsym(RTLD_DEFAULT, "__ZN8RPGStats5m_ptrE"));

    if (ptr == NULL) {
        log_message("RPGStats not initialized yet");
        return NULL;
    }

    // Additional verification: check if it points to valid memory
    if (!is_valid_pointer(ptr)) {
        log_message("RPGStats pointer is invalid");
        return NULL;
    }

    return ptr;
}
```

## Common Mistakes and Fixes

### Mistake 1: Assuming Windows Layout on ARM64

**Problem:**
```c
// From Windows BG3SE headers
struct RPGStats {
    void* VMT;                          // 0x00
    CNamedElementManager Objects;       // 0x08 on x86_64
    // ARM64? Objects is at 0xC0!
};
```

**Solution:**
```c
// Document the ARM64 offset separately
#ifdef __aarch64__
    #define RPGSTATS_OBJECTS_OFFSET 0xC0
#else
    #define RPGSTATS_OBJECTS_OFFSET 0x08
#endif
```

### Mistake 2: Not Dereferencing const& Parameters

**Problem:**
```c
// Hook for function with const& parameter
void fake_Init(const uint32_t& spell_name) {
    // On ARM64, spell_name is a POINTER, not the value!
    uint32_t value = spell_name;  // ❌ Wrong - reading pointer value as int
}
```

**Solution:**
```c
// Treat const& as pointer on ARM64
void fake_Init(const uint32_t* spell_name) {
    // Now it's explicit that we need to dereference
    uint32_t value = *spell_name;  // ✅ Correct
}
```

### Mistake 3: Calling Functions with Wrong Register Setup

**Problem:**
```c
// Trying to call a function that needs x8
ls::Result result;
((TryGetSingletonFn)function_ptr)(&result);  // ❌ x8 not set!
```

**Solution:**
```c
// Use the ARM64 ABI wrapper
ls::Result result = {0};
call_try_get_singleton_with_x8((TryGetSingletonFn)function_ptr, world);
```

### Mistake 4: ADRP+LDR Corruption After Hooking

**Problem:**
```asm
; Original: Loads correct value
ADRP x8, #0x108900000
LDR  x8, [x8, #0xac80]

; After Dobby hook: Address or offset corrupted
ADRP x8, #0x10899d000  ; ← WRONG PAGE!
LDR  x8, [x8, #0xac80]
```

**Solution:**
Don't hook functions with ADRP+LDR patterns. Use direct memory reads instead:

```c
// Instead of hooking:
void* mgr = hook_to_capture_singleton();

// Do this:
void* mgr = *((void**)(MODULE_BASE + 0x1089bac80));
```

### Mistake 5: Not Checking Function Return Type Size

**Problem:**
```c
// Function returns large struct
typedef struct {
    void* value;
    uint64_t reserved[5];
    uint8_t has_error;
    // ...
} LsResult;  // 64 bytes!

// Call it naively
LsResult result = function(arg);  // ❌ x8 not set, result corrupted
```

**Solution:**
```c
// Check size and use appropriate wrapper
if (sizeof(LsResult) > 16) {
    // Must use x8 indirect return
    LsResult result = {0};
    result.has_error = 1;
    __asm__ volatile(
        "mov x8, %[buf]\n"
        "blr %[fn]\n"
        : "+m"(result)
        : [buf] "r"(&result), [fn] "r"(function_ptr)
        : "memory"
    );
} else {
    // Can return in x0/x1
    SimpleStruct result = function(arg);
}
```

## ARM64-Specific Gotchas

### Gotcha 1: Alignment Padding

**What happens:**
```c
struct Example {
    uint32_t a;     // offset 0x00
    uint64_t b;     // offset 0x08 (NOT 0x04! - ARM64 aligns to 8 bytes)
    uint32_t c;     // offset 0x10
};
```

**How to find correct offsets:**
```lua
-- Probe to find actual memory layout
function probe_struct_layout(base_addr)
    local results = Ext.Debug.ProbeStruct(base_addr, 0, 256, 8)
    for offset, data in pairs(results) do
        if data.ptr then
            Ext.Print(string.format("+0x%X: pointer=%p", offset, data.ptr))
        elseif data.u32 ~= 0 then
            Ext.Print(string.format("+0x%X: u32=0x%X", offset, data.u32))
        end
    end
end
```

### Gotcha 2: Inlined Functions

**What happens:**
You can't hook a function if it was inlined during compilation. Ghidra might show it exists, but there's no executable code to hook.

**How to detect:**
```bash
# Use nm to find the symbol
nm -gU "BG3 binary" | grep function_name
# If it doesn't appear: the function was inlined

# Look in Ghidra disassembly around the expected address
# If you see different instructions: the function was inlined into caller
```

**Solution:**
Hook the *caller* instead:

```c
// Can't hook inlined_function()
// But can hook its caller: some_wrapper()
DobbyHook(address_of_caller, fake_caller, &orig_caller);
```

### Gotcha 3: Position-Independent Executable (PIE)

**What happens:**
On modern macOS, the binary uses ASLR (Address Space Layout Randomization). The addresses change on every run.

**How to handle:**
```c
// Never hardcode absolute addresses
// void* bad_addr = (void*)0x101234567;  // ❌ Wrong!

// Always use offsets from module base
void* module_base = dlopen("Baldur's Gate 3.app", RTLD_LAZY);
void* correct_addr = module_base + OFFSET_RELATIVE_TO_BASE;
```

### Gotcha 4: const& vs Regular Parameters

**What happens:**
```c
// These look the same in C++:
void func_by_value(uint32_t x);
void func_by_ref(const uint32_t& x);

// But they're called differently on ARM64:
// func_by_value: x0 = 42
// func_by_ref: x0 = pointer to 42
```

**How to verify:**
```bash
# Use Ghidra to decompile and see the actual parameter usage
# If you see "*(something + 0)" you know it's a pointer
# If you see "ldr w0, [...]" it's probably a value
```

## Performance Troubleshooting

### Issue: Hooks Are Slow

**Diagnosis:**
```lua
-- Measure hook overhead
function benchmark_hooked_function()
    local iterations = 1000
    local start = Ext.Debug.Timestamp()

    for i = 1, iterations do
        -- Call potentially hooked function
        local result = expensive_function()
    end

    local elapsed = Ext.Debug.Timestamp() - start
    local avg_ms = elapsed * 1000 / iterations

    Ext.Print(string.format("Average time: %.3f ms", avg_ms))

    -- Baseline: typical function should be < 0.1 ms
    if avg_ms > 1 then
        Ext.Print("⚠️  Function is slow, likely because of hook")
    end
end
```

**Solutions:**
1. **Use onEnter-only Frida hooks** (faster than onEnter+onLeave)
2. **Cache results** (if the function is pure/deterministic)
3. **Use Lua instead of C hooks** (if applicable)

```c
// Compare: C hook in hot path
void fake_expensive_function(void *arg) {
    log_message("Called");  // ❌ Logging in every call = slow!

    // This is called 1000x per second
    return orig_expensive_function(arg);
}

// Better: Only log sometimes
static int call_count = 0;
void fake_expensive_function(void *arg) {
    if (call_count++ % 1000 == 0) {
        log_message("Called %d times so far", call_count);
    }
    return orig_expensive_function(arg);
}
```

### Issue: Memory Reads Are Slow

**Diagnosis:**
```lua
function benchmark_memory_reads()
    local iterations = 10000
    local addr = Ext.Memory.GetModuleBase("Baldur")
    local start = Ext.Debug.Timestamp()

    for i = 1, iterations do
        local value = Ext.Memory.Read(addr + 0x89c5730, 8)
    end

    local elapsed = Ext.Debug.Timestamp() - start
    local avg_micros = elapsed * 1000000 / iterations

    Ext.Print(string.format("Average read: %.1f µs", avg_micros))
end
```

**Solutions:**
1. **Cache values** - If reading the same address repeatedly
2. **Batch reads** - Read multiple values in one call if possible
3. **Avoid in hot loops** - Move memory reads outside performance-critical code

## Crash Debugging

### The Crash Investigation Workflow

**Step 1: Check the logs**
```bash
# Get the last 100 lines of the log
tail -100 "/Users/<username>/Library/Application Support/BG3SE/bg3se.log"

# Look for the last successful operation before crash
# e.g., "Calling GetRawComponent" followed by crash = issue in that function
```

**Step 2: Isolate the feature**
```c
// Temporarily disable the feature that crashed
#define FEATURE_ENABLED 0

if (FEATURE_ENABLED) {
    // This code caused the crash - comment it out
    DobbyHook(address, fake, &orig);
}

// If game doesn't crash: we found the culprit
```

**Step 3: Enable verbose logging**
```c
// Add logging before every potentially dangerous operation
log_message("ENTER: get_singleton()");

void* ptr = dlsym(...);
if (ptr == NULL) {
    log_message("dlsym failed");
    return NULL;
}

log_message("dlsym returned: %p", ptr);

void* deref = *(void**)ptr;
log_message("Dereferenced: %p", deref);

if (!is_valid_pointer(deref)) {
    log_message("Invalid pointer!");
    return NULL;
}

log_message("EXIT: get_singleton() successfully");
```

**Step 4: Add null checks**
```c
// Before and after every hook
int result = DobbyHook(addr, fake, &orig);
if (result != DOBBY_SUCCESS) {
    log_message("Hook failed: %d", result);
    // Don't continue
    return;
}

if (orig == NULL) {
    log_message("Original function pointer is NULL!");
    return;
}
```

### Interpreting Crash Patterns

**Pattern: Crash immediately after injection**
→ Problem: Hook installation is failing
→ Solution: Check if address is valid, check if function is writable

**Pattern: Crash when feature is first used**
→ Problem: Singleton not initialized yet
→ Solution: Add initialization check

**Pattern: Random crashes, hard to reproduce**
→ Problem: Memory corruption from ADRP+LDR corruption
→ Solution: Stop using Dobby on main binary

**Pattern: Crash only in specific game state**
→ Problem: Memory layout changes between states
→ Solution: Add state-specific handling

## Recovery Strategies

### If You Crash the Game

1. **Check logs for the last operation**
   ```bash
   grep "ENTER\|CALLED\|ERROR" "/Users/<user>/Library/Application Support/BG3SE/bg3se.log" | tail -20
   ```

2. **Identify which code caused it**
   - Last log line before crash is the culprit
   - Disable that code feature

3. **Run with safe defaults**
   ```c
   // In initialization
   #define USE_EXPERIMENTAL_HOOKS 0

   if (USE_EXPERIMENTAL_HOOKS) {
       // This caused crashes - disabled for now
       DobbyHook(experimental_addr, fake, &orig);
   }
   ```

4. **Test incrementally**
   - Hook one function
   - Test thoroughly
   - Only then hook the next
   - If crashes: revert the last hook

### If You Corrupt Memory

**Symptoms:**
- Stats have wrong values
- Components are inaccessible
- Entities behave strangely

**Solution:**
1. Stop the current process
2. Don't save the game (corrupted state)
3. Revert your code changes
4. Identify which memory write was wrong
5. Add validation before all memory writes

```c
// ALWAYS validate before writing
void safe_write(void* addr, uint64_t value) {
    if (!is_valid_pointer(addr)) {
        log_message("ERROR: Cannot write to invalid pointer: %p", addr);
        return;
    }

    // Write
    *(uint64_t*)addr = value;

    // Verify it worked
    uint64_t verify = *(uint64_t*)addr;
    if (verify != value) {
        log_message("ERROR: Write verification failed: %p", addr);
    }
}
```

## Summary Table: Symptoms → Causes → Fixes

| Symptom | Cause | Fix |
|---------|-------|-----|
| Immediate crash | Dobby on main binary | Use Frida or direct reads |
| Wrong return values | x8 not set for large returns | Use x8 wrapper |
| Hook never called | Wrong address or inlined | Verify address, hook caller |
| Sporadic crashes | Uninitialized singleton | Add NULL check |
| Return struct corrupted | ARM64 alignment mismatch | Verify with runtime probe |
| Slow performance | Excessive logging in hook | Log less frequently |
| Memory reads sporadic | Timing-dependent initialization | Add is_initialized() check |
| const& param read wrong | Not dereferencing pointer | Cast to pointer type |
| ADRP+LDR corruption | Dobby hook artifact | Don't hook this function |
| Can't find function | Inlined or wrong name | Search for caller function |

## Related Documentation

- **ARM64 Prevention Strategies**: `/docs/arm64-hooking-prevention.md`
- **ARM64 Testing Strategies**: `/docs/arm64-testing-strategies.md`
- **Architecture Guide**: `/agent_docs/architecture.md`
- **Ghidra Analysis**: `/agent_docs/ghidra.md`

## Getting Help

When you encounter an ARM64 issue:

1. **Reproduce it reliably** - If it only happens sometimes, get consistent reproduction steps
2. **Check the logs** - The answer is usually in the logs
3. **Isolate the component** - Disable other features
4. **Verify with runtime probing** - Use Lua console to inspect state
5. **Consult the prevention guide** - Is this a known pattern?
6. **Document it** - Add to this troubleshooting guide so others learn

The patterns in this guide are based on real bugs from BG3SE-macOS development. Future issues will likely match one of these patterns.
