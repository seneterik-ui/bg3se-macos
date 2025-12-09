# Plan: Fix Osiris Function Name Caching (Issue #10)

## Problem Statement

The `extract_func_name_from_def()` function in `src/osiris/osiris_functions.c` incorrectly reads the function name at offset +8 of `OsiFunctionDef`. However, offset +8 contains `uint32_t Line` (a line number), not a name pointer.

### Evidence

From logs:
```
[ExtractName] funcDef 0x60002f1d8180: namePtr 0x4a8 not valid string ptr
```

- `0x4a8` = 1192 decimal - this is a **line number**, NOT a valid pointer
- Valid ARM64 pointers should be in the `0x1xxxxxxxx` range (slide-adjusted text segment)

### Root Cause

The current implementation assumes:
```c
struct COsiFunctionDef {
    void* vtable;      // +0x00
    char* Name;        // +0x08  <-- WRONG: This is Line!
};
```

But the actual Windows BG3SE structure (from `Osiris.h:902-918`) shows:
```cpp
struct OsiFunctionDef : public ProtectedGameObject<OsiFunctionDef> {
    void * VMT;                      // +0x00
    uint32_t Line;                   // +0x08  <-- This is what we're reading!
    uint32_t Unknown1;               // +0x0C
    uint32_t Unknown2;               // +0x10
    FunctionSignature * Signature;   // +0x14 (x86) or +0x18 (ARM64 8-byte aligned)
    // ... more fields
};

struct FunctionSignature : public ProtectedGameObject<FunctionSignature> {
    void * VMT;               // +0x00
    const char * Name;        // +0x08  <-- Name is actually HERE
    // ... more fields
};
```

### Solution

Follow the Windows pattern: Read `Signature` pointer from `OsiFunctionDef`, then read `Name` from `FunctionSignature`.

---

## Implementation Phases

### Phase 1: Ghidra Structure Analysis (Required First)

**Goal:** Verify ARM64 macOS structure layout matches Windows (with alignment adjustments)

**Tasks:**

1. **Locate OsiFunctionDef instances in memory**
   - Use existing `g_osirisFuncs` base address from pattern scanning
   - Walk the function table to find individual OsiFunctionDef pointers
   - Document at least 3 different instances for validation

2. **Analyze OsiFunctionDef layout**
   - Verify offset +0x08 contains small integers (line numbers), not pointers
   - Find the `Signature` pointer field (expected at +0x18 due to ARM64 8-byte alignment)
   - Look for pointer-sized values that point to valid memory regions

3. **Analyze FunctionSignature layout**
   - Follow Signature pointer to FunctionSignature structure
   - Verify offset +0x08 contains a pointer to ASCII string
   - Confirm Name pointer points to readable null-terminated strings

4. **Document findings**
   - Update `ghidra/offsets/OSIRIS_FUNCTIONS.md` with correct structure layout
   - Include ASCII art diagram of pointer chain

**Expected Layout (to verify):**
```
OsiFunctionDef (ARM64 macOS)
+0x00: void* VMT
+0x08: uint32_t Line        <-- Currently misread as name!
+0x0C: uint32_t Unknown1
+0x10: uint32_t Unknown2
+0x14: (4 bytes padding for 8-byte alignment)
+0x18: FunctionSignature* Signature  <-- Read this pointer

FunctionSignature (ARM64 macOS)
+0x00: void* VMT
+0x08: const char* Name     <-- Then read this to get actual name
+0x10: ... (more fields)
```

---

### Phase 2: Update extract_func_name_from_def()

**File:** `src/osiris/osiris_functions.c` (Lines 60-179)

**Current broken code:**
```c
/* Read the name pointer at offset 0x08 */
void *namePtr = NULL;
if (!safe_memory_read_pointer(funcDefAddr + 8, &namePtr)) {
    log_message("[ExtractName] funcDef %p: Failed to read namePtr", (void*)funcDefAddr);
    return;
}
```

**Fixed implementation:**

```c
// Define offsets based on Ghidra analysis
#define OSIFUNCDEF_SIGNATURE_OFFSET 0x18  // ARM64: 8-byte aligned after Line/Unknown fields
#define FUNCSIG_NAME_OFFSET 0x08          // Name pointer in FunctionSignature

static void extract_func_name_from_def(uintptr_t funcDefAddr, uint32_t funcId) {
    // Step 1: Read Signature pointer from OsiFunctionDef
    void *signaturePtr = NULL;
    if (!safe_memory_read_pointer(funcDefAddr + OSIFUNCDEF_SIGNATURE_OFFSET, &signaturePtr)) {
        log_message("[ExtractName] funcDef %p: Failed to read Signature ptr at +0x%x",
                    (void*)funcDefAddr, OSIFUNCDEF_SIGNATURE_OFFSET);
        return;
    }

    // Validate Signature pointer
    if (!signaturePtr || (uintptr_t)signaturePtr < 0x100000000ULL) {
        log_message("[ExtractName] funcDef %p: Invalid Signature ptr %p",
                    (void*)funcDefAddr, signaturePtr);
        return;
    }

    // Step 2: Read Name pointer from FunctionSignature
    void *namePtr = NULL;
    if (!safe_memory_read_pointer((uintptr_t)signaturePtr + FUNCSIG_NAME_OFFSET, &namePtr)) {
        log_message("[ExtractName] Signature %p: Failed to read Name ptr at +0x%x",
                    signaturePtr, FUNCSIG_NAME_OFFSET);
        return;
    }

    // Validate Name pointer
    if (!namePtr || (uintptr_t)namePtr < 0x100000000ULL) {
        log_message("[ExtractName] Signature %p: Invalid Name ptr %p",
                    signaturePtr, namePtr);
        return;
    }

    // Step 3: Read the actual name string
    char nameBuf[256];
    if (!safe_memory_read_string((uintptr_t)namePtr, nameBuf, sizeof(nameBuf))) {
        log_message("[ExtractName] Name %p: Failed to read string", namePtr);
        return;
    }

    // Validate string content (should be printable ASCII)
    if (nameBuf[0] == '\0' || !isprint((unsigned char)nameBuf[0])) {
        log_message("[ExtractName] Name %p: Invalid string content", namePtr);
        return;
    }

    // Success - cache the function name
    osi_cache_function(funcId, nameBuf);
    log_message("[ExtractName] funcId %u = \"%s\"", funcId, nameBuf);
}
```

**Key changes:**
1. Two-step pointer dereference: `funcDef->Signature->Name`
2. Validate each pointer before dereferencing
3. Use defined constants for offsets (easy to update if Ghidra reveals different values)
4. Improved logging for debugging

---

### Phase 3: Add Helper for Safe String Reading

If `safe_memory_read_string` doesn't exist, add it:

```c
/**
 * Safely read a null-terminated string from memory.
 * Returns 1 on success, 0 on failure.
 */
int safe_memory_read_string(uintptr_t addr, char *buf, size_t buf_size) {
    if (!buf || buf_size == 0) return 0;

    mach_vm_size_t read_size = 0;
    kern_return_t kr = mach_vm_read_overwrite(
        mach_task_self(),
        addr,
        buf_size - 1,  // Leave room for null terminator
        (mach_vm_address_t)buf,
        &read_size
    );

    if (kr != KERN_SUCCESS) {
        return 0;
    }

    // Ensure null termination
    buf[read_size] = '\0';

    // Find actual string length (stop at first null)
    for (size_t i = 0; i < read_size; i++) {
        if (buf[i] == '\0') break;
    }

    return 1;
}
```

---

### Phase 4: Update Ghidra Documentation

**File:** `ghidra/offsets/OSIRIS_FUNCTIONS.md`

Add/update structure documentation:

```markdown
## OsiFunctionDef Structure (ARM64 macOS)

Based on Ghidra analysis and Windows BG3SE reference (`Osiris.h:902-918`):

### Memory Layout

| Offset | Size | Type | Field | Notes |
|--------|------|------|-------|-------|
| +0x00 | 8 | void* | VMT | Virtual method table |
| +0x08 | 4 | uint32_t | Line | Source line number (e.g., 1192) |
| +0x0C | 4 | uint32_t | Unknown1 | |
| +0x10 | 4 | uint32_t | Unknown2 | |
| +0x14 | 4 | (padding) | - | 8-byte alignment padding |
| +0x18 | 8 | FunctionSignature* | Signature | Pointer to signature struct |
| +0x20 | ... | ... | ... | Additional fields TBD |

### FunctionSignature Structure

| Offset | Size | Type | Field | Notes |
|--------|------|------|-------|-------|
| +0x00 | 8 | void* | VMT | Virtual method table |
| +0x08 | 8 | const char* | Name | Pointer to function name string |
| +0x10 | ... | ... | ... | Additional fields TBD |

### Pointer Chain Diagram

```
OsiFunctionDef @ 0x60002f1d8180
    │
    ├── +0x00: VMT (0x10xxxxxxxx)
    ├── +0x08: Line = 0x4a8 (1192)  ← OLD CODE READ THIS AS NAME!
    ├── +0x0C: Unknown1
    ├── +0x10: Unknown2
    ├── +0x14: (padding)
    └── +0x18: Signature* ─────────────────┐
                                           ▼
                              FunctionSignature @ 0x6000xxxxxxxx
                                  │
                                  ├── +0x00: VMT
                                  └── +0x08: Name* ────────────────┐
                                                                   ▼
                                                    "GetPlayerInfo\0"
```
```

---

### Phase 5: Testing

**Test Plan:**

1. **Build and inject**
   ```bash
   cd build && cmake --build . && ./scripts/launch_bg3.sh
   ```

2. **Check logs for successful extraction**
   ```bash
   tail -f /tmp/bg3se_macos.log | grep ExtractName
   ```

3. **Expected success output:**
   ```
   [ExtractName] funcId 123 = "GetPlayerInfo"
   [ExtractName] funcId 124 = "CharacterGetHostCharacter"
   [ExtractName] funcId 125 = "DB_Players"
   ```

4. **Verify no crashes during Osiris function enumeration**

5. **Test Osi.* Lua calls with discovered function names**

**Success Criteria:**
- Function names successfully extracted for >90% of enumerated functions
- No crashes during enumeration
- Osiris Lua API continues to work with named functions

---

## Files to Modify

| File | Changes |
|------|---------|
| `src/osiris/osiris_functions.c` | Update `extract_func_name_from_def()` with two-level indirection |
| `src/osiris/osiris_functions.h` | Add offset constants if not already defined |
| `ghidra/offsets/OSIRIS_FUNCTIONS.md` | Document correct structure layout |
| `src/core/safe_memory.c` | Add `safe_memory_read_string()` if not present |

---

## Risk Assessment

| Risk | Likelihood | Impact | Mitigation |
|------|------------|--------|------------|
| Wrong Signature offset | Medium | High (crash or no names) | Verify with Ghidra before coding |
| NULL Signature pointers | Low | Medium (skip function) | Validate pointer before dereference |
| Game version differences | Low | High (wrong offsets) | Document offsets clearly for updates |
| Performance regression | Very Low | Low | Caching still amortizes cost |

---

## Dependencies

- **Ghidra analysis must complete first** - Cannot implement without verified offsets
- Safe memory read APIs (already implemented in v0.10.5)
- Existing Osiris function table enumeration (working)

---

## Estimated Scope

- Phase 1 (Ghidra): ~30-60 minutes of reverse engineering
- Phase 2-3 (Code): ~15-20 lines changed
- Phase 4 (Docs): ~30 lines of markdown
- Phase 5 (Test): ~15 minutes of gameplay testing

This is primarily a **reverse engineering task** to discover the correct offset, followed by a simple code fix.
