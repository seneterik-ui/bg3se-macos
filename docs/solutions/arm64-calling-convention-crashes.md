# ARM64 Calling Convention Crashes: Lessons Learned

**Date:** December 14, 2025
**Issue:** #39 (Ext.Localization)
**Commit:** 4c7dd3f

## Problem Statement

The localization module crashed when calling `Ext.Loca.UpdateTranslatedString()` and `Ext.Loca.GetTranslatedString()`. Analysis revealed two distinct ARM64 calling convention issues.

## Crash #1: FixedString::Create Output Parameter

### Symptom
- Crash at address `0x9` (near the string length 10 for "h00000001")
- Stack trace: `ls::_murmur3a32::Update` → `ls::gst::Add` → `ls::FixedString::Create`

### Root Cause
The function signature was incorrectly assumed to return a value:

```c
// WRONG - assumed return value
typedef uint32_t (*FixedStringCreateFn)(const char *str, int len);
uint32_t fs_index = s_loca.fs_create(handle, (int)strlen(handle));
```

The **actual** ARM64 signature uses an **output parameter**:

```c
// CORRECT - output parameter
typedef void (*FixedStringCreateFn)(uint32_t *out_index, const char *str, int len);
uint32_t fs_index = 0xFFFFFFFF;
s_loca.fs_create(&fs_index, handle, (int)strlen(handle));
```

### Why This Happened
When we passed `(handle, len)`:
- x0 = handle pointer (e.g., `0x7ff...`)
- x1 = len (e.g., `10`)

The function treated x0 as `out_index` and dereferenced it, writing to an address that was actually a string pointer. The `0x9` crash address was likely `len - 1` after some arithmetic went wrong.

### Lesson
**Compare function signatures with working implementations.** The correct signature was already in `src/strings/fixed_string.c`:

```c
typedef void (*FixedStringCreate_t)(uint32_t *out_fs_index, const char *str, int len);
```

## Crash #2: TryGet on Non-Existent Handles

### Symptom
- Crash at address `0x0` (NULL dereference)
- Stack trace: `TryGet` function

### Root Cause
The game's `TranslatedStringRepository::TryGet` function crashes when given a handle that doesn't exist in the translation HashMap. It does NOT gracefully return an empty optional - it dereferences a NULL bucket pointer.

### Solution
Implemented safe stubs that return fallback values instead of calling into the game's functions:

```c
// Safe stub - defers full implementation
const char* localization_get(const char *handle, const char *fallback) {
    LOG_CORE_DEBUG("LOCA: GetTranslatedString called for '%s', returning fallback (deferred)",
                   handle ? handle : "(null)");
    return fallback ? fallback : "";
}

bool localization_set(const char *handle, const char *value) {
    LOG_CORE_INFO("LOCA: UpdateTranslatedString deferred - requires HashMap insertion support");
    return false;
}
```

### Lesson
**Always validate that game functions handle edge cases before calling them.** BG3's TryGet assumes the handle exists - it doesn't validate first.

## ARM64 Calling Convention Quick Reference

### Output Parameters vs Return Values
Many C++ functions that "return" values actually use output parameters on ARM64:

| Pattern | x0 | x1 | x2+ |
|---------|----|----|-----|
| Return value | return | arg1 | arg2+ |
| Output param | **out_ptr** | arg1 | arg2+ |

### const& Parameters
On ARM64, `const&` is passed as a **pointer**, not by value:

```c
// C++ declaration
void Init(FixedString const& name);

// ARM64 reality - x0 = this, x1 = POINTER to FixedString
void Init(void* this, const uint32_t* name_ptr);
```

### Large Struct Returns (>16 bytes)
Functions returning structs >16 bytes use x8 indirect return:
- Caller allocates buffer
- Caller passes buffer address in x8
- Callee writes result to buffer

## Verification Pattern

Before calling any game function:

1. **Check existing implementations** - Look for the same function used elsewhere in the codebase
2. **Analyze Ghidra decompilation** - Verify parameter order and types
3. **Test with safe values first** - Use known-good inputs before edge cases
4. **Add fallback handling** - Gracefully handle errors before calling game code

## Files Modified

- `src/localization/localization.c` - Fixed FixedStringCreateFn signature and call site
- Added safe stubs for Get/Update until full implementation is ready

## Status

- `GetLanguage()` - ✅ Working (returns "English")
- `GetTranslatedString()` - ✅ Safe stub (returns fallback)
- `UpdateTranslatedString()` - ✅ Safe stub (returns false)

Full implementation of Get/Update requires:
1. Pre-validation of handle existence before TryGet
2. HashMap insertion support for UpdateTranslatedString (AddTranslatedString only works for existing entries)
