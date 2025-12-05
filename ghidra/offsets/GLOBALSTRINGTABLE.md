# GlobalStringTable Discovery - ARM64 macOS

## Current Status: FOUND ✓

**Dec 5, 2025:** GlobalStringTable pointer successfully discovered via Ghidra analysis of `ls::gst::Get()` function.

### Key Discovery

| Item | Value |
|------|-------|
| **GST Pointer Global Variable** | `0x108aeccd8` (Ghidra) |
| **Offset from Module Base** | `0x8aeccd8` |
| **Runtime Address (example)** | `0x10b2d4cd8` |
| **GST Heap Address** | `0x1501f8000` |

### How It Works

The `ls::gst::Get(uint32_t fsIndex)` function at `0x1064bb224`:

```asm
adrp x8, 0x108aec000       ; Load page address
ldr  x8, [x8, #0xcd8]      ; Load GST base pointer from 0x108aeccd8
and  w9, w0, #0xf          ; subTableIdx = fsIndex & 0x0F
mov  w10, #0x1200          ; SubTable size = 0x1200 (4608 bytes)
umaddl x20, w9, w10, x8    ; SubTable = GST + subTableIdx * 0x1200
...
ubfx w9, w19, #4, #0x10    ; bucketIdx = (fsIndex >> 4) & 0xFFFF
ldr  x21, [x8, w9, UXTW #3] ; Load bucket pointer
...
lsr  w8, w19, #0x14        ; entryIdx = fsIndex >> 20
madd x8, x22, x8, x21      ; entry = bucket + entryIdx * entrySize
add  x0, x8, #0x18         ; Return string pointer (entry + 0x18)
ldr  w1, [x8, #0x8]        ; Return string length (entry + 0x8)
```

### SubTable Structure (ARM64 macOS)

Each SubTable is `0x1200` (4608) bytes. Key offsets:

| Offset | Size | Field | Notes |
|--------|------|-------|-------|
| `+0x1088` | 8 | EntrySize | Used for entry addressing |
| `+0x1140` | 8 | BucketsPtr | Pointer to bucket array |

### FixedString Index Decoding (Confirmed)

```c
uint32_t index;
uint32_t subTableIdx = index & 0x0F;           // bits 0-3
uint32_t bucketIdx   = (index >> 4) & 0xFFFF;  // bits 4-19
uint32_t entryIdx    = index >> 20;            // bits 20-31
```

### StringEntry Structure (Confirmed)

```c
struct StringEntry {
    uint32_t Hash;          // +0x00
    uint32_t RefCount;      // +0x04
    uint32_t Length;        // +0x08 (returned in w1)
    uint32_t Id;            // +0x0C
    uint64_t NextFreeIndex; // +0x10
    char     String[];      // +0x18 (returned in x0)
};
```

---

## Historical Discovery Attempts

The GlobalStringTable is needed to resolve FixedString indices (like `0x20200011`) to actual string values (like `"Strength"`).

### Runtime Address Mapping

**Critical Discovery:**

| Item | Value |
|------|-------|
| Runtime module base | `0x1027e8000` |
| Ghidra analysis base | `0x100000000` |
| **ASLR offset** | `0x27e8000` |
| Stats system pointer | `0x15d191800` (heap) |

**Address Translation Formula:**

```
Runtime Address = Ghidra Address - 0x100000000 + Runtime Base
               = Ghidra Address + ASLR Offset
```

Example: Ghidra `0x1089fc198` → Runtime `0x1027e8000 + 0x89fc198 = 0x10b1e4198`

### GST Pointer Candidates (from 0xC600 Pattern Analysis)

Found via Ghidra script `find_incref_function.py`:

| Ghidra Address | Offset from Base | Runtime Address (example) |
|----------------|-----------------|---------------------------|
| `0x1089fc000 + 0x198` | `0x89fc198` | `0x10b1e4198` |
| `0x1089fa000 + 0xee8` | `0x89faee8` | `0x10b1e2ee8` |
| `0x108aec000` | `0x8aec000` | `0x10b0d4000` |

**Code pattern at these locations:**

```asm
adrp x8, 0x1089fc000        ; Load page address
ldr  x8, [x8, #0x198]       ; Load GST pointer from offset
...
mov  w25, #0xc600           ; MainTable offset
```

The `ldr` instruction loads the GlobalStringTable pointer from a global variable.

### Console Probe Results (Dec 5, 2025)

**GST Candidate 1:** `0x10b1e4198` (runtime addr)
- Contents: `D0 41 1E 0B 01 00 00 00` → pointer `0x10b1e41d0`
- Data at `0x10b1e41d0`: `01 00 20 24 00 00 00 00 ...` (not a heap pointer)

**GST Candidate 2:** `0x10b1e2ee8` (runtime addr)
- Contents: `80 2E 1E 0B 01 00 00 00` → pointer `0x10b1e2e80`
- Also binary data segment, not heap

**Conclusion:** These addresses contain pointers to binary data, not the heap-allocated GlobalStringTable. The 0xC600 pattern in these functions may be for a different purpose.

### Larian ls::FixedString Symbols Found

Key functions using `ls::FixedString`:

| Symbol | Address | Purpose |
|--------|---------|---------|
| `ls::LSFStringTable::Add(FixedString&)` | `0x1064e3c04` | LSF string table operations |
| `ls::DefaultObjectVisitor::AddToFixedStringTable(FixedString&)` | `0x1064fc0e4` | Visitor pattern string handling |
| `ls::FixedStringMap<NSCursor*>::~FixedStringMap()` | `0x100bd1a54` | Cursor management destructor |
| `ls::DynamicArray<FixedString>::~DynamicArray()` | `0x100c2bcf4` | Array destructor |

Many functions in `cocoa::CocoaWindowManager` use `ls::FixedString` for cursor names.

## What We Know

### FixedString Encoding (ARM64)
On macOS ARM64, FixedString is a 32-bit index, not a pointer:
```
uint32_t index = 0x20200011
subTableIdx = index & 0x0F          = 1  (0-10 for 11 subtables)
bucketIdx   = (index >> 4) & 0xFFFF = 0x2001
entryIdx    = index >> 20           = 0x20
```

### StringEntry Structure (Windows Reference)
From BG3SE Windows code, StringEntry layout is:
```c
struct StringEntry {
    uint32_t Hash;          // +0x00
    uint32_t RefCount;      // +0x04
    uint32_t Length;        // +0x08
    uint32_t Id;            // +0x0C (FixedString index)
    uint32_t NextFreeIndex; // +0x10
    uint32_t Reserved;      // +0x14
    char     String[];      // +0x18 (24 bytes header)
};
```

### SubTable Structure (Windows Reference)
```c
struct SubTable {
    uint32_t NumBuckets;        // +0x00 on Windows
    uint32_t EntriesPerBucket;  // +0x04 on Windows
    uint64_t EntrySize;         // +0x08 on Windows
    void*    Buckets;           // +0x10 on Windows
    // ... other fields
};
```

**Note:** ARM64 offsets may differ due to alignment.

## Discovery Attempts

### 1. dlsym Lookup - FAILED
Symbol `_ZN8GlobalStringTable5m_ptrE` is not exported.

### 2. Reference-Based Discovery - PARTIALLY SUCCESSFUL
Searched for known strings ("Strength", "Dexterity", etc.) in `__DATA` section:
- Found "Strength" at `0x10cd3f34b`
- Found "Weapon" at `0x10d6e3348`

However, header validation failed. These strings are **literal string constants** in the binary, NOT GlobalStringTable entries.

**Key Insight:** GlobalStringTable entries are in **heap memory**, not the binary `__DATA` section.

### 3. Exhaustive __DATA Probe - FAILED
Scanned 64MB of `__DATA` section looking for SubTable structure signatures. Found 0 candidates.

### 4. Interactive Console Exploration (Dec 5, 2025)

Using the new `Ext.Memory.*` API via file-based console:

**Module bases discovered:**
- `Baldur` (main game): `0x100f9c000`
- `libOsiris`: `0x10fa50000`
- `bg3se` (our dylib): `0x10fc3c000`

**String searches:**
- "Weapon" in binary range (`0x100f9c000` + 512MB): **62 matches**
- Sample addresses: `0x1087e41a9`, `0x1087e46c0`, `0x1087e61db`
- Bytes before strings show adjacent strings (packed string table), NOT GST headers

**Finding:** Strings at `0x1087e*` are **constant strings** in a read-only section, likely `__TEXT` or `__RODATA`. They're packed sequentially without the 24-byte GST header structure.

**"ProficiencyBonus" search:**
- Found at `0x1087e5160`
- Bytes before: `ls.thoth.shared.Entity.Get...` (Lua method path)
- Confirms these are Lua/script-related constant strings, not GST entries

## Next Steps

### Option A: Heap Memory Scanning (Most Promising)
The GlobalStringTable is allocated on the heap at runtime. Strategy:
1. Search higher memory ranges (`0x600000000+`) for GST header patterns
2. Look for the 24-byte header structure: `[Hash:4][RefCount:4][Length:4][Id:4][Next:4][Reserved:4][String...]`
3. Validate by checking if Id matches the expected FixedString index

**Console command for heap exploration:**
```lua
-- Search for potential GST entries with specific header patterns
local results = Ext.Memory.Search("XX XX XX XX 01 00 00 00", 0x600000000, 0x200000000)
```

### Option B: Function Hooking
Hook a function that uses FixedString resolution:
- `FixedString::GetString()`
- `FixedString::CreateFromRaw()`
- Capture the GlobalStringTable pointer when the function is called

### Option C: Ghidra Analysis
Find the GlobalStringTable via static analysis:
1. Search for XREF to "Strength" string
2. Find the code that creates FixedString("Strength")
3. Trace the GlobalStringTable access pattern

### Option D: Trace RPGStats String Access
Since RPGStats has FixedString fields:
1. Find the function that reads stat names
2. Hook it to capture GST pointer during string resolution

## Related Files
- `src/strings/fixed_string.c` - Current implementation
- `src/strings/fixed_string.h` - API declarations
- `src/stats/stats_manager.c` - Uses `fixed_string_resolve()`

## RPGStats Integration Status
- RPGStats pointer: FOUND at offset `0x89c5730`
- Stats Objects count: 15,774 entries
- Stats names: Showing as `<FSIdx:0x...>` (FixedString not resolved)
- `Ext.Stats.GetAll()`: Returns empty because type comparison fails without string resolution
