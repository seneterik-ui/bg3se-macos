# Plan: Close Issue #3 - Ext.Stats API

## Overview

Implement the `Ext.Stats` API for reading and writing RPGStats properties, enabling mods to query and modify game statistics like weapon damage, armor values, spell effects, etc.

**Current State (Dec 5, 2025):** ✅ **~80% Complete**
- GlobalStringTable discovered and FixedString resolution working (47,326 strings resolved)
- `Ext.Stats.GetAll()` returns 15,774 stat names (actual strings, not indices!)
- `Ext.Stats.Get(name)` retrieves stats by name with property access
- `stat.Name` returns resolved string names

**Remaining Work:**
- ModifierList name resolution (for `stat.Type` and type filtering)
- Test property write functionality
- Consider `stat:Sync()` implementation

---

## Phase 1: GlobalStringTable Discovery ✅ COMPLETE

### 1.1 Ghidra Pattern Analysis for GST Access

**Goal:** Find the ARM64 pattern that accesses `ls__gGlobalStringTable`

**Approach:**
1. Search for XREF to known string like "Strength" or "ProficiencyBonus"
2. Find the code path that creates `FixedString("Strength")`
3. Identify the ADRP+LDR pattern accessing the GST global pointer
4. Document the offset from module base

**Commands:**
```bash
# Run Ghidra script to find GST access pattern
JAVA_HOME="/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home" \
  ~/ghidra/support/analyzeHeadless ~/ghidra_projects BG3Analysis \
  -process BG3_arm64_thin \
  -scriptPath /Users/tomdimino/Desktop/Programming/bg3se-macos/ghidra/scripts \
  -preScript optimize_analysis.py \
  -postScript find_globalstringtable.py
```

**Reference from Windows BG3SE:**
```cpp
// Pattern: "48 8D 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8B D8 48 85 C0"
// Resolves to: ls__gGlobalStringTable<RuntimeStringHandle>
```

### 1.2 Console-Based GST Probing

**Goal:** Use `Ext.Memory.*` API to locate GST in heap memory

**Strategy:**
1. Search for GST header signature in heap ranges (0x600000000+)
2. Look for the 24-byte StringEntry header pattern
3. Validate by checking if Id field matches expected FixedString indices

**Console Commands:**
```lua
-- Search for potential GST entries with RefCount=1 pattern
local results = Ext.Memory.Search("XX XX XX XX 01 00 00 00", 0x600000000, 0x200000000)
Ext.Print("Found " .. #results .. " candidates")

-- For each candidate, check if it has valid header structure
-- Hash(4) + RefCount(4) + Length(4) + Id(4) + NextFreeIndex(8) + String
```

### 1.3 Function Hook Approach (Fallback)

**Goal:** Capture GST pointer by hooking FixedString resolution

**Target Functions:**
- `FixedString::GetString()` - called when resolving index to string
- `FixedString::CreateFromRaw()` - called when creating FixedString from C string

**Implementation:**
```c
// Hook the function that accesses GST
void *original_fixedstring_getstring = NULL;

const char* hooked_fixedstring_getstring(uint32_t index) {
    // First call reveals GST pointer location
    // Capture it and store for future use
    const char* result = original_fixedstring_getstring(index);
    if (!g_gst_captured) {
        // Extract GST base from register state or stack
    }
    return result;
}
```

---

## Phase 2: FixedString Resolution ✅ COMPLETE

### 2.1 Implement GST Access

**File:** `src/strings/fixed_string.c`

**Structure (from Windows BG3SE):**
```c
struct GlobalStringTable {
    SubTable* SubTables[11];  // 11 subtables
};

struct SubTable {
    uint32_t NumBuckets;        // +0x00
    uint32_t EntriesPerBucket;  // +0x04
    uint64_t EntrySize;         // +0x08
    StringEntry** Buckets;      // +0x10
};

struct StringEntry {
    uint32_t Hash;          // +0x00
    uint32_t RefCount;      // +0x04
    uint32_t Length;        // +0x08
    uint32_t Id;            // +0x0C (FixedString index)
    uint64_t NextFreeIndex; // +0x10
    char String[];          // +0x18 (variable length)
};
```

**Decoding Logic:**
```c
const char* fixed_string_resolve(uint32_t fs_index) {
    if (fs_index == 0) return "";

    uint32_t subTableIdx = fs_index & 0x0F;           // bits 0-3
    uint32_t bucketIdx = (fs_index >> 4) & 0xFFFF;    // bits 4-19
    uint32_t entryIdx = fs_index >> 20;               // bits 20-31

    if (subTableIdx >= 11) return "<invalid subtable>";

    SubTable* st = g_gst->SubTables[subTableIdx];
    if (!st || bucketIdx >= st->NumBuckets) return "<invalid bucket>";

    StringEntry* entry = st->Buckets[bucketIdx];
    for (uint32_t i = 0; i < entryIdx && entry; i++) {
        entry = (StringEntry*)((char*)entry + st->EntrySize);
    }

    return entry ? entry->String : "<not found>";
}
```

### 2.2 Update Stats Display

**File:** `src/stats/stats_manager.c`

Replace `<FSIdx:0x%x>` placeholders with actual resolved strings:
```c
const char* stats_get_name(StatsObject* obj) {
    return fixed_string_resolve(obj->NameIndex);
}
```

---

## Phase 3: Property Read Implementation ✅ MOSTLY COMPLETE

### 3.1 Lua API: Ext.Stats.Get()

**Signature:** `Ext.Stats.Get(statName) -> StatObject`

```lua
local weapon = Ext.Stats.Get("WPN_Longsword")
print(weapon.Name)           -- "WPN_Longsword"
print(weapon.Damage)         -- "1d8"
print(weapon.DamageType)     -- "Slashing"
print(weapon.ValueLevel)     -- 1
```

**Implementation:**
```c
int lua_stats_get(lua_State *L) {
    const char *name = luaL_checkstring(L, 1);

    // Linear search through stats objects
    StatsObject *obj = stats_find_by_name(name);
    if (!obj) {
        lua_pushnil(L);
        return 1;
    }

    // Create userdata wrapper
    StatsObject **udata = lua_newuserdata(L, sizeof(StatsObject*));
    *udata = obj;
    luaL_setmetatable(L, "Ext.Stats.Object");
    return 1;
}
```

### 3.2 Property Access via __index Metatable

**Goal:** Enable `stat.PropertyName` syntax for reading properties

**Property Types (from Windows BG3SE):**
- `Int` - Integer values
- `Int64` - 64-bit integers
- `Float` - Floating point
- `FixedString` - String indices
- `TranslatedString` - Localized strings
- `StatsFunctors` - Damage/effect formulas
- `Conditions` - Boolean conditions
- `Requirements` - Stat requirements

### 3.3 Lua API: Ext.Stats.GetAll()

**Signature:** `Ext.Stats.GetAll([statType]) -> string[]`

```lua
local allWeapons = Ext.Stats.GetAll("Weapon")
local allStats = Ext.Stats.GetAll()  -- All stats
```

**Current Issue:** Returns empty because type comparison uses unresolved FixedStrings.

---

## Phase 4: Property Write Implementation

### 4.1 Lua API: Stat Property Assignment

```lua
local weapon = Ext.Stats.Get("WPN_Longsword")
weapon.Damage = "2d6"  -- Modify damage
weapon.DamageType = "Fire"  -- Change damage type
```

### 4.2 Stat Sync to Server/Client

**Goal:** Propagate stat changes across network

**Reference API:**
```lua
Ext.Stats.Sync(statName)  -- Sync specific stat
Ext.Stats.SyncAll()       -- Sync all modified stats
```

---

## Implementation Order

| Step | Task | Blocked By | Est. Effort |
|------|------|------------|-------------|
| 1.1 | Ghidra GST pattern analysis | None | 2-4 hours |
| 1.2 | Console-based GST probing | None | 1-2 hours |
| 1.3 | Function hook fallback | 1.1 or 1.2 | 2-3 hours |
| 2.1 | GST access implementation | Phase 1 | 3-4 hours |
| 2.2 | Stats display update | 2.1 | 1 hour |
| 3.1 | Ext.Stats.Get() | 2.2 | 2-3 hours |
| 3.2 | Property __index metatable | 3.1 | 3-4 hours |
| 3.3 | Ext.Stats.GetAll() | 2.2 | 1-2 hours |
| 4.1 | Property write | 3.2 | 2-3 hours |
| 4.2 | Stat sync | 4.1 | 3-4 hours |

**Total Estimated:** 20-30 hours of focused development

---

## Tools & Resources

### Available Tools
- **Lua Console**: `echo 'cmd' >> ~/Library/Application\ Support/BG3SE/commands.txt`
- **Ext.Memory API**: Read, ReadString, Search, GetModuleBase
- **osgrep**: Semantic search of Windows BG3SE reference implementation
- **Ghidra**: Static analysis with optimized scripts
- **Exa MCP**: Web search for RE techniques and documentation

### Key Reference Files (Windows BG3SE)
```bash
# Search for specific patterns
osgrep "GlobalStringTable" -p /Users/tomdimino/Desktop/Programming/bg3se
osgrep "FixedString resolve" -p /Users/tomdimino/Desktop/Programming/bg3se
osgrep "Stats property read" -p /Users/tomdimino/Desktop/Programming/bg3se
```

### Module Bases (from console testing)
- `Baldur` (main game): `0x100f9c000`
- `libOsiris`: `0x10fa50000`
- `bg3se` (our dylib): `0x10fc3c000`

---

## Success Criteria

1. **FixedString Resolution**: `fixed_string_resolve(0x20200011)` returns "Strength"
2. **Stats Enumeration**: `Ext.Stats.GetAll()` returns 15,774 stat names (not indices)
3. **Property Read**: `Ext.Stats.Get("WPN_Longsword").Damage` returns "1d8"
4. **Property Write**: Modifying `weapon.Damage = "2d6"` persists in game
5. **Type Filtering**: `Ext.Stats.GetAll("Weapon")` returns only weapon stats

---

## Risk Mitigation

| Risk | Mitigation |
|------|------------|
| GST structure differs from Windows | Validate with known FixedString indices |
| ARM64 memory alignment issues | Test with Ext.Memory.Read before implementing |
| Property types undocumented | Cross-reference with Windows BG3SE types |
| Heap ASLR randomizes GST address | Use pattern scanning, not hardcoded offset |

---

## Next Action

**Start with Phase 1.1**: Create Ghidra script `find_globalstringtable.py` to locate GST access pattern in the ARM64 binary. This is the critical blocker for all subsequent work.
