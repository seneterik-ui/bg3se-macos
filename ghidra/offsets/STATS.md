# Stats System Offsets (macOS ARM64)

## Overview

The stats system manages game statistics including weapons, armor, spells, statuses, and passives. The central manager is `RPGStats` which contains multiple `CNamedElementManager<T>` instances for different stat types.

## Key Symbols

| Symbol | Address | Description |
|--------|---------|-------------|
| `RPGStats::m_ptr` | `0x1089c5730` | Global pointer to RPGStats instance (static class member) |
| `eoc::IsStatsItem(int)::rpgStats` | `0x1089c55a8` | Local static cached reference |
| `CRPGStats_Object_Manager::~CRPGStats_Object_Manager()` | `0x10211cfa8` | Object manager destructor |

## Mangled Symbol Names

```
__ZN8RPGStats5m_ptrE                                     -> RPGStats::m_ptr
__ZZN3eoc11IsStatsItemEiE8rpgStats                       -> eoc::IsStatsItem(int)::rpgStats
__ZN24CRPGStats_Object_ManagerD1Ev                       -> CRPGStats_Object_Manager::~CRPGStats_Object_Manager()
```

## CNamedElementManager Template Instantiations

These are discovered template instantiations for managing different stat types:

| Type | Key Methods | Notes |
|------|-------------|-------|
| `CRPGStats_Modifier` | Insert @ `0x1021217cc`, GetEntry @ `0x102121b84` | Property modifiers |
| `CRPGStats_Modifier_List` | Insert @ `0x101c5fc74`, GetEntry @ `0x101c5ffac` | Modifier lists (stat types) |
| `CRPGStats_Modifier_ValueList` | Insert @ `0x10211d5d0`, GetEntry @ `0x10211d980` | Enum value lists |
| `CRPGStats_Treasure_Table` | Insert @ `0x10211ed58`, GetEntry @ `0x10211f0dc` | Loot tables |
| `CRPGStats_Treasure_SubTable` | Insert @ `0x10211e54c`, GetEntry @ `0x10211e8d0` | Loot sub-tables |

## RPGStats Structure

Based on Windows BG3SE reference (`BG3Extender/GameDefinitions/Stats/Stats.h`):

```c
struct RPGStats {
    void* VMT;                                                    // 0x00
    CNamedElementManager<RPGEnumeration> ModifierValueLists;      // Type definitions (enums)
    CNamedElementManager<ModifierList> ModifierLists;             // Stat types (Weapon, Armor, etc.)
    CNamedElementManager<Object> Objects;                         // Actual stat objects
    // ... SpellPrototypes, StatusPrototypes, PassivePrototypes
    // ... Property pools (FixedStrings, Floats, Int64s, GUIDs, etc.)
    // ... ExtraData and other managers
};
```

### Runtime-Verified Offsets (macOS ARM64)

**Verified via console probing on Dec 5, 2025:**

| Member | Offset | Verified Values |
|--------|--------|-----------------|
| `ModifierLists` | `+0x60` | size=9 (9 stat types: Weapon, Armor, Character, etc.) |
| `Objects` | `+0xC0` | size=15,774 (all stat entries in the game) |

**Sample Runtime Values:**
```
RPGStats base:     0x11f08f800
ModifierLists:     +0x60 -> buf=0x600000637c00, cap=16, size=9
Objects:           +0xC0 -> buf=0x1749e8000, cap=16384, size=15774
```

**Console Probe Commands Used:**
```lua
-- Get RPGStats pointer
local rpg = Ext.Memory.Read(Ext.Memory.GetModuleBase("Baldur") + 0x89c5730, 8)

-- Read ModifierLists manager at +0x60
-- CNamedElementManager layout: VMT(8) + buf_(8) + cap_(4) + size_(4) = 24 bytes
local ml_base = rpg_addr + 0x60
local ml_buf = Ext.Memory.Read(ml_base + 0x08, 8)   -- Array.buf_
local ml_cap = Ext.Memory.Read(ml_base + 0x10, 4)   -- Array.cap_ (expect 16)
local ml_size = Ext.Memory.Read(ml_base + 0x14, 4)  -- Array.size_ (expect 9)
```

**Note:** These offsets differ from the Windows version due to ARM64 alignment and potential structure packing differences.

## CNamedElementManager<T> Structure

```c
template<typename T>
struct CNamedElementManager {
    void* VMT;                           // 0x00 (8 bytes)
    Array<T*> Primitives;                // 0x08: Element storage (buf_ + cap_ + size_)
    HashMap<FixedString, int32_t> NameHashMap;  // Name to index lookup
    int32_t HighestIndex;                // Next available index
};

// Array<T> layout (verified via runtime probing):
struct Array {
    T* buf_;      // +0x00: Pointer to element storage
    uint32_t cap_;     // +0x08: Capacity
    uint32_t size_;    // +0x0C: Current size (element count)
};
// Total: 16 bytes (not 24 as in some Windows layouts)
```

### CNamedElementManager Verified Layout

| Field | Offset | Size | Notes |
|-------|--------|------|-------|
| VMT | +0x00 | 8 | Virtual method table |
| Primitives.buf_ | +0x08 | 8 | Pointer to element array |
| Primitives.cap_ | +0x10 | 4 | Array capacity |
| Primitives.size_ | +0x14 | 4 | Element count |
| NameHashMap | +0x18 | ~48 | HashMap for name lookups |
| HighestIndex | varies | 4 | Next allocation index |

**Total CNamedElementManager size:** ~0x60 bytes (96 bytes), which explains the +0x60 stride between managers in RPGStats.

## stats::Object Structure

Based on Windows BG3SE (`BG3Extender/GameDefinitions/Stats/Common.h`):

```c
struct Object {
    void* VMT;                           // 0x00
    Array<int32_t> IndexedProperties;    // Indices into global pools
    FixedString Name;                    // Stat entry name
    // ... AI flags, functors, requirements
    int32_t Using;                       // Parent stat index (-1 if none)
    uint32_t ModifierListIndex;          // Type reference (which ModifierList)
    uint32_t Level;                      // Level value
};
```

## Related TypeIds

| Component | TypeId Global | Notes |
|-----------|---------------|-------|
| `eoc::RPGStatsComponent` | `0x1088ec680` | ECS component for entity stats |
| `esv::RPGStatsSystem` | `0x108a1e220` | Server-side stats system |

## Usage Pattern

To access the stats system:

```c
// 1. Resolve RPGStats::m_ptr symbol
void** pRPGStatsPtr = dlsym(handle, "__ZN8RPGStats5m_ptrE");

// 2. Dereference to get RPGStats instance
RPGStats* stats = *pRPGStatsPtr;

// 3. Access Objects manager at appropriate offset
CNamedElementManager<Object>* objects = (void*)stats + OFFSET_OBJECTS;

// 4. Look up stat by name via NameHashMap
int32_t index = hashmap_lookup(objects->NameHashMap, "Weapon_Longsword");

// 5. Get object from Primitives array
Object* stat = objects->Primitives[index];
```

## VTable Addresses

| Class | VTable Address |
|-------|----------------|
| `CNamedElementManager<CRPGStats_Modifier>` | `0x1086c28c0` |
| `CNamedElementManager<CRPGStats_Modifier_List>` | `0x1086c2518` |
| `CNamedElementManager<CRPGStats_Modifier_ValueList>` | `0x1086c2448` |
| `CNamedElementManager<CRPGStats_Treasure_Table>` | `0x1086c2788` |
| `CRPGStats_Modifier_List` | `0x1086c2858` |
| `CRPGStats_Object_Manager` | `0x1086c2580` |
| `CRPGStats_ItemType_Manager` | `0x1086c2378` |
| `CRPGStats_Modifier_List_Manager` | `0x1086c24b0` |

## ModifierList Discovery (Dec 2025)

Results from `find_modifierlist_offsets.py` Ghidra script:

### ModifierList-Related Symbols

| Symbol | Address | Notes |
|--------|---------|-------|
| `GetModifierListByIdAndType` | `0x10114a0d8` | Useful for understanding ModifierList access |
| `gui::VMBoostModifiers::GetFromUIBoostModifierList` | `0x10226e248` | UI boost modifiers |
| `gui::DCActiveRoll::GetFromUISelectedBoostModifierList` | `0x102274374` | Active roll UI |

### Stat Type Name Strings

| Type Name | String Address | DATA XREF | Notes |
|-----------|----------------|-----------|-------|
| `Weapon` | `0x1078481a9` | None | No XREF found |
| `Armor` | `0x10784a2f1` | None | No XREF found |
| `SpellData` | `0x107864734` | None | No XREF found |
| `StatusData` | `0x107b72fbd` | `0x10868a218` | Has DATA reference |
| `PassiveData` | `0x107b73be3` | `0x10868c288` | Has DATA reference |
| `Character` | `0x107847596` | None | No XREF found |

**Observation:** StatusData and PassiveData have DATA references ~8KB apart (`0x10868c288 - 0x10868a218 = 0x2070`). These may be entries in a ModifierList name table or type registry. Investigating these addresses could reveal the ModifierList structure layout.

### RPGStats-Related Symbols (364 total)

Key functions found:
- `eoc::active_roll::ComputeFinalModifiers` @ `0x101149030`, `0x1011492dc`
- `CItemCombinationManager::LoadText(..., RPGStats&)` @ `0x1011bc0cc`
- `eoc::RPGStatsComponent` type registration @ `0x10194da60`

## Ghidra Analysis Notes

### Finding RPGStats::m_ptr

The symbol `__ZN8RPGStats5m_ptrE` is exported and can be resolved via dlsym. This is a `b` (BSS) section symbol, meaning it's an uninitialized global that gets populated at runtime.

### Usage in Functions

Functions that use RPGStats typically take it as a reference parameter:
- `CItemCombinationManager::LoadText(..., RPGStats&)` @ `0x1011bc0cc`
- `CTreasureCategoryGroups::ShouldCategoriesDrop(..., RPGStats*)` @ `0x10211b0ac`

## Implementation Notes

Unlike the Entity system where we had to capture pointers via hooks, `RPGStats::m_ptr` is a static member that can be resolved directly via dlsym once the game loads. However, it will be NULL/0 until the stats system initializes.

**Timing:** The stats system typically initializes early in game startup, before SessionLoaded. Safe to access after main menu appears.

## Related Files in Windows BG3SE

- `BG3Extender/GameDefinitions/Stats/Stats.h` - RPGStats struct definition
- `BG3Extender/GameDefinitions/Stats/Common.h` - Object, ModifierList structs
- `BG3Extender/Lua/Libs/Stats.inl` - Lua bindings
- `BG3Extender/GameDefinitions/Symbols.h` - gRPGStats declaration
