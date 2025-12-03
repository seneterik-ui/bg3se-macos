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

**Note:** ARM64 macOS may have different offsets due to alignment. Verify with Ghidra.

## CNamedElementManager<T> Structure

```c
template<typename T>
struct CNamedElementManager {
    void* VMT;                           // 0x00
    Array<T*> Primitives;                // Element storage (Elements array)
    HashMap<FixedString, int32_t> NameHashMap;  // Name to index lookup
    int32_t HighestIndex;                // Next available index
};
```

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
