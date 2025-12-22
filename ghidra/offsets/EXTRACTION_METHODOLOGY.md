# Component Expansion Methodology

## Overview

This document describes the **accelerated workflow** for expanding component coverage from 55 to 150+ components. The goal is batch expansion - adding 100+ components at a time, not one-by-one.

## Pipeline Overview

```
┌─────────────────────────────────────────────────────────────────────────┐
│                     COMPONENT EXPANSION PIPELINE                        │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  Step 1: TypeId Extraction                                              │
│  ─────────────────────────                                              │
│  tools/extract_typeids.py → src/entity/generated_typeids.h             │
│  Result: 1,999 component TypeId addresses from binary symbols           │
│                                                                         │
│  Step 2: Property Parsing                                               │
│  ────────────────────────                                               │
│  tools/parse_component_headers.py → src/entity/generated_property_defs.h│
│  Result: 504 property definitions from Windows BG3SE headers            │
│                                                                         │
│  Step 3: ARM64 Size Verification (Ghidra MCP)                           │
│  ────────────────────────────────────────────                           │
│  Ghidra decompilation → ghidra/offsets/component_sizes.json             │
│  Result: 30+ verified struct sizes (ongoing)                            │
│                                                                         │
│  Step 4: Implementation                                                 │
│  ─────────────────────                                                  │
│  Combine TypeId + Properties + Size → component_offsets.h               │
│  Result: Working Lua property access for component                      │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

## Step 1: TypeId Extraction

Extract all component TypeId addresses from the macOS binary:

```bash
python3 tools/extract_typeids.py > src/entity/generated_typeids.h
```

This parses `nm -gU` output for `TypeId<T>::m_TypeIndex` symbols, producing:
- 1,999 total components
- Categorized by namespace (eoc, esv, ecl, ls, gui, navcloud, ecs)
- Ready-to-use C `#define` macros

## Step 2: Property Parsing

Parse Windows BG3SE headers to get field names and types:

```bash
python3 tools/parse_component_headers.py
```

This reads `BG3Extender/GameDefinitions/Components/*.h` and generates:
- Property names, estimated offsets, field types
- ComponentLayoutDef structures ready for registration
- **WARNING**: Offsets are Windows x64 - may differ on ARM64!

## Step 3: ARM64 Size Verification (Ghidra MCP)

This is the critical step. ARM64 struct sizes may differ from Windows x64.

## Extraction Pattern

BG3's ECS uses templated `AddComponent<T>` functions that allocate component storage via `ComponentFrameStorageAllocRaw`. The size argument passed to this function is the exact component struct size.

### Key Function Signature

```c
ComponentFrameStorageAllocRaw(
    ComponentFrameStorage* storage,  // Storage at this_00 + 0x48
    size_t component_size,           // ← This is the struct size we want
    ComponentFrameStorageIndex* out
);
```

### Example Decompilation

```c
// From AddComponent<eoc::HealthComponent>
pSVar9 = (StatusImmunitiesComponent *)
         ComponentFrameStorageAllocRaw(
             (ComponentFrameStorage *)(this_00 + 0x48),
             0x40,  // ← Component size: 64 bytes
             (ComponentFrameStorageIndex *)(pIVar8 + 8)
         );
```

## Extraction Workflow

### Step 1: Search for AddComponent Template

```
mcp__ghidra__search_functions_by_name("ComponentName")
```

Look for results matching:
- `AddComponent<namespace::ComponentName>` - Simplified single-param version
- `AddComponent<namespace::ComponentName,namespace::ComponentName>` - Dual-param version

The simplified version typically has the cleaner decompilation.

### Step 2: Decompile the Function

```
mcp__ghidra__decompile_function_by_address("0xADDRESS")
```

### Step 3: Extract Size from Decompilation

Search for `ComponentFrameStorageAllocRaw` call. The size appears as:
- **Hex literal**: `ComponentFrameStorageAllocRaw(..., 0x40, ...)` → 64 bytes
- **Decimal literal**: `ComponentFrameStorageAllocRaw(..., 8, ...)` → 8 bytes

### Step 4: Record in JSON

```json
"namespace::ComponentName": {
  "size": 64,
  "size_hex": "0x40",
  "address": "0x101e544d0"
}
```

## Common Patterns Discovered

### Marker Components (1 byte)
Components that act as tags with no data:
- `eoc::combat::DelayedFanfareComponent`: 1 byte
- `eoc::inventory::CanBeInComponent`: 1 byte

### Container Components (16-64 bytes)
Components holding arrays/maps:
- `eoc::BoostsContainerComponent`: 16 bytes (DynamicArray)
- `eoc::status::ContainerComponent`: 64 bytes (HashTable + array)
- `eoc::StatusImmunitiesComponent`: 64 bytes (HashMap)

### Data Components (4-160 bytes)
Components with actual game data:
- `eoc::LevelComponent`: 4 bytes (single int32)
- `eoc::HealthComponent`: 40 bytes
- `eoc::StatsComponent`: 160 bytes (largest core component)

## Size vs Windows

ARM64 sizes may differ from Windows x64 due to:
- Pointer alignment requirements
- Struct packing differences
- Virtual table layout

Always verify against actual ARM64 binary, not Windows headers.

## Batch Extraction Script

For batch extraction without MCP, use the headless Ghidra script:

```bash
GHIDRA_INSTALL_DIR=/path/to/ghidra \
JAVA_HOME=/path/to/java \
analyzeHeadless /project/dir ProjectName \
  -noanalysis \
  -postScript batch_extract_component_sizes.py
```

Output: `ghidra/offsets/component_sizes.json`

## Statistics (2025-12-22)

- **Total TypeIds extracted**: 1,999 components
- **Property definitions parsed**: 504 components
- **ARM64 sizes verified**: 30 components
- **Namespace breakdown** (sizes):
  - eoc:: 25 components
  - esv:: 1 component
  - ecl:: 1 component
  - Sub-namespaces: status (4), combat (1), god (1), inventory (1), spell (1)

## Batch Expansion Strategy

With the infrastructure in place, we can now expand coverage rapidly:

### Phase 1: Tag Components (Zero Effort)
Tag components have no fields - presence IS the data. Just register them:
```c
{ "eoc::CombatParticipantFlagComponent", NULL, 0, 0 }  // 0 size = tag
```
**Target**: 100+ tag components in one batch

### Phase 2: Simple Data Components
Components with 1-5 simple fields (int32, float, GUID):
1. Get TypeId from `generated_typeids.h`
2. Get properties from `generated_property_defs.h`
3. Verify ARM64 size via Ghidra (or trust Windows if small)
4. Add to `component_offsets.h`

**Target**: 50+ data components

### Phase 3: Complex Components
Components with arrays, hash maps, nested structs:
1. Full Ghidra analysis required
2. Runtime probing to verify offsets
3. Custom marshaling code if needed

**Target**: 20-30 high-priority components

## Next Steps

1. **Batch register 100+ tag components** - zero-field components just need TypeId
2. **Verify property offsets** for 504 parsed components via runtime probing
3. **Continue Ghidra extraction** for remaining high-priority sizes
4. **Cross-reference with Windows** to catch ARM64-specific differences
