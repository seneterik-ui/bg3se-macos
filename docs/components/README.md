# BG3SE-macOS Component Reference

This directory contains documentation for all 1,999 entity components in Baldur's Gate 3.

## Overview

| Namespace | Components | Description |
|-----------|------------|-------------|
| `eoc::` | 701 | Engine of Combat - BG3 gameplay systems |
| `esv::` | 596 | Server-side components |
| `ecl::` | 429 | Client-side components |
| `ls::` | 233 | Larian Studios base components |
| `gui::` | 26 | GUI-related components |
| `navcloud::` | 13 | Navigation/pathfinding components |
| `ecs::` | 1 | ECS system internals |

## Component Access

### Checking if an Entity Has a Component

```lua
local entity = Ext.Entity.Get("GUID")
if entity:HasComponent("eoc::HealthComponent") then
    -- Component exists
end
```

### Getting All Components

```lua
local entity = Ext.Entity.Get("GUID")
local components = entity:GetAllComponents()
for name, _ in pairs(components) do
    Ext.Print(name)
end
```

### Accessing Component Properties

Property access requires verified offsets. High-priority components with property layouts:

| Component | Properties | Verified |
|-----------|------------|----------|
| `eoc::HealthComponent` | Hp, MaxHp, TemporaryHp, MaxTemporaryHp, IsInvulnerable | Yes |
| `eoc::ArmorComponent` | ArmorType, ArmorClass, AbilityModifierCap, ArmorClassAbility, EquipmentType | Yes |
| `eoc::BaseHpComponent` | Vitality, VitalityBoost | Yes |
| `eoc::StatsComponent` | InitiativeBonus, Abilities[7], AbilityModifiers[7], Skills[18], ProficiencyBonus | Partial |
| `eoc::DataComponent` | Weight, StatsId, StepsType | Yes |
| `eoc::ClassesComponent` | Classes (array of ClassInfo) | Yes |
| `eoc::MovementComponent` | Direction, Acceleration, Speed, Speed2 | Yes |
| `eoc::ResistancesComponent` | Resistances[14], AC | Partial |
| `eoc::WeaponComponent` | WeaponRange, DamageRange, WeaponProperties, WeaponGroup, Ability | Yes |
| `eoc::ValueComponent` | Value, Rarity, Unique | Yes |
| `eoc::OriginComponent` | field_18, Origin | Yes |
| `eoc::BackgroundComponent` | Background (GUID) | Yes |
| `eoc::RaceComponent` | Race (GUID) | Yes |
| `eoc::GodComponent` | God, HasGodOverride, GodOverride | Yes |
| `eoc::DisplayNameComponent` | Name, Title | Yes |
| `eoc::ExperienceComponent` | CurrentLevelExperience, NextLevelExperience, TotalExperience | Yes |
| `eoc::TurnBasedComponent` | IsActiveCombatTurn, Removed, RequestedEndTurn, etc. | Yes |
| `eoc::ConcentrationComponent` | Caster, TargetCount, SpellPrototype | Yes |

## Windows Header Property Coverage

**504 components** have property layouts parsed from Windows BG3SE headers.
See `src/entity/generated_property_defs.h` for generated definitions.

| Namespace | Total | With Properties | Coverage |
|-----------|-------|-----------------|----------|
| `eoc::` | 701 | 276 | 39% |
| `esv::` | 596 | 146 | 24% |
| `ecl::` | 429 | 48 | 11% |
| `ls::` | 233 | 34 | 15% |
| **Total** | **1,999** | **504** | **25%** |

Generate property layouts with:
```bash
python3 tools/parse_component_headers.py > src/entity/generated_property_defs.h  # All 504
python3 tools/parse_component_headers.py --high-priority  # Just 21 high-priority
python3 tools/parse_component_headers.py --list  # List all components
python3 tools/parse_component_headers.py --component Health  # Show specific component
```

**Note:** All 504 components are now in `src/entity/generated_property_defs.h` (8,968 lines).

## Documentation Files

- [eoc-components.md](eoc-components.md) - 701 gameplay components (276 with property layouts)
- [esv-components.md](esv-components.md) - 596 server components (146 with property layouts)
- [ecl-components.md](ecl-components.md) - 429 client components (48 with property layouts)
- [ls-components.md](ls-components.md) - 233 base components (34 with property layouts)
- [misc-components.md](misc-components.md) - gui, navcloud, ecs components

## Coverage Status

**Current:** 1,999 components registered (TypeId detection)
**Ghidra Verified:** 27 components with exact ARM64 sizes via AddComponent<T> decompilation
**Property Access:** 55 components with verified ARM64 layouts
**Windows Reference:** 504 components with estimated layouts (need ARM64 verification)
**Target:** Property access for 150+ high-priority components

## Adding Property Access

To enable property access for a component:

1. Find component offsets via Ghidra or runtime probing
2. Add layout to `src/entity/component_offsets.h`
3. Rebuild

See [development.md](../development.md) for detailed workflow.
