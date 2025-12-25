# ls:: Component Layout Generation Summary

**Date:** 2025-12-24
**Generated File:** `/Users/tomdimino/Desktop/Programming/bg3se-macos/ghidra/offsets/staging/generated_ls_layouts.c`

## Overview

Generated **45 component layouts** for the ls:: namespace by cross-referencing:
1. **Ghidra ARM64 sizes** from `COMPONENT_SIZES_LS*.md` files
2. **Windows BG3SE headers** from `/Users/tomdimino/Desktop/Programming/bg3se/BG3Extender/GameDefinitions/Components/`

## Breakdown by Category

### Tag Components (1 byte, no fields) - 16 components
- `ls::AlwaysUpdateEffectComponent`
- `ls::AnimationUpdateComponent`
- `ls::ClusterAttachRequestComponent`
- `ls::ClusterComponent`
- `ls::EffectCreateOneFrameComponent`
- `ls::IsGlobalComponent`
- `ls::LevelInstanceLoadComponent`
- `ls::LevelIsOwnerComponent`
- `ls::PhysicsLoadedComponent`
- `ls::PhysicsStreamLoadComponent`
- `ls::RoomTriggerTagComponent`
- `ls::SavegameComponent`
- `ls::SoundActivatedComponent`
- `ls::VisualChangedEventOneFrameComponent`
- `ls::VisualLoadedComponent`
- `ls::animation::AnimationSetUpdateRequestComponent`

### Primitive Components (2-8 bytes) - 19 components

**2 bytes:**
- `ls::CullComponent` (2 uint8 flags)

**4 bytes:**
- `ls::TimeFactorComponent` (float)
- `ls::LevelRootComponent` (FixedString)
- `ls::LevelUnloadedOneFrameComponent` (FixedString)
- `ls::ClusterBoundMaxComponent` (float)
- `ls::ClusterDistMaxComponent` (float)
- `ls::ClusterDistMinComponent` (float)
- `ls::ClusterPositionXComponent` (float)
- `ls::ClusterPositionYComponent` (float)
- `ls::ClusterPositionZComponent` (float)
- `ls::ClusterRadiusComponent` (float)
- `ls::VisualStreamHintComponent` (uint32)
- `ls::scene::SceneStageComponent` (uint32)

**8 bytes:**
- `ls::AnimationBlueprintComponent` (pointer)
- `ls::AnimationSetComponent` (pointer)
- `ls::ParentEntityComponent` (EntityHandle)
- `ls::SaveWithComponent` (EntityHandle)
- `ls::level::LevelInstanceTempDestroyedComponent` (EntityHandle)
- `ls::anubis::LoadRequestOneFrameComponent` (pointer)

### Structured Components (16+ bytes) - 10 components

**16 bytes:**
- `ls::uuid::Component` (Guid)
- `ls::LevelComponent` (EntityHandle + FixedString)
- `ls::VisualComponent` (pointer + 3 bytes of flags)
- `ls::trigger::IsInsideOfComponent` (Array<Guid>)
- `ls::animation::DynamicAnimationTagsComponent` (Array)
- `ls::animation::TemplateAnimationSetOverrideComponent` (Array)
- `ls::animation::LoadAnimationSetGameplayRequestOneFrameComponent` (Array)

**24 bytes:**
- `ls::PhysicsComponent` (7 fields: pointer, 3 uint32s, 3 bools)

**40 bytes:**
- `ls::TransformComponent` (Transform matrix)

**48 bytes:**
- `ls::animation::RemoveAnimationSetsGameplayRequestOneFrameComponent` (HashSet)

**64 bytes:**
- `ls::uuid::ToHandleMappingComponent` (HashMap<Guid, EntityHandle>)
- `ls::LevelInstanceComponent` (9 fields: 3 FixedStrings, 6 bools/flags)

## Field Type Coverage

### Fully Supported Types
- `FIELD_TYPE_BOOL` (1 byte)
- `FIELD_TYPE_UINT8` (1 byte)
- `FIELD_TYPE_UINT32` (4 bytes)
- `FIELD_TYPE_INT32` (4 bytes)
- `FIELD_TYPE_FLOAT` (4 bytes)
- `FIELD_TYPE_FIXEDSTRING` (4 bytes)
- `FIELD_TYPE_ENTITYHANDLE` (8 bytes)
- `FIELD_TYPE_GUID` (16 bytes)
- `FIELD_TYPE_PTR` (8 bytes)

### Partial Support (Placeholders)
- `FIELD_TYPE_ARRAY` - Used for Array<T> types (16 bytes typical)
- `FIELD_TYPE_HASHMAP` - Used for HashMap<K,V> types (64 bytes typical)
- `FIELD_TYPE_HASHSET` - Used for HashSet<T> types (48 bytes typical)
- `FIELD_TYPE_TRANSFORM` - Used for Transform matrix (40 bytes)

## Components NOT Included

### Skipped (Singleton Components)
Components marked as "Singleton" in Ghidra analysis were skipped as they don't have standard component allocation:
- `ls::GameplayEffectSetTimeFactorRequestsSingletonComponent`
- `ls::GameplayVFXSetPlayTimeRequestsSingletonComponent`
- `ls::GameplayVFXSingletonComponent`
- `ls::VisualLoadRequestsSingletonComponent`
- `ls::animation::GameplayEventsSingletonComponent`
- `ls::animation::TextKeyEventsSingletonComponent`

### Skipped (No Size Data)
Components without reliable size information from Ghidra:
- `ls::VisualAttachRequestOneFrameComponent`
- `ls::VisualChangeRequestOneFrameComponent`
- `ls::WorldMapCameraBehavior`
- `ls::SkeletonSoundObjectTransformComponent`
- `ls::SkeletonSoundObjectsComponent`
- `ls::SoundCameraComponent`
- `ls::trigger::AreaComponent`
- `ls::trigger::ContainerComponent`
- `ls::anubis::EventsForwardingComponent`
- `ls::anubis::RuntimeComponent`
- `ls::anubis::TreeComponent`
- `ls::game::PauseComponent`

## Next Steps

1. **Add to component_offsets.h** - Copy layouts to main header file
2. **Verify field offsets** - Use `Ext.Debug.ProbeStruct()` in-game to validate ARM64 offsets
3. **Register layouts** - Add to `g_AllComponentLayouts` array
4. **Test in-game** - Use `Ext.Entity.Get(guid).ComponentName` to verify field access

## Notes

- **ARM64 offsets assumed** - Field offsets calculated based on Windows struct definitions may differ from ARM64 due to alignment differences
- **Pointer fields** - All pointer fields use `FIELD_TYPE_PTR` placeholder
- **Complex types** - Arrays, HashMaps, and HashSets use placeholder types and will need custom serialization
- **Transform component** - Uses placeholder type; actual layout is position (vec3) + rotation (quat) + scale (vec3)

## Source Files

**Ghidra Size Data:**
- `/Users/tomdimino/Desktop/Programming/bg3se-macos/ghidra/offsets/components/COMPONENT_SIZES_LS_CORE.md` (105 components)
- `/Users/tomdimino/Desktop/Programming/bg3se-macos/ghidra/offsets/components/COMPONENT_SIZES_LS_ANIMATION.md` (10 components)
- `/Users/tomdimino/Desktop/Programming/bg3se-macos/ghidra/offsets/components/COMPONENT_SIZES_LS_MISC.md` (23 components)

**Windows Headers:**
- `/Users/tomdimino/Desktop/Programming/bg3se/BG3Extender/GameDefinitions/Components/Components.h`
- `/Users/tomdimino/Desktop/Programming/bg3se/BG3Extender/GameDefinitions/Components/Visual.h`

## Statistics

- **Total ls:: components in Ghidra:** 138 (excluding singletons)
- **Components with size data:** 114
- **Components generated:** 45
- **Coverage:** 39% of sized components (focused on simpler components)
- **Total lines of C code:** ~665

## Component Size Distribution

- **1 byte (tags):** 16 components
- **2 bytes:** 1 component
- **4 bytes:** 12 components
- **8 bytes:** 6 components
- **16 bytes:** 7 components
- **24 bytes:** 1 component
- **40 bytes:** 1 component
- **48 bytes:** 1 component
- **64 bytes:** 2 components

## Key Components for Entity System

### Core Entity Components
- `ls::uuid::Component` - Entity GUID (essential for GUID lookup)
- `ls::ParentEntityComponent` - Entity hierarchy
- `ls::TransformComponent` - Position/rotation/scale

### Visual System
- `ls::VisualComponent` - Visual resource pointer
- `ls::AnimationBlueprintComponent` - Animation blueprint
- `ls::AnimationSetComponent` - Animation sets

### Level Management
- `ls::LevelComponent` - Level association
- `ls::LevelInstanceComponent` - Level instance data
- `ls::LevelRootComponent` - Level root marker

### Physics
- `ls::PhysicsComponent` - Physics object reference
- `ls::StaticPhysicsComponent` - Static physics (not in generated list)

## Sample Generated Code

```c
// ls::TimeFactorComponent - 4 bytes (0x04)
// Source: Components.h, COMPONENT_SIZES_LS_CORE.md
static const ComponentPropertyDef g_ls_TimeFactor_Properties[] = {
    { "Value", 0x00, FIELD_TYPE_FLOAT, 0, true },
};
static const ComponentLayoutDef g_ls_TimeFactor_Layout = {
    .componentName = "ls::TimeFactorComponent",
    .shortName = "TimeFactor",
    .componentTypeIndex = 0,
    .componentSize = 0x04,
    .properties = g_ls_TimeFactor_Properties,
    .propertyCount = sizeof(g_ls_TimeFactor_Properties) / sizeof(g_ls_TimeFactor_Properties[0]),
};
```

## Sub-namespace Coverage

- **ls::animation::** 6 components
- **ls::uuid::** 2 components
- **ls::level::** 1 component
- **ls::scene::** 1 component
- **ls::trigger::** 1 component
- **ls::anubis::** 1 component
- **ls:: (root):** 33 components

## Verification Strategy

For each component, verify in-game:

1. **Tag components (1 byte)** - Just check presence/absence
2. **Primitive components** - Verify field values match expected types
3. **Structured components** - Use ProbeStruct to validate offsets

Example verification:
```lua
-- Get player entity
local player = Ext.Entity.Get(Osi.GetHostCharacter())

-- Check TimeFactor component
if player.TimeFactor then
    _P("TimeFactor.Value:", player.TimeFactor.Value)
end

-- Check Transform component
if player.Transform then
    _P("Transform:", player.Transform.Transform)
end

-- Check UUID component
if player.Uuid then
    _P("UUID:", player.Uuid.EntityUuid)
end
```
