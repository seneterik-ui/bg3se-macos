# ecl:: Components (Client-Side)

429 total components in the `ecl::` namespace. **48 have property layouts** parsed from Windows BG3SE headers.

## Components with Property Layouts

Run `python3 tools/parse_component_headers.py --list 2>/dev/null | grep "ecl::"` to see all 48 components.

### Key Categories

| Category | Examples | Count |
|----------|----------|-------|
| Camera | CameraBehavior, CombatTarget, SelectorMode | ~5 |
| Character Creation | BaseDefinition, CompanionDefinition, DummyDefinition | ~8 |
| Character Light | CharacterLight, CharacterLightSingleton | ~2 |
| Dummy | DummyComponent, DummyEquipmentVisuals, DummySplatter | ~15 |
| Equipment | EquipmentVisuals, VisualsDesiredState | ~3 |
| Photo Mode | CameraOffset, CameraTilt, DummyAnimationUpdate | ~12 |

### Notable Components

| Component | Full Name | Properties |
|-----------|-----------|------------|
| GameCameraBehavior | ecl::GameCameraBehavior | 72 |
| ClientCCDummyDefinition | ecl::character_creation::DummyDefinitionComponent | 18 |
| ClientCCCompanionDefinition | ecl::character_creation::CompanionDefinitionComponent | 9 |
| CharacterLight | ecl::CharacterLightComponent | 8 |
| PhotoModeCameraSavedTransform | ecl::photo_mode::CameraSavedTransformComponent | 5 |

## Usage

Client components are accessed in client-side scripts (BootstrapClient.lua):

```lua
-- Client context only
if Ext.IsClient() then
    local entity = Ext.Entity.Get("GUID")
    local light = entity["ecl::CharacterLightComponent"]
    if light then
        -- Access lighting data
    end
end
```

## Note

Client components handle rendering, UI, and visual state. They're separate from gameplay logic in eoc::/esv:: namespaces.
