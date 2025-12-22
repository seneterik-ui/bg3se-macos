# ls:: Components (Larian Studios Base)

233 total components in the `ls::` namespace. **34 have property layouts** parsed from Windows BG3SE headers.

## Components with Property Layouts

Run `python3 tools/parse_component_headers.py --list 2>/dev/null | grep "ls::"` to see all 34 components.

### Key Categories

| Category | Examples | Count |
|----------|----------|-------|
| Animation | AnimationBlueprintComponent | 1 |
| Audio | AudioData, FoleySound | 3 |
| Scene | SceneLighting, SceneFog | 2 |
| Transform | TransformComponent | 1 |
| Visual | MaterialOverride, VisualBounds | 5 |

### Notable Components

| Component | Full Name | Properties |
|-----------|-----------|------------|
| AnimationBlueprint | ls::AnimationBlueprintComponent | 2 |
| SceneLighting | ls::SceneLightingComponent | 4 |
| SceneFog | ls::SceneFogComponent | 3 |
| TransformComponent | ls::TransformComponent | 3 |
| VisualBounds | ls::VisualBoundsComponent | 2 |

## Verified ARM64 Layouts

| Component | Properties | Status |
|-----------|------------|--------|
| Transform | Rotation, Position, Scale | Verified |
| Level | LevelName | Verified |

## Usage

ls:: components are base engine components used across client and server:

```lua
local entity = Ext.Entity.Get("GUID")

-- Transform is commonly used
local transform = entity.Transform
if transform then
    local pos = transform.Position
    Ext.Print(string.format("Position: %.2f, %.2f, %.2f", pos[1], pos[2], pos[3]))
end
```

## Note

ls:: components are low-level engine primitives. For gameplay data, prefer eoc:: components.
