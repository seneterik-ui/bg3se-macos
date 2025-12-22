# Miscellaneous Components

This file documents components in the smaller namespaces: `gui::`, `navcloud::`, and `ecs::`.

## gui:: Components (26 total)

GUI-related components for user interface systems.

| Count | Description |
|-------|-------------|
| 26 | UI state, widgets, input handling |

No property layouts currently parsed from Windows headers.

## navcloud:: Components (13 total)

Navigation and pathfinding components.

| Count | Description |
|-------|-------------|
| 13 | Navigation mesh, pathfinding, AI movement |

No property layouts currently parsed from Windows headers.

## ecs:: Components (1 total)

ECS system internals.

| Count | Description |
|-------|-------------|
| 1 | Internal component system management |

No property layouts currently parsed from Windows headers.

## Usage

These components are typically internal and not directly accessed by mods. For modding purposes, focus on:

- **eoc::** for gameplay systems
- **esv::** for server-side logic
- **ecl::** for client-side visuals
- **ls::** for base engine features

## Adding Property Layouts

If you need to access properties on these components:

1. Find the component in Windows BG3SE GameDefinitions/
2. Add to `tools/parse_component_headers.py` type mappings
3. Generate and verify offsets on ARM64

See [README.md](README.md) for the full workflow.
