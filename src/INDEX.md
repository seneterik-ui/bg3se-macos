# src/ Index

Source modules for BG3SE-macOS. Each subsystem is a header+source pair with static state.

## Core
| Module | Files | Description |
|--------|-------|-------------|
| `injector/` | main.c | Core injection, Dobby hooks, Lua state, Osi dispatch, Ext API registration |
| `core/` | logging, version, crashlog, mach_exception, safe_memory | Logging, crash diagnostics, mmap ring buffer |
| `hooks/` | hook stubs | Legacy hook stubs (actual hooks in main.c) |
| `platform/` | platform utils | macOS platform utilities |

## Lua API
| Module | Files | Description |
|--------|-------|-------------|
| `lua/` | lua_ext, lua_json, lua_osiris, lua_stats, lua_events, lua_logging, lua_level, lua_audio, lua_timer, lua_net, lua_imgui, lua_staticdata, lua_template, lua_resource, lua_ide_helpers, lua_context, lua_ui | Ext.* API implementations |
| `math/` | lua_math | Ext.Math namespace |
| `vars/` | persistentvars, uservars, modvars | Ext.Vars namespace |

## Game Systems
| Module | Files | Description |
|--------|-------|-------------|
| `entity/` | entity_system, guid_lookup, arm64_call, component_registry, component_property, component_typeid, entity_events | Entity Component System, GUID lookup, 1999 components |
| `stats/` | stats_manager | RPGStats system access, stat property resolution |
| `osiris/` | osiris_types, osiris_functions, custom_functions | Osiris function cache, handle encoding, pattern scanning |
| `enum/` | enum_registry | Enum/bitfield type system |
| `staticdata/` | staticdata | Immutable game data (Feat, Race, Background, etc.) |
| `template/` | template | Game object templates |
| `resource/` | resource | Non-GUID resources (Visual, Material, etc.) |

## Infrastructure
| Module | Files | Description |
|--------|-------|-------------|
| `console/` | console | File-based + socket Lua command input |
| `overlay/` | overlay | In-game console overlay |
| `input/` | input_hooks | CGEventTap keyboard/mouse capture |
| `imgui/` | imgui_metal_backend, imgui_input_hooks, lua_imgui | Dear ImGui overlay (Metal + CGEventTap) |
| `network/` | net_hooks, net_protocol | Network hooks, ExtenderProtocol |
| `timer/` | timer | Timer system (WaitFor, persistent timers) |
| `lifetime/` | lifetime | Lifetime scoping for Lua objects |

## I/O & Data
| Module | Files | Description |
|--------|-------|-------------|
| `io/` | path_override | File I/O, path redirection |
| `pak/` | pak_reader | LSPK v18 PAK file reading |
| `mod/` | mod_loader | Mod detection from modsettings.lsx |
| `localization/` | localization | Localization/translation system |
| `strings/` | global_string_table | GlobalStringTable access |
| `level/` | level_manager | LevelManager, PhysicsScene, AiGrid |
| `audio/` | audio_manager | WWise SoundManager |
| `game/` | game_state | Game state tracking |
