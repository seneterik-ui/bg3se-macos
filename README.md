<p align="center">
  <img src="assets/tanit.svg" alt="Symbol of Tanit" width="80" height="100"/>
</p>

# BG3SE-macOS

**Baldur's Gate 3 Script Extender for macOS**

A native macOS implementation of the BG3 Script Extender, working toward full feature parity with Norbyte's Windows BG3SE. Enables mods that require scripting capabilities to work on Mac—including companion mods, gameplay tweaks, UI enhancements, and more.

> **Note:** This is a ground-up rebuild, not a port—the Windows BG3SE uses x86_64 assembly and Windows APIs that don't exist on macOS ARM64. We use the Windows codebase as architectural reference while reverse-engineering the macOS binary via Ghidra.

## Quick Start

### Requirements

- macOS 12+ (tested on macOS 15.6.1)
- Apple Silicon Mac (recommended) or Intel Mac (limited functionality)
- Baldur's Gate 3 (Steam)
- Xcode Command Line Tools: `xcode-select --install`
- CMake: `brew install cmake`

### Build & Install

```bash
# Build
cd bg3se-macos
./scripts/build.sh

# Set Steam launch options for BG3:
/path/to/bg3se-macos/scripts/bg3w.sh %command%
```

### Using SE Mods

SE mods work automatically—just install them like any other mod:

1. Download the mod's `.pak` file from Nexus Mods
2. Place it in `~/Documents/Larian Studios/Baldur's Gate 3/Mods/`
3. Enable the mod in the game's mod manager
4. Launch via Steam

**BG3SE-macOS reads scripts directly from PAK files—no extraction needed!**

## Status

**Version:** v0.32.4 | **Feature Parity:** ~57%

| Feature | Status |
|---------|--------|
| DYLD Injection | ✅ Complete |
| Lua Runtime | ✅ Lua 5.4 with Ext API |
| Mod Loading | ✅ PAK file reading, auto-detection |
| Ext.Osiris | ✅ Event listeners, custom functions (NewCall/NewQuery/NewEvent/RaiseEvent/GetCustomFunctions) |
| Ext.Entity | ✅ GUID lookup, 36 component layouts, GetAllEntitiesWithComponent, GetByHandle |
| Ext.Stats | ✅ 15,774 stats, property read/write, **Sync complete (created + existing stats)** |
| Ext.Events | ✅ 10 events with Prevent pattern |
| Ext.Timer | ✅ WaitFor, Cancel, Pause, Resume |
| Ext.Vars | ✅ PersistentVars + User Variables + Mod Variables |
| Ext.Input | ✅ Hotkeys, key injection |
| Ext.Math | ✅ Vector/matrix operations |
| Ext.Enums | ✅ 14 enum/bitfield types |
| Ext.StaticData | 🔶 Feat type (hook-based capture) |
| Lifetime Scoping | ✅ Prevents stale object access |
| Debug Console | ✅ Socket + file + in-game overlay |
| Testing | ✅ `!test` suite, Debug.* helpers, Frida scripts |

See [ROADMAP.md](ROADMAP.md) for detailed progress.

## Documentation

| Document | Description |
|----------|-------------|
| **[docs/getting-started.md](docs/getting-started.md)** | Installation, building, first launch |
| **[docs/api-reference.md](docs/api-reference.md)** | Complete Ext.* and Osi.* API docs |
| **[docs/architecture.md](docs/architecture.md)** | Technical deep-dive: injection, hooks, ARM64 |
| **[docs/development.md](docs/development.md)** | Contributing, building features, debugging |
| **[docs/contributor-workflow.md](docs/contributor-workflow.md)** | End-to-end guide: research, Ghidra, implementation |
| **[docs/reverse-engineering.md](docs/reverse-engineering.md)** | Ghidra workflows, offset discovery |
| **[docs/troubleshooting.md](docs/troubleshooting.md)** | Common issues and solutions |

## Live Console

Three ways to interact with the Lua runtime:

1. **In-Game Overlay** - Press **Ctrl+`** to toggle
2. **Socket Console** - `./build/bin/bg3se-console`
3. **File-Based** - Write to `~/Library/Application Support/BG3SE/commands.txt`

```bash
# Socket console (recommended for development)
./build/bin/bg3se-console

# Or via socat
socat - UNIX-CONNECT:/tmp/bg3se.sock
```

## File Structure

```
bg3se-macos/
├── src/
│   ├── injector/
│   │   └── main.c              # Core injection, Dobby hooks, Lua state init
│   ├── core/
│   │   ├── logging.c/h         # Structured logging (14 modules, 4 levels)
│   │   ├── safe_memory.c/h     # Safe memory read/write (mach_vm)
│   │   └── version.h           # Version info, data paths
│   ├── lua/
│   │   ├── lua_ext.c/h         # Ext.Print, Ext.Utils, Ext.Memory
│   │   ├── lua_stats.c/h       # Ext.Stats API
│   │   ├── lua_events.c/h      # Ext.Events system
│   │   ├── lua_timer.c/h       # Ext.Timer API
│   │   ├── lua_osiris.c/h      # Osi.* namespace bindings
│   │   ├── lua_debug.c/h       # Ext.Debug memory introspection
│   │   ├── lua_json.c/h        # JSON encode/decode
│   │   └── lua_persistentvars.c/h  # Ext.Vars persistence
│   ├── entity/
│   │   ├── entity_system.c/h   # Core ECS, Lua bindings
│   │   ├── guid_lookup.c/h     # GUID parsing, HashMap ops
│   │   ├── arm64_call.c/h      # ARM64 ABI wrappers (x8 indirect return)
│   │   ├── component_*.c/h     # Component registry, lookup, TypeId
│   │   └── entity_storage.h    # Storage structures, Ghidra base addr
│   ├── stats/
│   │   └── stats_manager.c/h   # RPGStats access, property resolution
│   ├── strings/
│   │   └── fixed_string.c/h    # GlobalStringTable resolution
│   ├── osiris/
│   │   ├── osiris_functions.c/h    # Osiris function lookup/call
│   │   ├── osiris_types.h      # FuncDef, OsiArgumentDesc structs
│   │   ├── custom_functions.c/h    # Custom Osiris function registration
│   │   └── pattern_scan.c/h    # Memory pattern scanning
│   ├── console/
│   │   └── console.c/h         # Socket + file-based console
│   ├── input/
│   │   ├── input_hooks.m       # macOS input event hooks
│   │   └── lua_input.c         # Ext.Input API
│   ├── overlay/
│   │   └── overlay.m/h         # In-game debug overlay (NSWindow)
│   ├── timer/
│   │   └── timer.c/h           # Timer system implementation
│   ├── game/
│   │   └── game_state.c/h      # Game state tracking
│   ├── mod/
│   │   └── mod_loader.c/h      # Mod detection, PAK loading
│   ├── pak/
│   │   └── pak_reader.c/h      # LSPK v18 PAK file parsing
│   ├── math/
│   │   └── math_ext.c/h        # Ext.Math vector/matrix ops
│   └── hooks/
│       └── osiris_hooks.c/h    # Osiris event interception
│
├── ghidra/
│   ├── scripts/                # Ghidra Python analysis scripts
│   │   ├── run_analysis.sh     # Headless analyzer wrapper
│   │   ├── find_rpgstats.py    # Discover gRPGStats global
│   │   ├── find_entity_offsets.py
│   │   └── ...
│   └── offsets/                # Discovered offset documentation
│       ├── STATS.md            # RPGStats, FixedStrings (0x348)
│       ├── ENTITY_SYSTEM.md    # ECS architecture
│       └── ...
│
├── docs/                       # User-facing documentation
├── tools/
│   ├── bg3se-console.c         # Standalone readline console client
│   ├── extract_pak.py          # PAK file extractor
│   └── frida/                  # Frida instrumentation scripts
│
├── scripts/
│   ├── build.sh                # Build script
│   ├── bg3w.sh                 # Steam launch wrapper (ARM64)
│   ├── bg3w-intel.sh           # Steam launch wrapper (Intel)
│   └── launch_bg3.sh           # Direct launch for testing
│
├── lib/                        # Third-party libraries
│   ├── Dobby/                  # Inline hooking framework
│   ├── lua/                    # Lua 5.4
│   └── lz4/                    # Compression for PAK files
│
├── agent_docs/                 # Claude Code context docs
├── plans/                      # Implementation plans
└── test-mods/                  # Test mod examples
```

## Acknowledgments

### Special Thanks

This project would not be possible without **[Norbyte](https://github.com/Norbyte)** and their pioneering work on the original [BG3 Script Extender](https://github.com/Norbyte/bg3se) for Windows. Their reverse engineering of Larian's Osiris scripting engine, comprehensive API design, and years of dedication to the modding community laid the foundation that made this macOS port conceivable. We are deeply grateful for their open-source contribution to the BG3 modding ecosystem.

### Credits

- [Norbyte's BG3SE](https://github.com/Norbyte/bg3se) - The original Windows Script Extender
- [Dobby](https://github.com/jmpews/Dobby) - Inline hooking framework for ARM64/x86_64
- [fishhook](https://github.com/facebook/fishhook) - Symbol rebinding library
- [LZ4](https://github.com/lz4/lz4) - Fast compression for PAK file reading
- Test mod: [More Reactive Companions](https://www.nexusmods.com/baldursgate3/mods/5447) by LightningLarryL

## License

MIT License

## Authors

- Tom di Mino (the artist formerly known as [Pnutmaster](https://wiki.twcenter.net/index.php?title=Blood_Broads_%26_Bastards) / [Nexus](https://next.nexusmods.com/profile/Pnutmaster/mods?gameId=130))
- [Claude Code](https://claude.ai/claude-code) (Anthropic)

## Support This Project

If you love exceptionally well-crafted RPGs like Baldur's Gate 3, and the ability to extend its gameplay through mods and scripting, you're more than welcome to toss me some coin.

[![PayPal](https://img.shields.io/badge/PayPal-Donate-blue?logo=paypal)](https://www.paypal.com/donate?business=contact@tomdimino.com&currency_code=USD)

Donations help fund continued development, testing across game updates, and expanding mod compatibility. Every contribution is appreciated!

### P.S.

I'd also like to extend my thanks to the OP and commentators of this BG3SE issue: **["[Feature Bounty - $350] MacOS Supported Version of BG3 SE"](https://github.com/Norbyte/bg3se/issues/162)**. You kicked off this quest :)
