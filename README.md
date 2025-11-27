# BG3SE-macOS

**Baldur's Gate 3 Script Extender for macOS**

A native macOS implementation of the BG3 Script Extender, enabling mods that require scripting capabilities (like "More Reactive Companions") to work on Mac.

## Status

🚧 **Work in Progress** - Proof of Concept Working!

| Phase | Status | Notes |
|-------|--------|-------|
| DYLD Injection | ✅ Complete | Working via `open --env` launch method |
| Symbol Resolution | ✅ Complete | All 6/6 libOsiris symbols resolved |
| Function Hooking | 🔄 In Progress | Dobby inline hooking integrated |
| Lua Runtime | ⏳ Pending | |
| Mod Compatibility | ⏳ Pending | Target: More Reactive Companions |

### Verified Working (Nov 27, 2025)

- ✅ Steam launch with injection via wrapper script
- ✅ Universal binary (ARM64 native + x86_64 Rosetta)
- ✅ Game runs natively on Apple Silicon with injection
- ✅ Game loads to main menu with injection active
- ✅ **Successfully loaded saved games with injection active**
- ✅ 533 loaded images enumerated
- ✅ libOsiris.dylib symbol addresses resolved (6/6):
  - `DebugHook`, `CreateRule`, `DefineFunction`, `SetInitSection`
  - `COsiris::InitGame`, `COsiris::Load`

## Requirements

- macOS 12+ (tested on macOS 15.6.1)
- Apple Silicon or Intel Mac
- Baldur's Gate 3 (Steam version)
- Xcode Command Line Tools (`xcode-select --install`)

## Quick Start

### Build

```bash
cd bg3se-macos
./scripts/build.sh
```

This builds a universal binary supporting both ARM64 (native) and x86_64 (Rosetta).

### Install

1. Create wrapper script `/tmp/bg3w.sh`:

```bash
#!/bin/bash
DYLIB_PATH="/path/to/bg3se-macos/build/lib/libbg3se.dylib"
exec open -W --env "DYLD_INSERT_LIBRARIES=$DYLIB_PATH" "$1"
```

2. Make executable:
```bash
chmod +x /tmp/bg3w.sh
```

3. Set Steam launch options for BG3:
```
/tmp/bg3w.sh %command%
```

4. Launch BG3 via Steam normally

### Verify

Check `/tmp/bg3se_macos.log` for injection logs:
```
=== BG3SE-macOS v0.3.0 ===
[timestamp] === BG3SE-macOS v0.3.0 initialized ===
[timestamp] Running in process: Baldur's Gate 3 (PID: XXXXX)
[timestamp] Architecture: ARM64 (Apple Silicon)
[timestamp] Loaded images: 533
[timestamp] libOsiris.dylib handle obtained!
[timestamp] Found 6/6 key Osiris symbols
```

## How It Works

BG3SE-macOS uses `DYLD_INSERT_LIBRARIES` to inject a dynamic library into the BG3 process at launch. This works because:

1. BG3 macOS has **no hardened runtime** (`flags=0x0`)
2. DYLD injection is allowed for non-hardened apps
3. libOsiris.dylib exports clean C symbols we can hook

### Key Discoveries

#### 1. Launch Method Matters

macOS apps must be launched as `.app` bundles via the `open` command:

| Method | Result |
|--------|--------|
| `exec "$APP/Contents/MacOS/Baldur's Gate 3"` | ❌ Crashes |
| `open -W "$APP"` | ✅ Works (but env not inherited) |
| `open -W --env "DYLD_INSERT_LIBRARIES=..." "$APP"` | ✅ Works perfectly |

#### 2. Environment Variable Inheritance

The `open` command does **not** inherit environment variables from the parent shell. You must use `open --env VAR=value` to pass environment variables to the launched application.

#### 3. Universal Binary Required

BG3 can run either natively (ARM64) or under Rosetta (x86_64). The `open --env` method launches natively on Apple Silicon, so our dylib must be a universal binary containing both architectures.

### Architecture

```
┌─────────────────────────────────────────────────┐
│                  BG3 Process                    │
├─────────────────────────────────────────────────┤
│  ┌──────────────┐    ┌───────────────────────┐  │
│  │ libOsiris    │◄───│ BG3SE Hooks           │  │
│  │ (Scripting)  │    │ - COsiris::InitGame   │  │
│  └──────────────┘    │ - CreateRule          │  │
│                      │ - DefineFunction      │  │
│  ┌──────────────┐    └───────────────────────┘  │
│  │ Main Game    │              ▲               │
│  │ Executable   │              │               │
│  └──────────────┘    ┌─────────┴─────────┐    │
│                      │  Lua Runtime       │    │
│                      │  (Mod Scripts)     │    │
│                      └───────────────────┘    │
└─────────────────────────────────────────────────┘
```

## File Structure

```
bg3se-macos/
├── src/
│   └── injector/
│       └── main.c          # Entry point & initialization
├── lib/
│   ├── fishhook/           # Symbol rebinding (for imported symbols)
│   └── Dobby/              # Inline hooking (for internal functions)
├── scripts/
│   └── build.sh            # Build script (universal binary)
├── build/
│   └── lib/
│       └── libbg3se.dylib  # Built dylib (universal: arm64 + x86_64)
└── README.md
```

## Technical Details

### Why This Works

| Factor | Value |
|--------|-------|
| Hardened Runtime | `flags=0x0` (none) |
| Code Signing | Developer ID signed, but not hardened |
| DYLD Injection | Allowed |
| libOsiris Exports | 1,013 symbols |

### Hooking Strategy

- **fishhook**: For imported symbols (PLT/GOT rebinding)
- **Dobby**: For internal library functions (inline hooking)

Osiris functions like `DebugHook`, `CreateRule`, etc. are internal to `libOsiris.dylib`, requiring inline hooking via Dobby.

### Key libOsiris Symbols

```
_DebugHook           - Debug interface
_CreateRule          - Script rule creation
_DefineFunction      - Function registration
_SetInitSection      - Initialization hook
_ZN7COsiris8InitGameEv    - COsiris::InitGame
_ZN7COsiris4LoadER12COsiSmartBuf - COsiris::Load
```

### Sample Log Output (v0.3.0)

```
=== BG3SE-macOS v0.3.0 ===
Injection timestamp: 1764227581
Process ID: 32878
[2025-11-27 02:13:01] === BG3SE-macOS v0.3.0 initialized ===
[2025-11-27 02:13:01] Running in process: Baldur's Gate 3 (PID: 32878)
[2025-11-27 02:13:01] Architecture: ARM64 (Apple Silicon)
[2025-11-27 02:13:01] Loaded images: 533
[2025-11-27 02:13:01]   [0] .../libbg3se.dylib
[2025-11-27 02:13:01]   [1] .../Baldur's Gate 3
[2025-11-27 02:13:01]   [5] .../libOsiris.dylib
[2025-11-27 02:13:01] libOsiris.dylib handle obtained!
[2025-11-27 02:13:01] Osiris symbol addresses:
[2025-11-27 02:13:01]   DebugHook: 0x113434b68
[2025-11-27 02:13:01]   CreateRule: 0x113437570
[2025-11-27 02:13:01]   DefineFunction: 0x113430b18
[2025-11-27 02:13:01]   SetInitSection: 0x113432130
[2025-11-27 02:13:01]   COsiris::InitGame: 0x11342d9b8
[2025-11-27 02:13:01]   COsiris::Load: 0x11342b150
[2025-11-27 02:13:01] Found 6/6 key Osiris symbols
```

## Target Mod

Primary goal: Enable **"More Reactive Companions"** ([Nexusmods #5447](https://www.nexusmods.com/baldursgate3/mods/5447)) to work on macOS.

Required SE APIs:
- `Ext.Require()`
- `Ext.IO.LoadFile()`
- `Ext.Json.Parse()`
- `Osi.*` functions

## Troubleshooting

### Injection Not Working

1. Check `/tmp/bg3se_macos.log` for errors
2. Verify the dylib is built: `file build/lib/libbg3se.dylib`
3. Ensure it's universal: should show both `x86_64` and `arm64`
4. Ensure wrapper uses `open --env` (not just `export`)

### Game Crashes at Launch

1. Make sure wrapper script uses `open -W --env "DYLD_INSERT_LIBRARIES=..." "$1"`
2. Verify dylib is universal binary (check with `file` command)
3. Try running without injection: clear Steam launch options
4. Check Console.app for crash reports

### Architecture Mismatch Error

If you see "incompatible architecture" in crash reports:
1. Rebuild with `./scripts/build.sh` (creates universal binary)
2. Verify with: `file build/lib/libbg3se.dylib`
3. Should show: `Mach-O universal binary with 2 architectures: [x86_64] [arm64]`

## Maintenance

When BG3 updates:

1. Run `nm -gU` on the new libOsiris.dylib
2. Compare with previous symbol addresses
3. Update any hardcoded offsets
4. Rebuild and test

## License

MIT License

## Credits

- Inspired by [Norbyte's BG3SE](https://github.com/Norbyte/bg3se)
- [Dobby](https://github.com/jmpews/Dobby) - Inline hooking framework
- [fishhook](https://github.com/facebook/fishhook) - Symbol rebinding library
