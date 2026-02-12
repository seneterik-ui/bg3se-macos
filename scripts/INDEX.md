# scripts/ Index

Build, deployment, launch, and reverse engineering scripts.

## Build & Deploy
| Script | Description |
|--------|-------------|
| `build.sh` | Build the project |
| `rebuild.sh` | Clean rebuild |
| `deploy.sh` | Deploy dylib to Steam folder (called by CMake POST_BUILD) |

## Launch
| Script | Description |
|--------|-------------|
| `launch_bg3.sh` | Launch BG3 with dylib injected (DYLD_INSERT_LIBRARIES) |
| `launch_bg3.sh.example` | Template for launch script |
| `launch_via_steam.sh` | Launch through Steam |
| `launch_via_steam.sh.example` | Template for Steam launch |
| `bg3-wrapper.sh` | Wrapper for BG3 binary |
| `bg3-wrapper.sh.example` | Template for wrapper |
| `bg3w.sh` | Short alias wrapper |
| `bg3w-intel.sh` | Intel/Rosetta wrapper |

## Testing
| Script | Description |
|--------|-------------|
| `test_components.lua` | Component property validation |

## Reverse Engineering
| Directory | Description |
|-----------|-------------|
| `re/` | RE helper scripts (ADRP scanner, ARM64 disassembler, string finder) |
| `parallel_ghidra.sh` | Parallel Ghidra MCP extraction |

## Libraries
| Directory | Description |
|-----------|-------------|
| `library/` | Shared script libraries |
