# Ghidra Analysis Scripts

Scripts for reverse engineering the BG3 macOS ARM64 binary.

## Usage

```bash
JAVA_HOME="/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home" \
  ~/ghidra/support/analyzeHeadless ~/ghidra_projects BG3Analysis \
  -process BG3_arm64_thin \
  -scriptPath /Users/tomdimino/Desktop/Programming/bg3se-macos/ghidra/scripts \
  [-preScript optimize_analysis.py] \
  -postScript <script_name.py>
```

## Script Categories

### Optimization

| Script | Purpose |
|--------|---------|
| `optimize_analysis.py` | **Pre-script** to disable slow analyzers (Stack, Decompiler) for faster runs |

### Osiris Functions

| Script | Purpose |
|--------|---------|
| `analyze_osiris_functions.py` | Enumerate and analyze Osiris function registration |
| `find_osiris_offsets.py` | Find Osiris-related memory offsets |

### Entity System

| Script | Purpose |
|--------|---------|
| `analyze_entity_storage.py` | Analyze EntityWorld and entity storage |
| `find_entity_offsets.py` | Discover Entity system offsets |
| `find_uuid_mapping.py` | Find UuidToHandleMappingComponent for GUID lookup |

### Components

| Script | Purpose |
|--------|---------|
| `find_getrawcomponent_v4.py` | Find GetRawComponent template instances (latest version) |
| `find_component_strings_fresh.py` | Search for component type strings |
| `decompile_getcomponent.py` | Decompile GetComponent functions |
| `quick_component_search.py` | Fast component XREF search |

### Stats System

| Script | Purpose |
|--------|---------|
| `find_rpgstats.py` | Find RPGStats singleton and structure offsets |

### GlobalStringTable

| Script | Purpose | Status |
|--------|---------|--------|
| `find_global_string_table.py` | **NEW** - Comprehensive GST finder with structure validation | Recommended |
| `find_arm64_global_string_table.py` | Search for GlobalStringTable via multiple patterns | Exploratory |

#### Running find_global_string_table.py

```bash
JAVA_HOME="/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home" \
  ~/ghidra/support/analyzeHeadless ~/ghidra_projects BG3Analysis \
  -process BG3_arm64_thin \
  -noanalysis \
  -scriptPath /Users/tomdimino/Desktop/Programming/bg3se-macos/ghidra/scripts \
  -postScript find_global_string_table.py
```

This script uses three discovery methods:
1. **String XREFs** - Finds references to "GlobalStringTable", "FixedString", etc.
2. **Data section scan** - Validates pointers in __DATA against SubTable structure
3. **ADD 0xC600 search** - Finds MainTable offset access patterns

## Archived Scripts

Scripts in `archive/` folder are kept for reference but no longer actively used:
- `find_c600_offset.py` - Confirmed ARM64 doesn't use direct 0xC600 add instructions
- `find_entityworld_access.py` - EntityWorld discovery (completed)
- `find_eocserver_singleton.py` - EoCServer singleton search (completed)
- Various other exploratory scripts

## Key Findings

See `/ghidra/offsets/` for documented offsets:
- `GLOBAL_STRING_TABLE.md` - FixedString resolution investigation
- `STATS_SYSTEM.md` - RPGStats structure at offset 0x89c5730

## Notes

- **Binary base in Ghidra:** `0x100000000`
- **__DATA section:** `0x108970000 - 0x108af7fff` (1.5MB)
- **Use `-noanalysis` flag** to run scripts on already-analyzed binary
