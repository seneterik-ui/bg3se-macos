# Ghidra Analysis

## Quick Launch

```bash
ghidra-bg3  # Opens Ghidra with BG3 binary pre-loaded (defined in shell aliases)
```

For the 1GB+ BG3 binary, **always use the wrapper script**:

```bash
# Run script on already-analyzed project (read-only, fast)
./ghidra/scripts/run_analysis.sh find_modifierlist_offsets.py

# Force re-analysis with optimized settings (slow, only if needed)
./ghidra/scripts/run_analysis.sh find_modifierlist_offsets.py -analyze

# Monitor progress:
tail -f /tmp/ghidra_progress.log
```

## Wrapper Script Behavior
- **Default mode**: Uses `-noanalysis` for fast read-only script execution
- **With `-analyze`**: Applies `optimize_analysis.py` prescript for re-analysis
- Logs to `/tmp/ghidra_progress.log` (progress) and `/tmp/ghidra_output.log` (full output)

## Parallel Analysis

For running multiple scripts simultaneously (accelerates offset discovery):

```bash
# Run 2-3 scripts in parallel (default: 2 concurrent jobs)
./ghidra/scripts/parallel_ghidra.sh find_status_manager.py find_prototype_managers.py find_localization.py

# Increase concurrency (requires more RAM - ~4GB per Ghidra instance)
./ghidra/scripts/parallel_ghidra.sh --max-jobs 4 script1.py script2.py script3.py script4.py

# Show all available scripts
./ghidra/scripts/parallel_ghidra.sh --help
```

**Features:**
- Job limiting to prevent OOM (configurable via `--max-jobs`)
- Per-script logging to `/tmp/ghidra_parallel/<script>.log`
- Summary report at `/tmp/ghidra_parallel/summary.txt`

**RAM Warning:** Each Ghidra instance loads the full BG3 binary (~500MB). Default 2 concurrent jobs is safe for 16GB machines.

## Available Scripts

### Wrapper Scripts
| Script | Purpose |
|--------|---------|
| `run_analysis.sh` | Single-script execution wrapper |
| `parallel_ghidra.sh` | Multi-script parallel execution |

### Analysis Scripts
| Script | Purpose |
|--------|---------|
| `find_modifierlist_offsets.py` | ModifierList structure offsets |
| `find_property_access.py` | Stats property access offsets |
| `find_rpgstats.py` | gRPGStats global pointer |
| `find_getfixedstring.py` | FixedStrings pool offset |
| `find_uuid_mapping.py` | UuidToHandleMappingComponent |
| `find_entity_offsets.py` | Entity system offsets |
| `find_prototype_managers.py` | Prototype manager singletons |
| `find_status_manager.py` | StatusPrototypeManager addresses |
| `find_localization.py` | Localization string tables |
| `analyze_prototype_init.py` | Prototype Init function analysis |
| `quick_component_search.py` | XREFs to component strings |
| `find_staticdata_singletons.py` | StaticData manager singletons (Feat, Race, etc.) |

## Offset Documentation
Detailed findings in `ghidra/offsets/`:
- `STATS.md` - RPGStats system, FixedStrings pool (0x348)
- `ENTITY_SYSTEM.md` - ECS architecture, EntityWorld capture
- `COMPONENTS.md` - GetComponent addresses
- `STRUCTURES.md` - C structure definitions

## Key Discovered Offsets

### Stats System (from STATS.md)
- `RPGSTATS_OFFSET_FIXEDSTRINGS = 0x348` - FixedStrings pool (verified via Ghidra)
- Property resolution: `stat.Name` → IndexedProperties → FixedStrings[pool_index]

### Entity System
- `LEGACY_IsInCombat` hook at `0x10124f92c` captures EntityWorld&
- `TryGetSingleton<UuidToHandleMappingComponent>` at `0x1010dc924`

**Note:** The optimizer prescript disables slow analyzers that would cause analysis to take hours.

## pyGhidra MCP (Interactive Decompilation)

When Ghidra is running with the BG3 binary loaded and MCP plugin enabled, Claude has direct access to decompilation via MCP tools.

### Token Optimization Strategies

Ghidra MCP queries can consume significant tokens. Use these strategies to minimize cost:

| Strategy | Description | Token Impact |
|----------|-------------|--------------|
| **nm/grep first** | Use `nm -gU ... \| c++filt \| grep` for bulk symbol discovery | Very low |
| **Targeted decompilation** | Only call `decompile_function` for specific functions you need | Medium |
| **Limit parameters** | Use `limit` parameter on `search_functions_by_name`, `list_strings` | Reduces bloat |
| **Skip list_strings** | String search often times out on large binaries; use grep instead | Avoids timeouts |

### Recommended Workflow

1. **Discovery phase** (low cost):
   ```bash
   # Find all symbols matching a pattern
   nm -gU "/Applications/Baldur's Gate 3.app/Contents/MacOS/Baldur's Gate 3" 2>/dev/null | c++filt | grep "PatternHere"
   ```

2. **Analysis phase** (targeted):
   ```
   # Only decompile specific functions you've identified
   mcp__ghidra__decompile_function("FunctionName")
   mcp__ghidra__get_xrefs_to("0xADDRESS")
   ```

3. **Structure discovery** (if needed):
   ```
   # Use disassembly for offset patterns
   mcp__ghidra__disassemble_function("0xADDRESS")
   ```

### Available MCP Tools

| Tool | Purpose | Token Cost |
|------|---------|------------|
| `decompile_function` | Decompile by name | Medium |
| `decompile_function_by_address` | Decompile by address | Medium |
| `disassemble_function` | Get assembly listing | Low-Medium |
| `search_functions_by_name` | Find functions (use limit!) | Variable |
| `get_xrefs_to` | Find references to address | Low |
| `get_xrefs_from` | Find outgoing references | Low |
| `list_strings` | Search strings (often times out) | High/Timeout |
| `get_current_function` | Get selected function | Very Low |

### Example: Finding a Singleton

```bash
# Step 1: nm/grep to find symbol addresses (fast, cheap)
nm -gU "BG3" | c++filt | grep "MyManager"
# Found: 0x1089abc00 D ls::TypeId<eoc::MyManager>::m_TypeIndex

# Step 2: Find functions that reference it (targeted Ghidra query)
mcp__ghidra__get_xrefs_to("0x1089abc00")

# Step 3: Decompile only the relevant function
mcp__ghidra__decompile_function_by_address("0x101234567")
```

### MCP vs Python Scripts: When to Use Each

| Approach | Best For | Limitations |
|----------|----------|-------------|
| **MCP** | Quick ad-hoc queries, interactive exploration | Timeouts on large functions, network overhead |
| **Python Scripts** | Batch operations, pattern searches, complex workflows | Requires script development time |

**MCP Limitations:**
- Timeouts on large functions (>5 seconds)
- String searches often timeout on 1GB+ binaries
- Network overhead for each query
- Can't batch operations efficiently

**Python Script Advantages:**
- Run locally without network timeouts
- Batch operations: "find all ADRP+LDR patterns near TypeId xrefs"
- Persist state between operations
- Better for pattern-based singleton discovery

**Decision Guide:**
- Use MCP for: "Decompile this one function", "Get xrefs to this address"
- Use Python for: "Find all singleton patterns matching X", "Batch analyze multiple managers"

### Singleton Discovery Script

For finding manager singletons that aren't exported via dlsym, use:
```bash
./ghidra/scripts/run_analysis.sh find_staticdata_singletons.py
```
This script traces TypeId xrefs → ADRP+LDR patterns to find singleton addresses.
