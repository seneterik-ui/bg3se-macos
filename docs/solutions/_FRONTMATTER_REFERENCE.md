# YAML Frontmatter Reference for Solution Documentation

This document provides a comprehensive reference for the YAML frontmatter structure used in BG3SE-macOS solution documentation.

## Purpose

The YAML frontmatter enables:
- Consistent metadata across all solution documents
- Machine-readable issue/component tracking
- Cross-reference discovery via tags
- Quick scanning for relevant solutions

## Frontmatter Structure

```yaml
---
# Required fields (must always be present)
title: "Ext.StaticData Implementation: FeatManager Discovery & Frida Capture"
date: 2025-12-15
category: reverse-engineering
component: Ext.StaticData
issue: "#40"
severity: architecture

# Required tagging
tags:
  - arm64
  - staticdata
  - frida

# Optional fields (include when relevant)
parent_issue: "#33"
blocked_by: null
blocks: ["#41"]
related_offsets:
  - "0x01b752b4: GetFeats function"
---
```

## Field Reference

### Required Fields

#### `title`
**Type:** String
**Length:** 50-120 characters recommended
**Examples:**
- "Ext.StaticData Implementation: FeatManager Discovery & Frida Capture"
- "TypeContext Returns Metadata, Not Real Data: Solved via Frida File Capture"
- "ARM64 PC-Relative Corruption: Why Dobby Hooks Failed"

**Guidelines:**
- Begin with component or problem description
- Include solution approach in title
- Make searchable with key terms
- Avoid generic titles like "Solution for Issue #40"

---

#### `date`
**Type:** Date (YYYY-MM-DD format)
**Value:** ISO 8601 date when solution was finalized
**Do Not Use:** Investigation start date or commit date

**Examples:**
```yaml
date: 2025-12-15      # When solution became working
date: 2025-12-14      # Or previous working version
```

---

#### `category`
**Type:** Single string (not array)
**Allowed Values:**
- `reverse-engineering` - Offset/structure discovery
- `architecture` - Design patterns, integration approaches
- `feature` - New API or capability
- `bug-fix` - Fixing broken functionality
- `investigation` - Analysis without actionable solution yet

**Decision Matrix:**

| Scenario | Category |
|----------|----------|
| "Found SpellPrototype::Init at 0x101f72754" | reverse-engineering |
| "Frida Interceptor vs Dobby for hooking" | architecture |
| "Implemented Ext.StaticData.GetAll()" | feature |
| "Fixed stat name resolution crash" | bug-fix |
| "Analyzed NetChannel message format" | investigation |

---

#### `component`
**Type:** Single string or comma-separated
**Format:** Full namespace path from BG3SE
**Examples:**
- `Ext.StaticData` - Static data API
- `Ext.Entity` - Entity component system
- `Ext.Stats` - Stats system
- `Ext.Events` - Event system
- `Core/Hooking` - Core infrastructure
- `Ext.Stats, Ext.Events` - Multiple components

**Lookup Table:**

| Component | Folder |
|-----------|--------|
| Ext.StaticData | `src/lua/lua_staticdata.c` |
| Ext.Entity | `src/entity/entity_system.c` |
| Ext.Stats | `src/lua/lua_stats.c` |
| Ext.Events | `src/lua/lua_events.c` |
| Ext.Osiris | `src/lua/lua_osiris.c` |
| Ext.Debug | `src/lua/lua_debug.c` |
| Core/Hooking | `src/injector/main.c` |

---

#### `issue`
**Type:** String
**Format:** "#NUMBER" or "#NUMBER, #NUMBER"
**Examples:**
- `issue: "#40"` - Single issue
- `issue: "#40, #41"` - Multiple issues

**How to Find:**
- Search GitHub issues at https://github.com/tdimino/bg3se-macos/issues
- Primary issue goes first
- Use null if no issue number exists

---

#### `severity`
**Type:** Single string
**Allowed Values:**
- `blocker` - Prevents core functionality (game crashes, feature completely broken)
- `high` - Breaks major features (missing entire API)
- `medium` - Affects multiple systems (impacts several features)
- `low` - Minor issues (workaround exists)
- `documentation` - Informational (no functional impact)
- `architecture` - Affects design decisions affecting multiple systems

**Decision Matrix:**

| Severity | Example |
|----------|---------|
| blocker | "Without this, Ext.StaticData returns nothing" |
| high | "Feat data inaccessible, but other static data types work" |
| medium | "Feat selection UI works, but missing advanced features" |
| low | "Feat GUIDs sometimes don't match" |
| documentation | "Discovery notes on prototype managers" |
| architecture | "Hooking pattern affects future component implementations" |

### Optional Fields

#### `parent_issue`
**Type:** String or null
**Format:** "#NUMBER"
**When to Use:** When this solution relates to a broader tracking issue

**Example:**
```yaml
issue: "#40"              # This specific feat issue
parent_issue: "#33"       # Broader static data tracking
```

---

#### `blocked_by`
**Type:** Array or null
**Format:** ["#NUMBER", "#NUMBER"]
**When to Use:** When other issues must be resolved first

**Example:**
```yaml
issue: "#40"
blocked_by: ["#44", "#15"]    # Requires ARM64 hooking + Client state
```

---

#### `blocks`
**Type:** Array or null
**Format:** ["#NUMBER", "#NUMBER"]
**When to Use:** When this solution enables other issues

**Example:**
```yaml
issue: "#40"
blocks: ["#41"]           # Feat implementation unblocks Race/Background
```

---

#### `related_offsets`
**Type:** Array or null
**Format:** "0xADDRESS: Description"
**When to Use:** Always include for reverse-engineering solutions

**Examples:**
```yaml
related_offsets:
  - "0x01b752b4: FeatManager::GetFeats function"
  - "0x7C: FeatManager count field offset"
  - "0x80: FeatManager array field offset"
  - "0x128: Feat struct size (296 bytes)"
  - "0x08: Feat.GUID offset (after VMT)"
```

---

#### `tags`
**Type:** Array (must be array, not string)
**Count:** 3-8 recommended
**Avoid:** Platform tags (always arm64 on macOS)

**Tag Categories:**

##### Platform Tags
- `arm64` - ARM64-specific solution
- `x86_64` - x86_64 code (Windows cross-reference)
- `macos` - macOS-specific
- `universal-binary` - Works on both architectures

##### Technique Tags
- `frida` - Uses Frida runtime instrumentation
- `dobby` - Uses Dobby inline hooking
- `ghidra` - Uses Ghidra decompilation/analysis
- `pattern-scanning` - Binary pattern matching
- `symbol-resolution` - dlsym or symbol table lookup
- `file-based-capture` - File I/O integration

##### Architecture Tags
- `hook-based` - Function hooking approach
- `singleton-discovery` - Finding singleton instances
- `type-context` - Uses type reflection system
- `environment-capture` - Captures Environment parameter
- `interceptor` - Non-invasive interception (vs replacement)

##### Domain Tags
- `memory-layout` - Struct offset discovery
- `calling-convention` - ARM64 ABI specifics
- `pc-relative` - PC-relative instruction handling
- `manager-capture` - Manager instance discovery
- `refmap-discovery` - HashMap/RefMap structure discovery

##### Component-Specific Tags
- `featmanager` - FeatManager component
- `entity-system` - ECS system
- `stats-system` - RPGStats system
- `prototype-managers` - Spell/Status/Passive prototype managers
- `component-system` - Component registration/access

##### Status Tags (when relevant)
- `working` - Solution fully implemented
- `partial` - Partial implementation
- `blocked` - Solution blocked by dependencies
- `alternative-approach` - Alternative that didn't work

**Good Tag Set Examples:**

```yaml
# Frida-based approach
tags: [arm64, frida, hook-based, memory-layout, featmanager]

# Dobby failure case study
tags: [arm64, dobby, pc-relative, architecture, alternative-approach]

# Entity system discovery
tags: [arm64, ghidra, pattern-scanning, entity-system, manager-capture]

# Stats sync investigation
tags: [arm64, ghidra, refmap-discovery, prototype-managers, working]
```

---

## Complete Example

```yaml
---
title: "Ext.StaticData Implementation: FeatManager Discovery & Frida Capture"
date: 2025-12-15
category: reverse-engineering
component: Ext.StaticData
issue: "#40"
severity: architecture

tags:
  - arm64
  - staticdata
  - frida
  - file-based-capture
  - featmanager

parent_issue: "#33"
blocked_by: null
blocks: ["#41"]

related_offsets:
  - "0x01b752b4: FeatManager::GetFeats function"
  - "0x7C: FeatManager count offset"
  - "0x80: FeatManager array offset"
  - "0x128: Feat struct size"
  - "0x08: Feat.GUID offset"
---
```

## YAML Syntax Notes

### Arrays
```yaml
# Valid array formats (both work):
tags:
  - arm64
  - frida
  - staticdata

blocks: ["#41"]        # Single-line array

related_offsets:
  - "0x01b752b4: Function"
  - "0x7C: Field"

# Invalid (don't use):
tags: arm64, frida     # Without dashes
```

### Null Values
```yaml
# Valid:
blocked_by: null
parent_issue: null

# Invalid:
blocked_by:            # Will be interpreted as null anyway
parent_issue: ""       # Empty string, not null
```

### Multi-line Strings
```yaml
# If title is very long:
title: |
  Ext.StaticData Implementation: FeatManager Discovery
  and File-Based Frida Capture Pattern

# Better: keep title concise, use content section instead
```

---

## Searching and Filtering

These frontmatter fields enable:

### By Category
```bash
grep -r "^category: reverse-engineering" docs/solutions/
grep -r "^category: architecture" docs/solutions/
```

### By Component
```bash
grep -r "^component: Ext.StaticData" docs/solutions/
grep -r "^component: Ext.Entity" docs/solutions/
```

### By Issue
```bash
grep -r "^issue: \"#40\"" docs/solutions/
grep -r "^issue: \"#40, #41\"" docs/solutions/
```

### By Severity
```bash
grep -r "^severity: blocker" docs/solutions/
grep -r "^severity: architecture" docs/solutions/
```

### By Tag
```bash
grep -r "- frida" docs/solutions/
grep -r "- arm64" docs/solutions/
grep -r "- ghidra" docs/solutions/
```

### Complex Queries (Python)
```python
import yaml

def find_solutions_for_issue(issue_num):
    """Find all solutions related to an issue."""
    pattern = f'"#{issue_num}"'
    # grep for issue or parent_issue fields

def find_solutions_by_technique(technique):
    """Find all solutions using a specific technique."""
    # grep for tag in tags array

def find_blocking_solutions():
    """Find solutions that currently block other issues."""
    # Find documents where blocks is not empty
```

---

## Maintenance

### Updating After Implementation
When a solution becomes fully implemented:

```yaml
# Before (investigation phase)
severity: low
tags: [investigation, partial]

# After (working implementation)
severity: architecture
tags: [working, frida, arm64]
```

### Cross-referencing Issues
When a solution resolves multiple issues:

```yaml
issue: "#40, #41"       # Both issues resolved

# Or if hierarchical:
issue: "#40"
blocks: ["#41", "#35"]  # These can now be solved
```

### Date Updates
Keep date as final working date (don't update on minor revisions):

```yaml
# Initial implementation
date: 2025-12-15

# Months later: don't update for small fixes
# Only update if solution fundamentally changes
```

---

## Template File Location

Default template:
- `/Users/tomdimino/Desktop/Programming/bg3se-macos/docs/solutions/_FRONTMATTER_TEMPLATE.yaml`

Frontmatter reference:
- `/Users/tomdimino/Desktop/Programming/bg3se-macos/docs/solutions/_FRONTMATTER_REFERENCE.md` (this file)

Example implementations:
- `/Users/tomdimino/Desktop/Programming/bg3se-macos/docs/solutions/reverse-engineering/ext-staticdata-implementation.md`
- `/Users/tomdimino/Desktop/Programming/bg3se-macos/docs/solutions/reverse-engineering/staticdata-featmanager-discovery.md`
