#!/usr/bin/env python3
"""
Component Size Consolidation Script v2
Merges staging files into main documentation with deduplication.
"""

import re
from collections import defaultdict
from pathlib import Path

BASE_DIR = Path(__file__).parent.parent
COMPONENTS_DIR = BASE_DIR / "components"
STAGING_DIR = BASE_DIR / "staging"

def parse_table_line(line):
    """Parse a markdown table line into component data."""
    if not line.strip().startswith("|"):
        return None
    parts = [p.strip() for p in line.split("|")]
    if len(parts) < 4:
        return None
    name = parts[1].replace('`', '').strip()
    if not "::" in name or name in ("Component", "---"):
        return None
    return {
        "name": name,
        "hex": parts[2] if len(parts) > 2 else "",
        "bytes": parts[3] if len(parts) > 3 else "",
        "notes": parts[4] if len(parts) > 4 else "",
        "raw_line": line.strip()
    }

def validate_component(comp):
    """Validate a component entry. Returns (is_valid, reason)."""
    name = comp.get("name", "")
    size_str = comp.get("bytes", "").strip()
    hex_str = comp.get("hex", "").strip()

    # Skip placeholders
    if "(pending)" in size_str.lower() or size_str == "-":
        return False, "placeholder"
    if "(pending)" in hex_str.lower() or hex_str == "-":
        return False, "placeholder"

    # Skip empty sizes
    if not size_str and not hex_str:
        return False, "empty_size"

    # Parse numeric size
    size = None
    if size_str:
        # Handle various formats: "32", "0x20", "32 | 0x20"
        match = re.search(r'(\d+)', size_str.replace(',', ''))
        if match:
            size = int(match.group(1))
    elif hex_str:
        # Try hex format
        match = re.search(r'0x([0-9a-fA-F]+)', hex_str)
        if match:
            size = int(match.group(1), 16)

    if size is None:
        return False, "unparseable_size"

    # Flag suspiciously large sizes (> 16KB for a single component)
    if size > 16384:
        return False, f"suspicious_size_{size}"

    # Flag zero size
    if size == 0:
        return False, "zero_size"

    return True, None

def get_namespace_file(name):
    """Determine which file a component belongs to."""
    parts = name.split("::")
    root = parts[0].lower()  # eoc, esv, ecl, ls, navcloud

    if root == "navcloud":
        return "COMPONENT_SIZES_NAVCLOUD.md"

    # Check for boost components
    if "BoostComponent" in name:
        return f"COMPONENT_SIZES_{root.upper()}_BOOST.md"

    # Check for known sub-namespaces
    if len(parts) >= 3:
        sub = parts[1].lower()
        sub_map = {
            "combat": "COMBAT",
            "spell_cast": "SPELL_CAST",
            "spell": "SPELL",
            "status": "STATUS",
            "inventory": "INVENTORY",
            "character_creation": "CHARACTER_CREATION",
            "notification": "NOTIFICATION",
            "hit": "HIT",
            "interrupt": "INTERRUPT",
            "party": "PARTY",
            "item": "ITEM",
            "platform": "PLATFORM",
            "camp": "CAMP",
            "death": "DEATH",
            "escort": "ESCORT",
            "ftb": "FTB",
            "crowds": "CROWDS",
            "summon": "SUMMON",
            "trigger": "TRIGGER",
            "character": "CHARACTER",
            "analytics": "ANALYTICS",
        }
        if sub in sub_map:
            return f"COMPONENT_SIZES_{root.upper()}_{sub_map[sub]}.md"

    # Default: use CORE for main namespace, MISC for unknown
    return f"COMPONENT_SIZES_{root.upper()}_CORE.md"

def read_all_components(directory, pattern="COMPONENT_SIZES_*.md"):
    """Read all components from markdown files in a directory."""
    components = {}
    for filepath in directory.glob(pattern):
        if "INDEX" in filepath.name:
            continue
        with open(filepath) as f:
            for line in f:
                comp = parse_table_line(line)
                if comp:
                    components[comp["name"]] = comp
    return components

def read_staging_files():
    """Read all components from staging files with validation."""
    components = {}
    rejected = defaultdict(list)  # reason -> [component_names]

    if not STAGING_DIR.exists():
        return components, rejected

    for filepath in STAGING_DIR.glob("*.md"):
        with open(filepath) as f:
            for line in f:
                comp = parse_table_line(line)
                if comp:
                    is_valid, reason = validate_component(comp)
                    if is_valid:
                        components[comp["name"]] = comp
                    else:
                        rejected[reason].append(comp["name"])

    return components, rejected

def format_component_line(comp):
    """Format a component as a markdown table line."""
    return f"| {comp['name']} | {comp['hex']} | {comp['bytes']} | {comp.get('notes', '')} |"

def update_file(filepath, components_to_add, existing_names):
    """Add new components to an existing file or create it."""
    new_comps = [c for c in components_to_add if c["name"] not in existing_names]
    if not new_comps:
        return 0

    if filepath.exists():
        with open(filepath, "a") as f:
            for comp in new_comps:
                f.write(format_component_line(comp) + "\n")
    else:
        # Create new file with header
        ns = filepath.stem.replace("COMPONENT_SIZES_", "").replace("_", "::")
        with open(filepath, "w") as f:
            f.write(f"# {ns} Components - ARM64 Sizes\n\n")
            f.write("| Component | Hex | Bytes | Notes |\n")
            f.write("|-----------|-----|-------|-------|\n")
            for comp in new_comps:
                f.write(format_component_line(comp) + "\n")

    return len(new_comps)

def main():
    print("Component Consolidation v2 (with validation)")
    print("=" * 50)

    # Read existing components
    existing = read_all_components(COMPONENTS_DIR)
    print(f"Existing components in main docs: {len(existing)}")

    # Read staging with validation
    staging, rejected = read_staging_files()
    print(f"Valid components in staging: {len(staging)}")

    # Report rejected entries
    if rejected:
        print("\n⚠️  Rejected entries (not merged):")
        for reason, names in sorted(rejected.items()):
            print(f"  [{reason}]: {len(names)} entries")
            if len(names) <= 5:
                for name in names:
                    print(f"    - {name}")
            else:
                for name in names[:3]:
                    print(f"    - {name}")
                print(f"    ... and {len(names) - 3} more")
        print()

    # Find new components
    new_components = {k: v for k, v in staging.items() if k not in existing}
    print(f"New unique components to add: {len(new_components)}")

    if not new_components:
        print("No new components to add.")
        return

    # Group by target file
    by_file = defaultdict(list)
    for name, comp in new_components.items():
        target = get_namespace_file(name)
        by_file[target].append(comp)

    # Add to files
    total_added = 0
    for filename, comps in sorted(by_file.items()):
        filepath = COMPONENTS_DIR / filename
        added = update_file(filepath, comps, set(existing.keys()))
        if added > 0:
            print(f"  {filename}: +{added}")
            total_added += added

    # Final count
    final = read_all_components(COMPONENTS_DIR)
    print("=" * 50)
    print(f"Final component count: {len(final)}")
    print(f"Coverage: {len(final) / 1999 * 100:.1f}% of 1,999 TypeIds")

    # Clean staging if successful
    if total_added > 0:
        print("\nClearing staging files...")
        for f in STAGING_DIR.glob("*.md"):
            f.unlink()
        print("Done!")

if __name__ == "__main__":
    main()
