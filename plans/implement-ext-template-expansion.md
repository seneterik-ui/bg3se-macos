# Implementation Plan: Ext.Resource & Ext.Template (Issue #41)

## Status: COMPLETE (v0.36.0)

## Issue Summary

Implement `Ext.Resource` and expand `Ext.Template` for resource and template management. Asset-driven mods depend on these APIs.

## Current State Analysis

### Ext.Template (Partially Implemented)

**Already working (12 functions):**
- `Get(guid)` - Cascading search
- `GetRootTemplate(guid)` - GlobalTemplateBank lookup
- `GetCacheTemplate(guid)` - CacheTemplateManager lookup
- `GetAllRootTemplates()` - All templates from GlobalTemplateBank
- `GetAllCacheTemplates()` - All templates from CacheTemplateManager
- `GetCount([managerType])` - Template count
- `GetType(template)` - Type name (returns "Unknown" currently)
- `IsReady()` - Manager status
- `LoadFridaCapture()` / `HasFridaCapture()` - Frida integration
- `DumpStatus()` / `DumpEntries()` - Debug utilities

**Missing from Issue #41:**
- `GetAllLocalCacheTemplates()` - Not implemented
- **Template properties** - Only 4 basic fields (Guid, TemplateId, NameId, Type)
  - Windows exposes 150+ properties (Name, Stats, Equipment, Icon, Passives, etc.)
- **Type detection** - Always returns "Unknown" (VMT mapping needed)

### Ext.Resource (Not Implemented)

Required functions per Issue #41:
- `Exists(path)` - Check if resource exists
- `Load(path, resourceType)` - Load resource by path
- `GetLoaded(resourceType)` - Get loaded resources
- `Validate(resource)` - Validate resource

## Implementation Strategy

### Phase 1: Template Properties (High Impact, Low Risk)

Expand template objects from 4 properties to core set (~20 properties).

**Files to modify:**
- `src/template/template_manager.h` - Add property accessors
- `src/template/template_manager.c` - Implement property reading
- `src/lua/lua_template.c` - Expose properties to Lua

**Priority properties to add:**
| Property | Offset | Type | Notes |
|----------|--------|------|-------|
| Name | TBD | TranslatedString | Display name |
| TemplateName | +0x14 | FixedString | Already captured |
| Stats | TBD | FixedString | Stats reference |
| Icon | TBD | FixedString | Icon path |
| ParentTemplateId | +0x18 | FixedString | Parent template |

**Type-specific properties (Phase 1b):**
- CharacterTemplate: Equipment, Passives
- ItemTemplate: InventoryType, UseAction

### Phase 2: GetAllLocalCacheTemplates()

Add missing function to complete Template API acceptance criteria.

**Files to modify:**
- `src/lua/lua_template.c` - Add `lua_template_get_all_local_cache()`
- `src/template/template_manager.h/c` - Add LOCAL_CACHE enumeration support

### Phase 3: Template Type Detection

Fix `GetType()` to return proper type names instead of "Unknown".

**Approach options:**
1. **VMT-based** - Build VMT address → TemplateType mapping at runtime
2. **Field-based** - Read type field from template struct
3. **Frida capture** - Capture type alongside template address

**Files to modify:**
- `src/template/template_manager.c` - `template_get_type()` implementation

### Phase 4: Ext.Resource (Deferred/Optional)

Ext.Resource requires discovering ResourceManager singleton and understanding the resource loading pipeline. This is more complex than template expansion.

**Recommendation:** Defer to separate issue. Template properties provide more immediate value to mods.

## Files to Modify

| File | Changes |
|------|---------|
| `src/template/template_manager.h` | Add 10-15 property accessor declarations |
| `src/template/template_manager.c` | Implement property reading with ARM64 offsets |
| `src/lua/lua_template.c` | Add properties to `push_template_to_lua()`, add GetAllLocalCacheTemplates |
| `docs/api-reference.md` | Document new template properties |
| `docs/CHANGELOG.md` | Version entry |

## Acceptance Criteria Mapping

| Criterion | Implementation | Priority |
|-----------|---------------|----------|
| `GetAllLocalCacheTemplates()` | Phase 2 | High |
| `Get(guid)` returns template | ✅ Already works | Done |
| Type detection works | Phase 3 | Medium |
| Character/Item properties | Phase 1b | High |
| `Ext.Resource.Exists()` | Phase 4 (defer) | Low |
| `Ext.Resource.Load()` | Phase 4 (defer) | Low |

## Estimated Effort

- Phase 1 (Template Properties): 2-3 hours
- Phase 2 (LocalCache): 30 minutes
- Phase 3 (Type Detection): 1 hour
- Phase 4 (Ext.Resource): Separate issue

## Dependencies

- Current Frida capture workflow for template manager pointers
- ARM64 offset verification via runtime probing

## Windows BG3SE Reference

From `/Users/tomdimino/Desktop/Programming/bg3se/BG3Extender/GameDefinitions/RootTemplates.h`:

**GameObjectTemplate base fields:**
- Tags (TemplateTagContainer*)
- Id (FixedString)
- TemplateName (FixedString)
- ParentTemplateId (FixedString)
- TemplateHandle (uint32_t)
- Name (STDString)
- VisualTemplate (OverrideableProperty<FixedString>)

**CharacterTemplate adds:**
- Stats, Icon, Equipment, SpellSet (all FixedString)
- DefaultDialog, Race, many more

**ItemTemplate adds:**
- Stats, Icon (FixedString)
- InventoryType (enum)
- Description (TranslatedString)
