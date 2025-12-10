/**
 * BG3SE-macOS - Component Offset Definitions
 *
 * Data-driven property layouts for ECS components.
 * Offsets are derived from Windows BG3SE GameDefinitions and verified on ARM64.
 *
 * BaseComponent is empty, so all offsets start from 0.
 */

#ifndef COMPONENT_OFFSETS_H
#define COMPONENT_OFFSETS_H

#include "component_property.h"
#include <stddef.h>  // For NULL

// ============================================================================
// HealthComponent (eoc::HealthComponent)
// From: BG3Extender/GameDefinitions/Components/Data.h:57-67
// ============================================================================

static const ComponentPropertyDef g_HealthComponent_Properties[] = {
    { "Hp",             0x00, FIELD_TYPE_INT32, 0, false },
    { "MaxHp",          0x04, FIELD_TYPE_INT32, 0, false },
    { "TemporaryHp",    0x08, FIELD_TYPE_INT32, 0, false },
    { "MaxTemporaryHp", 0x0C, FIELD_TYPE_INT32, 0, false },
    // field_10 is Guid (16 bytes) at 0x10
    { "IsInvulnerable", 0x20, FIELD_TYPE_BOOL,  0, false },
};

static const ComponentLayoutDef g_HealthComponent_Layout = {
    .componentName = "eoc::HealthComponent",
    .shortName = "Health",
    .componentTypeIndex = 0,  // Set dynamically from TypeId discovery
    .componentSize = 0x24,
    .properties = g_HealthComponent_Properties,
    .propertyCount = sizeof(g_HealthComponent_Properties) / sizeof(g_HealthComponent_Properties[0]),
};

// ============================================================================
// BaseHpComponent (eoc::BaseHpComponent)
// From: BG3Extender/GameDefinitions/Components/Stats.h:33-39
// ============================================================================

static const ComponentPropertyDef g_BaseHpComponent_Properties[] = {
    { "Vitality",      0x00, FIELD_TYPE_INT32, 0, false },
    { "VitalityBoost", 0x04, FIELD_TYPE_INT32, 0, false },
};

static const ComponentLayoutDef g_BaseHpComponent_Layout = {
    .componentName = "eoc::BaseHpComponent",
    .shortName = "BaseHp",
    .componentTypeIndex = 0,
    .componentSize = 0x08,
    .properties = g_BaseHpComponent_Properties,
    .propertyCount = sizeof(g_BaseHpComponent_Properties) / sizeof(g_BaseHpComponent_Properties[0]),
};

// ============================================================================
// ArmorComponent (eoc::ArmorComponent)
// From: BG3Extender/GameDefinitions/Components/Stats.h:8-17
// ============================================================================

static const ComponentPropertyDef g_ArmorComponent_Properties[] = {
    { "ArmorType",          0x00, FIELD_TYPE_INT32, 0, true },
    { "ArmorClass",         0x04, FIELD_TYPE_INT32, 0, true },
    { "AbilityModifierCap", 0x08, FIELD_TYPE_INT32, 0, true },
    { "ArmorClassAbility",  0x0C, FIELD_TYPE_UINT8, 0, true },
    { "EquipmentType",      0x0D, FIELD_TYPE_UINT8, 0, true },
};

static const ComponentLayoutDef g_ArmorComponent_Layout = {
    .componentName = "eoc::ArmorComponent",
    .shortName = "Armor",
    .componentTypeIndex = 0,
    .componentSize = 0x10,
    .properties = g_ArmorComponent_Properties,
    .propertyCount = sizeof(g_ArmorComponent_Properties) / sizeof(g_ArmorComponent_Properties[0]),
};

// ============================================================================
// StatsComponent (eoc::StatsComponent)
// From: BG3Extender/GameDefinitions/Components/Stats.h:113-129
// ============================================================================

static const ComponentPropertyDef g_StatsComponent_Properties[] = {
    { "InitiativeBonus",     0x00, FIELD_TYPE_INT32,       0, true },
    { "Abilities",           0x04, FIELD_TYPE_INT32_ARRAY, 7, true },
    { "AbilityModifiers",    0x20, FIELD_TYPE_INT32_ARRAY, 7, true },
    { "Skills",              0x3C, FIELD_TYPE_INT32_ARRAY, 18, true },
    { "ProficiencyBonus",    0x84, FIELD_TYPE_INT32,       0, true },
    { "SpellCastingAbility", 0x88, FIELD_TYPE_UINT8,       0, true },
    { "ArmorType",           0x94, FIELD_TYPE_INT32,       0, true },
    { "ArmorType2",          0x98, FIELD_TYPE_INT32,       0, true },
    { "UnarmedAttackAbility",0x9C, FIELD_TYPE_UINT8,       0, true },
    { "RangedAttackAbility", 0x9D, FIELD_TYPE_UINT8,       0, true },
};

static const ComponentLayoutDef g_StatsComponent_Layout = {
    .componentName = "eoc::StatsComponent",
    .shortName = "Stats",
    .componentTypeIndex = 0,
    .componentSize = 0xA0,
    .properties = g_StatsComponent_Properties,
    .propertyCount = sizeof(g_StatsComponent_Properties) / sizeof(g_StatsComponent_Properties[0]),
};

// ============================================================================
// BaseStatsComponent (eoc::BaseStatsComponent)
// From: BG3Extender/GameDefinitions/Components/Data.h:97-102
// ============================================================================

static const ComponentPropertyDef g_BaseStatsComponent_Properties[] = {
    { "BaseAbilities", 0x00, FIELD_TYPE_INT32_ARRAY, 7, true },
};

static const ComponentLayoutDef g_BaseStatsComponent_Layout = {
    .componentName = "eoc::BaseStatsComponent",
    .shortName = "BaseStats",
    .componentTypeIndex = 0,
    .componentSize = 0x1C,
    .properties = g_BaseStatsComponent_Properties,
    .propertyCount = sizeof(g_BaseStatsComponent_Properties) / sizeof(g_BaseStatsComponent_Properties[0]),
};

// ============================================================================
// All Component Layouts (for bulk registration)
// ============================================================================

static const ComponentLayoutDef* g_AllComponentLayouts[] = {
    &g_HealthComponent_Layout,
    &g_BaseHpComponent_Layout,
    &g_ArmorComponent_Layout,
    &g_StatsComponent_Layout,
    &g_BaseStatsComponent_Layout,
    NULL  // Sentinel
};

#endif // COMPONENT_OFFSETS_H
