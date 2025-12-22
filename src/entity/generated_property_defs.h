/**
 * generated_property_defs.h - Auto-generated component property definitions
 *
 * Generated from Windows BG3SE headers by tools/parse_component_headers.py
 * Total components: 504
 *
 * WARNING: Offsets are ESTIMATED from Windows x64 ABI.
 * ARM64 may differ for complex types. Verify via runtime probing!
 *
 * Usage: Include this file in component_offsets.h and add entries to g_AllComponentLayouts[]
 */

#ifndef GENERATED_PROPERTY_DEFS_H
#define GENERATED_PROPERTY_DEFS_H

#include "component_property.h"

// ecl::CharacterIconRequestComponent (from Visual.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_ClientCharacterIconRequestComponent_Properties[] = {
    { "Visual", 0x00, FIELD_TYPE_UINT32, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "VisualSet", 0x08, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "Equipment", 0x10, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "Template", 0x18, FIELD_TYPE_UINT32, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "ArmorSetState", 0x20, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_190", 0x28, FIELD_TYPE_UINT64, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "Trigger", 0x30, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_1B0", 0x38, FIELD_TYPE_INT32, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_ClientCharacterIconRequestComponent_Layout = {
    .componentName = "ecl::CharacterIconRequestComponent",
    .shortName = "ClientCharacterIconRequest",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x3c,
    .properties = g_ClientCharacterIconRequestComponent_Properties,
    .propertyCount = sizeof(g_ClientCharacterIconRequestComponent_Properties) / sizeof(g_ClientCharacterIconRequestComponent_Properties[0]),
};

// ecl::CharacterIconResultComponent (from Visual.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_ClientCharacterIconResultComponent_Properties[] = {
    { "Icon", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_ClientCharacterIconResultComponent_Layout = {
    .componentName = "ecl::CharacterIconResultComponent",
    .shortName = "ClientCharacterIconResult",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x08,
    .properties = g_ClientCharacterIconResultComponent_Properties,
    .propertyCount = sizeof(g_ClientCharacterIconResultComponent_Properties) / sizeof(g_ClientCharacterIconResultComponent_Properties[0]),
};

// ecl::CharacterLightComponent (from Visual.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_CharacterLightComponent_Properties[] = {
    { "Enabled", 0x00, FIELD_TYPE_BOOL, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "LightChannel", 0x01, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_2", 0x02, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_3", 0x03, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_4", 0x04, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_5", 0x05, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_6", 0x06, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_7", 0x07, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_CharacterLightComponent_Layout = {
    .componentName = "ecl::CharacterLightComponent",
    .shortName = "CharacterLight",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x08,
    .properties = g_CharacterLightComponent_Properties,
    .propertyCount = sizeof(g_CharacterLightComponent_Properties) / sizeof(g_CharacterLightComponent_Properties[0]),
};

// ecl::CharacterLightSingletonComponent (from Visual.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_CharacterLightSingletonComponent_Properties[] = {
    { "Views", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_CharacterLightSingletonComponent_Layout = {
    .componentName = "ecl::CharacterLightSingletonComponent",
    .shortName = "CharacterLightSingleton",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x08,
    .properties = g_CharacterLightSingletonComponent_Properties,
    .propertyCount = sizeof(g_CharacterLightSingletonComponent_Properties) / sizeof(g_CharacterLightSingletonComponent_Properties[0]),
};

// ecl::ClientTimelineActorControlComponent (from Timeline.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_ClientTimelineActorControlComponent_Properties[] = {
    { "field_0", 0x00, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_10", 0x10, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_20", 0x20, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_21", 0x21, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_22", 0x22, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_ClientTimelineActorControlComponent_Layout = {
    .componentName = "ecl::ClientTimelineActorControlComponent",
    .shortName = "ClientTimelineActorControl",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x23,
    .properties = g_ClientTimelineActorControlComponent_Properties,
    .propertyCount = sizeof(g_ClientTimelineActorControlComponent_Properties) / sizeof(g_ClientTimelineActorControlComponent_Properties[0]),
};

// ecl::EquipmentVisualsComponent (from Visual.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_ClientEquipmentVisualsComponent_Properties[] = {
    { "Entity", 0x00, FIELD_TYPE_UINT64, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "Equipment", 0x08, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_ClientEquipmentVisualsComponent_Layout = {
    .componentName = "ecl::EquipmentVisualsComponent",
    .shortName = "ClientEquipmentVisuals",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x10,
    .properties = g_ClientEquipmentVisualsComponent_Properties,
    .propertyCount = sizeof(g_ClientEquipmentVisualsComponent_Properties) / sizeof(g_ClientEquipmentVisualsComponent_Properties[0]),
};

// ecl::GameCameraBehavior (from Camera.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_GameCameraBehaviorComponent_Properties[] = {
    { "Trigger", 0x00, FIELD_TYPE_UINT64, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "Target", 0x08, FIELD_TYPE_UINT64, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "TargetFalling", 0x10, FIELD_TYPE_BOOL, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_11", 0x11, FIELD_TYPE_BOOL, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "MovingToTarget", 0x12, FIELD_TYPE_BOOL, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_13", 0x13, FIELD_TYPE_BOOL, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_14", 0x14, FIELD_TYPE_FLOAT, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "TargetPreviousDestination", 0x18, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "TargetDestination", 0x20, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_30", 0x28, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_3C", 0x30, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "TargetCurrent", 0x38, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "Distance", 0x40, FIELD_TYPE_FLOAT, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_58", 0x44, FIELD_TYPE_FLOAT, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_5C", 0x48, FIELD_TYPE_FLOAT, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_60", 0x4c, FIELD_TYPE_FLOAT, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_64", 0x50, FIELD_TYPE_FLOAT, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_68", 0x54, FIELD_TYPE_FLOAT, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "MovementDistanceMax", 0x58, FIELD_TYPE_FLOAT, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "Direction", 0x60, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "DirectionDestination", 0x68, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_88", 0x70, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "SpeedXZ", 0x78, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "XRotationSpeed", 0x80, FIELD_TYPE_FLOAT, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "XRotationSpeedMouse", 0x84, FIELD_TYPE_INT32, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "ZoomSpeed", 0x88, FIELD_TYPE_FLOAT, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "CameraMode", 0x8c, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_A9", 0x8d, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "RotationY", 0x90, FIELD_TYPE_FLOAT, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "RotationTarget", 0x98, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "MouseRotationSpeed", 0xa0, FIELD_TYPE_FLOAT, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "TargetLastPosition", 0xa8, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_D0", 0xb0, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_D8", 0xb8, FIELD_TYPE_FLOAT, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_DC", 0xbc, FIELD_TYPE_FLOAT, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_E0", 0xc0, FIELD_TYPE_FLOAT, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_E4", 0xc4, FIELD_TYPE_FLOAT, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_E8", 0xc8, FIELD_TYPE_FLOAT, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "FollowTarget", 0xd0, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "Targets", 0xd8, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "LastPlayerInputTime", 0xe0, FIELD_TYPE_FLOAT, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "PlayerInControl", 0xe4, FIELD_TYPE_BOOL, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_145", 0xe5, FIELD_TYPE_BOOL, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "IsPaused", 0xe6, FIELD_TYPE_BOOL, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "TargetMode", 0xe8, FIELD_TYPE_UINT32, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "SelectMode", 0xec, FIELD_TYPE_BOOL, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "WasInSelectMode", 0xed, FIELD_TYPE_BOOL, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_150", 0xf0, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_15C", 0xf8, FIELD_TYPE_FLOAT, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "Zoom", 0xfc, FIELD_TYPE_FLOAT, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "PitchDegrees", 0x100, FIELD_TYPE_FLOAT, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "TacticalMode", 0x108, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "TacticalTimeout", 0x110, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "EffectEntities", 0x118, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_188", 0x120, FIELD_TYPE_BOOL, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "FreezeHeight", 0x121, FIELD_TYPE_BOOL, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_18A", 0x122, FIELD_TYPE_BOOL, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_18B", 0x123, FIELD_TYPE_BOOL, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_190__EH_CameraCollisionDebugInfo", 0x128, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "DebugPosition", 0x130, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "DebugOffset", 0x138, FIELD_TYPE_FLOAT, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_1E0", 0x140, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "TrackTarget", 0x148, FIELD_TYPE_UINT64, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "IsMoving", 0x150, FIELD_TYPE_BOOL, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "IsRotating", 0x151, FIELD_TYPE_BOOL, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_1F2", 0x152, FIELD_TYPE_BOOL, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "IsSnapping", 0x153, FIELD_TYPE_BOOL, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "LastPickingTarget", 0x158, FIELD_TYPE_UINT64, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_200", 0x160, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_208", 0x168, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_238", 0x170, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_248", 0x178, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_GameCameraBehaviorComponent_Layout = {
    .componentName = "ecl::GameCameraBehavior",
    .shortName = "GameCameraBehavior",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x180,
    .properties = g_GameCameraBehaviorComponent_Properties,
    .propertyCount = sizeof(g_GameCameraBehaviorComponent_Properties) / sizeof(g_GameCameraBehaviorComponent_Properties[0]),
};

// ecl::PaperdollComponent (from Visual.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_ClientPaperdollComponent_Properties[] = {
    { "Entity", 0x00, FIELD_TYPE_UINT64, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "Combat", 0x08, FIELD_TYPE_BOOL, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_ClientPaperdollComponent_Layout = {
    .componentName = "ecl::PaperdollComponent",
    .shortName = "ClientPaperdoll",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x09,
    .properties = g_ClientPaperdollComponent_Properties,
    .propertyCount = sizeof(g_ClientPaperdollComponent_Properties) / sizeof(g_ClientPaperdollComponent_Properties[0]),
};

// ecl::camera::CombatTargetComponent (from Camera.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_CameraCombatTargetComponent_Properties[] = {
    { "Target", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_CameraCombatTargetComponent_Layout = {
    .componentName = "ecl::camera::CombatTargetComponent",
    .shortName = "CameraCombatTarget",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x08,
    .properties = g_CameraCombatTargetComponent_Properties,
    .propertyCount = sizeof(g_CameraCombatTargetComponent_Properties) / sizeof(g_CameraCombatTargetComponent_Properties[0]),
};

// ecl::camera::SelectorModeComponent (from Camera.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_CameraSelectorModeComponent_Properties[] = {
    { "Mode", 0x00, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_CameraSelectorModeComponent_Layout = {
    .componentName = "ecl::camera::SelectorModeComponent",
    .shortName = "CameraSelectorMode",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x01,
    .properties = g_CameraSelectorModeComponent_Properties,
    .propertyCount = sizeof(g_CameraSelectorModeComponent_Properties) / sizeof(g_CameraSelectorModeComponent_Properties[0]),
};

// ecl::camera::TargetComponent (from Camera.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_CameraTargetComponent_Properties[] = {
    { "Target", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_CameraTargetComponent_Layout = {
    .componentName = "ecl::camera::TargetComponent",
    .shortName = "CameraTarget",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x08,
    .properties = g_CameraTargetComponent_Properties,
    .propertyCount = sizeof(g_CameraTargetComponent_Properties) / sizeof(g_CameraTargetComponent_Properties[0]),
};

// ecl::character_creation::BaseDefinitionComponent (from CharacterCreation.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_ClientCCBaseDefinitionStateComponent_Properties[] = {
    { "Definition", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_ClientCCBaseDefinitionStateComponent_Layout = {
    .componentName = "ecl::character_creation::BaseDefinitionComponent",
    .shortName = "ClientCCBaseDefinitionState",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x08,
    .properties = g_ClientCCBaseDefinitionStateComponent_Properties,
    .propertyCount = sizeof(g_ClientCCBaseDefinitionStateComponent_Properties) / sizeof(g_ClientCCBaseDefinitionStateComponent_Properties[0]),
};

// ecl::character_creation::ChangeAppearanceDefinitionComponent (from CharacterCreation.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_ClientCCChangeAppearanceDefinitionComponent_Properties[] = {
    { "Definition", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_ClientCCChangeAppearanceDefinitionComponent_Layout = {
    .componentName = "ecl::character_creation::ChangeAppearanceDefinitionComponent",
    .shortName = "ClientCCChangeAppearanceDefinition",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x08,
    .properties = g_ClientCCChangeAppearanceDefinitionComponent_Properties,
    .propertyCount = sizeof(g_ClientCCChangeAppearanceDefinitionComponent_Properties) / sizeof(g_ClientCCChangeAppearanceDefinitionComponent_Properties[0]),
};

// ecl::character_creation::CompanionDefinitionComponent (from CharacterCreation.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_ClientCCCompanionDefinitionComponent_Properties[] = {
    { "field_0", 0x00, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_10", 0x10, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_20", 0x20, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_21", 0x21, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_28", 0x28, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "Visual", 0x38, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_110", 0x40, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_120", 0x50, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_130", 0x60, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_ClientCCCompanionDefinitionComponent_Layout = {
    .componentName = "ecl::character_creation::CompanionDefinitionComponent",
    .shortName = "ClientCCCompanionDefinition",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x61,
    .properties = g_ClientCCCompanionDefinitionComponent_Properties,
    .propertyCount = sizeof(g_ClientCCCompanionDefinitionComponent_Properties) / sizeof(g_ClientCCCompanionDefinitionComponent_Properties[0]),
};

// ecl::character_creation::DefinitionStateComponent (from CharacterCreation.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_ClientCCDefinitionStateComponent_Properties[] = {
    { "Entity", 0x00, FIELD_TYPE_UINT64, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_8", 0x08, FIELD_TYPE_UINT32, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_C", 0x0c, FIELD_TYPE_UINT32, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "ChangeId", 0x10, FIELD_TYPE_UINT32, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "Errors", 0x18, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_ClientCCDefinitionStateComponent_Layout = {
    .componentName = "ecl::character_creation::DefinitionStateComponent",
    .shortName = "ClientCCDefinitionState",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x20,
    .properties = g_ClientCCDefinitionStateComponent_Properties,
    .propertyCount = sizeof(g_ClientCCDefinitionStateComponent_Properties) / sizeof(g_ClientCCDefinitionStateComponent_Properties[0]),
};

// ecl::character_creation::DefinitionStateExComponent (from CharacterCreation.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_ClientCCDefinitionStateExComponent_Properties[] = {
    { "field_0", 0x00, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_1", 0x01, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_2", 0x02, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_8", 0x08, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "ChangeId", 0x10, FIELD_TYPE_UINT32, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "NeedsSync", 0x14, FIELD_TYPE_BOOL, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_ClientCCDefinitionStateExComponent_Layout = {
    .componentName = "ecl::character_creation::DefinitionStateExComponent",
    .shortName = "ClientCCDefinitionStateEx",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x15,
    .properties = g_ClientCCDefinitionStateExComponent_Properties,
    .propertyCount = sizeof(g_ClientCCDefinitionStateExComponent_Properties) / sizeof(g_ClientCCDefinitionStateExComponent_Properties[0]),
};

// ecl::character_creation::DummyDefinitionComponent (from CharacterCreation.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_ClientCCDummyDefinitionComponent_Properties[] = {
    { "Dummy", 0x00, FIELD_TYPE_UINT64, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "ChangeId", 0x08, FIELD_TYPE_INT32, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "ChangeId2", 0x0c, FIELD_TYPE_INT32, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_10", 0x10, FIELD_TYPE_INT32, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_18_Map_unk_FS", 0x18, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_58", 0x20, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_59", 0x21, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_5A", 0x22, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_5B", 0x23, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "RootTemplate", 0x28, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "Origin", 0x38, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "BodyType", 0x48, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "BodyShape", 0x49, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "Race", 0x50, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "Subrace", 0x60, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_A8", 0x70, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_1A0", 0x78, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_1A8", 0x80, FIELD_TYPE_UINT64, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_ClientCCDummyDefinitionComponent_Layout = {
    .componentName = "ecl::character_creation::DummyDefinitionComponent",
    .shortName = "ClientCCDummyDefinition",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x88,
    .properties = g_ClientCCDummyDefinitionComponent_Properties,
    .propertyCount = sizeof(g_ClientCCDummyDefinitionComponent_Properties) / sizeof(g_ClientCCDummyDefinitionComponent_Properties[0]),
};

// ecl::character_creation::FullRespecDefinitionComponent (from CharacterCreation.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_ClientCCFullRespecDefinitionComponent_Properties[] = {
    { "field_0", 0x00, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_10", 0x10, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_20", 0x20, FIELD_TYPE_INT32, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "LevelUpUpgrades", 0x28, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "SpellIds", 0x30, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_ClientCCFullRespecDefinitionComponent_Layout = {
    .componentName = "ecl::character_creation::FullRespecDefinitionComponent",
    .shortName = "ClientCCFullRespecDefinition",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x38,
    .properties = g_ClientCCFullRespecDefinitionComponent_Properties,
    .propertyCount = sizeof(g_ClientCCFullRespecDefinitionComponent_Properties) / sizeof(g_ClientCCFullRespecDefinitionComponent_Properties[0]),
};

// ecl::character_creation::LevelUpDefinitionComponent (from CharacterCreation.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_ClientCCLevelUpDefinitionComponent_Properties[] = {
    { "Definition", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_ClientCCLevelUpDefinitionComponent_Layout = {
    .componentName = "ecl::character_creation::LevelUpDefinitionComponent",
    .shortName = "ClientCCLevelUpDefinition",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x08,
    .properties = g_ClientCCLevelUpDefinitionComponent_Properties,
    .propertyCount = sizeof(g_ClientCCLevelUpDefinitionComponent_Properties) / sizeof(g_ClientCCLevelUpDefinitionComponent_Properties[0]),
};

// ecl::dummy::AnimationStateComponent (from Dummy.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_DummyAnimationStateComponent_Properties[] = {
    { "State", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_DummyAnimationStateComponent_Layout = {
    .componentName = "ecl::dummy::AnimationStateComponent",
    .shortName = "DummyAnimationState",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x08,
    .properties = g_DummyAnimationStateComponent_Properties,
    .propertyCount = sizeof(g_DummyAnimationStateComponent_Properties) / sizeof(g_DummyAnimationStateComponent_Properties[0]),
};

// ecl::dummy::AvailableAnimationsComponent (from Dummy.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_DummyAvailableAnimationsComponent_Properties[] = {
    { "EmoteCollections", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "FaceExpressionCollections", 0x08, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_DummyAvailableAnimationsComponent_Layout = {
    .componentName = "ecl::dummy::AvailableAnimationsComponent",
    .shortName = "DummyAvailableAnimations",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x10,
    .properties = g_DummyAvailableAnimationsComponent_Properties,
    .propertyCount = sizeof(g_DummyAvailableAnimationsComponent_Properties) / sizeof(g_DummyAvailableAnimationsComponent_Properties[0]),
};

// ecl::dummy::CharacterVFXInitializationComponent (from Dummy.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_DummyCharacterVFXInitializationComponent_Properties[] = {
    { "Effects", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_DummyCharacterVFXInitializationComponent_Layout = {
    .componentName = "ecl::dummy::CharacterVFXInitializationComponent",
    .shortName = "DummyCharacterVFXInitialization",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x08,
    .properties = g_DummyCharacterVFXInitializationComponent_Properties,
    .propertyCount = sizeof(g_DummyCharacterVFXInitializationComponent_Properties) / sizeof(g_DummyCharacterVFXInitializationComponent_Properties[0]),
};

// ecl::dummy::DummiesCreatedSingletonComponent (from Dummy.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_DummiesCreatedSingletonComponent_Properties[] = {
    { "Dummies", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_DummiesCreatedSingletonComponent_Layout = {
    .componentName = "ecl::dummy::DummiesCreatedSingletonComponent",
    .shortName = "DummiesCreatedSingleton",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x08,
    .properties = g_DummiesCreatedSingletonComponent_Properties,
    .propertyCount = sizeof(g_DummiesCreatedSingletonComponent_Properties) / sizeof(g_DummiesCreatedSingletonComponent_Properties[0]),
};

// ecl::dummy::DummyComponent (from Dummy.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_DummyComponent_Properties[] = {
    { "Entity", 0x00, FIELD_TYPE_UINT64, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_DummyComponent_Layout = {
    .componentName = "ecl::dummy::DummyComponent",
    .shortName = "Dummy",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x08,
    .properties = g_DummyComponent_Properties,
    .propertyCount = sizeof(g_DummyComponent_Properties) / sizeof(g_DummyComponent_Properties[0]),
};

// ecl::dummy::EquipmentVisualsStateComponent (from Dummy.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_DummyEquipmentVisualsStateComponent_Properties[] = {
    { "field_0", 0x00, FIELD_TYPE_INT32, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_DummyEquipmentVisualsStateComponent_Layout = {
    .componentName = "ecl::dummy::EquipmentVisualsStateComponent",
    .shortName = "DummyEquipmentVisualsState",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x04,
    .properties = g_DummyEquipmentVisualsStateComponent_Properties,
    .propertyCount = sizeof(g_DummyEquipmentVisualsStateComponent_Properties) / sizeof(g_DummyEquipmentVisualsStateComponent_Properties[0]),
};

// ecl::dummy::FootIKStateComponent (from Dummy.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_DummyFootIKStateComponent_Properties[] = {
    { "field_0", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_8", 0x08, FIELD_TYPE_INT32, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_C", 0x0c, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_D", 0x0d, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_E", 0x0e, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_DummyFootIKStateComponent_Layout = {
    .componentName = "ecl::dummy::FootIKStateComponent",
    .shortName = "DummyFootIKState",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x0f,
    .properties = g_DummyFootIKStateComponent_Properties,
    .propertyCount = sizeof(g_DummyFootIKStateComponent_Properties) / sizeof(g_DummyFootIKStateComponent_Properties[0]),
};

// ecl::dummy::HasDummyComponent (from Dummy.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_HasDummyComponent_Properties[] = {
    { "Entity", 0x00, FIELD_TYPE_UINT64, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_HasDummyComponent_Layout = {
    .componentName = "ecl::dummy::HasDummyComponent",
    .shortName = "HasDummy",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x08,
    .properties = g_HasDummyComponent_Properties,
    .propertyCount = sizeof(g_HasDummyComponent_Properties) / sizeof(g_HasDummyComponent_Properties[0]),
};

// ecl::dummy::OriginalTransformComponent (from Dummy.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_DummyOriginalTransformComponent_Properties[] = {
    { "Transform", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_DummyOriginalTransformComponent_Layout = {
    .componentName = "ecl::dummy::OriginalTransformComponent",
    .shortName = "DummyOriginalTransform",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x08,
    .properties = g_DummyOriginalTransformComponent_Properties,
    .propertyCount = sizeof(g_DummyOriginalTransformComponent_Properties) / sizeof(g_DummyOriginalTransformComponent_Properties[0]),
};

// ecl::dummy::SpellVFXInitializationComponent (from Dummy.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_DummySpellVFXInitializationComponent_Properties[] = {
    { "Effects", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_DummySpellVFXInitializationComponent_Layout = {
    .componentName = "ecl::dummy::SpellVFXInitializationComponent",
    .shortName = "DummySpellVFXInitialization",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x08,
    .properties = g_DummySpellVFXInitializationComponent_Properties,
    .propertyCount = sizeof(g_DummySpellVFXInitializationComponent_Properties) / sizeof(g_DummySpellVFXInitializationComponent_Properties[0]),
};

// ecl::dummy::SplatterComponent (from Dummy.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_DummySplatterComponent_Properties[] = {
    { "field_0", 0x00, FIELD_TYPE_INT32, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_4", 0x04, FIELD_TYPE_INT32, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_8", 0x08, FIELD_TYPE_INT32, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_C", 0x0c, FIELD_TYPE_INT32, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "byte10", 0x10, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_DummySplatterComponent_Layout = {
    .componentName = "ecl::dummy::SplatterComponent",
    .shortName = "DummySplatter",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x11,
    .properties = g_DummySplatterComponent_Properties,
    .propertyCount = sizeof(g_DummySplatterComponent_Properties) / sizeof(g_DummySplatterComponent_Properties[0]),
};

// ecl::dummy::StoredClothComponent (from Dummy.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_DummyStoredClothComponent_Properties[] = {
    { "Cloths", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "Attachments", 0x08, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_DummyStoredClothComponent_Layout = {
    .componentName = "ecl::dummy::StoredClothComponent",
    .shortName = "DummyStoredCloth",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x10,
    .properties = g_DummyStoredClothComponent_Properties,
    .propertyCount = sizeof(g_DummyStoredClothComponent_Properties) / sizeof(g_DummyStoredClothComponent_Properties[0]),
};

// ecl::dummy::TransformRequestsSingletonComponent (from Dummy.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_DummyTransformRequestsSingletonComponent_Properties[] = {
    { "Requests", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "Requests2", 0x08, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_DummyTransformRequestsSingletonComponent_Layout = {
    .componentName = "ecl::dummy::TransformRequestsSingletonComponent",
    .shortName = "DummyTransformRequestsSingleton",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x10,
    .properties = g_DummyTransformRequestsSingletonComponent_Properties,
    .propertyCount = sizeof(g_DummyTransformRequestsSingletonComponent_Properties) / sizeof(g_DummyTransformRequestsSingletonComponent_Properties[0]),
};

// ecl::dummy::UnsheathComponent (from Dummy.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_DummyUnsheathComponent_Properties[] = {
    { "field_0", 0x00, FIELD_TYPE_INT32, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_4", 0x04, FIELD_TYPE_INT32, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_8", 0x08, FIELD_TYPE_INT32, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_C", 0x0c, FIELD_TYPE_INT32, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_DummyUnsheathComponent_Layout = {
    .componentName = "ecl::dummy::UnsheathComponent",
    .shortName = "DummyUnsheath",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x10,
    .properties = g_DummyUnsheathComponent_Properties,
    .propertyCount = sizeof(g_DummyUnsheathComponent_Properties) / sizeof(g_DummyUnsheathComponent_Properties[0]),
};

// ecl::dummy::VFXEntitiesComponent (from Dummy.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_DummyVFXEntitiesComponent_Properties[] = {
    { "field_0", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_DummyVFXEntitiesComponent_Layout = {
    .componentName = "ecl::dummy::VFXEntitiesComponent",
    .shortName = "DummyVFXEntities",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x08,
    .properties = g_DummyVFXEntitiesComponent_Properties,
    .propertyCount = sizeof(g_DummyVFXEntitiesComponent_Properties) / sizeof(g_DummyVFXEntitiesComponent_Properties[0]),
};

// ecl::equipment::VisualsDesiredStateComponent (from Visual.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_ClientVisualsDesiredStateComponent_Properties[] = {
    { "Slots", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_ClientVisualsDesiredStateComponent_Layout = {
    .componentName = "ecl::equipment::VisualsDesiredStateComponent",
    .shortName = "ClientVisualsDesiredState",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x08,
    .properties = g_ClientVisualsDesiredStateComponent_Properties,
    .propertyCount = sizeof(g_ClientVisualsDesiredStateComponent_Properties) / sizeof(g_ClientVisualsDesiredStateComponent_Properties[0]),
};

// ecl::equipment::VisualsVisibilityStateComponent (from Visual.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_ClientEquipmentVisibilityStateComponent_Properties[] = {
    { "Equipment", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_40", 0x08, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_41", 0x09, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_ClientEquipmentVisibilityStateComponent_Layout = {
    .componentName = "ecl::equipment::VisualsVisibilityStateComponent",
    .shortName = "ClientEquipmentVisibilityState",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x0a,
    .properties = g_ClientEquipmentVisibilityStateComponent_Properties,
    .propertyCount = sizeof(g_ClientEquipmentVisibilityStateComponent_Properties) / sizeof(g_ClientEquipmentVisibilityStateComponent_Properties[0]),
};

// ecl::interrupt::PlayerDecisionComponent (from Interrupt.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_ClientInterruptPlayerDecisionComponent_Properties[] = {
    { "Decisions", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_ClientInterruptPlayerDecisionComponent_Layout = {
    .componentName = "ecl::interrupt::PlayerDecisionComponent",
    .shortName = "ClientInterruptPlayerDecision",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x08,
    .properties = g_ClientInterruptPlayerDecisionComponent_Properties,
    .propertyCount = sizeof(g_ClientInterruptPlayerDecisionComponent_Properties) / sizeof(g_ClientInterruptPlayerDecisionComponent_Properties[0]),
};

// ecl::photo_mode::CameraOffsetComponent (from Dummy.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_PhotoModeCameraOffsetComponent_Properties[] = {
    { "field_0", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_C", 0x08, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_PhotoModeCameraOffsetComponent_Layout = {
    .componentName = "ecl::photo_mode::CameraOffsetComponent",
    .shortName = "PhotoModeCameraOffset",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x10,
    .properties = g_PhotoModeCameraOffsetComponent_Properties,
    .propertyCount = sizeof(g_PhotoModeCameraOffsetComponent_Properties) / sizeof(g_PhotoModeCameraOffsetComponent_Properties[0]),
};

// ecl::photo_mode::CameraSavedTransformComponent (from Dummy.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_PhotoModeCameraSavedTransformComponent_Properties[] = {
    { "field_0", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_28", 0x08, FIELD_TYPE_INT32, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_2C", 0x0c, FIELD_TYPE_INT32, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_30", 0x10, FIELD_TYPE_INT32, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_34", 0x14, FIELD_TYPE_INT32, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_PhotoModeCameraSavedTransformComponent_Layout = {
    .componentName = "ecl::photo_mode::CameraSavedTransformComponent",
    .shortName = "PhotoModeCameraSavedTransform",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x18,
    .properties = g_PhotoModeCameraSavedTransformComponent_Properties,
    .propertyCount = sizeof(g_PhotoModeCameraSavedTransformComponent_Properties) / sizeof(g_PhotoModeCameraSavedTransformComponent_Properties[0]),
};

// ecl::photo_mode::CameraTiltComponent (from Dummy.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_PhotoModeCameraTiltComponent_Properties[] = {
    { "field_0", 0x00, FIELD_TYPE_FLOAT, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_4", 0x04, FIELD_TYPE_FLOAT, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_PhotoModeCameraTiltComponent_Layout = {
    .componentName = "ecl::photo_mode::CameraTiltComponent",
    .shortName = "PhotoModeCameraTilt",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x08,
    .properties = g_PhotoModeCameraTiltComponent_Properties,
    .propertyCount = sizeof(g_PhotoModeCameraTiltComponent_Properties) / sizeof(g_PhotoModeCameraTiltComponent_Properties[0]),
};

// ecl::photo_mode::CameraTrackingComponent (from Dummy.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_PhotoModeCameraTrackingComponent_Properties[] = {
    { "field_0", 0x00, FIELD_TYPE_UINT64, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_PhotoModeCameraTrackingComponent_Layout = {
    .componentName = "ecl::photo_mode::CameraTrackingComponent",
    .shortName = "PhotoModeCameraTracking",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x08,
    .properties = g_PhotoModeCameraTrackingComponent_Properties,
    .propertyCount = sizeof(g_PhotoModeCameraTrackingComponent_Properties) / sizeof(g_PhotoModeCameraTrackingComponent_Properties[0]),
};

// ecl::photo_mode::DummyAnimationUpdateSingletonComponent (from Dummy.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_PhotoModeDummyAnimationUpdateSingletonComponent_Properties[] = {
    { "Updates", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_PhotoModeDummyAnimationUpdateSingletonComponent_Layout = {
    .componentName = "ecl::photo_mode::DummyAnimationUpdateSingletonComponent",
    .shortName = "PhotoModeDummyAnimationUpdateSingleton",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x08,
    .properties = g_PhotoModeDummyAnimationUpdateSingletonComponent_Properties,
    .propertyCount = sizeof(g_PhotoModeDummyAnimationUpdateSingletonComponent_Properties) / sizeof(g_PhotoModeDummyAnimationUpdateSingletonComponent_Properties[0]),
};

// ecl::photo_mode::DummyEquipmentSetupOneFrameComponent (from Dummy.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_PhotoModeDummyEquipmentSetupOneFrameComponent_Properties[] = {
    { "field_0", 0x00, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_1", 0x01, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_2", 0x02, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_3", 0x03, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_PhotoModeDummyEquipmentSetupOneFrameComponent_Layout = {
    .componentName = "ecl::photo_mode::DummyEquipmentSetupOneFrameComponent",
    .shortName = "PhotoModeDummyEquipmentSetupOneFrame",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x04,
    .properties = g_PhotoModeDummyEquipmentSetupOneFrameComponent_Properties,
    .propertyCount = sizeof(g_PhotoModeDummyEquipmentSetupOneFrameComponent_Properties) / sizeof(g_PhotoModeDummyEquipmentSetupOneFrameComponent_Properties[0]),
};

// ecl::photo_mode::DummyEquipmentVisualUpdateSingletonComponent (from Dummy.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_PhotoModeDummyEquipmentVisualUpdateSingletonComponent_Properties[] = {
    { "Updates", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_PhotoModeDummyEquipmentVisualUpdateSingletonComponent_Layout = {
    .componentName = "ecl::photo_mode::DummyEquipmentVisualUpdateSingletonComponent",
    .shortName = "PhotoModeDummyEquipmentVisualUpdateSingleton",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x08,
    .properties = g_PhotoModeDummyEquipmentVisualUpdateSingletonComponent_Properties,
    .propertyCount = sizeof(g_PhotoModeDummyEquipmentVisualUpdateSingletonComponent_Properties) / sizeof(g_PhotoModeDummyEquipmentVisualUpdateSingletonComponent_Properties[0]),
};

// ecl::photo_mode::DummySplatterUpdateSingletonComponent (from Dummy.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_PhotoModeDummySplatterUpdateSingletonComponent_Properties[] = {
    { "Updates", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_PhotoModeDummySplatterUpdateSingletonComponent_Layout = {
    .componentName = "ecl::photo_mode::DummySplatterUpdateSingletonComponent",
    .shortName = "PhotoModeDummySplatterUpdateSingleton",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x08,
    .properties = g_PhotoModeDummySplatterUpdateSingletonComponent_Properties,
    .propertyCount = sizeof(g_PhotoModeDummySplatterUpdateSingletonComponent_Properties) / sizeof(g_PhotoModeDummySplatterUpdateSingletonComponent_Properties[0]),
};

// ecl::photo_mode::DummyTransformUpdateSingletonComponent (from Dummy.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_PhotoModeDummyTransformUpdateSingletonComponent_Properties[] = {
    { "Updates", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_PhotoModeDummyTransformUpdateSingletonComponent_Layout = {
    .componentName = "ecl::photo_mode::DummyTransformUpdateSingletonComponent",
    .shortName = "PhotoModeDummyTransformUpdateSingleton",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x08,
    .properties = g_PhotoModeDummyTransformUpdateSingletonComponent_Properties,
    .propertyCount = sizeof(g_PhotoModeDummyTransformUpdateSingletonComponent_Properties) / sizeof(g_PhotoModeDummyTransformUpdateSingletonComponent_Properties[0]),
};

// ecl::photo_mode::InvisibilityRequestSingletonComponent (from Dummy.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_PhotoModeInvisibilityRequestSingletonComponent_Properties[] = {
    { "Requests", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_PhotoModeInvisibilityRequestSingletonComponent_Layout = {
    .componentName = "ecl::photo_mode::InvisibilityRequestSingletonComponent",
    .shortName = "PhotoModeInvisibilityRequestSingleton",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x08,
    .properties = g_PhotoModeInvisibilityRequestSingletonComponent_Properties,
    .propertyCount = sizeof(g_PhotoModeInvisibilityRequestSingletonComponent_Properties) / sizeof(g_PhotoModeInvisibilityRequestSingletonComponent_Properties[0]),
};

// ecl::photo_mode::RequestedSingletonComponent (from Dummy.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_PhotoModeRequestedSingletonComponent_Properties[] = {
    { "Requested", 0x00, FIELD_TYPE_BOOL, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_PhotoModeRequestedSingletonComponent_Layout = {
    .componentName = "ecl::photo_mode::RequestedSingletonComponent",
    .shortName = "PhotoModeRequestedSingleton",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x01,
    .properties = g_PhotoModeRequestedSingletonComponent_Properties,
    .propertyCount = sizeof(g_PhotoModeRequestedSingletonComponent_Properties) / sizeof(g_PhotoModeRequestedSingletonComponent_Properties[0]),
};

// eoc::ArmorComponent (from Stats.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_ArmorComponent_Properties[] = {
    { "ArmorType", 0x00, FIELD_TYPE_INT32, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "ArmorClass", 0x04, FIELD_TYPE_INT32, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "AbilityModifierCap", 0x08, FIELD_TYPE_INT32, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "ArmorClassAbility", 0x0c, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "EquipmentType", 0x10, FIELD_TYPE_INT32, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_ArmorComponent_Layout = {
    .componentName = "eoc::ArmorComponent",
    .shortName = "Armor",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x14,
    .properties = g_ArmorComponent_Properties,
    .propertyCount = sizeof(g_ArmorComponent_Properties) / sizeof(g_ArmorComponent_Properties[0]),
};

// eoc::AttributeFlagsComponent (from Stats.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_AttributeFlagsComponent_Properties[] = {
    { "AttributeFlags", 0x00, FIELD_TYPE_UINT32, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_AttributeFlagsComponent_Layout = {
    .componentName = "eoc::AttributeFlagsComponent",
    .shortName = "AttributeFlags",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x04,
    .properties = g_AttributeFlagsComponent_Properties,
    .propertyCount = sizeof(g_AttributeFlagsComponent_Properties) / sizeof(g_AttributeFlagsComponent_Properties[0]),
};

// eoc::BackgroundComponent (from Data.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_BackgroundComponent_Properties[] = {
    { "Background", 0x00, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_BackgroundComponent_Layout = {
    .componentName = "eoc::BackgroundComponent",
    .shortName = "Background",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x10,
    .properties = g_BackgroundComponent_Properties,
    .propertyCount = sizeof(g_BackgroundComponent_Properties) / sizeof(g_BackgroundComponent_Properties[0]),
};

// eoc::BackgroundPassivesComponent (from Data.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_BackgroundPassivesComponent_Properties[] = {
    { "field_18", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_BackgroundPassivesComponent_Layout = {
    .componentName = "eoc::BackgroundPassivesComponent",
    .shortName = "BackgroundPassives",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x08,
    .properties = g_BackgroundPassivesComponent_Properties,
    .propertyCount = sizeof(g_BackgroundPassivesComponent_Properties) / sizeof(g_BackgroundPassivesComponent_Properties[0]),
};

// eoc::BackgroundTagComponent (from Data.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_BackgroundTagComponent_Properties[] = {
    { "Tags", 0x00, FIELD_TYPE_GUID, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_BackgroundTagComponent_Layout = {
    .componentName = "eoc::BackgroundTagComponent",
    .shortName = "BackgroundTag",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x08,
    .properties = g_BackgroundTagComponent_Properties,
    .propertyCount = sizeof(g_BackgroundTagComponent_Properties) / sizeof(g_BackgroundTagComponent_Properties[0]),
};

// eoc::BaseHpComponent (from Stats.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_BaseHpComponent_Properties[] = {
    { "Vitality", 0x00, FIELD_TYPE_INT32, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "VitalityBoost", 0x04, FIELD_TYPE_INT32, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_BaseHpComponent_Layout = {
    .componentName = "eoc::BaseHpComponent",
    .shortName = "BaseHp",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x08,
    .properties = g_BaseHpComponent_Properties,
    .propertyCount = sizeof(g_BaseHpComponent_Properties) / sizeof(g_BaseHpComponent_Properties[0]),
};

// eoc::BaseStatsComponent (from Data.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_BaseStatsComponent_Properties[] = {
    { "BaseAbilities", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_BaseStatsComponent_Layout = {
    .componentName = "eoc::BaseStatsComponent",
    .shortName = "BaseStats",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x08,
    .properties = g_BaseStatsComponent_Properties,
    .propertyCount = sizeof(g_BaseStatsComponent_Properties) / sizeof(g_BaseStatsComponent_Properties[0]),
};

// eoc::BlockAbilityModifierFromACComponent (from Boosts.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_BlockAbilityModifierFromACBoostComponent_Properties[] = {
    { "Ability", 0x00, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_BlockAbilityModifierFromACBoostComponent_Layout = {
    .componentName = "eoc::BlockAbilityModifierFromACComponent",
    .shortName = "BlockAbilityModifierFromACBoost",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x01,
    .properties = g_BlockAbilityModifierFromACBoostComponent_Properties,
    .propertyCount = sizeof(g_BlockAbilityModifierFromACBoostComponent_Properties) / sizeof(g_BlockAbilityModifierFromACBoostComponent_Properties[0]),
};

// eoc::BodyTypeComponent (from Data.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_BodyTypeComponent_Properties[] = {
    { "BodyType", 0x00, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "BodyType2", 0x01, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_BodyTypeComponent_Layout = {
    .componentName = "eoc::BodyTypeComponent",
    .shortName = "BodyType",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x02,
    .properties = g_BodyTypeComponent_Properties,
    .propertyCount = sizeof(g_BodyTypeComponent_Properties) / sizeof(g_BodyTypeComponent_Properties[0]),
};

// eoc::BoostConditionComponent (from Boosts.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_BoostConditionComponent_Properties[] = {
    { "ConditionFlags", 0x00, FIELD_TYPE_INT32, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_1C", 0x04, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_BoostConditionComponent_Layout = {
    .componentName = "eoc::BoostConditionComponent",
    .shortName = "BoostCondition",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x05,
    .properties = g_BoostConditionComponent_Properties,
    .propertyCount = sizeof(g_BoostConditionComponent_Properties) / sizeof(g_BoostConditionComponent_Properties[0]),
};

// eoc::BoostInfoComponent (from Boosts.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_BoostInfoComponent_Properties[] = {
    { "CauseUuid", 0x00, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_20", 0x10, FIELD_TYPE_BOOL, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "Cause", 0x18, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "Owner", 0x20, FIELD_TYPE_UINT64, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "Params", 0x28, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "Type", 0x30, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "Prototype", 0x38, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_BoostInfoComponent_Layout = {
    .componentName = "eoc::BoostInfoComponent",
    .shortName = "BoostInfo",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x48,
    .properties = g_BoostInfoComponent_Properties,
    .propertyCount = sizeof(g_BoostInfoComponent_Properties) / sizeof(g_BoostInfoComponent_Properties[0]),
};

// eoc::BoostsContainerComponent (from Boosts.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_BoostsContainerComponent_Properties[] = {
    { "Boosts", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_BoostsContainerComponent_Layout = {
    .componentName = "eoc::BoostsContainerComponent",
    .shortName = "BoostsContainer",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x08,
    .properties = g_BoostsContainerComponent_Properties,
    .propertyCount = sizeof(g_BoostsContainerComponent_Properties) / sizeof(g_BoostsContainerComponent_Properties[0]),
};

// eoc::CanBeDisarmedComponent (from Data.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_CanBeDisarmedComponent_Properties[] = {
    { "Flags", 0x00, FIELD_TYPE_UINT16, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_CanBeDisarmedComponent_Layout = {
    .componentName = "eoc::CanBeDisarmedComponent",
    .shortName = "CanBeDisarmed",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x02,
    .properties = g_CanBeDisarmedComponent_Properties,
    .propertyCount = sizeof(g_CanBeDisarmedComponent_Properties) / sizeof(g_CanBeDisarmedComponent_Properties[0]),
};

// eoc::CanBeLootedComponent (from Data.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_CanBeLootedComponent_Properties[] = {
    { "Flags", 0x00, FIELD_TYPE_UINT16, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_CanBeLootedComponent_Layout = {
    .componentName = "eoc::CanBeLootedComponent",
    .shortName = "CanBeLooted",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x02,
    .properties = g_CanBeLootedComponent_Properties,
    .propertyCount = sizeof(g_CanBeLootedComponent_Properties) / sizeof(g_CanBeLootedComponent_Properties[0]),
};

// eoc::CanDeflectProjectilesComponent (from Data.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_CanDeflectProjectilesComponent_Properties[] = {
    { "Flags", 0x00, FIELD_TYPE_UINT16, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_CanDeflectProjectilesComponent_Layout = {
    .componentName = "eoc::CanDeflectProjectilesComponent",
    .shortName = "CanDeflectProjectiles",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x02,
    .properties = g_CanDeflectProjectilesComponent_Properties,
    .propertyCount = sizeof(g_CanDeflectProjectilesComponent_Properties) / sizeof(g_CanDeflectProjectilesComponent_Properties[0]),
};

// eoc::CanDoActionsComponent (from Data.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_CanDoActionsComponent_Properties[] = {
    { "Flags", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_CanDoActionsComponent_Layout = {
    .componentName = "eoc::CanDoActionsComponent",
    .shortName = "CanDoActions",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x08,
    .properties = g_CanDoActionsComponent_Properties,
    .propertyCount = sizeof(g_CanDoActionsComponent_Properties) / sizeof(g_CanDoActionsComponent_Properties[0]),
};

// eoc::CanDoRestComponent (from Data.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_CanDoRestComponent_Properties[] = {
    { "Flags", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "LongRestErrorFlags", 0x08, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "ShortRestErrorFlags", 0x10, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_CanDoRestComponent_Layout = {
    .componentName = "eoc::CanDoRestComponent",
    .shortName = "CanDoRest",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x18,
    .properties = g_CanDoRestComponent_Properties,
    .propertyCount = sizeof(g_CanDoRestComponent_Properties) / sizeof(g_CanDoRestComponent_Properties[0]),
};

// eoc::CanInteractComponent (from Components.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_CanInteractComponent_Properties[] = {
    { "Flags", 0x00, FIELD_TYPE_UINT32, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "Flags2", 0x04, FIELD_TYPE_UINT16, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_CanInteractComponent_Layout = {
    .componentName = "eoc::CanInteractComponent",
    .shortName = "CanInteract",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x06,
    .properties = g_CanInteractComponent_Properties,
    .propertyCount = sizeof(g_CanInteractComponent_Properties) / sizeof(g_CanInteractComponent_Properties[0]),
};

// eoc::CanModifyHealthComponent (from Data.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_CanModifyHealthComponent_Properties[] = {
    { "Flags", 0x00, FIELD_TYPE_UINT16, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_CanModifyHealthComponent_Layout = {
    .componentName = "eoc::CanModifyHealthComponent",
    .shortName = "CanModifyHealth",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x02,
    .properties = g_CanModifyHealthComponent_Properties,
    .propertyCount = sizeof(g_CanModifyHealthComponent_Properties) / sizeof(g_CanModifyHealthComponent_Properties[0]),
};

// eoc::CanMoveComponent (from Data.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_CanMoveComponent_Properties[] = {
    { "Flags", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_4", 0x08, FIELD_TYPE_UINT16, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_6", 0x0a, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_CanMoveComponent_Layout = {
    .componentName = "eoc::CanMoveComponent",
    .shortName = "CanMove",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x0b,
    .properties = g_CanMoveComponent_Properties,
    .propertyCount = sizeof(g_CanMoveComponent_Properties) / sizeof(g_CanMoveComponent_Properties[0]),
};

// eoc::CanSenseComponent (from Data.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_CanSenseComponent_Properties[] = {
    { "Flags", 0x00, FIELD_TYPE_UINT16, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_CanSenseComponent_Layout = {
    .componentName = "eoc::CanSenseComponent",
    .shortName = "CanSense",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x02,
    .properties = g_CanSenseComponent_Properties,
    .propertyCount = sizeof(g_CanSenseComponent_Properties) / sizeof(g_CanSenseComponent_Properties[0]),
};

// eoc::CanSpeakComponent (from Components.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_CanSpeakComponent_Properties[] = {
    { "Flags", 0x00, FIELD_TYPE_UINT16, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_CanSpeakComponent_Layout = {
    .componentName = "eoc::CanSpeakComponent",
    .shortName = "CanSpeak",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x02,
    .properties = g_CanSpeakComponent_Properties,
    .propertyCount = sizeof(g_CanSpeakComponent_Properties) / sizeof(g_CanSpeakComponent_Properties[0]),
};

// eoc::CanTravelComponent (from Data.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_CanTravelComponent_Properties[] = {
    { "Flags", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_2", 0x08, FIELD_TYPE_UINT16, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "ErrorFlags", 0x10, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_CanTravelComponent_Layout = {
    .componentName = "eoc::CanTravelComponent",
    .shortName = "CanTravel",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x18,
    .properties = g_CanTravelComponent_Properties,
    .propertyCount = sizeof(g_CanTravelComponent_Properties) / sizeof(g_CanTravelComponent_Properties[0]),
};

// eoc::CharacterCreationStatsComponent (from Data.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_CharacterCreationStatsComponent_Properties[] = {
    { "Race", 0x00, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "SubRace", 0x10, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "BodyType", 0x20, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "BodyShape", 0x21, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "Name", 0x28, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "Abilities", 0x30, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_5C", 0x38, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_CharacterCreationStatsComponent_Layout = {
    .componentName = "eoc::CharacterCreationStatsComponent",
    .shortName = "CharacterCreationStats",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x39,
    .properties = g_CharacterCreationStatsComponent_Properties,
    .propertyCount = sizeof(g_CharacterCreationStatsComponent_Properties) / sizeof(g_CharacterCreationStatsComponent_Properties[0]),
};

// eoc::ClassTagComponent (from Data.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_ClassTagComponent_Properties[] = {
    { "Tags", 0x00, FIELD_TYPE_GUID, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_ClassTagComponent_Layout = {
    .componentName = "eoc::ClassTagComponent",
    .shortName = "ClassTag",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x08,
    .properties = g_ClassTagComponent_Properties,
    .propertyCount = sizeof(g_ClassTagComponent_Properties) / sizeof(g_ClassTagComponent_Properties[0]),
};

// eoc::ClassesComponent (from Stats.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_ClassesComponent_Properties[] = {
    { "Classes", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_ClassesComponent_Layout = {
    .componentName = "eoc::ClassesComponent",
    .shortName = "Classes",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x08,
    .properties = g_ClassesComponent_Properties,
    .propertyCount = sizeof(g_ClassesComponent_Properties) / sizeof(g_ClassesComponent_Properties[0]),
};

// eoc::CustomIconComponent (from Visual.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_CustomIconComponent_Properties[] = {
    { "Icon", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "Source", 0x08, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_CustomIconComponent_Layout = {
    .componentName = "eoc::CustomIconComponent",
    .shortName = "CustomIcon",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x09,
    .properties = g_CustomIconComponent_Properties,
    .propertyCount = sizeof(g_CustomIconComponent_Properties) / sizeof(g_CustomIconComponent_Properties[0]),
};

// eoc::CustomIconsStorageSingletonComponent (from Visual.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_CustomIconsStorageComponent_Properties[] = {
    { "Icons", 0x00, FIELD_TYPE_GUID, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_CustomIconsStorageComponent_Layout = {
    .componentName = "eoc::CustomIconsStorageSingletonComponent",
    .shortName = "CustomIconsStorage",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x08,
    .properties = g_CustomIconsStorageComponent_Properties,
    .propertyCount = sizeof(g_CustomIconsStorageComponent_Properties) / sizeof(g_CustomIconsStorageComponent_Properties[0]),
};

// eoc::CustomNameComponent (from Visual.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_CustomNameComponent_Properties[] = {
    { "Name", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_CustomNameComponent_Layout = {
    .componentName = "eoc::CustomNameComponent",
    .shortName = "CustomName",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x08,
    .properties = g_CustomNameComponent_Properties,
    .propertyCount = sizeof(g_CustomNameComponent_Properties) / sizeof(g_CustomNameComponent_Properties[0]),
};

// eoc::CustomStatsComponent (from Data.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_CustomStatsComponent_Properties[] = {
    { "Stats", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_CustomStatsComponent_Layout = {
    .componentName = "eoc::CustomStatsComponent",
    .shortName = "CustomStats",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x08,
    .properties = g_CustomStatsComponent_Properties,
    .propertyCount = sizeof(g_CustomStatsComponent_Properties) / sizeof(g_CustomStatsComponent_Properties[0]),
};

// eoc::DamageReductionBoostComponent (from Boosts.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_DamageReductionBoostComponent_Properties[] = {
    { "DamageType", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "Amount", 0x08, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "Flat", 0x10, FIELD_TYPE_BOOL, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "Half", 0x11, FIELD_TYPE_BOOL, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_DamageReductionBoostComponent_Layout = {
    .componentName = "eoc::DamageReductionBoostComponent",
    .shortName = "DamageReductionBoost",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x12,
    .properties = g_DamageReductionBoostComponent_Properties,
    .propertyCount = sizeof(g_DamageReductionBoostComponent_Properties) / sizeof(g_DamageReductionBoostComponent_Properties[0]),
};

// eoc::DarknessComponent (from Data.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_DarknessComponent_Properties[] = {
    { "Sneaking", 0x00, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "Obscurity", 0x01, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "SneakingConesVisibility", 0x02, FIELD_TYPE_BOOL, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "CharacterSneaking", 0x03, FIELD_TYPE_BOOL, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "ActuallySneaking", 0x04, FIELD_TYPE_BOOL, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "GracePeriod", 0x08, FIELD_TYPE_FLOAT, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "GraceFrames", 0x0c, FIELD_TYPE_FLOAT, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_DarknessComponent_Layout = {
    .componentName = "eoc::DarknessComponent",
    .shortName = "Darkness",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x10,
    .properties = g_DarknessComponent_Properties,
    .propertyCount = sizeof(g_DarknessComponent_Properties) / sizeof(g_DarknessComponent_Properties[0]),
};

// eoc::DataComponent (from Stats.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_DataComponent_Properties[] = {
    { "Weight", 0x00, FIELD_TYPE_INT32, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "StatsId", 0x04, FIELD_TYPE_UINT32, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "StepsType", 0x08, FIELD_TYPE_UINT32, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_DataComponent_Layout = {
    .componentName = "eoc::DataComponent",
    .shortName = "Data",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x0c,
    .properties = g_DataComponent_Properties,
    .propertyCount = sizeof(g_DataComponent_Properties) / sizeof(g_DataComponent_Properties[0]),
};

// eoc::DetachedComponent (from Data.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_DetachedComponent_Properties[] = {
    { "Flags", 0x00, FIELD_TYPE_UINT32, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_DetachedComponent_Layout = {
    .componentName = "eoc::DetachedComponent",
    .shortName = "Detached",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x04,
    .properties = g_DetachedComponent_Properties,
    .propertyCount = sizeof(g_DetachedComponent_Properties) / sizeof(g_DetachedComponent_Properties[0]),
};

// eoc::DifficultyCheckComponent (from Data.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_DifficultyCheckComponent_Properties[] = {
    { "AbilityDC", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "AbilityModifiers", 0x08, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "Abilities", 0x10, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_30", 0x18, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_40", 0x20, FIELD_TYPE_INT32, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_44", 0x24, FIELD_TYPE_INT32, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_DifficultyCheckComponent_Layout = {
    .componentName = "eoc::DifficultyCheckComponent",
    .shortName = "DifficultyCheck",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x28,
    .properties = g_DifficultyCheckComponent_Properties,
    .propertyCount = sizeof(g_DifficultyCheckComponent_Properties) / sizeof(g_DifficultyCheckComponent_Properties[0]),
};

// eoc::DisabledEquipmentComponent (from Data.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_DisabledEquipmentComponent_Properties[] = {
    { "ShapeshiftFlag", 0x00, FIELD_TYPE_BOOL, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_DisabledEquipmentComponent_Layout = {
    .componentName = "eoc::DisabledEquipmentComponent",
    .shortName = "DisabledEquipment",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x01,
    .properties = g_DisabledEquipmentComponent_Properties,
    .propertyCount = sizeof(g_DisabledEquipmentComponent_Properties) / sizeof(g_DisabledEquipmentComponent_Properties[0]),
};

// eoc::DisarmableComponent (from Data.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_DisarmableComponent_Properties[] = {
    { "field_0", 0x00, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_10", 0x10, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_11", 0x11, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_DisarmableComponent_Layout = {
    .componentName = "eoc::DisarmableComponent",
    .shortName = "Disarmable",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x12,
    .properties = g_DisarmableComponent_Properties,
    .propertyCount = sizeof(g_DisarmableComponent_Properties) / sizeof(g_DisarmableComponent_Properties[0]),
};

// eoc::DisplayNameComponent (from Visual.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_DisplayNameComponent_Properties[] = {
    { "Name", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "Title", 0x08, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_DisplayNameComponent_Layout = {
    .componentName = "eoc::DisplayNameComponent",
    .shortName = "DisplayName",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x10,
    .properties = g_DisplayNameComponent_Properties,
    .propertyCount = sizeof(g_DisplayNameComponent_Properties) / sizeof(g_DisplayNameComponent_Properties[0]),
};

// eoc::DualWieldingComponent (from Data.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_DualWieldingComponent_Properties[] = {
    { "MeleeToggledOn", 0x00, FIELD_TYPE_BOOL, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "MeleeUI", 0x01, FIELD_TYPE_BOOL, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "HasMeleeBoosts", 0x02, FIELD_TYPE_BOOL, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "RangedToggledOn", 0x03, FIELD_TYPE_BOOL, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "RangedUI", 0x04, FIELD_TYPE_BOOL, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "HasRangedBoosts", 0x05, FIELD_TYPE_BOOL, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "ToggledOn", 0x06, FIELD_TYPE_BOOL, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_DualWieldingComponent_Layout = {
    .componentName = "eoc::DualWieldingComponent",
    .shortName = "DualWielding",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x07,
    .properties = g_DualWieldingComponent_Properties,
    .propertyCount = sizeof(g_DualWieldingComponent_Properties) / sizeof(g_DualWieldingComponent_Properties[0]),
};

// eoc::EquipableComponent (from Stats.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_EquipableComponent_Properties[] = {
    { "EquipmentTypeID", 0x00, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "Slot", 0x10, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_EquipableComponent_Layout = {
    .componentName = "eoc::EquipableComponent",
    .shortName = "Equipable",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x11,
    .properties = g_EquipableComponent_Properties,
    .propertyCount = sizeof(g_EquipableComponent_Properties) / sizeof(g_EquipableComponent_Properties[0]),
};

// eoc::FleeCapabilityComponent (from Data.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_FleeCapabilityComponent_Properties[] = {
    { "Flags", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "FleeDistance", 0x08, FIELD_TYPE_FLOAT, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "CurrentFleeDistance", 0x0c, FIELD_TYPE_FLOAT, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_FleeCapabilityComponent_Layout = {
    .componentName = "eoc::FleeCapabilityComponent",
    .shortName = "FleeCapability",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x10,
    .properties = g_FleeCapabilityComponent_Properties,
    .propertyCount = sizeof(g_FleeCapabilityComponent_Properties) / sizeof(g_FleeCapabilityComponent_Properties[0]),
};

// eoc::FloatingComponent (from Data.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_FloatingComponent_Properties[] = {
    { "field_18", 0x00, FIELD_TYPE_INT32, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_1C", 0x04, FIELD_TYPE_INT32, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_FloatingComponent_Layout = {
    .componentName = "eoc::FloatingComponent",
    .shortName = "Floating",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x08,
    .properties = g_FloatingComponent_Properties,
    .propertyCount = sizeof(g_FloatingComponent_Properties) / sizeof(g_FloatingComponent_Properties[0]),
};

// eoc::GameObjectVisualComponent (from Visual.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_GameObjectVisualComponent_Properties[] = {
    { "RootTemplateId", 0x00, FIELD_TYPE_UINT32, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "RootTemplateType", 0x04, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "Icon", 0x08, FIELD_TYPE_UINT32, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "Scale", 0x0c, FIELD_TYPE_FLOAT, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "Type", 0x10, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_GameObjectVisualComponent_Layout = {
    .componentName = "eoc::GameObjectVisualComponent",
    .shortName = "GameObjectVisual",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x11,
    .properties = g_GameObjectVisualComponent_Properties,
    .propertyCount = sizeof(g_GameObjectVisualComponent_Properties) / sizeof(g_GameObjectVisualComponent_Properties[0]),
};

// eoc::GameplayLightComponent (from Visual.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_GameplayLightComponent_Properties[] = {
    { "Active", 0x00, FIELD_TYPE_BOOL, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "Radius", 0x04, FIELD_TYPE_FLOAT, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "EdgeSharpening", 0x08, FIELD_TYPE_FLOAT, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "SpotlightAngle", 0x0c, FIELD_TYPE_FLOAT, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "DirectionalDimensions", 0x10, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "LightType", 0x18, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "IsHalfLit", 0x20, FIELD_TYPE_BOOL, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "Sunlight", 0x21, FIELD_TYPE_BOOL, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "AttachAt", 0x28, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "PointLightVerticalLimit", 0x30, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "CheckLOS", 0x38, FIELD_TYPE_BOOL, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "LightCookie", 0x3c, FIELD_TYPE_UINT32, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_3C", 0x40, FIELD_TYPE_FLOAT, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_40", 0x44, FIELD_TYPE_FLOAT, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_44", 0x48, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_GameplayLightComponent_Layout = {
    .componentName = "eoc::GameplayLightComponent",
    .shortName = "GameplayLight",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x49,
    .properties = g_GameplayLightComponent_Properties,
    .propertyCount = sizeof(g_GameplayLightComponent_Properties) / sizeof(g_GameplayLightComponent_Properties[0]),
};

// eoc::GravityDisabledUntilMovedComponent (from Data.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_GravityDisabledUntilMovedComponent_Properties[] = {
    { "Transform", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_GravityDisabledUntilMovedComponent_Layout = {
    .componentName = "eoc::GravityDisabledUntilMovedComponent",
    .shortName = "GravityDisabledUntilMoved",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x08,
    .properties = g_GravityDisabledUntilMovedComponent_Properties,
    .propertyCount = sizeof(g_GravityDisabledUntilMovedComponent_Properties) / sizeof(g_GravityDisabledUntilMovedComponent_Properties[0]),
};

// eoc::HealthComponent (from Data.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_HealthComponent_Properties[] = {
    { "Hp", 0x00, FIELD_TYPE_INT32, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "MaxHp", 0x04, FIELD_TYPE_INT32, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "TemporaryHp", 0x08, FIELD_TYPE_INT32, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "MaxTemporaryHp", 0x0c, FIELD_TYPE_INT32, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_10", 0x10, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "IsInvulnerable", 0x20, FIELD_TYPE_BOOL, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_HealthComponent_Layout = {
    .componentName = "eoc::HealthComponent",
    .shortName = "Health",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x21,
    .properties = g_HealthComponent_Properties,
    .propertyCount = sizeof(g_HealthComponent_Properties) / sizeof(g_HealthComponent_Properties[0]),
};

// eoc::HearingComponent (from Stats.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_HearingComponent_Properties[] = {
    { "Hearing", 0x00, FIELD_TYPE_FLOAT, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_HearingComponent_Layout = {
    .componentName = "eoc::HearingComponent",
    .shortName = "Hearing",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x04,
    .properties = g_HearingComponent_Properties,
    .propertyCount = sizeof(g_HearingComponent_Properties) / sizeof(g_HearingComponent_Properties[0]),
};

// eoc::IconComponent (from Visual.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_IconComponent_Properties[] = {
    { "Icon", 0x00, FIELD_TYPE_UINT32, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_IconComponent_Layout = {
    .componentName = "eoc::IconComponent",
    .shortName = "Icon",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x04,
    .properties = g_IconComponent_Properties,
    .propertyCount = sizeof(g_IconComponent_Properties) / sizeof(g_IconComponent_Properties[0]),
};

// eoc::IncreaseMaxHPBoostComponent (from Boosts.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_IncreaseMaxHPBoostComponent_Properties[] = {
    { "Amount", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_30", 0x08, FIELD_TYPE_INT32, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_IncreaseMaxHPBoostComponent_Layout = {
    .componentName = "eoc::IncreaseMaxHPBoostComponent",
    .shortName = "IncreaseMaxHPBoost",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x0c,
    .properties = g_IncreaseMaxHPBoostComponent_Properties,
    .propertyCount = sizeof(g_IncreaseMaxHPBoostComponent_Properties) / sizeof(g_IncreaseMaxHPBoostComponent_Properties[0]),
};

// eoc::InteractionFilterComponent (from Data.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_InteractionFilterComponent_Properties[] = {
    { "field_0", 0x00, FIELD_TYPE_GUID, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_30", 0x08, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_31", 0x09, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_InteractionFilterComponent_Layout = {
    .componentName = "eoc::InteractionFilterComponent",
    .shortName = "InteractionFilter",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x0a,
    .properties = g_InteractionFilterComponent_Properties,
    .propertyCount = sizeof(g_InteractionFilterComponent_Properties) / sizeof(g_InteractionFilterComponent_Properties[0]),
};

// eoc::InvisibilityComponent (from Data.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_InvisibilityComponent_Properties[] = {
    { "field_0", 0x00, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_4", 0x08, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_10", 0x10, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_InvisibilityComponent_Layout = {
    .componentName = "eoc::InvisibilityComponent",
    .shortName = "Invisibility",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x11,
    .properties = g_InvisibilityComponent_Properties,
    .propertyCount = sizeof(g_InvisibilityComponent_Properties) / sizeof(g_InvisibilityComponent_Properties[0]),
};

// eoc::ItemBoostsComponent (from Data.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_ItemBoostsComponent_Properties[] = {
    { "Boosts", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_ItemBoostsComponent_Layout = {
    .componentName = "eoc::ItemBoostsComponent",
    .shortName = "ItemBoosts",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x08,
    .properties = g_ItemBoostsComponent_Properties,
    .propertyCount = sizeof(g_ItemBoostsComponent_Properties) / sizeof(g_ItemBoostsComponent_Properties[0]),
};

// eoc::LevelComponent (from Stats.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_EocLevelComponent_Properties[] = {
    { "Level", 0x00, FIELD_TYPE_INT32, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_EocLevelComponent_Layout = {
    .componentName = "eoc::LevelComponent",
    .shortName = "EocLevel",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x04,
    .properties = g_EocLevelComponent_Properties,
    .propertyCount = sizeof(g_EocLevelComponent_Properties) / sizeof(g_EocLevelComponent_Properties[0]),
};

// eoc::LootComponent (from Data.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_LootComponent_Properties[] = {
    { "Flags", 0x00, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "InventoryType", 0x01, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_LootComponent_Layout = {
    .componentName = "eoc::LootComponent",
    .shortName = "Loot",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x02,
    .properties = g_LootComponent_Properties,
    .propertyCount = sizeof(g_LootComponent_Properties) / sizeof(g_LootComponent_Properties[0]),
};

// eoc::LootingStateComponent (from Data.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_LootingStateComponent_Properties[] = {
    { "Looter_M", 0x00, FIELD_TYPE_UINT64, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "State", 0x08, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_24", 0x0c, FIELD_TYPE_INT32, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_LootingStateComponent_Layout = {
    .componentName = "eoc::LootingStateComponent",
    .shortName = "LootingState",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x10,
    .properties = g_LootingStateComponent_Properties,
    .propertyCount = sizeof(g_LootingStateComponent_Properties) / sizeof(g_LootingStateComponent_Properties[0]),
};

// eoc::MaterialParameterOverrideComponent (from Components.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_MaterialParameterOverrideComponent_Properties[] = {
    { "field_0", 0x00, FIELD_TYPE_GUID, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_10", 0x08, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_MaterialParameterOverrideComponent_Layout = {
    .componentName = "eoc::MaterialParameterOverrideComponent",
    .shortName = "MaterialParameterOverride",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x10,
    .properties = g_MaterialParameterOverrideComponent_Properties,
    .propertyCount = sizeof(g_MaterialParameterOverrideComponent_Properties) / sizeof(g_MaterialParameterOverrideComponent_Properties[0]),
};

// eoc::MovementComponent (from Data.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_MovementComponent_Properties[] = {
    { "Direction", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "Acceleration", 0x08, FIELD_TYPE_FLOAT, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "Speed", 0x0c, FIELD_TYPE_FLOAT, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "Speed2", 0x10, FIELD_TYPE_FLOAT, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_MovementComponent_Layout = {
    .componentName = "eoc::MovementComponent",
    .shortName = "Movement",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x14,
    .properties = g_MovementComponent_Properties,
    .propertyCount = sizeof(g_MovementComponent_Properties) / sizeof(g_MovementComponent_Properties[0]),
};

// eoc::ObjectInteractionComponent (from Data.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_ObjectInteractionComponent_Properties[] = {
    { "Interactions", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_ObjectInteractionComponent_Layout = {
    .componentName = "eoc::ObjectInteractionComponent",
    .shortName = "ObjectInteraction",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x08,
    .properties = g_ObjectInteractionComponent_Properties,
    .propertyCount = sizeof(g_ObjectInteractionComponent_Properties) / sizeof(g_ObjectInteractionComponent_Properties[0]),
};

// eoc::ObjectSizeComponent (from Data.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_ObjectSizeComponent_Properties[] = {
    { "Size", 0x00, FIELD_TYPE_INT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "SoundSize", 0x01, FIELD_TYPE_INT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_ObjectSizeComponent_Layout = {
    .componentName = "eoc::ObjectSizeComponent",
    .shortName = "ObjectSize",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x02,
    .properties = g_ObjectSizeComponent_Properties,
    .propertyCount = sizeof(g_ObjectSizeComponent_Properties) / sizeof(g_ObjectSizeComponent_Properties[0]),
};

// eoc::OriginAppearanceTagComponent (from Data.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_OriginAppearanceTagComponent_Properties[] = {
    { "Tags", 0x00, FIELD_TYPE_GUID, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_OriginAppearanceTagComponent_Layout = {
    .componentName = "eoc::OriginAppearanceTagComponent",
    .shortName = "OriginAppearanceTag",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x08,
    .properties = g_OriginAppearanceTagComponent_Properties,
    .propertyCount = sizeof(g_OriginAppearanceTagComponent_Properties) / sizeof(g_OriginAppearanceTagComponent_Properties[0]),
};

// eoc::OriginComponent (from Components.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_OriginComponent_Properties[] = {
    { "field_18", 0x00, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "Origin", 0x10, FIELD_TYPE_UINT32, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_OriginComponent_Layout = {
    .componentName = "eoc::OriginComponent",
    .shortName = "Origin",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x14,
    .properties = g_OriginComponent_Properties,
    .propertyCount = sizeof(g_OriginComponent_Properties) / sizeof(g_OriginComponent_Properties[0]),
};

// eoc::OriginPassivesComponent (from Data.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_OriginPassivesComponent_Properties[] = {
    { "Passives", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_OriginPassivesComponent_Layout = {
    .componentName = "eoc::OriginPassivesComponent",
    .shortName = "OriginPassives",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x08,
    .properties = g_OriginPassivesComponent_Properties,
    .propertyCount = sizeof(g_OriginPassivesComponent_Properties) / sizeof(g_OriginPassivesComponent_Properties[0]),
};

// eoc::OriginTagComponent (from Data.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_OriginTagComponent_Properties[] = {
    { "Tags", 0x00, FIELD_TYPE_GUID, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_OriginTagComponent_Layout = {
    .componentName = "eoc::OriginTagComponent",
    .shortName = "OriginTag",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x08,
    .properties = g_OriginTagComponent_Properties,
    .propertyCount = sizeof(g_OriginTagComponent_Properties) / sizeof(g_OriginTagComponent_Properties[0]),
};

// eoc::PassiveComponent (from Passives.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_PassiveComponent_Properties[] = {
    { "Type", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "PassiveId", 0x08, FIELD_TYPE_UINT32, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "Source", 0x10, FIELD_TYPE_UINT64, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "Item", 0x18, FIELD_TYPE_UINT64, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "ToggledOn", 0x20, FIELD_TYPE_BOOL, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "Disabled", 0x21, FIELD_TYPE_BOOL, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_1C", 0x24, FIELD_TYPE_UINT32, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_PassiveComponent_Layout = {
    .componentName = "eoc::PassiveComponent",
    .shortName = "Passive",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x28,
    .properties = g_PassiveComponent_Properties,
    .propertyCount = sizeof(g_PassiveComponent_Properties) / sizeof(g_PassiveComponent_Properties[0]),
};

// eoc::PassiveContainerComponent (from Passives.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_PassiveContainerComponent_Properties[] = {
    { "Passives", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_PassiveContainerComponent_Layout = {
    .componentName = "eoc::PassiveContainerComponent",
    .shortName = "PassiveContainer",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x08,
    .properties = g_PassiveContainerComponent_Properties,
    .propertyCount = sizeof(g_PassiveContainerComponent_Properties) / sizeof(g_PassiveContainerComponent_Properties[0]),
};

// eoc::PathingComponent (from Runtime.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_PathingComponent_Properties[] = {
    { "VectorParameters", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "PathParameters", 0x08, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_20", 0x10, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "MovementTiltToRemap", 0x18, FIELD_TYPE_UINT32, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_30", 0x20, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_38", 0x28, FIELD_TYPE_INT32, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "PathId", 0x2c, FIELD_TYPE_INT32, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "Flags", 0x30, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "PathMovementSpeed", 0x34, FIELD_TYPE_FLOAT, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_48", 0x38, FIELD_TYPE_INT32, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "ServerControl", 0x3c, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_PathingComponent_Layout = {
    .componentName = "eoc::PathingComponent",
    .shortName = "Pathing",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x3d,
    .properties = g_PathingComponent_Properties,
    .propertyCount = sizeof(g_PathingComponent_Properties) / sizeof(g_PathingComponent_Properties[0]),
};

// eoc::RaceComponent (from Data.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_RaceComponent_Properties[] = {
    { "Race", 0x00, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_RaceComponent_Layout = {
    .componentName = "eoc::RaceComponent",
    .shortName = "Race",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x10,
    .properties = g_RaceComponent_Properties,
    .propertyCount = sizeof(g_RaceComponent_Properties) / sizeof(g_RaceComponent_Properties[0]),
};

// eoc::RequestedRollComponent (from Roll.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_RequestedRollComponent_Properties[] = {
    { "RollEntity", 0x00, FIELD_TYPE_UINT64, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "RollUuid", 0x08, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "RollComponentType", 0x18, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "RollType", 0x19, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "Roller", 0x20, FIELD_TYPE_UINT64, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "StatsExpression", 0x28, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "AdvantageType", 0x30, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "DC", 0x38, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "NaturalRoll", 0x39, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "DiscardedDiceTotal", 0x3a, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "DiceAdditionalValue", 0x3b, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "AdditionalValue", 0x3c, FIELD_TYPE_INT32, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "SpellCheck", 0x40, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "Finished", 0x41, FIELD_TYPE_BOOL, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "Canceled", 0x42, FIELD_TYPE_BOOL, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_4F", 0x43, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "PassiveRollDelay", 0x44, FIELD_TYPE_FLOAT, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "RollContext", 0x48, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "FromScript", 0x49, FIELD_TYPE_BOOL, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "DialogId", 0x4c, FIELD_TYPE_INT32, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "Subject", 0x50, FIELD_TYPE_UINT64, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "ResolvedRollBonuses", 0x58, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "FixedRollBonuses", 0x60, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "RolledComponentType0", 0x68, FIELD_TYPE_BOOL, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_89", 0x69, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_8A", 0x6a, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "ExcludedBonusesTags", 0x70, FIELD_TYPE_GUID, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "Ability", 0x78, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "Skill", 0x80, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "ConsumedInspirationPoint", 0x88, FIELD_TYPE_BOOL, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "Roll", 0x90, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "Result", 0x98, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "Metadata", 0xa0, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_1B0", 0xa8, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "RollDelayRemaining", 0xb0, FIELD_TYPE_FLOAT, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "RequestStop", 0xb4, FIELD_TYPE_BOOL, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "EntityUuid", 0xb8, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "Entity2Uuid", 0xc8, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_RequestedRollComponent_Layout = {
    .componentName = "eoc::RequestedRollComponent",
    .shortName = "RequestedRoll",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0xd8,
    .properties = g_RequestedRollComponent_Properties,
    .propertyCount = sizeof(g_RequestedRollComponent_Properties) / sizeof(g_RequestedRollComponent_Properties[0]),
};

// eoc::ResistancesComponent (from Stats.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_ResistancesComponent_Properties[] = {
    { "Resistances", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_E", 0x08, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "AC", 0x0c, FIELD_TYPE_INT32, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "PerDamageTypeHealthThresholds", 0x10, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "PerDamageTypeHealthThresholds2", 0x18, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_ResistancesComponent_Layout = {
    .componentName = "eoc::ResistancesComponent",
    .shortName = "Resistances",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x20,
    .properties = g_ResistancesComponent_Properties,
    .propertyCount = sizeof(g_ResistancesComponent_Properties) / sizeof(g_ResistancesComponent_Properties[0]),
};

// eoc::SpeakerComponent (from Components.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_SpeakerComponent_Properties[] = {
    { "field_0", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_SpeakerComponent_Layout = {
    .componentName = "eoc::SpeakerComponent",
    .shortName = "Speaker",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x08,
    .properties = g_SpeakerComponent_Properties,
    .propertyCount = sizeof(g_SpeakerComponent_Properties) / sizeof(g_SpeakerComponent_Properties[0]),
};

// eoc::StatsComponent (from Stats.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_StatsComponent_Properties[] = {
    { "InitiativeBonus", 0x00, FIELD_TYPE_INT32, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "Abilities", 0x08, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "AbilityModifiers", 0x10, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "Skills", 0x18, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "ProficiencyBonus", 0x20, FIELD_TYPE_INT32, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "SpellCastingAbility", 0x24, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_8C", 0x28, FIELD_TYPE_INT32, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_90", 0x2c, FIELD_TYPE_INT32, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "ArmorType", 0x30, FIELD_TYPE_INT32, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "ArmorType2", 0x34, FIELD_TYPE_INT32, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "UnarmedAttackAbility", 0x38, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "RangedAttackAbility", 0x39, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_StatsComponent_Layout = {
    .componentName = "eoc::StatsComponent",
    .shortName = "Stats",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x3a,
    .properties = g_StatsComponent_Properties,
    .propertyCount = sizeof(g_StatsComponent_Properties) / sizeof(g_StatsComponent_Properties[0]),
};

// eoc::StealthComponent (from Data.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_StealthComponent_Properties[] = {
    { "SeekHiddenFlag", 0x00, FIELD_TYPE_BOOL, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "Position", 0x08, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "SeekHiddenTimeout", 0x10, FIELD_TYPE_FLOAT, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_14", 0x14, FIELD_TYPE_FLOAT, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_18", 0x18, FIELD_TYPE_INT32, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_1C", 0x1c, FIELD_TYPE_FLOAT, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_20", 0x20, FIELD_TYPE_FLOAT, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_StealthComponent_Layout = {
    .componentName = "eoc::StealthComponent",
    .shortName = "Stealth",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x24,
    .properties = g_StealthComponent_Properties,
    .propertyCount = sizeof(g_StealthComponent_Properties) / sizeof(g_StealthComponent_Properties[0]),
};

// eoc::SteeringComponent (from Runtime.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_SteeringComponent_Properties[] = {
    { "field_0", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "TargetRotation", 0x08, FIELD_TYPE_FLOAT, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "Speed", 0x0c, FIELD_TYPE_FLOAT, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "RequestSteering", 0x10, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_18", 0x14, FIELD_TYPE_FLOAT, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_1C", 0x18, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_SteeringComponent_Layout = {
    .componentName = "eoc::SteeringComponent",
    .shortName = "Steering",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x19,
    .properties = g_SteeringComponent_Properties,
    .propertyCount = sizeof(g_SteeringComponent_Properties) / sizeof(g_SteeringComponent_Properties[0]),
};

// eoc::SurfacePathInfluencesComponent (from Components.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_SurfacePathInfluencesComponent_Properties[] = {
    { "PathInfluences", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_SurfacePathInfluencesComponent_Layout = {
    .componentName = "eoc::SurfacePathInfluencesComponent",
    .shortName = "SurfacePathInfluences",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x08,
    .properties = g_SurfacePathInfluencesComponent_Properties,
    .propertyCount = sizeof(g_SurfacePathInfluencesComponent_Properties) / sizeof(g_SurfacePathInfluencesComponent_Properties[0]),
};

// eoc::TagComponent (from Components.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_TagComponent_Properties[] = {
    { "Tags", 0x00, FIELD_TYPE_GUID, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_TagComponent_Layout = {
    .componentName = "eoc::TagComponent",
    .shortName = "Tag",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x08,
    .properties = g_TagComponent_Properties,
    .propertyCount = sizeof(g_TagComponent_Properties) / sizeof(g_TagComponent_Properties[0]),
};

// eoc::TimelineActorDataComponent (from Timeline.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_TimelineActorDataComponent_Properties[] = {
    { "field_0", 0x00, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_10", 0x10, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_20", 0x20, FIELD_TYPE_UINT16, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_22", 0x22, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_23", 0x23, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_TimelineActorDataComponent_Layout = {
    .componentName = "eoc::TimelineActorDataComponent",
    .shortName = "TimelineActorData",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x24,
    .properties = g_TimelineActorDataComponent_Properties,
    .propertyCount = sizeof(g_TimelineActorDataComponent_Properties) / sizeof(g_TimelineActorDataComponent_Properties[0]),
};

// eoc::TurnBasedComponent (from Combat.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_TurnBasedComponent_Properties[] = {
    { "IsActiveCombatTurn", 0x00, FIELD_TYPE_BOOL, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "Removed", 0x01, FIELD_TYPE_BOOL, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "RequestedEndTurn", 0x02, FIELD_TYPE_BOOL, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "TurnActionsCompleted", 0x03, FIELD_TYPE_BOOL, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "ActedThisRoundInCombat", 0x04, FIELD_TYPE_BOOL, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "HadTurnInCombat", 0x05, FIELD_TYPE_BOOL, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "CanActInCombat", 0x06, FIELD_TYPE_BOOL, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "Timeout", 0x08, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "PauseTimer", 0x10, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "EndTurnHoldTimer", 0x18, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "CombatTeam", 0x20, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_TurnBasedComponent_Layout = {
    .componentName = "eoc::TurnBasedComponent",
    .shortName = "TurnBased",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x30,
    .properties = g_TurnBasedComponent_Properties,
    .propertyCount = sizeof(g_TurnBasedComponent_Properties) / sizeof(g_TurnBasedComponent_Properties[0]),
};

// eoc::TurnOrderComponent (from Combat.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_TurnOrderComponent_Properties[] = {
    { "TurnOrderIndices", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "Groups", 0x08, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "TurnOrderIndices2", 0x10, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "Groups2", 0x18, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_40", 0x20, FIELD_TYPE_INT32, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_44", 0x24, FIELD_TYPE_INT32, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_48", 0x28, FIELD_TYPE_INT32, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_4C", 0x2c, FIELD_TYPE_FLOAT, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_TurnOrderComponent_Layout = {
    .componentName = "eoc::TurnOrderComponent",
    .shortName = "TurnOrder",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x30,
    .properties = g_TurnOrderComponent_Properties,
    .propertyCount = sizeof(g_TurnOrderComponent_Properties) / sizeof(g_TurnOrderComponent_Properties[0]),
};

// eoc::UseBoostsComponent (from Boosts.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_UseBoostsComponent_Properties[] = {
    { "Boosts", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_UseBoostsComponent_Layout = {
    .componentName = "eoc::UseBoostsComponent",
    .shortName = "UseBoosts",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x08,
    .properties = g_UseBoostsComponent_Properties,
    .propertyCount = sizeof(g_UseBoostsComponent_Properties) / sizeof(g_UseBoostsComponent_Properties[0]),
};

// eoc::UseComponent (from Stats.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_UseComponent_Properties[] = {
    { "Requirements", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "Charges", 0x08, FIELD_TYPE_INT32, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "MaxCharges", 0x0c, FIELD_TYPE_INT32, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "ItemUseType", 0x10, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "ItemUseBlocked", 0x11, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "CanCombine", 0x12, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "CombineFlag", 0x13, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "Boosts", 0x18, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "BoostsOnEquipMainHand", 0x20, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "BoostsOnEquipOffHand", 0x28, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_UseComponent_Layout = {
    .componentName = "eoc::UseComponent",
    .shortName = "Use",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x30,
    .properties = g_UseComponent_Properties,
    .propertyCount = sizeof(g_UseComponent_Properties) / sizeof(g_UseComponent_Properties[0]),
};

// eoc::ValueComponent (from Stats.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_ValueComponent_Properties[] = {
    { "Value", 0x00, FIELD_TYPE_INT32, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "Rarity", 0x04, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "Unique", 0x05, FIELD_TYPE_BOOL, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_ValueComponent_Layout = {
    .componentName = "eoc::ValueComponent",
    .shortName = "Value",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x06,
    .properties = g_ValueComponent_Properties,
    .propertyCount = sizeof(g_ValueComponent_Properties) / sizeof(g_ValueComponent_Properties[0]),
};

// eoc::VoiceComponent (from Data.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_VoiceComponent_Properties[] = {
    { "Voice", 0x00, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_VoiceComponent_Layout = {
    .componentName = "eoc::VoiceComponent",
    .shortName = "Voice",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x10,
    .properties = g_VoiceComponent_Properties,
    .propertyCount = sizeof(g_VoiceComponent_Properties) / sizeof(g_VoiceComponent_Properties[0]),
};

// eoc::VoiceTagComponent (from Data.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_VoiceTagComponent_Properties[] = {
    { "Tags", 0x00, FIELD_TYPE_GUID, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_VoiceTagComponent_Layout = {
    .componentName = "eoc::VoiceTagComponent",
    .shortName = "VoiceTag",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x08,
    .properties = g_VoiceTagComponent_Properties,
    .propertyCount = sizeof(g_VoiceTagComponent_Properties) / sizeof(g_VoiceTagComponent_Properties[0]),
};

// eoc::WeaponComponent (from Stats.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_WeaponComponent_Properties[] = {
    { "WeaponRange", 0x00, FIELD_TYPE_FLOAT, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "DamageRange", 0x04, FIELD_TYPE_FLOAT, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "WeaponProperties", 0x08, FIELD_TYPE_UINT32, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "WeaponGroup", 0x0c, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "Ability", 0x0d, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "DamageValues", 0x10, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "DamageDice", 0x18, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "VersatileDamageDice", 0x19, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_WeaponComponent_Layout = {
    .componentName = "eoc::WeaponComponent",
    .shortName = "Weapon",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x1a,
    .properties = g_WeaponComponent_Properties,
    .propertyCount = sizeof(g_WeaponComponent_Properties) / sizeof(g_WeaponComponent_Properties[0]),
};

// eoc::WeaponSetComponent (from Components.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_WeaponSetComponent_Properties[] = {
    { "WeaponSet", 0x00, FIELD_TYPE_INT32, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_WeaponSetComponent_Layout = {
    .componentName = "eoc::WeaponSetComponent",
    .shortName = "WeaponSet",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x04,
    .properties = g_WeaponSetComponent_Properties,
    .propertyCount = sizeof(g_WeaponSetComponent_Properties) / sizeof(g_WeaponSetComponent_Properties[0]),
};

// eoc::WieldingComponent (from Components.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_WieldingComponent_Properties[] = {
    { "Owner", 0x00, FIELD_TYPE_UINT64, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_WieldingComponent_Layout = {
    .componentName = "eoc::WieldingComponent",
    .shortName = "Wielding",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x08,
    .properties = g_WieldingComponent_Properties,
    .propertyCount = sizeof(g_WieldingComponent_Properties) / sizeof(g_WieldingComponent_Properties[0]),
};

// eoc::action::ActionUseConditionsComponent (from Data.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_ActionUseConditionsComponent_Properties[] = {
    { "Conditions", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_ActionUseConditionsComponent_Layout = {
    .componentName = "eoc::action::ActionUseConditionsComponent",
    .shortName = "ActionUseConditions",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x08,
    .properties = g_ActionUseConditionsComponent_Properties,
    .propertyCount = sizeof(g_ActionUseConditionsComponent_Properties) / sizeof(g_ActionUseConditionsComponent_Properties[0]),
};

// eoc::active_roll::ModifiersComponent (from Roll.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_RollModifiersComponent_Properties[] = {
    { "Entity", 0x00, FIELD_TYPE_UINT64, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "DynamicModifiers", 0x08, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_18", 0x10, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_19", 0x11, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "StaticModifiers", 0x18, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "DynamicModifiers2", 0x20, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "ConsumableModifiers", 0x28, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "ItemSpellModifiers", 0x30, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "SpellModifiers", 0x38, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "ToggledPassiveModifiers", 0x40, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "DynamicModifiers3", 0x48, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_RollModifiersComponent_Layout = {
    .componentName = "eoc::active_roll::ModifiersComponent",
    .shortName = "RollModifiers",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x50,
    .properties = g_RollModifiersComponent_Properties,
    .propertyCount = sizeof(g_RollModifiersComponent_Properties) / sizeof(g_RollModifiersComponent_Properties[0]),
};

// eoc::approval::RatingsComponent (from Data.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_ApprovalRatingsComponent_Properties[] = {
    { "Ratings", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_70", 0x08, FIELD_TYPE_GUID, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_ApprovalRatingsComponent_Layout = {
    .componentName = "eoc::approval::RatingsComponent",
    .shortName = "ApprovalRatings",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x10,
    .properties = g_ApprovalRatingsComponent_Properties,
    .propertyCount = sizeof(g_ApprovalRatingsComponent_Properties) / sizeof(g_ApprovalRatingsComponent_Properties[0]),
};

// eoc::armor_set::StateComponent (from Stats.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_ArmorSetStateComponent_Properties[] = {
    { "State", 0x00, FIELD_TYPE_INT32, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_ArmorSetStateComponent_Layout = {
    .componentName = "eoc::armor_set::StateComponent",
    .shortName = "ArmorSetState",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x04,
    .properties = g_ArmorSetStateComponent_Properties,
    .propertyCount = sizeof(g_ArmorSetStateComponent_Properties) / sizeof(g_ArmorSetStateComponent_Properties[0]),
};

// eoc::attitude::AttitudesToPlayersComponent (from Data.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_AttitudesToPlayersComponent_Properties[] = {
    { "Attitudes", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_AttitudesToPlayersComponent_Layout = {
    .componentName = "eoc::attitude::AttitudesToPlayersComponent",
    .shortName = "AttitudesToPlayers",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x08,
    .properties = g_AttitudesToPlayersComponent_Properties,
    .propertyCount = sizeof(g_AttitudesToPlayersComponent_Properties) / sizeof(g_AttitudesToPlayersComponent_Properties[0]),
};

// eoc::calendar::DaysPassedComponent (from Data.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_CalendarDaysPassedComponent_Properties[] = {
    { "Days", 0x00, FIELD_TYPE_INT32, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_CalendarDaysPassedComponent_Layout = {
    .componentName = "eoc::calendar::DaysPassedComponent",
    .shortName = "CalendarDaysPassed",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x04,
    .properties = g_CalendarDaysPassedComponent_Properties,
    .propertyCount = sizeof(g_CalendarDaysPassedComponent_Properties) / sizeof(g_CalendarDaysPassedComponent_Properties[0]),
};

// eoc::calendar::StartingDateComponent (from Data.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_CalendarStartingDateComponent_Properties[] = {
    { "Day", 0x00, FIELD_TYPE_INT32, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "Year", 0x04, FIELD_TYPE_INT32, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_CalendarStartingDateComponent_Layout = {
    .componentName = "eoc::calendar::StartingDateComponent",
    .shortName = "CalendarStartingDate",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x08,
    .properties = g_CalendarStartingDateComponent_Properties,
    .propertyCount = sizeof(g_CalendarStartingDateComponent_Properties) / sizeof(g_CalendarStartingDateComponent_Properties[0]),
};

// eoc::camp::ChestComponent (from Camp.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_CampChestComponent_Properties[] = {
    { "field_0", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "UserID", 0x08, FIELD_TYPE_INT32, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_1C", 0x0c, FIELD_TYPE_UINT32, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_20", 0x10, FIELD_TYPE_UINT64, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_28", 0x18, FIELD_TYPE_INT32, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_CampChestComponent_Layout = {
    .componentName = "eoc::camp::ChestComponent",
    .shortName = "CampChest",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x1c,
    .properties = g_CampChestComponent_Properties,
    .propertyCount = sizeof(g_CampChestComponent_Properties) / sizeof(g_CampChestComponent_Properties[0]),
};

// eoc::camp::EndTheDayStateComponent (from Camp.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_CampEndTheDayStateComponent_Properties[] = {
    { "State", 0x00, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_8", 0x08, FIELD_TYPE_UINT64, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_CampEndTheDayStateComponent_Layout = {
    .componentName = "eoc::camp::EndTheDayStateComponent",
    .shortName = "CampEndTheDayState",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x10,
    .properties = g_CampEndTheDayStateComponent_Properties,
    .propertyCount = sizeof(g_CampEndTheDayStateComponent_Properties) / sizeof(g_CampEndTheDayStateComponent_Properties[0]),
};

// eoc::camp::QualityComponent (from Camp.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_CampQualityComponent_Properties[] = {
    { "field_0", 0x00, FIELD_TYPE_INT32, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_4", 0x04, FIELD_TYPE_INT32, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_CampQualityComponent_Layout = {
    .componentName = "eoc::camp::QualityComponent",
    .shortName = "CampQuality",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x08,
    .properties = g_CampQualityComponent_Properties,
    .propertyCount = sizeof(g_CampQualityComponent_Properties) / sizeof(g_CampQualityComponent_Properties[0]),
};

// eoc::camp::SettingsComponent (from Camp.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_CampSettingsComponent_Properties[] = {
    { "field_0", 0x00, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_1", 0x01, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_4", 0x04, FIELD_TYPE_INT32, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_CampSettingsComponent_Layout = {
    .componentName = "eoc::camp::SettingsComponent",
    .shortName = "CampSettings",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x08,
    .properties = g_CampSettingsComponent_Properties,
    .propertyCount = sizeof(g_CampSettingsComponent_Properties) / sizeof(g_CampSettingsComponent_Properties[0]),
};

// eoc::camp::SupplyComponent (from Camp.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_CampSupplyComponent_Properties[] = {
    { "Amount", 0x00, FIELD_TYPE_INT32, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_CampSupplyComponent_Layout = {
    .componentName = "eoc::camp::SupplyComponent",
    .shortName = "CampSupply",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x04,
    .properties = g_CampSupplyComponent_Properties,
    .propertyCount = sizeof(g_CampSupplyComponent_Properties) / sizeof(g_CampSupplyComponent_Properties[0]),
};

// eoc::camp::TotalSuppliesComponent (from Camp.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_CampTotalSuppliesComponent_Properties[] = {
    { "Amount", 0x00, FIELD_TYPE_INT32, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_CampTotalSuppliesComponent_Layout = {
    .componentName = "eoc::camp::TotalSuppliesComponent",
    .shortName = "CampTotalSupplies",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x04,
    .properties = g_CampTotalSuppliesComponent_Properties,
    .propertyCount = sizeof(g_CampTotalSuppliesComponent_Properties) / sizeof(g_CampTotalSuppliesComponent_Properties[0]),
};

// eoc::character::EquipmentVisualComponent (from Components.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_EquipmentVisualComponent_Properties[] = {
    { "State", 0x00, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_EquipmentVisualComponent_Layout = {
    .componentName = "eoc::character::EquipmentVisualComponent",
    .shortName = "EquipmentVisual",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x01,
    .properties = g_EquipmentVisualComponent_Properties,
    .propertyCount = sizeof(g_EquipmentVisualComponent_Properties) / sizeof(g_EquipmentVisualComponent_Properties[0]),
};

// eoc::character_creation::AppearanceComponent (from Visual.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_CharacterCreationAppearanceComponent_Properties[] = {
    { "Visuals", 0x00, FIELD_TYPE_GUID, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "Elements", 0x08, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "AdditionalChoices", 0x10, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "SkinColor", 0x18, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "EyeColor", 0x28, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "SecondEyeColor", 0x38, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "HairColor", 0x48, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_CharacterCreationAppearanceComponent_Layout = {
    .componentName = "eoc::character_creation::AppearanceComponent",
    .shortName = "CharacterCreationAppearance",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x58,
    .properties = g_CharacterCreationAppearanceComponent_Properties,
    .propertyCount = sizeof(g_CharacterCreationAppearanceComponent_Properties) / sizeof(g_CharacterCreationAppearanceComponent_Properties[0]),
};

// eoc::character_creation::ChangeAppearanceDefinitionComponent (from CharacterCreation.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_CCChangeAppearanceDefinitionComponent_Properties[] = {
    { "Definition", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "Appearance", 0x08, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_2E0", 0x10, FIELD_TYPE_INT32, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_2E4", 0x14, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_2E8", 0x18, FIELD_TYPE_UINT64, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_CCChangeAppearanceDefinitionComponent_Layout = {
    .componentName = "eoc::character_creation::ChangeAppearanceDefinitionComponent",
    .shortName = "CCChangeAppearanceDefinition",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x20,
    .properties = g_CCChangeAppearanceDefinitionComponent_Properties,
    .propertyCount = sizeof(g_CCChangeAppearanceDefinitionComponent_Properties) / sizeof(g_CCChangeAppearanceDefinitionComponent_Properties[0]),
};

// eoc::character_creation::CharacterDefinitionComponent (from CharacterCreation.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_CCCharacterDefinitionComponent_Properties[] = {
    { "Definition", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_288", 0x08, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "ChangeId", 0x0c, FIELD_TYPE_INT32, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "NeedsSync", 0x10, FIELD_TYPE_BOOL, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_CCCharacterDefinitionComponent_Layout = {
    .componentName = "eoc::character_creation::CharacterDefinitionComponent",
    .shortName = "CCCharacterDefinition",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x11,
    .properties = g_CCCharacterDefinitionComponent_Properties,
    .propertyCount = sizeof(g_CCCharacterDefinitionComponent_Properties) / sizeof(g_CCCharacterDefinitionComponent_Properties[0]),
};

// eoc::character_creation::CompanionDefinitionComponent (from CharacterCreation.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_CCCompanionDefinitionComponent_Properties[] = {
    { "field_0", 0x00, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_10", 0x10, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_20", 0x20, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_21", 0x21, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_28", 0x28, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "Visual", 0x38, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_110", 0x40, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_120", 0x50, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_130", 0x60, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "IconVersion", 0x64, FIELD_TYPE_UINT32, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "HasIcon", 0x68, FIELD_TYPE_BOOL, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_CCCompanionDefinitionComponent_Layout = {
    .componentName = "eoc::character_creation::CompanionDefinitionComponent",
    .shortName = "CCCompanionDefinition",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x69,
    .properties = g_CCCompanionDefinitionComponent_Properties,
    .propertyCount = sizeof(g_CCCompanionDefinitionComponent_Properties) / sizeof(g_CCCompanionDefinitionComponent_Properties[0]),
};

// eoc::character_creation::DefinitionCommonComponent (from CharacterCreation.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_CCDefinitionCommonComponent_Properties[] = {
    { "ChangeId", 0x00, FIELD_TYPE_INT32, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_8", 0x08, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "Error", 0x10, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_CCDefinitionCommonComponent_Layout = {
    .componentName = "eoc::character_creation::DefinitionCommonComponent",
    .shortName = "CCDefinitionCommon",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x18,
    .properties = g_CCDefinitionCommonComponent_Properties,
    .propertyCount = sizeof(g_CCDefinitionCommonComponent_Properties) / sizeof(g_CCDefinitionCommonComponent_Properties[0]),
};

// eoc::character_creation::FullRespecDefinitionComponent (from CharacterCreation.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_CCFullRespecDefinitionComponent_Properties[] = {
    { "Definition", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_1C0", 0x08, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_1D0", 0x18, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_1E0", 0x28, FIELD_TYPE_INT32, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "LevelUpUpgrades", 0x30, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "Spells", 0x38, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_268", 0x40, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_CCFullRespecDefinitionComponent_Layout = {
    .componentName = "eoc::character_creation::FullRespecDefinitionComponent",
    .shortName = "CCFullRespecDefinition",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x41,
    .properties = g_CCFullRespecDefinitionComponent_Properties,
    .propertyCount = sizeof(g_CCFullRespecDefinitionComponent_Properties) / sizeof(g_CCFullRespecDefinitionComponent_Properties[0]),
};

// eoc::character_creation::LevelUpComponent (from CharacterCreation.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_CCLevelUpComponent_Properties[] = {
    { "LevelUps", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_CCLevelUpComponent_Layout = {
    .componentName = "eoc::character_creation::LevelUpComponent",
    .shortName = "CCLevelUp",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x08,
    .properties = g_CCLevelUpComponent_Properties,
    .propertyCount = sizeof(g_CCLevelUpComponent_Properties) / sizeof(g_CCLevelUpComponent_Properties[0]),
};

// eoc::character_creation::LevelUpDefinitionComponent (from CharacterCreation.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_CCLevelUpDefinitionComponent_Properties[] = {
    { "Definition", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "LevelUp", 0x08, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_160", 0x10, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "ChangeId", 0x14, FIELD_TYPE_INT32, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "NeedsSync", 0x18, FIELD_TYPE_BOOL, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_16C", 0x1c, FIELD_TYPE_INT32, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "Character", 0x20, FIELD_TYPE_UINT64, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_CCLevelUpDefinitionComponent_Layout = {
    .componentName = "eoc::character_creation::LevelUpDefinitionComponent",
    .shortName = "CCLevelUpDefinition",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x28,
    .properties = g_CCLevelUpDefinitionComponent_Properties,
    .propertyCount = sizeof(g_CCLevelUpDefinitionComponent_Properties) / sizeof(g_CCLevelUpDefinitionComponent_Properties[0]),
};

// eoc::character_creation::RespecDefinitionComponent (from CharacterCreation.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_CCRespecDefinitionComponent_Properties[] = {
    { "field_0", 0x00, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "Definition", 0x10, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_298", 0x18, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_CCRespecDefinitionComponent_Layout = {
    .componentName = "eoc::character_creation::RespecDefinitionComponent",
    .shortName = "CCRespecDefinition",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x19,
    .properties = g_CCRespecDefinitionComponent_Properties,
    .propertyCount = sizeof(g_CCRespecDefinitionComponent_Properties) / sizeof(g_CCRespecDefinitionComponent_Properties[0]),
};

// eoc::character_creation::SessionCommonComponent (from CharacterCreation.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_CCSessionCommonComponent_Properties[] = {
    { "NetId", 0x00, FIELD_TYPE_INT32, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_4", 0x04, FIELD_TYPE_INT32, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_8", 0x08, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_CCSessionCommonComponent_Layout = {
    .componentName = "eoc::character_creation::SessionCommonComponent",
    .shortName = "CCSessionCommon",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x09,
    .properties = g_CCSessionCommonComponent_Properties,
    .propertyCount = sizeof(g_CCSessionCommonComponent_Properties) / sizeof(g_CCSessionCommonComponent_Properties[0]),
};

// eoc::character_creation::StateComponent (from CharacterCreation.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_CCStateComponent_Properties[] = {
    { "HasDummy", 0x00, FIELD_TYPE_BOOL, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "Canceled", 0x01, FIELD_TYPE_BOOL, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_2", 0x02, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_CCStateComponent_Layout = {
    .componentName = "eoc::character_creation::StateComponent",
    .shortName = "CCState",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x03,
    .properties = g_CCStateComponent_Properties,
    .propertyCount = sizeof(g_CCStateComponent_Properties) / sizeof(g_CCStateComponent_Properties[0]),
};

// eoc::character_creation::definition::CreationComponent (from CharacterCreation.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_CCCreationComponent_Properties[] = {
    { "field_0", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_10", 0x08, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_CCCreationComponent_Layout = {
    .componentName = "eoc::character_creation::definition::CreationComponent",
    .shortName = "CCCreation",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x09,
    .properties = g_CCCreationComponent_Properties,
    .propertyCount = sizeof(g_CCCreationComponent_Properties) / sizeof(g_CCCreationComponent_Properties[0]),
};

// eoc::character_creation::definition::FullRespecComponent (from CharacterCreation.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_CCFullRespecComponent_Properties[] = {
    { "Character", 0x00, FIELD_TYPE_UINT64, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "Respec", 0x08, FIELD_TYPE_UINT64, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_CCFullRespecComponent_Layout = {
    .componentName = "eoc::character_creation::definition::FullRespecComponent",
    .shortName = "CCFullRespec",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x10,
    .properties = g_CCFullRespecComponent_Properties,
    .propertyCount = sizeof(g_CCFullRespecComponent_Properties) / sizeof(g_CCFullRespecComponent_Properties[0]),
};

// eoc::character_creation::definition::LevelUpComponent (from CharacterCreation.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_CCDefinitionLevelUpComponent_Properties[] = {
    { "field_0", 0x00, FIELD_TYPE_UINT64, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_8", 0x08, FIELD_TYPE_UINT64, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_10", 0x10, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_CCDefinitionLevelUpComponent_Layout = {
    .componentName = "eoc::character_creation::definition::LevelUpComponent",
    .shortName = "CCDefinitionLevelUp",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x11,
    .properties = g_CCDefinitionLevelUpComponent_Properties,
    .propertyCount = sizeof(g_CCDefinitionLevelUpComponent_Properties) / sizeof(g_CCDefinitionLevelUpComponent_Properties[0]),
};

// eoc::character_creation::definition::RespecComponent (from CharacterCreation.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_CCRespecComponent_Properties[] = {
    { "Character", 0x00, FIELD_TYPE_UINT64, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "Respec", 0x08, FIELD_TYPE_UINT64, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_CCRespecComponent_Layout = {
    .componentName = "eoc::character_creation::definition::RespecComponent",
    .shortName = "CCRespec",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x10,
    .properties = g_CCRespecComponent_Properties,
    .propertyCount = sizeof(g_CCRespecComponent_Properties) / sizeof(g_CCRespecComponent_Properties[0]),
};

// eoc::chasm::CanEnterChasmComponent (from Components.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_CanEnterChasmComponent_Properties[] = {
    { "CanEnter", 0x00, FIELD_TYPE_BOOL, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_CanEnterChasmComponent_Layout = {
    .componentName = "eoc::chasm::CanEnterChasmComponent",
    .shortName = "CanEnterChasm",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x01,
    .properties = g_CanEnterChasmComponent_Properties,
    .propertyCount = sizeof(g_CanEnterChasmComponent_Properties) / sizeof(g_CanEnterChasmComponent_Properties[0]),
};

// eoc::combat::IsCombatPausedComponent (from Combat.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_IsCombatPausedComponent_Properties[] = {
    { "PauseSourceTypes", 0x00, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_IsCombatPausedComponent_Layout = {
    .componentName = "eoc::combat::IsCombatPausedComponent",
    .shortName = "IsCombatPaused",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x01,
    .properties = g_IsCombatPausedComponent_Properties,
    .propertyCount = sizeof(g_IsCombatPausedComponent_Properties) / sizeof(g_IsCombatPausedComponent_Properties[0]),
};

// eoc::combat::IsThreatenedComponent (from Combat.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_CombatIsThreatenedComponent_Properties[] = {
    { "ThreatenedBy", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_CombatIsThreatenedComponent_Layout = {
    .componentName = "eoc::combat::IsThreatenedComponent",
    .shortName = "CombatIsThreatened",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x08,
    .properties = g_CombatIsThreatenedComponent_Properties,
    .propertyCount = sizeof(g_CombatIsThreatenedComponent_Properties) / sizeof(g_CombatIsThreatenedComponent_Properties[0]),
};

// eoc::combat::ParticipantComponent (from Combat.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_CombatParticipantComponent_Properties[] = {
    { "CombatHandle", 0x00, FIELD_TYPE_UINT64, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "CombatGroupId", 0x08, FIELD_TYPE_UINT32, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "InitiativeRoll", 0x0c, FIELD_TYPE_INT32, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "Flags", 0x10, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "AiHint", 0x18, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_CombatParticipantComponent_Layout = {
    .componentName = "eoc::combat::ParticipantComponent",
    .shortName = "CombatParticipant",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x28,
    .properties = g_CombatParticipantComponent_Properties,
    .propertyCount = sizeof(g_CombatParticipantComponent_Properties) / sizeof(g_CombatParticipantComponent_Properties[0]),
};

// eoc::combat::StateComponent (from Combat.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_CombatStateComponent_Properties[] = {
    { "MyGuid", 0x00, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "Initiatives", 0x10, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "Participants", 0x18, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_98", 0x20, FIELD_TYPE_UINT64, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_A0", 0x28, FIELD_TYPE_UINT64, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "Level", 0x30, FIELD_TYPE_UINT32, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_AC", 0x34, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "IsInNarrativeCombat", 0x35, FIELD_TYPE_BOOL, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_B0", 0x38, FIELD_TYPE_FLOAT, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_B8", 0x40, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_D0", 0x48, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_CombatStateComponent_Layout = {
    .componentName = "eoc::combat::StateComponent",
    .shortName = "CombatState",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x49,
    .properties = g_CombatStateComponent_Properties,
    .propertyCount = sizeof(g_CombatStateComponent_Properties) / sizeof(g_CombatStateComponent_Properties[0]),
};

// eoc::combat::ThreatRangeComponent (from Combat.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_ThreatRangeComponent_Properties[] = {
    { "Range", 0x00, FIELD_TYPE_FLOAT, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "TargetCeiling", 0x04, FIELD_TYPE_FLOAT, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "TargetFloor", 0x08, FIELD_TYPE_FLOAT, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_ThreatRangeComponent_Layout = {
    .componentName = "eoc::combat::ThreatRangeComponent",
    .shortName = "ThreatRange",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x0c,
    .properties = g_ThreatRangeComponent_Properties,
    .propertyCount = sizeof(g_ThreatRangeComponent_Properties) / sizeof(g_ThreatRangeComponent_Properties[0]),
};

// eoc::concentration::ConcentrationComponent (from Data.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_ConcentrationComponent_Properties[] = {
    { "Caster", 0x00, FIELD_TYPE_UINT64, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "Targets", 0x08, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "SpellId", 0x10, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_ConcentrationComponent_Layout = {
    .componentName = "eoc::concentration::ConcentrationComponent",
    .shortName = "Concentration",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x18,
    .properties = g_ConcentrationComponent_Properties,
    .propertyCount = sizeof(g_ConcentrationComponent_Properties) / sizeof(g_ConcentrationComponent_Properties[0]),
};

// eoc::death::DeadByDefaultComponent (from Death.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_DeadByDefaultComponent_Properties[] = {
    { "DeadByDefault", 0x00, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_DeadByDefaultComponent_Layout = {
    .componentName = "eoc::death::DeadByDefaultComponent",
    .shortName = "DeadByDefault",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x01,
    .properties = g_DeadByDefaultComponent_Properties,
    .propertyCount = sizeof(g_DeadByDefaultComponent_Properties) / sizeof(g_DeadByDefaultComponent_Properties[0]),
};

// eoc::death::DeathTypeComponent (from Death.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_DeathTypeComponent_Properties[] = {
    { "DeathType", 0x00, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_DeathTypeComponent_Layout = {
    .componentName = "eoc::death::DeathTypeComponent",
    .shortName = "DeathType",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x01,
    .properties = g_DeathTypeComponent_Properties,
    .propertyCount = sizeof(g_DeathTypeComponent_Properties) / sizeof(g_DeathTypeComponent_Properties[0]),
};

// eoc::death::DownedComponent (from Death.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_DownedComponent_Properties[] = {
    { "DownedStatus", 0x00, FIELD_TYPE_UINT32, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "Entity", 0x08, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_DownedComponent_Layout = {
    .componentName = "eoc::death::DownedComponent",
    .shortName = "Downed",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x18,
    .properties = g_DownedComponent_Properties,
    .propertyCount = sizeof(g_DownedComponent_Properties) / sizeof(g_DownedComponent_Properties[0]),
};

// eoc::death::StateComponent (from Death.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_DeathStateComponent_Properties[] = {
    { "State", 0x00, FIELD_TYPE_UINT32, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_DeathStateComponent_Layout = {
    .componentName = "eoc::death::StateComponent",
    .shortName = "DeathState",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x04,
    .properties = g_DeathStateComponent_Properties,
    .propertyCount = sizeof(g_DeathStateComponent_Properties) / sizeof(g_DeathStateComponent_Properties[0]),
};

// eoc::dialog::StateComponent (from Components.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_DialogStateComponent_Properties[] = {
    { "field_0", 0x00, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_1", 0x01, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_2", 0x02, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "DialogId", 0x04, FIELD_TYPE_INT32, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_8", 0x08, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_DialogStateComponent_Layout = {
    .componentName = "eoc::dialog::StateComponent",
    .shortName = "DialogState",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x09,
    .properties = g_DialogStateComponent_Properties,
    .propertyCount = sizeof(g_DialogStateComponent_Properties) / sizeof(g_DialogStateComponent_Properties[0]),
};

// eoc::encumbrance::StateComponent (from Stats.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_EncumbranceStateComponent_Properties[] = {
    { "State", 0x00, FIELD_TYPE_UINT32, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_EncumbranceStateComponent_Layout = {
    .componentName = "eoc::encumbrance::StateComponent",
    .shortName = "EncumbranceState",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x04,
    .properties = g_EncumbranceStateComponent_Properties,
    .propertyCount = sizeof(g_EncumbranceStateComponent_Properties) / sizeof(g_EncumbranceStateComponent_Properties[0]),
};

// eoc::encumbrance::StatsComponent (from Stats.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_EncumbranceStatsComponent_Properties[] = {
    { "UnencumberedWeight", 0x00, FIELD_TYPE_INT32, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "EncumberedWeight", 0x04, FIELD_TYPE_INT32, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "HeavilyEncumberedWeight", 0x08, FIELD_TYPE_INT32, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_EncumbranceStatsComponent_Layout = {
    .componentName = "eoc::encumbrance::StatsComponent",
    .shortName = "EncumbranceStats",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x0c,
    .properties = g_EncumbranceStatsComponent_Properties,
    .propertyCount = sizeof(g_EncumbranceStatsComponent_Properties) / sizeof(g_EncumbranceStatsComponent_Properties[0]),
};

// eoc::exp::AvailableLevelComponent (from Data.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_AvailableLevelComponent_Properties[] = {
    { "Level", 0x00, FIELD_TYPE_INT32, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_AvailableLevelComponent_Layout = {
    .componentName = "eoc::exp::AvailableLevelComponent",
    .shortName = "AvailableLevel",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x04,
    .properties = g_AvailableLevelComponent_Properties,
    .propertyCount = sizeof(g_AvailableLevelComponent_Properties) / sizeof(g_AvailableLevelComponent_Properties[0]),
};

// eoc::exp::ExperienceComponent (from Data.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_ExperienceComponent_Properties[] = {
    { "CurrentLevelExperience", 0x00, FIELD_TYPE_INT32, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "NextLevelExperience", 0x04, FIELD_TYPE_INT32, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "TotalExperience", 0x08, FIELD_TYPE_INT32, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_28", 0x0c, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_ExperienceComponent_Layout = {
    .componentName = "eoc::exp::ExperienceComponent",
    .shortName = "Experience",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x0d,
    .properties = g_ExperienceComponent_Properties,
    .propertyCount = sizeof(g_ExperienceComponent_Properties) / sizeof(g_ExperienceComponent_Properties[0]),
};

// eoc::expertise::ExpertiseComponent (from Data.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_ExpertiseComponent_Properties[] = {
    { "Expertise", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_ExpertiseComponent_Layout = {
    .componentName = "eoc::expertise::ExpertiseComponent",
    .shortName = "Expertise",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x08,
    .properties = g_ExpertiseComponent_Properties,
    .propertyCount = sizeof(g_ExpertiseComponent_Properties) / sizeof(g_ExpertiseComponent_Properties[0]),
};

// eoc::ftb::ParticipantComponent (from Combat.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_FTBParticipantComponent_Properties[] = {
    { "field_18", 0x00, FIELD_TYPE_UINT64, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_FTBParticipantComponent_Layout = {
    .componentName = "eoc::ftb::ParticipantComponent",
    .shortName = "FTBParticipant",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x08,
    .properties = g_FTBParticipantComponent_Properties,
    .propertyCount = sizeof(g_FTBParticipantComponent_Properties) / sizeof(g_FTBParticipantComponent_Properties[0]),
};

// eoc::ftb::ZoneBlockReasonComponent (from Combat.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_FTBZoneBlockReasonComponent_Properties[] = {
    { "Reason", 0x00, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_FTBZoneBlockReasonComponent_Layout = {
    .componentName = "eoc::ftb::ZoneBlockReasonComponent",
    .shortName = "FTBZoneBlockReason",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x01,
    .properties = g_FTBZoneBlockReasonComponent_Properties,
    .propertyCount = sizeof(g_FTBZoneBlockReasonComponent_Properties) / sizeof(g_FTBZoneBlockReasonComponent_Properties[0]),
};

// eoc::god::GodComponent (from Data.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_GodComponent_Properties[] = {
    { "God", 0x00, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "GodOverride", 0x10, FIELD_TYPE_GUID, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_GodComponent_Layout = {
    .componentName = "eoc::god::GodComponent",
    .shortName = "God",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x18,
    .properties = g_GodComponent_Properties,
    .propertyCount = sizeof(g_GodComponent_Properties) / sizeof(g_GodComponent_Properties[0]),
};

// eoc::god::TagComponent (from Data.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_GodTagComponent_Properties[] = {
    { "Tags", 0x00, FIELD_TYPE_GUID, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_GodTagComponent_Layout = {
    .componentName = "eoc::god::TagComponent",
    .shortName = "GodTag",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x08,
    .properties = g_GodTagComponent_Properties,
    .propertyCount = sizeof(g_GodTagComponent_Properties) / sizeof(g_GodTagComponent_Properties[0]),
};

// eoc::hit::AttackerComponent (from Hit.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_HitAttackerComponent_Properties[] = {
    { "Attacker", 0x00, FIELD_TYPE_UINT64, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_HitAttackerComponent_Layout = {
    .componentName = "eoc::hit::AttackerComponent",
    .shortName = "HitAttacker",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x08,
    .properties = g_HitAttackerComponent_Properties,
    .propertyCount = sizeof(g_HitAttackerComponent_Properties) / sizeof(g_HitAttackerComponent_Properties[0]),
};

// eoc::hit::LifetimeComponent (from Hit.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_HitLifetimeComponent_Properties[] = {
    { "Lifetime", 0x00, FIELD_TYPE_FLOAT, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_4", 0x04, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_HitLifetimeComponent_Layout = {
    .componentName = "eoc::hit::LifetimeComponent",
    .shortName = "HitLifetime",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x05,
    .properties = g_HitLifetimeComponent_Properties,
    .propertyCount = sizeof(g_HitLifetimeComponent_Properties) / sizeof(g_HitLifetimeComponent_Properties[0]),
};

// eoc::hit::MetaComponent (from Hit.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_HitMetaComponent_Properties[] = {
    { "HitGuid", 0x00, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_HitMetaComponent_Layout = {
    .componentName = "eoc::hit::MetaComponent",
    .shortName = "HitMeta",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x10,
    .properties = g_HitMetaComponent_Properties,
    .propertyCount = sizeof(g_HitMetaComponent_Properties) / sizeof(g_HitMetaComponent_Properties[0]),
};

// eoc::hit::ProxyComponent (from Hit.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_HitProxyComponent_Properties[] = {
    { "Owner", 0x00, FIELD_TYPE_UINT64, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_8", 0x08, FIELD_TYPE_UINT32, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_HitProxyComponent_Layout = {
    .componentName = "eoc::hit::ProxyComponent",
    .shortName = "HitProxy",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x0c,
    .properties = g_HitProxyComponent_Properties,
    .propertyCount = sizeof(g_HitProxyComponent_Properties) / sizeof(g_HitProxyComponent_Properties[0]),
};

// eoc::hit::ProxyOwnerComponent (from Hit.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_HitProxyOwnerComponent_Properties[] = {
    { "Owners", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_HitProxyOwnerComponent_Layout = {
    .componentName = "eoc::hit::ProxyOwnerComponent",
    .shortName = "HitProxyOwner",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x08,
    .properties = g_HitProxyOwnerComponent_Properties,
    .propertyCount = sizeof(g_HitProxyOwnerComponent_Properties) / sizeof(g_HitProxyOwnerComponent_Properties[0]),
};

// eoc::hit::ReactionComponent (from Hit.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_HitReactionComponent_Properties[] = {
    { "Reactions", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_HitReactionComponent_Layout = {
    .componentName = "eoc::hit::ReactionComponent",
    .shortName = "HitReaction",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x08,
    .properties = g_HitReactionComponent_Properties,
    .propertyCount = sizeof(g_HitReactionComponent_Properties) / sizeof(g_HitReactionComponent_Properties[0]),
};

// eoc::hit::TargetComponent (from Hit.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_HitTargetComponent_Properties[] = {
    { "field_0", 0x00, FIELD_TYPE_UINT64, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_8", 0x08, FIELD_TYPE_UINT64, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "Target", 0x10, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_HitTargetComponent_Layout = {
    .componentName = "eoc::hit::TargetComponent",
    .shortName = "HitTarget",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x18,
    .properties = g_HitTargetComponent_Properties,
    .propertyCount = sizeof(g_HitTargetComponent_Properties) / sizeof(g_HitTargetComponent_Properties[0]),
};

// eoc::hit::ThrownObjectComponent (from Hit.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_HitThrownObjectComponent_Properties[] = {
    { "ThrownObject", 0x00, FIELD_TYPE_UINT64, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_HitThrownObjectComponent_Layout = {
    .componentName = "eoc::hit::ThrownObjectComponent",
    .shortName = "HitThrownObject",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x08,
    .properties = g_HitThrownObjectComponent_Properties,
    .propertyCount = sizeof(g_HitThrownObjectComponent_Properties) / sizeof(g_HitThrownObjectComponent_Properties[0]),
};

// eoc::hit::WeaponComponent (from Hit.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_HitWeaponComponent_Properties[] = {
    { "Weapon", 0x00, FIELD_TYPE_UINT64, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_HitWeaponComponent_Layout = {
    .componentName = "eoc::hit::WeaponComponent",
    .shortName = "HitWeapon",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x08,
    .properties = g_HitWeaponComponent_Properties,
    .propertyCount = sizeof(g_HitWeaponComponent_Properties) / sizeof(g_HitWeaponComponent_Properties[0]),
};

// eoc::hotbar::ContainerComponent (from Data.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_HotbarContainerComponent_Properties[] = {
    { "ActiveContainer", 0x00, FIELD_TYPE_UINT32, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_HotbarContainerComponent_Layout = {
    .componentName = "eoc::hotbar::ContainerComponent",
    .shortName = "HotbarContainer",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x04,
    .properties = g_HotbarContainerComponent_Properties,
    .propertyCount = sizeof(g_HotbarContainerComponent_Properties) / sizeof(g_HotbarContainerComponent_Properties[0]),
};

// eoc::hotbar::CurrentDecksComponent (from Data.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_HotbarDecksComponent_Properties[] = {
    { "Decks", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_HotbarDecksComponent_Layout = {
    .componentName = "eoc::hotbar::CurrentDecksComponent",
    .shortName = "HotbarDecks",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x08,
    .properties = g_HotbarDecksComponent_Properties,
    .propertyCount = sizeof(g_HotbarDecksComponent_Properties) / sizeof(g_HotbarDecksComponent_Properties[0]),
};

// eoc::identity::IdentityComponent (from Components.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_IdentityComponent_Properties[] = {
    { "field_0", 0x00, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_IdentityComponent_Layout = {
    .componentName = "eoc::identity::IdentityComponent",
    .shortName = "Identity",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x01,
    .properties = g_IdentityComponent_Properties,
    .propertyCount = sizeof(g_IdentityComponent_Properties) / sizeof(g_IdentityComponent_Properties[0]),
};

// eoc::identity::OriginalIdentityComponent (from Components.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_OriginalIdentityComponent_Properties[] = {
    { "field_0", 0x00, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_OriginalIdentityComponent_Layout = {
    .componentName = "eoc::identity::OriginalIdentityComponent",
    .shortName = "OriginalIdentity",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x01,
    .properties = g_OriginalIdentityComponent_Properties,
    .propertyCount = sizeof(g_OriginalIdentityComponent_Properties) / sizeof(g_OriginalIdentityComponent_Properties[0]),
};

// eoc::identity::StateComponent (from Components.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_IdentityStateComponent_Properties[] = {
    { "Disguised", 0x00, FIELD_TYPE_BOOL, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_IdentityStateComponent_Layout = {
    .componentName = "eoc::identity::StateComponent",
    .shortName = "IdentityState",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x01,
    .properties = g_IdentityStateComponent_Properties,
    .propertyCount = sizeof(g_IdentityStateComponent_Properties) / sizeof(g_IdentityStateComponent_Properties[0]),
};

// eoc::improvised_weapon::WieldedComponent (from Data.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_ImprovisedWeaponWieldedComponent_Properties[] = {
    { "Wielder", 0x00, FIELD_TYPE_UINT64, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_8", 0x08, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_9", 0x09, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_ImprovisedWeaponWieldedComponent_Layout = {
    .componentName = "eoc::improvised_weapon::WieldedComponent",
    .shortName = "ImprovisedWeaponWielded",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x0a,
    .properties = g_ImprovisedWeaponWieldedComponent_Properties,
    .propertyCount = sizeof(g_ImprovisedWeaponWieldedComponent_Properties) / sizeof(g_ImprovisedWeaponWieldedComponent_Properties[0]),
};

// eoc::improvised_weapon::WieldingComponent (from Data.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_ImprovisedWeaponWieldingComponent_Properties[] = {
    { "Weapon", 0x00, FIELD_TYPE_UINT64, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_ImprovisedWeaponWieldingComponent_Layout = {
    .componentName = "eoc::improvised_weapon::WieldingComponent",
    .shortName = "ImprovisedWeaponWielding",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x08,
    .properties = g_ImprovisedWeaponWieldingComponent_Properties,
    .propertyCount = sizeof(g_ImprovisedWeaponWieldingComponent_Properties) / sizeof(g_ImprovisedWeaponWieldingComponent_Properties[0]),
};

// eoc::interrupt::ActionStateComponent (from Interrupt.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_InterruptActionStateComponent_Properties[] = {
    { "Event", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "Actions", 0x08, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "SpellCastGuid", 0x10, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_InterruptActionStateComponent_Layout = {
    .componentName = "eoc::interrupt::ActionStateComponent",
    .shortName = "InterruptActionState",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x20,
    .properties = g_InterruptActionStateComponent_Properties,
    .propertyCount = sizeof(g_InterruptActionStateComponent_Properties) / sizeof(g_InterruptActionStateComponent_Properties[0]),
};

// eoc::interrupt::ConditionallyDisabledComponent (from Interrupt.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_InterruptConditionallyDisabledComponent_Properties[] = {
    { "Dummy", 0x00, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_InterruptConditionallyDisabledComponent_Layout = {
    .componentName = "eoc::interrupt::ConditionallyDisabledComponent",
    .shortName = "InterruptConditionallyDisabled",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x01,
    .properties = g_InterruptConditionallyDisabledComponent_Properties,
    .propertyCount = sizeof(g_InterruptConditionallyDisabledComponent_Properties) / sizeof(g_InterruptConditionallyDisabledComponent_Properties[0]),
};

// eoc::interrupt::ContainerComponent (from Interrupt.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_InterruptContainerComponent_Properties[] = {
    { "Interrupts", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_InterruptContainerComponent_Layout = {
    .componentName = "eoc::interrupt::ContainerComponent",
    .shortName = "InterruptContainer",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x08,
    .properties = g_InterruptContainerComponent_Properties,
    .propertyCount = sizeof(g_InterruptContainerComponent_Properties) / sizeof(g_InterruptContainerComponent_Properties[0]),
};

// eoc::interrupt::DataComponent (from Interrupt.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_InterruptDataComponent_Properties[] = {
    { "Interrupt", 0x00, FIELD_TYPE_UINT32, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_4", 0x04, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "InterruptEntity", 0x08, FIELD_TYPE_UINT64, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "Caster", 0x10, FIELD_TYPE_UINT64, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "Spell", 0x18, FIELD_TYPE_UINT32, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_InterruptDataComponent_Layout = {
    .componentName = "eoc::interrupt::DataComponent",
    .shortName = "InterruptData",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x1c,
    .properties = g_InterruptDataComponent_Properties,
    .propertyCount = sizeof(g_InterruptDataComponent_Properties) / sizeof(g_InterruptDataComponent_Properties[0]),
};

// eoc::interrupt::DecisionComponent (from Interrupt.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_InterruptDecisionComponent_Properties[] = {
    { "Decisions", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_InterruptDecisionComponent_Layout = {
    .componentName = "eoc::interrupt::DecisionComponent",
    .shortName = "InterruptDecision",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x08,
    .properties = g_InterruptDecisionComponent_Properties,
    .propertyCount = sizeof(g_InterruptDecisionComponent_Properties) / sizeof(g_InterruptDecisionComponent_Properties[0]),
};

// eoc::interrupt::PreferencesComponent (from Interrupt.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_InterruptPreferencesComponent_Properties[] = {
    { "Preferences", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_InterruptPreferencesComponent_Layout = {
    .componentName = "eoc::interrupt::PreferencesComponent",
    .shortName = "InterruptPreferences",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x08,
    .properties = g_InterruptPreferencesComponent_Properties,
    .propertyCount = sizeof(g_InterruptPreferencesComponent_Properties) / sizeof(g_InterruptPreferencesComponent_Properties[0]),
};

// eoc::interrupt::PreparedComponent (from Interrupt.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_InterruptPreparedComponent_Properties[] = {
    { "Dummy", 0x00, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_InterruptPreparedComponent_Layout = {
    .componentName = "eoc::interrupt::PreparedComponent",
    .shortName = "InterruptPrepared",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x01,
    .properties = g_InterruptPreparedComponent_Properties,
    .propertyCount = sizeof(g_InterruptPreparedComponent_Properties) / sizeof(g_InterruptPreparedComponent_Properties[0]),
};

// eoc::interrupt::ZoneComponent (from Interrupt.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_InterruptZoneComponent_Properties[] = {
    { "field_0", 0x00, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_InterruptZoneComponent_Layout = {
    .componentName = "eoc::interrupt::ZoneComponent",
    .shortName = "InterruptZone",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x10,
    .properties = g_InterruptZoneComponent_Properties,
    .propertyCount = sizeof(g_InterruptZoneComponent_Properties) / sizeof(g_InterruptZoneComponent_Properties[0]),
};

// eoc::interrupt::ZoneParticipantComponent (from Interrupt.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_InterruptZoneParticipantComponent_Properties[] = {
    { "field_0", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_InterruptZoneParticipantComponent_Layout = {
    .componentName = "eoc::interrupt::ZoneParticipantComponent",
    .shortName = "InterruptZoneParticipant",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x08,
    .properties = g_InterruptZoneParticipantComponent_Properties,
    .propertyCount = sizeof(g_InterruptZoneParticipantComponent_Properties) / sizeof(g_InterruptZoneParticipantComponent_Properties[0]),
};

// eoc::interrupt::ZoneSourceComponent (from Interrupt.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_InterruptZoneSourceComponent_Properties[] = {
    { "Dummy", 0x00, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_InterruptZoneSourceComponent_Layout = {
    .componentName = "eoc::interrupt::ZoneSourceComponent",
    .shortName = "InterruptZoneSource",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x01,
    .properties = g_InterruptZoneSourceComponent_Properties,
    .propertyCount = sizeof(g_InterruptZoneSourceComponent_Properties) / sizeof(g_InterruptZoneSourceComponent_Properties[0]),
};

// eoc::inventory::ContainerComponent (from Inventory.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_InventoryContainerComponent_Properties[] = {
    { "Items", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_InventoryContainerComponent_Layout = {
    .componentName = "eoc::inventory::ContainerComponent",
    .shortName = "InventoryContainer",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x08,
    .properties = g_InventoryContainerComponent_Properties,
    .propertyCount = sizeof(g_InventoryContainerComponent_Properties) / sizeof(g_InventoryContainerComponent_Properties[0]),
};

// eoc::inventory::DataComponent (from Inventory.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_InventoryDataComponent_Properties[] = {
    { "Type", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "SlotLimit", 0x08, FIELD_TYPE_UINT16, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_InventoryDataComponent_Layout = {
    .componentName = "eoc::inventory::DataComponent",
    .shortName = "InventoryData",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x0a,
    .properties = g_InventoryDataComponent_Properties,
    .propertyCount = sizeof(g_InventoryDataComponent_Properties) / sizeof(g_InventoryDataComponent_Properties[0]),
};

// eoc::inventory::IsOwnedComponent (from Inventory.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_InventoryIsOwnedComponent_Properties[] = {
    { "Owner", 0x00, FIELD_TYPE_UINT64, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_InventoryIsOwnedComponent_Layout = {
    .componentName = "eoc::inventory::IsOwnedComponent",
    .shortName = "InventoryIsOwned",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x08,
    .properties = g_InventoryIsOwnedComponent_Properties,
    .propertyCount = sizeof(g_InventoryIsOwnedComponent_Properties) / sizeof(g_InventoryIsOwnedComponent_Properties[0]),
};

// eoc::inventory::MemberComponent (from Inventory.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_InventoryMemberComponent_Properties[] = {
    { "Inventory", 0x00, FIELD_TYPE_UINT64, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "EquipmentSlot", 0x08, FIELD_TYPE_INT16, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_InventoryMemberComponent_Layout = {
    .componentName = "eoc::inventory::MemberComponent",
    .shortName = "InventoryMember",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x0a,
    .properties = g_InventoryMemberComponent_Properties,
    .propertyCount = sizeof(g_InventoryMemberComponent_Properties) / sizeof(g_InventoryMemberComponent_Properties[0]),
};

// eoc::inventory::MemberTransformComponent (from Inventory.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_InventoryMemberTransformComponent_Properties[] = {
    { "Transform", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_InventoryMemberTransformComponent_Layout = {
    .componentName = "eoc::inventory::MemberTransformComponent",
    .shortName = "InventoryMemberTransform",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x08,
    .properties = g_InventoryMemberTransformComponent_Properties,
    .propertyCount = sizeof(g_InventoryMemberTransformComponent_Properties) / sizeof(g_InventoryMemberTransformComponent_Properties[0]),
};

// eoc::inventory::OwnerComponent (from Inventory.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_InventoryOwnerComponent_Properties[] = {
    { "Inventories", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "PrimaryInventory", 0x08, FIELD_TYPE_UINT64, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_InventoryOwnerComponent_Layout = {
    .componentName = "eoc::inventory::OwnerComponent",
    .shortName = "InventoryOwner",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x10,
    .properties = g_InventoryOwnerComponent_Properties,
    .propertyCount = sizeof(g_InventoryOwnerComponent_Properties) / sizeof(g_InventoryOwnerComponent_Properties[0]),
};

// eoc::inventory::StackComponent (from Inventory.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_InventoryStackComponent_Properties[] = {
    { "Elements", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "Entries", 0x08, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_InventoryStackComponent_Layout = {
    .componentName = "eoc::inventory::StackComponent",
    .shortName = "InventoryStack",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x10,
    .properties = g_InventoryStackComponent_Properties,
    .propertyCount = sizeof(g_InventoryStackComponent_Properties) / sizeof(g_InventoryStackComponent_Properties[0]),
};

// eoc::inventory::StackMemberComponent (from Inventory.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_InventoryStackMemberComponent_Properties[] = {
    { "Stack", 0x00, FIELD_TYPE_UINT64, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_InventoryStackMemberComponent_Layout = {
    .componentName = "eoc::inventory::StackMemberComponent",
    .shortName = "InventoryStackMember",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x08,
    .properties = g_InventoryStackMemberComponent_Properties,
    .propertyCount = sizeof(g_InventoryStackMemberComponent_Properties) / sizeof(g_InventoryStackMemberComponent_Properties[0]),
};

// eoc::inventory::TopOwnerComponent (from Inventory.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_InventoryTopOwnerComponent_Properties[] = {
    { "TopOwner", 0x00, FIELD_TYPE_UINT64, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_InventoryTopOwnerComponent_Layout = {
    .componentName = "eoc::inventory::TopOwnerComponent",
    .shortName = "InventoryTopOwner",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x08,
    .properties = g_InventoryTopOwnerComponent_Properties,
    .propertyCount = sizeof(g_InventoryTopOwnerComponent_Properties) / sizeof(g_InventoryTopOwnerComponent_Properties[0]),
};

// eoc::inventory::TradeBuybackDataComponent (from Inventory.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_TradeBuybackDataComponent_Properties[] = {
    { "Amount", 0x00, FIELD_TYPE_UINT16, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "Trader", 0x08, FIELD_TYPE_UINT64, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "Buyer", 0x10, FIELD_TYPE_UINT64, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_TradeBuybackDataComponent_Layout = {
    .componentName = "eoc::inventory::TradeBuybackDataComponent",
    .shortName = "TradeBuybackData",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x18,
    .properties = g_TradeBuybackDataComponent_Properties,
    .propertyCount = sizeof(g_TradeBuybackDataComponent_Properties) / sizeof(g_TradeBuybackDataComponent_Properties[0]),
};

// eoc::inventory::WeightComponent (from Inventory.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_InventoryWeightComponent_Properties[] = {
    { "Weight", 0x00, FIELD_TYPE_INT32, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_InventoryWeightComponent_Layout = {
    .componentName = "eoc::inventory::WeightComponent",
    .shortName = "InventoryWeight",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x04,
    .properties = g_InventoryWeightComponent_Properties,
    .propertyCount = sizeof(g_InventoryWeightComponent_Properties) / sizeof(g_InventoryWeightComponent_Properties[0]),
};

// eoc::inventory::WieldedComponent (from Inventory.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_WieldedComponent_Properties[] = {
    { "field_0", 0x00, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_WieldedComponent_Layout = {
    .componentName = "eoc::inventory::WieldedComponent",
    .shortName = "Wielded",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x10,
    .properties = g_WieldedComponent_Properties,
    .propertyCount = sizeof(g_WieldedComponent_Properties) / sizeof(g_WieldedComponent_Properties[0]),
};

// eoc::inventory::WieldingHistoryComponent (from Inventory.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_WieldingHistoryComponent_Properties[] = {
    { "field_0", 0x00, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_WieldingHistoryComponent_Layout = {
    .componentName = "eoc::inventory::WieldingHistoryComponent",
    .shortName = "WieldingHistory",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x10,
    .properties = g_WieldingHistoryComponent_Properties,
    .propertyCount = sizeof(g_WieldingHistoryComponent_Properties) / sizeof(g_WieldingHistoryComponent_Properties[0]),
};

// eoc::item::DestroyedComponent (from Item.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_ItemDestroyedComponent_Properties[] = {
    { "Info", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_ItemDestroyedComponent_Layout = {
    .componentName = "eoc::item::DestroyedComponent",
    .shortName = "ItemDestroyed",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x08,
    .properties = g_ItemDestroyedComponent_Properties,
    .propertyCount = sizeof(g_ItemDestroyedComponent_Properties) / sizeof(g_ItemDestroyedComponent_Properties[0]),
};

// eoc::item::DyeComponent (from Item.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_ItemDyeComponent_Properties[] = {
    { "Color", 0x00, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_ItemDyeComponent_Layout = {
    .componentName = "eoc::item::DyeComponent",
    .shortName = "ItemDye",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x10,
    .properties = g_ItemDyeComponent_Properties,
    .propertyCount = sizeof(g_ItemDyeComponent_Properties) / sizeof(g_ItemDyeComponent_Properties[0]),
};

// eoc::item::MapMarkerStyleComponent (from Item.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_MapMarkerStyleComponent_Properties[] = {
    { "Style", 0x00, FIELD_TYPE_UINT32, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_MapMarkerStyleComponent_Layout = {
    .componentName = "eoc::item::MapMarkerStyleComponent",
    .shortName = "MapMarkerStyle",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x04,
    .properties = g_MapMarkerStyleComponent_Properties,
    .propertyCount = sizeof(g_MapMarkerStyleComponent_Properties) / sizeof(g_MapMarkerStyleComponent_Properties[0]),
};

// eoc::item::PortalComponent (from Item.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_ItemPortalComponent_Properties[] = {
    { "field_0", 0x00, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_1", 0x01, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_ItemPortalComponent_Layout = {
    .componentName = "eoc::item::PortalComponent",
    .shortName = "ItemPortal",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x02,
    .properties = g_ItemPortalComponent_Properties,
    .propertyCount = sizeof(g_ItemPortalComponent_Properties) / sizeof(g_ItemPortalComponent_Properties[0]),
};

// eoc::item_template::ActionTypeComponent (from Item.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_ActionTypeComponent_Properties[] = {
    { "ActionTypes", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_ActionTypeComponent_Layout = {
    .componentName = "eoc::item_template::ActionTypeComponent",
    .shortName = "ActionType",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x08,
    .properties = g_ActionTypeComponent_Properties,
    .propertyCount = sizeof(g_ActionTypeComponent_Properties) / sizeof(g_ActionTypeComponent_Properties[0]),
};

// eoc::item_template::UseActionComponent (from Item.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_UseActionComponent_Properties[] = {
    { "UseActions", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_UseActionComponent_Layout = {
    .componentName = "eoc::item_template::UseActionComponent",
    .shortName = "UseAction",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x08,
    .properties = g_UseActionComponent_Properties,
    .propertyCount = sizeof(g_UseActionComponent_Properties) / sizeof(g_UseActionComponent_Properties[0]),
};

// eoc::light::ActiveCharacterLightComponent (from Visual.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_ActiveCharacterLightComponent_Properties[] = {
    { "Light", 0x00, FIELD_TYPE_UINT32, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_ActiveCharacterLightComponent_Layout = {
    .componentName = "eoc::light::ActiveCharacterLightComponent",
    .shortName = "ActiveCharacterLight",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x04,
    .properties = g_ActiveCharacterLightComponent_Properties,
    .propertyCount = sizeof(g_ActiveCharacterLightComponent_Properties) / sizeof(g_ActiveCharacterLightComponent_Properties[0]),
};

// eoc::lock::KeyComponent (from Data.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_KeyComponent_Properties[] = {
    { "Key", 0x00, FIELD_TYPE_UINT32, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_KeyComponent_Layout = {
    .componentName = "eoc::lock::KeyComponent",
    .shortName = "Key",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x04,
    .properties = g_KeyComponent_Properties,
    .propertyCount = sizeof(g_KeyComponent_Properties) / sizeof(g_KeyComponent_Properties[0]),
};

// eoc::lock::LockComponent (from Data.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_LockComponent_Properties[] = {
    { "Key_M", 0x00, FIELD_TYPE_UINT32, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "LockDC", 0x04, FIELD_TYPE_INT32, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_8", 0x08, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_18", 0x18, FIELD_TYPE_GUID, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_LockComponent_Layout = {
    .componentName = "eoc::lock::LockComponent",
    .shortName = "Lock",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x20,
    .properties = g_LockComponent_Properties,
    .propertyCount = sizeof(g_LockComponent_Properties) / sizeof(g_LockComponent_Properties[0]),
};

// eoc::multiplayer::UserComponent (from Components.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_MultiplayerUserComponent_Properties[] = {
    { "UserID", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_MultiplayerUserComponent_Layout = {
    .componentName = "eoc::multiplayer::UserComponent",
    .shortName = "MultiplayerUser",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x08,
    .properties = g_MultiplayerUserComponent_Properties,
    .propertyCount = sizeof(g_MultiplayerUserComponent_Properties) / sizeof(g_MultiplayerUserComponent_Properties[0]),
};

// eoc::object_visual::AppearanceOverrideComponent (from Visual.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_AppearanceOverrideComponent_Properties[] = {
    { "Visual", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_AppearanceOverrideComponent_Layout = {
    .componentName = "eoc::object_visual::AppearanceOverrideComponent",
    .shortName = "AppearanceOverride",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x08,
    .properties = g_AppearanceOverrideComponent_Properties,
    .propertyCount = sizeof(g_AppearanceOverrideComponent_Properties) / sizeof(g_AppearanceOverrideComponent_Properties[0]),
};

// eoc::object_visual::CharacterCreationTemplateOverrideComponent (from Visual.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_CharacterCreationTemplateOverrideComponent_Properties[] = {
    { "Template", 0x00, FIELD_TYPE_UINT32, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_CharacterCreationTemplateOverrideComponent_Layout = {
    .componentName = "eoc::object_visual::CharacterCreationTemplateOverrideComponent",
    .shortName = "CharacterCreationTemplateOverride",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x04,
    .properties = g_CharacterCreationTemplateOverrideComponent_Properties,
    .propertyCount = sizeof(g_CharacterCreationTemplateOverrideComponent_Properties) / sizeof(g_CharacterCreationTemplateOverrideComponent_Properties[0]),
};

// eoc::ownership::OwneeCurrentComponent (from Item.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_OwneeCurrentComponent_Properties[] = {
    { "Ownee", 0x00, FIELD_TYPE_UINT64, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_OwneeCurrentComponent_Layout = {
    .componentName = "eoc::ownership::OwneeCurrentComponent",
    .shortName = "OwneeCurrent",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x08,
    .properties = g_OwneeCurrentComponent_Properties,
    .propertyCount = sizeof(g_OwneeCurrentComponent_Properties) / sizeof(g_OwneeCurrentComponent_Properties[0]),
};

// eoc::party::CompositionComponent (from Party.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_PartyCompositionComponent_Properties[] = {
    { "Party", 0x00, FIELD_TYPE_UINT64, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "PartyUuid", 0x08, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "Members", 0x18, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_PartyCompositionComponent_Layout = {
    .componentName = "eoc::party::CompositionComponent",
    .shortName = "PartyComposition",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x20,
    .properties = g_PartyCompositionComponent_Properties,
    .propertyCount = sizeof(g_PartyCompositionComponent_Properties) / sizeof(g_PartyCompositionComponent_Properties[0]),
};

// eoc::party::FollowerComponent (from Party.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_PartyFollowerComponent_Properties[] = {
    { "Following", 0x00, FIELD_TYPE_UINT64, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_PartyFollowerComponent_Layout = {
    .componentName = "eoc::party::FollowerComponent",
    .shortName = "PartyFollower",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x08,
    .properties = g_PartyFollowerComponent_Properties,
    .propertyCount = sizeof(g_PartyFollowerComponent_Properties) / sizeof(g_PartyFollowerComponent_Properties[0]),
};

// eoc::party::MemberComponent (from Party.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_PartyMemberComponent_Properties[] = {
    { "UserId", 0x00, FIELD_TYPE_INT32, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "UserUuid", 0x08, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "Party", 0x18, FIELD_TYPE_UINT64, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "ViewUuid", 0x20, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "IsPermanent", 0x30, FIELD_TYPE_BOOL, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_PartyMemberComponent_Layout = {
    .componentName = "eoc::party::MemberComponent",
    .shortName = "PartyMember",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x31,
    .properties = g_PartyMemberComponent_Properties,
    .propertyCount = sizeof(g_PartyMemberComponent_Properties) / sizeof(g_PartyMemberComponent_Properties[0]),
};

// eoc::party::PortalsComponent (from Party.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_PartyPortalsComponent_Properties[] = {
    { "Portals", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_PartyPortalsComponent_Layout = {
    .componentName = "eoc::party::PortalsComponent",
    .shortName = "PartyPortals",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x08,
    .properties = g_PartyPortalsComponent_Properties,
    .propertyCount = sizeof(g_PartyPortalsComponent_Properties) / sizeof(g_PartyPortalsComponent_Properties[0]),
};

// eoc::party::RecipesComponent (from Party.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_PartyRecipesComponent_Properties[] = {
    { "Recipes", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_PartyRecipesComponent_Layout = {
    .componentName = "eoc::party::RecipesComponent",
    .shortName = "PartyRecipes",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x08,
    .properties = g_PartyRecipesComponent_Properties,
    .propertyCount = sizeof(g_PartyRecipesComponent_Properties) / sizeof(g_PartyRecipesComponent_Properties[0]),
};

// eoc::party::ViewComponent (from Party.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_PartyViewComponent_Properties[] = {
    { "PartyUuid", 0x00, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "Views", 0x10, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "Characters", 0x18, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_PartyViewComponent_Layout = {
    .componentName = "eoc::party::ViewComponent",
    .shortName = "PartyView",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x20,
    .properties = g_PartyViewComponent_Properties,
    .propertyCount = sizeof(g_PartyViewComponent_Properties) / sizeof(g_PartyViewComponent_Properties[0]),
};

// eoc::party::WaypointsComponent (from Party.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_PartyWaypointsComponent_Properties[] = {
    { "Waypoints", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_PartyWaypointsComponent_Layout = {
    .componentName = "eoc::party::WaypointsComponent",
    .shortName = "PartyWaypoints",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x08,
    .properties = g_PartyWaypointsComponent_Properties,
    .propertyCount = sizeof(g_PartyWaypointsComponent_Properties) / sizeof(g_PartyWaypointsComponent_Properties[0]),
};

// eoc::passive::UsageCountComponent (from Passives.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_PassiveUsageCountComponent_Properties[] = {
    { "Passives", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_PassiveUsageCountComponent_Layout = {
    .componentName = "eoc::passive::UsageCountComponent",
    .shortName = "PassiveUsageCount",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x08,
    .properties = g_PassiveUsageCountComponent_Properties,
    .propertyCount = sizeof(g_PassiveUsageCountComponent_Properties) / sizeof(g_PassiveUsageCountComponent_Properties[0]),
};

// eoc::photo_mode::CameraTransformComponent (from Dummy.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_PhotoModeCameraTransformComponent_Properties[] = {
    { "Transform", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_PhotoModeCameraTransformComponent_Layout = {
    .componentName = "eoc::photo_mode::CameraTransformComponent",
    .shortName = "PhotoModeCameraTransform",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x08,
    .properties = g_PhotoModeCameraTransformComponent_Properties,
    .propertyCount = sizeof(g_PhotoModeCameraTransformComponent_Properties) / sizeof(g_PhotoModeCameraTransformComponent_Properties[0]),
};

// eoc::photo_mode::DummyAnimationStateComponent (from Dummy.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_PhotoModeDummyAnimationStateComponent_Properties[] = {
    { "field_0", 0x00, FIELD_TYPE_UINT32, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_4", 0x04, FIELD_TYPE_UINT32, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_8", 0x08, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "qwordC", 0x0c, FIELD_TYPE_INT32, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_10", 0x10, FIELD_TYPE_INT32, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "word14", 0x14, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_15", 0x15, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_16", 0x16, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_PhotoModeDummyAnimationStateComponent_Layout = {
    .componentName = "eoc::photo_mode::DummyAnimationStateComponent",
    .shortName = "PhotoModeDummyAnimationState",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x17,
    .properties = g_PhotoModeDummyAnimationStateComponent_Properties,
    .propertyCount = sizeof(g_PhotoModeDummyAnimationStateComponent_Properties) / sizeof(g_PhotoModeDummyAnimationStateComponent_Properties[0]),
};

// eoc::photo_mode::DummyComponent (from Dummy.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_PhotoModeDummyComponent_Properties[] = {
    { "Entity", 0x00, FIELD_TYPE_UINT64, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "UserId", 0x08, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_PhotoModeDummyComponent_Layout = {
    .componentName = "eoc::photo_mode::DummyComponent",
    .shortName = "PhotoModeDummy",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x10,
    .properties = g_PhotoModeDummyComponent_Properties,
    .propertyCount = sizeof(g_PhotoModeDummyComponent_Properties) / sizeof(g_PhotoModeDummyComponent_Properties[0]),
};

// eoc::photo_mode::DummyEquipmentVisualComponent (from Dummy.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_PhotoModeDummyEquipmentVisualComponent_Properties[] = {
    { "field_0", 0x00, FIELD_TYPE_INT32, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_PhotoModeDummyEquipmentVisualComponent_Layout = {
    .componentName = "eoc::photo_mode::DummyEquipmentVisualComponent",
    .shortName = "PhotoModeDummyEquipmentVisual",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x04,
    .properties = g_PhotoModeDummyEquipmentVisualComponent_Properties,
    .propertyCount = sizeof(g_PhotoModeDummyEquipmentVisualComponent_Properties) / sizeof(g_PhotoModeDummyEquipmentVisualComponent_Properties[0]),
};

// eoc::photo_mode::DummyShowSplatterComponent (from Dummy.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_PhotoModeDummyShowSplatterComponent_Properties[] = {
    { "field_0", 0x00, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_PhotoModeDummyShowSplatterComponent_Layout = {
    .componentName = "eoc::photo_mode::DummyShowSplatterComponent",
    .shortName = "PhotoModeDummyShowSplatter",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x01,
    .properties = g_PhotoModeDummyShowSplatterComponent_Properties,
    .propertyCount = sizeof(g_PhotoModeDummyShowSplatterComponent_Properties) / sizeof(g_PhotoModeDummyShowSplatterComponent_Properties[0]),
};

// eoc::photo_mode::DummyTransformComponent (from Dummy.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_PhotoModeDummyTransformComponent_Properties[] = {
    { "Transform", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_PhotoModeDummyTransformComponent_Layout = {
    .componentName = "eoc::photo_mode::DummyTransformComponent",
    .shortName = "PhotoModeDummyTransform",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x08,
    .properties = g_PhotoModeDummyTransformComponent_Properties,
    .propertyCount = sizeof(g_PhotoModeDummyTransformComponent_Properties) / sizeof(g_PhotoModeDummyTransformComponent_Properties[0]),
};

// eoc::photo_mode::SessionComponent (from Dummy.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_PhotoModeSessionComponent_Properties[] = {
    { "State", 0x00, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_PhotoModeSessionComponent_Layout = {
    .componentName = "eoc::photo_mode::SessionComponent",
    .shortName = "PhotoModeSession",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x01,
    .properties = g_PhotoModeSessionComponent_Properties,
    .propertyCount = sizeof(g_PhotoModeSessionComponent_Properties) / sizeof(g_PhotoModeSessionComponent_Properties[0]),
};

// eoc::pickup::PickUpRequestComponent (from Data.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_PickUpRequestComponent_Properties[] = {
    { "field_0", 0x00, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "State", 0x10, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_PickUpRequestComponent_Layout = {
    .componentName = "eoc::pickup::PickUpRequestComponent",
    .shortName = "PickUpRequest",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x11,
    .properties = g_PickUpRequestComponent_Properties,
    .propertyCount = sizeof(g_PickUpRequestComponent_Properties) / sizeof(g_PickUpRequestComponent_Properties[0]),
};

// eoc::progression::AbilityImprovementsComponent (from Progression.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_ProgressionAbilityImprovementsComponent_Properties[] = {
    { "Abilities", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "AbilityImprovements", 0x08, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_ProgressionAbilityImprovementsComponent_Layout = {
    .componentName = "eoc::progression::AbilityImprovementsComponent",
    .shortName = "ProgressionAbilityImprovements",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x10,
    .properties = g_ProgressionAbilityImprovementsComponent_Properties,
    .propertyCount = sizeof(g_ProgressionAbilityImprovementsComponent_Properties) / sizeof(g_ProgressionAbilityImprovementsComponent_Properties[0]),
};

// eoc::progression::FeatComponent (from Progression.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_ProgressionFeatComponent_Properties[] = {
    { "Feat", 0x00, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_10", 0x10, FIELD_TYPE_INT32, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "ConditionId", 0x18, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "Proficiencies", 0x20, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "Expertise", 0x28, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "AddSpells", 0x30, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "AddPassives", 0x38, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "AbilityImprovements", 0x40, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_ProgressionFeatComponent_Layout = {
    .componentName = "eoc::progression::FeatComponent",
    .shortName = "ProgressionFeat",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x48,
    .properties = g_ProgressionFeatComponent_Properties,
    .propertyCount = sizeof(g_ProgressionFeatComponent_Properties) / sizeof(g_ProgressionFeatComponent_Properties[0]),
};

// eoc::progression::LevelUpComponent (from Progression.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_LevelUpComponent_Properties[] = {
    { "LevelUps", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_LevelUpComponent_Layout = {
    .componentName = "eoc::progression::LevelUpComponent",
    .shortName = "LevelUp",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x08,
    .properties = g_LevelUpComponent_Properties,
    .propertyCount = sizeof(g_LevelUpComponent_Properties) / sizeof(g_LevelUpComponent_Properties[0]),
};

// eoc::progression::MetaComponent (from Progression.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_ProgressionMetaComponent_Properties[] = {
    { "field_18", 0x00, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "Progression", 0x08, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "Source", 0x18, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "ClassLevel", 0x28, FIELD_TYPE_INT32, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "SpellSourceType", 0x30, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "Level", 0x38, FIELD_TYPE_INT32, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "Owner", 0x40, FIELD_TYPE_UINT64, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "MulticlassSpellSlotOverride", 0x48, FIELD_TYPE_GUID, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_ProgressionMetaComponent_Layout = {
    .componentName = "eoc::progression::MetaComponent",
    .shortName = "ProgressionMeta",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x50,
    .properties = g_ProgressionMetaComponent_Properties,
    .propertyCount = sizeof(g_ProgressionMetaComponent_Properties) / sizeof(g_ProgressionMetaComponent_Properties[0]),
};

// eoc::progression::PassivesComponent (from Progression.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_ProgressionPassivesComponent_Properties[] = {
    { "AddPassives", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "RemovePassives", 0x08, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_ProgressionPassivesComponent_Layout = {
    .componentName = "eoc::progression::PassivesComponent",
    .shortName = "ProgressionPassives",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x10,
    .properties = g_ProgressionPassivesComponent_Properties,
    .propertyCount = sizeof(g_ProgressionPassivesComponent_Properties) / sizeof(g_ProgressionPassivesComponent_Properties[0]),
};

// eoc::progression::ReplicatedFeatComponent (from Progression.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_ProgressionReplicatedFeatComponent_Properties[] = {
    { "Feat", 0x00, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_10", 0x10, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_14", 0x14, FIELD_TYPE_INT32, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_ProgressionReplicatedFeatComponent_Layout = {
    .componentName = "eoc::progression::ReplicatedFeatComponent",
    .shortName = "ProgressionReplicatedFeat",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x18,
    .properties = g_ProgressionReplicatedFeatComponent_Properties,
    .propertyCount = sizeof(g_ProgressionReplicatedFeatComponent_Properties) / sizeof(g_ProgressionReplicatedFeatComponent_Properties[0]),
};

// eoc::progression::SkillsComponent (from Progression.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_ProgressionSkillsComponent_Properties[] = {
    { "Proficiencies", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "Expertise", 0x08, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_ProgressionSkillsComponent_Layout = {
    .componentName = "eoc::progression::SkillsComponent",
    .shortName = "ProgressionSkills",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x10,
    .properties = g_ProgressionSkillsComponent_Properties,
    .propertyCount = sizeof(g_ProgressionSkillsComponent_Properties) / sizeof(g_ProgressionSkillsComponent_Properties[0]),
};

// eoc::progression::SpellsComponent (from Progression.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_ProgressionSpellsComponent_Properties[] = {
    { "AddSpells", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "RemoveSpells", 0x08, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_ProgressionSpellsComponent_Layout = {
    .componentName = "eoc::progression::SpellsComponent",
    .shortName = "ProgressionSpells",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x10,
    .properties = g_ProgressionSpellsComponent_Properties,
    .propertyCount = sizeof(g_ProgressionSpellsComponent_Properties) / sizeof(g_ProgressionSpellsComponent_Properties[0]),
};

// eoc::projectile::SourceInfoComponent (from Projectile.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_ProjectileSourceComponent_Properties[] = {
    { "Spell", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "Entity", 0x08, FIELD_TYPE_UINT64, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_ProjectileSourceComponent_Layout = {
    .componentName = "eoc::projectile::SourceInfoComponent",
    .shortName = "ProjectileSource",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x10,
    .properties = g_ProjectileSourceComponent_Properties,
    .propertyCount = sizeof(g_ProjectileSourceComponent_Properties) / sizeof(g_ProjectileSourceComponent_Properties[0]),
};

// eoc::recruit::RecruiterComponent (from Party.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_RecruiterComponent_Properties[] = {
    { "Recruiters", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_RecruiterComponent_Layout = {
    .componentName = "eoc::recruit::RecruiterComponent",
    .shortName = "Recruiter",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x08,
    .properties = g_RecruiterComponent_Properties,
    .propertyCount = sizeof(g_RecruiterComponent_Properties) / sizeof(g_RecruiterComponent_Properties[0]),
};

// eoc::relation::FactionComponent (from Components.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_FactionComponent_Properties[] = {
    { "field_0", 0x00, FIELD_TYPE_UINT64, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_8", 0x08, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_18", 0x18, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "SummonOwner", 0x28, FIELD_TYPE_UINT64, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_FactionComponent_Layout = {
    .componentName = "eoc::relation::FactionComponent",
    .shortName = "Faction",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x30,
    .properties = g_FactionComponent_Properties,
    .propertyCount = sizeof(g_FactionComponent_Properties) / sizeof(g_FactionComponent_Properties[0]),
};

// eoc::relation::RelationComponent (from Components.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_RelationComponent_Properties[] = {
    { "field_0", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_40", 0x08, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_80", 0x10, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_C0", 0x18, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_100", 0x20, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_140", 0x28, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_170", 0x30, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_RelationComponent_Layout = {
    .componentName = "eoc::relation::RelationComponent",
    .shortName = "Relation",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x38,
    .properties = g_RelationComponent_Properties,
    .propertyCount = sizeof(g_RelationComponent_Properties) / sizeof(g_RelationComponent_Properties[0]),
};

// eoc::repose::StateComponent (from Components.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_ReposeComponent_Properties[] = {
    { "field_0", 0x00, FIELD_TYPE_UINT64, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_8", 0x08, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_18", 0x18, FIELD_TYPE_INT32, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_1C", 0x20, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_28", 0x28, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_ReposeComponent_Layout = {
    .componentName = "eoc::repose::StateComponent",
    .shortName = "Repose",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x29,
    .properties = g_ReposeComponent_Properties,
    .propertyCount = sizeof(g_ReposeComponent_Properties) / sizeof(g_ReposeComponent_Properties[0]),
};

// eoc::rest::LongRestState (from Data.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_LongRestStateComponent_Properties[] = {
    { "State", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "WaitingForOthers", 0x08, FIELD_TYPE_BOOL, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "FinishConfirmed", 0x09, FIELD_TYPE_BOOL, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "Finishing", 0x0a, FIELD_TYPE_BOOL, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "CancelReason", 0x10, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_8", 0x18, FIELD_TYPE_UINT32, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "Requester", 0x20, FIELD_TYPE_UINT64, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_LongRestStateComponent_Layout = {
    .componentName = "eoc::rest::LongRestState",
    .shortName = "LongRestState",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x28,
    .properties = g_LongRestStateComponent_Properties,
    .propertyCount = sizeof(g_LongRestStateComponent_Properties) / sizeof(g_LongRestStateComponent_Properties[0]),
};

// eoc::rest::LongRestTimeline (from Data.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_LongRestTimelineComponent_Properties[] = {
    { "Timeline", 0x00, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_LongRestTimelineComponent_Layout = {
    .componentName = "eoc::rest::LongRestTimeline",
    .shortName = "LongRestTimeline",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x10,
    .properties = g_LongRestTimelineComponent_Properties,
    .propertyCount = sizeof(g_LongRestTimelineComponent_Properties) / sizeof(g_LongRestTimelineComponent_Properties[0]),
};

// eoc::rest::LongRestTimers (from Data.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_LongRestTimersComponent_Properties[] = {
    { "field_0", 0x00, FIELD_TYPE_INT32, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_LongRestTimersComponent_Layout = {
    .componentName = "eoc::rest::LongRestTimers",
    .shortName = "LongRestTimers",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x04,
    .properties = g_LongRestTimersComponent_Properties,
    .propertyCount = sizeof(g_LongRestTimersComponent_Properties) / sizeof(g_LongRestTimersComponent_Properties[0]),
};

// eoc::rest::LongRestUsers (from Data.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_LongRestUsersComponent_Properties[] = {
    { "RequestRestore", 0x00, FIELD_TYPE_BOOL, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "States", 0x08, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "FinishConfirmation", 0x10, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_LongRestUsersComponent_Layout = {
    .componentName = "eoc::rest::LongRestUsers",
    .shortName = "LongRestUsers",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x18,
    .properties = g_LongRestUsersComponent_Properties,
    .propertyCount = sizeof(g_LongRestUsersComponent_Properties) / sizeof(g_LongRestUsersComponent_Properties[0]),
};

// eoc::rest::RestingEntities (from Data.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_RestingEntitiesComponent_Properties[] = {
    { "ScriptFinished", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "RestRequested", 0x08, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "RestStarted", 0x10, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "Party", 0x18, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "HasSurfaces", 0x20, FIELD_TYPE_BOOL, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_RestingEntitiesComponent_Layout = {
    .componentName = "eoc::rest::RestingEntities",
    .shortName = "RestingEntities",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x21,
    .properties = g_RestingEntitiesComponent_Properties,
    .propertyCount = sizeof(g_RestingEntitiesComponent_Properties) / sizeof(g_RestingEntitiesComponent_Properties[0]),
};

// eoc::ruleset::RulesetComponent (from Components.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_RulesetComponent_Properties[] = {
    { "Rulesets", 0x00, FIELD_TYPE_GUID, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_40", 0x08, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_RulesetComponent_Layout = {
    .componentName = "eoc::ruleset::RulesetComponent",
    .shortName = "Ruleset",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x18,
    .properties = g_RulesetComponent_Properties,
    .propertyCount = sizeof(g_RulesetComponent_Properties) / sizeof(g_RulesetComponent_Properties[0]),
};

// eoc::shapeshift::AnimationComponent (from Shapeshift.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_ShapeshiftAnimationComponent_Properties[] = {
    { "field_0", 0x00, FIELD_TYPE_UINT32, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_4", 0x04, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_ShapeshiftAnimationComponent_Layout = {
    .componentName = "eoc::shapeshift::AnimationComponent",
    .shortName = "ShapeshiftAnimation",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x05,
    .properties = g_ShapeshiftAnimationComponent_Properties,
    .propertyCount = sizeof(g_ShapeshiftAnimationComponent_Properties) / sizeof(g_ShapeshiftAnimationComponent_Properties[0]),
};

// eoc::shapeshift::RecoveryAnimationComponent (from Shapeshift.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_ShapeshiftRecoveryAnimationComponent_Properties[] = {
    { "Animation", 0x00, FIELD_TYPE_UINT32, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_ShapeshiftRecoveryAnimationComponent_Layout = {
    .componentName = "eoc::shapeshift::RecoveryAnimationComponent",
    .shortName = "ShapeshiftRecoveryAnimation",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x04,
    .properties = g_ShapeshiftRecoveryAnimationComponent_Properties,
    .propertyCount = sizeof(g_ShapeshiftRecoveryAnimationComponent_Properties) / sizeof(g_ShapeshiftRecoveryAnimationComponent_Properties[0]),
};

// eoc::shapeshift::ReplicatedChangesComponent (from Shapeshift.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_ShapeshiftReplicatedChangesComponent_Properties[] = {
    { "HP", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "VisualChanged", 0x08, FIELD_TYPE_BOOL, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "ForceFinish", 0x09, FIELD_TYPE_BOOL, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "ItemTooltipFlags", 0x0a, FIELD_TYPE_UINT16, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "ItemDescription", 0x10, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "GoldAmount", 0x18, FIELD_TYPE_INT32, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "ItemWeight", 0x1c, FIELD_TYPE_INT32, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "MuteEquipmentSound", 0x20, FIELD_TYPE_BOOL, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "DisableEquipment", 0x21, FIELD_TYPE_BOOL, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "HasWildShapeHotBar", 0x22, FIELD_TYPE_BOOL, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "HasWeightOverride", 0x23, FIELD_TYPE_BOOL, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "AC", 0x24, FIELD_TYPE_INT32, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_ShapeshiftReplicatedChangesComponent_Layout = {
    .componentName = "eoc::shapeshift::ReplicatedChangesComponent",
    .shortName = "ShapeshiftReplicatedChanges",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x28,
    .properties = g_ShapeshiftReplicatedChangesComponent_Properties,
    .propertyCount = sizeof(g_ShapeshiftReplicatedChangesComponent_Properties) / sizeof(g_ShapeshiftReplicatedChangesComponent_Properties[0]),
};

// eoc::shapeshift::SourceCacheComponent (from Shapeshift.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_ShapeshiftSourceCacheComponent_Properties[] = {
    { "Source", 0x00, FIELD_TYPE_GUID, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_ShapeshiftSourceCacheComponent_Layout = {
    .componentName = "eoc::shapeshift::SourceCacheComponent",
    .shortName = "ShapeshiftSourceCache",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x08,
    .properties = g_ShapeshiftSourceCacheComponent_Properties,
    .propertyCount = sizeof(g_ShapeshiftSourceCacheComponent_Properties) / sizeof(g_ShapeshiftSourceCacheComponent_Properties[0]),
};

// eoc::shapeshift::StateComponent (from Shapeshift.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_ShapeshiftStateComponent_Properties[] = {
    { "BloodSurfaceType", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "BloodType", 0x08, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "Template", 0x10, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_ShapeshiftStateComponent_Layout = {
    .componentName = "eoc::shapeshift::StateComponent",
    .shortName = "ShapeshiftState",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x18,
    .properties = g_ShapeshiftStateComponent_Properties,
    .propertyCount = sizeof(g_ShapeshiftStateComponent_Properties) / sizeof(g_ShapeshiftStateComponent_Properties[0]),
};

// eoc::sight::BaseComponent (from Components.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_SightComponent_Properties[] = {
    { "Sight", 0x00, FIELD_TYPE_FLOAT, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "DarkvisionRange", 0x04, FIELD_TYPE_FLOAT, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "FOV", 0x08, FIELD_TYPE_FLOAT, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "VerticalFOV", 0x0c, FIELD_TYPE_FLOAT, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_SightComponent_Layout = {
    .componentName = "eoc::sight::BaseComponent",
    .shortName = "Sight",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x10,
    .properties = g_SightComponent_Properties,
    .propertyCount = sizeof(g_SightComponent_Properties) / sizeof(g_SightComponent_Properties[0]),
};

// eoc::sight::DataComponent (from Components.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_SightDataComponent_Properties[] = {
    { "SightUuid", 0x00, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "DarkvisionRange", 0x10, FIELD_TYPE_FLOAT, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "FOV", 0x14, FIELD_TYPE_FLOAT, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "VerticalFOV", 0x18, FIELD_TYPE_FLOAT, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "Sight", 0x1c, FIELD_TYPE_FLOAT, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_20", 0x20, FIELD_TYPE_INT32, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_24", 0x24, FIELD_TYPE_INT32, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_SightDataComponent_Layout = {
    .componentName = "eoc::sight::DataComponent",
    .shortName = "SightData",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x28,
    .properties = g_SightDataComponent_Properties,
    .propertyCount = sizeof(g_SightDataComponent_Properties) / sizeof(g_SightDataComponent_Properties[0]),
};

// eoc::sight::EntityViewshedComponent (from Components.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_SightEntityViewshedComponent_Properties[] = {
    { "Viewshed", 0x00, FIELD_TYPE_GUID, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_SightEntityViewshedComponent_Layout = {
    .componentName = "eoc::sight::EntityViewshedComponent",
    .shortName = "SightEntityViewshed",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x08,
    .properties = g_SightEntityViewshedComponent_Properties,
    .propertyCount = sizeof(g_SightEntityViewshedComponent_Properties) / sizeof(g_SightEntityViewshedComponent_Properties[0]),
};

// eoc::sight::IgnoreSurfacesComponent (from Components.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_IgnoreSurfacesComponent_Properties[] = {
    { "SurfaceTypes", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_IgnoreSurfacesComponent_Layout = {
    .componentName = "eoc::sight::IgnoreSurfacesComponent",
    .shortName = "IgnoreSurfaces",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x08,
    .properties = g_IgnoreSurfacesComponent_Properties,
    .propertyCount = sizeof(g_IgnoreSurfacesComponent_Properties) / sizeof(g_IgnoreSurfacesComponent_Properties[0]),
};

// eoc::spatial_grid::DataComponent (from Data.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_SpatialGridComponent_Properties[] = {
    { "Grid", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "Level", 0x08, FIELD_TYPE_UINT32, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_94", 0x0c, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_SpatialGridComponent_Layout = {
    .componentName = "eoc::spatial_grid::DataComponent",
    .shortName = "SpatialGrid",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x0d,
    .properties = g_SpatialGridComponent_Properties,
    .propertyCount = sizeof(g_SpatialGridComponent_Properties) / sizeof(g_SpatialGridComponent_Properties[0]),
};

// eoc::spell::AddedSpellsComponent (from Spell.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_AddedSpellsComponent_Properties[] = {
    { "Spells", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_AddedSpellsComponent_Layout = {
    .componentName = "eoc::spell::AddedSpellsComponent",
    .shortName = "AddedSpells",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x08,
    .properties = g_AddedSpellsComponent_Properties,
    .propertyCount = sizeof(g_AddedSpellsComponent_Properties) / sizeof(g_AddedSpellsComponent_Properties[0]),
};

// eoc::spell::AiConditionsComponent (from Spell.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_SpellAiConditionsComponent_Properties[] = {
    { "Conditions", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_SpellAiConditionsComponent_Layout = {
    .componentName = "eoc::spell::AiConditionsComponent",
    .shortName = "SpellAiConditions",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x08,
    .properties = g_SpellAiConditionsComponent_Properties,
    .propertyCount = sizeof(g_SpellAiConditionsComponent_Properties) / sizeof(g_SpellAiConditionsComponent_Properties[0]),
};

// eoc::spell::AttackSpellOverrideComponent (from Spell.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_AttackSpellOverrideComponent_Properties[] = {
    { "AttackSpells", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_AttackSpellOverrideComponent_Layout = {
    .componentName = "eoc::spell::AttackSpellOverrideComponent",
    .shortName = "AttackSpellOverride",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x08,
    .properties = g_AttackSpellOverrideComponent_Properties,
    .propertyCount = sizeof(g_AttackSpellOverrideComponent_Properties) / sizeof(g_AttackSpellOverrideComponent_Properties[0]),
};

// eoc::spell::BookComponent (from Spell.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_SpellBookComponent_Properties[] = {
    { "Entity", 0x00, FIELD_TYPE_UINT64, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "Spells", 0x08, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_SpellBookComponent_Layout = {
    .componentName = "eoc::spell::BookComponent",
    .shortName = "SpellBook",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x10,
    .properties = g_SpellBookComponent_Properties,
    .propertyCount = sizeof(g_SpellBookComponent_Properties) / sizeof(g_SpellBookComponent_Properties[0]),
};

// eoc::spell::BookCooldownsComponent (from Spell.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_SpellBookCooldownsComponent_Properties[] = {
    { "Cooldowns", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_SpellBookCooldownsComponent_Layout = {
    .componentName = "eoc::spell::BookCooldownsComponent",
    .shortName = "SpellBookCooldowns",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x08,
    .properties = g_SpellBookCooldownsComponent_Properties,
    .propertyCount = sizeof(g_SpellBookCooldownsComponent_Properties) / sizeof(g_SpellBookCooldownsComponent_Properties[0]),
};

// eoc::spell::BookPreparesComponent (from Spell.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_SpellBookPreparesComponent_Properties[] = {
    { "PreparedSpells", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "ClassPreparedSpellCount", 0x08, FIELD_TYPE_GUID, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "ClassFallbackPreparedSpellCount", 0x10, FIELD_TYPE_GUID, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_SpellBookPreparesComponent_Layout = {
    .componentName = "eoc::spell::BookPreparesComponent",
    .shortName = "SpellBookPrepares",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x18,
    .properties = g_SpellBookPreparesComponent_Properties,
    .propertyCount = sizeof(g_SpellBookPreparesComponent_Properties) / sizeof(g_SpellBookPreparesComponent_Properties[0]),
};

// eoc::spell::CCPrepareSpellComponent (from Spell.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_CCPrepareSpellComponent_Properties[] = {
    { "Spells", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_CCPrepareSpellComponent_Layout = {
    .componentName = "eoc::spell::CCPrepareSpellComponent",
    .shortName = "CCPrepareSpell",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x08,
    .properties = g_CCPrepareSpellComponent_Properties,
    .propertyCount = sizeof(g_CCPrepareSpellComponent_Properties) / sizeof(g_CCPrepareSpellComponent_Properties[0]),
};

// eoc::spell::ContainerComponent (from Spell.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_SpellContainerComponent_Properties[] = {
    { "Spells", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_SpellContainerComponent_Layout = {
    .componentName = "eoc::spell::ContainerComponent",
    .shortName = "SpellContainer",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x08,
    .properties = g_SpellContainerComponent_Properties,
    .propertyCount = sizeof(g_SpellContainerComponent_Properties) / sizeof(g_SpellContainerComponent_Properties[0]),
};

// eoc::spell::LearnedSpellsComponent (from Spell.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_LearnedSpellsComponent_Properties[] = {
    { "SpellSchools", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_LearnedSpellsComponent_Layout = {
    .componentName = "eoc::spell::LearnedSpellsComponent",
    .shortName = "LearnedSpells",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x08,
    .properties = g_LearnedSpellsComponent_Properties,
    .propertyCount = sizeof(g_LearnedSpellsComponent_Properties) / sizeof(g_LearnedSpellsComponent_Properties[0]),
};

// eoc::spell::PlayerPrepareSpellComponent (from Spell.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_PlayerPrepareSpellComponent_Properties[] = {
    { "Spells", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "CharacterCreationPrepared", 0x08, FIELD_TYPE_BOOL, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_PlayerPrepareSpellComponent_Layout = {
    .componentName = "eoc::spell::PlayerPrepareSpellComponent",
    .shortName = "PlayerPrepareSpell",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x09,
    .properties = g_PlayerPrepareSpellComponent_Properties,
    .propertyCount = sizeof(g_PlayerPrepareSpellComponent_Properties) / sizeof(g_PlayerPrepareSpellComponent_Properties[0]),
};

// eoc::spell::ScriptedExplosionComponent (from Spell.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_ScriptedExplosionComponent_Properties[] = {
    { "Projectile", 0x00, FIELD_TYPE_UINT32, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_ScriptedExplosionComponent_Layout = {
    .componentName = "eoc::spell::ScriptedExplosionComponent",
    .shortName = "ScriptedExplosion",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x04,
    .properties = g_ScriptedExplosionComponent_Properties,
    .propertyCount = sizeof(g_ScriptedExplosionComponent_Properties) / sizeof(g_ScriptedExplosionComponent_Properties[0]),
};

// eoc::spell_cast::AnimationInfoComponent (from SpellCast.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_SpellCastAnimationInfoComponent_Properties[] = {
    { "Event", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "TargetHitPosition", 0x08, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "TargetPosition", 0x10, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "Target", 0x18, FIELD_TYPE_UINT64, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_28", 0x20, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "TargetIsCaster", 0x21, FIELD_TYPE_BOOL, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "LoopingCastAnimation", 0x22, FIELD_TYPE_BOOL, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_2B", 0x23, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "DualWielding", 0x24, FIELD_TYPE_BOOL, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "HasWeapon", 0x25, FIELD_TYPE_BOOL, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "ObjectSize", 0x26, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_SpellCastAnimationInfoComponent_Layout = {
    .componentName = "eoc::spell_cast::AnimationInfoComponent",
    .shortName = "SpellCastAnimationInfo",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x27,
    .properties = g_SpellCastAnimationInfoComponent_Properties,
    .propertyCount = sizeof(g_SpellCastAnimationInfoComponent_Properties) / sizeof(g_SpellCastAnimationInfoComponent_Properties[0]),
};

// eoc::spell_cast::CacheComponent (from SpellCast.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_SpellCastCacheComponent_Properties[] = {
    { "SpellCastingAbility", 0x00, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "Flags", 0x04, FIELD_TYPE_UINT32, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_SpellCastCacheComponent_Layout = {
    .componentName = "eoc::spell_cast::CacheComponent",
    .shortName = "SpellCastCache",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x08,
    .properties = g_SpellCastCacheComponent_Properties,
    .propertyCount = sizeof(g_SpellCastCacheComponent_Properties) / sizeof(g_SpellCastCacheComponent_Properties[0]),
};

// eoc::spell_cast::DataCacheSingletonComponent (from SpellCast.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_SpellCastDataCacheComponent_Properties[] = {
    { "Spells", 0x00, FIELD_TYPE_GUID, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_SpellCastDataCacheComponent_Layout = {
    .componentName = "eoc::spell_cast::DataCacheSingletonComponent",
    .shortName = "SpellCastDataCache",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x08,
    .properties = g_SpellCastDataCacheComponent_Properties,
    .propertyCount = sizeof(g_SpellCastDataCacheComponent_Properties) / sizeof(g_SpellCastDataCacheComponent_Properties[0]),
};

// eoc::spell_cast::ExecutionTimeComponent (from SpellCast.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_SpellCastExecutionTimeComponent_Properties[] = {
    { "Time", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_SpellCastExecutionTimeComponent_Layout = {
    .componentName = "eoc::spell_cast::ExecutionTimeComponent",
    .shortName = "SpellCastExecutionTime",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x08,
    .properties = g_SpellCastExecutionTimeComponent_Properties,
    .propertyCount = sizeof(g_SpellCastExecutionTimeComponent_Properties) / sizeof(g_SpellCastExecutionTimeComponent_Properties[0]),
};

// eoc::spell_cast::InterruptResultsComponent (from SpellCast.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_SpellCastInterruptResultsComponent_Properties[] = {
    { "HasReplacement", 0x00, FIELD_TYPE_BOOL, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "Results", 0x08, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_SpellCastInterruptResultsComponent_Layout = {
    .componentName = "eoc::spell_cast::InterruptResultsComponent",
    .shortName = "SpellCastInterruptResults",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x10,
    .properties = g_SpellCastInterruptResultsComponent_Properties,
    .propertyCount = sizeof(g_SpellCastInterruptResultsComponent_Properties) / sizeof(g_SpellCastInterruptResultsComponent_Properties[0]),
};

// eoc::spell_cast::IsCastingComponent (from SpellCast.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_SpellCastIsCastingComponent_Properties[] = {
    { "Cast", 0x00, FIELD_TYPE_UINT64, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_SpellCastIsCastingComponent_Layout = {
    .componentName = "eoc::spell_cast::IsCastingComponent",
    .shortName = "SpellCastIsCasting",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x08,
    .properties = g_SpellCastIsCastingComponent_Properties,
    .propertyCount = sizeof(g_SpellCastIsCastingComponent_Properties) / sizeof(g_SpellCastIsCastingComponent_Properties[0]),
};

// eoc::spell_cast::MovementComponent (from SpellCast.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_SpellCastMovementComponent_Properties[] = {
    { "Position", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_C", 0x08, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "TextKey", 0x10, FIELD_TYPE_UINT32, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_SpellCastMovementComponent_Layout = {
    .componentName = "eoc::spell_cast::MovementComponent",
    .shortName = "SpellCastMovement",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x14,
    .properties = g_SpellCastMovementComponent_Properties,
    .propertyCount = sizeof(g_SpellCastMovementComponent_Properties) / sizeof(g_SpellCastMovementComponent_Properties[0]),
};

// eoc::spell_cast::OutcomeComponent (from SpellCast.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_SpellCastOutcomeComponent_Properties[] = {
    { "Result", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_SpellCastOutcomeComponent_Layout = {
    .componentName = "eoc::spell_cast::OutcomeComponent",
    .shortName = "SpellCastOutcome",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x08,
    .properties = g_SpellCastOutcomeComponent_Properties,
    .propertyCount = sizeof(g_SpellCastOutcomeComponent_Properties) / sizeof(g_SpellCastOutcomeComponent_Properties[0]),
};

// eoc::spell_cast::RollsComponent (from SpellCast.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_SpellCastRollsComponent_Properties[] = {
    { "Rolls", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_SpellCastRollsComponent_Layout = {
    .componentName = "eoc::spell_cast::RollsComponent",
    .shortName = "SpellCastRolls",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x08,
    .properties = g_SpellCastRollsComponent_Properties,
    .propertyCount = sizeof(g_SpellCastRollsComponent_Properties) / sizeof(g_SpellCastRollsComponent_Properties[0]),
};

// eoc::spell_cast::StateComponent (from SpellCast.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_SpellCastStateComponent_Properties[] = {
    { "Entity", 0x00, FIELD_TYPE_UINT64, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "Caster", 0x08, FIELD_TYPE_UINT64, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "SpellId", 0x10, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "CastOptions", 0x18, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "Targets", 0x20, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "CastPosition", 0x28, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "CastEndPosition", 0x30, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "CasterStartPosition", 0x38, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "Source", 0x40, FIELD_TYPE_UINT64, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "Random", 0x48, FIELD_TYPE_UINT32, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "SpellCastGuid", 0x50, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "NetGuid", 0x60, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_SpellCastStateComponent_Layout = {
    .componentName = "eoc::spell_cast::StateComponent",
    .shortName = "SpellCastState",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x68,
    .properties = g_SpellCastStateComponent_Properties,
    .propertyCount = sizeof(g_SpellCastStateComponent_Properties) / sizeof(g_SpellCastStateComponent_Properties[0]),
};

// eoc::spell_cast::SyncTargetingComponent (from SpellCast.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_SpellSyncTargetingComponent_Properties[] = {
    { "Target", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "Targets", 0x08, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "CanMoveToThrowTarget", 0x10, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_44", 0x14, FIELD_TYPE_INT32, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_48", 0x18, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "HoverPosition", 0x20, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "CasterPosition", 0x28, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "CasterMoveToPosition", 0x30, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_88", 0x38, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_SpellSyncTargetingComponent_Layout = {
    .componentName = "eoc::spell_cast::SyncTargetingComponent",
    .shortName = "SpellSyncTargeting",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x40,
    .properties = g_SpellSyncTargetingComponent_Properties,
    .propertyCount = sizeof(g_SpellSyncTargetingComponent_Properties) / sizeof(g_SpellSyncTargetingComponent_Properties[0]),
};

// eoc::stats::proficiency::ProficiencyComponent (from Data.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_ProficiencyComponent_Properties[] = {
    { "Flags", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_ProficiencyComponent_Layout = {
    .componentName = "eoc::stats::proficiency::ProficiencyComponent",
    .shortName = "Proficiency",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x08,
    .properties = g_ProficiencyComponent_Properties,
    .propertyCount = sizeof(g_ProficiencyComponent_Properties) / sizeof(g_ProficiencyComponent_Properties[0]),
};

// eoc::stats::proficiency::ProficiencyGroupComponent (from Data.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_ProficiencyGroupComponent_Properties[] = {
    { "Flags", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_ProficiencyGroupComponent_Layout = {
    .componentName = "eoc::stats::proficiency::ProficiencyGroupComponent",
    .shortName = "ProficiencyGroup",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x08,
    .properties = g_ProficiencyGroupComponent_Properties,
    .propertyCount = sizeof(g_ProficiencyGroupComponent_Properties) / sizeof(g_ProficiencyGroupComponent_Properties[0]),
};

// eoc::status::CauseComponent (from Status.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_StatusCauseComponent_Properties[] = {
    { "Cause", 0x00, FIELD_TYPE_UINT64, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_StatusCauseComponent_Layout = {
    .componentName = "eoc::status::CauseComponent",
    .shortName = "StatusCause",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x08,
    .properties = g_StatusCauseComponent_Properties,
    .propertyCount = sizeof(g_StatusCauseComponent_Properties) / sizeof(g_StatusCauseComponent_Properties[0]),
};

// eoc::status::ContainerComponent (from Status.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_StatusContainerComponent_Properties[] = {
    { "Statuses", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_StatusContainerComponent_Layout = {
    .componentName = "eoc::status::ContainerComponent",
    .shortName = "StatusContainer",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x08,
    .properties = g_StatusContainerComponent_Properties,
    .propertyCount = sizeof(g_StatusContainerComponent_Properties) / sizeof(g_StatusContainerComponent_Properties[0]),
};

// eoc::status::IDComponent (from Status.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_StatusIDComponent_Properties[] = {
    { "ID", 0x00, FIELD_TYPE_UINT32, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_StatusIDComponent_Layout = {
    .componentName = "eoc::status::IDComponent",
    .shortName = "StatusID",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x04,
    .properties = g_StatusIDComponent_Properties,
    .propertyCount = sizeof(g_StatusIDComponent_Properties) / sizeof(g_StatusIDComponent_Properties[0]),
};

// eoc::status::IncapacitatedComponent (from Status.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_StatusIncapacitatedComponent_Properties[] = {
    { "field_0", 0x00, FIELD_TYPE_UINT32, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_48", 0x04, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_StatusIncapacitatedComponent_Layout = {
    .componentName = "eoc::status::IncapacitatedComponent",
    .shortName = "StatusIncapacitated",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x05,
    .properties = g_StatusIncapacitatedComponent_Properties,
    .propertyCount = sizeof(g_StatusIncapacitatedComponent_Properties) / sizeof(g_StatusIncapacitatedComponent_Properties[0]),
};

// eoc::status::LifetimeComponent (from Status.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_StatusLifetimeComponent_Properties[] = {
    { "field_0", 0x00, FIELD_TYPE_INT32, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "Lifetime", 0x04, FIELD_TYPE_FLOAT, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_StatusLifetimeComponent_Layout = {
    .componentName = "eoc::status::LifetimeComponent",
    .shortName = "StatusLifetime",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x08,
    .properties = g_StatusLifetimeComponent_Properties,
    .propertyCount = sizeof(g_StatusLifetimeComponent_Properties) / sizeof(g_StatusLifetimeComponent_Properties[0]),
};

// eoc::status::LoseControlComponent (from Status.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_StatusLoseControlComponent_Properties[] = {
    { "LoseControl", 0x00, FIELD_TYPE_BOOL, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_StatusLoseControlComponent_Layout = {
    .componentName = "eoc::status::LoseControlComponent",
    .shortName = "StatusLoseControl",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x01,
    .properties = g_StatusLoseControlComponent_Properties,
    .propertyCount = sizeof(g_StatusLoseControlComponent_Properties) / sizeof(g_StatusLoseControlComponent_Properties[0]),
};

// eoc::status::visual::DisabledComponent (from Status.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_StatusVisualDisabledComponent_Properties[] = {
    { "Visuals", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_StatusVisualDisabledComponent_Layout = {
    .componentName = "eoc::status::visual::DisabledComponent",
    .shortName = "StatusVisualDisabled",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x08,
    .properties = g_StatusVisualDisabledComponent_Properties,
    .propertyCount = sizeof(g_StatusVisualDisabledComponent_Properties) / sizeof(g_StatusVisualDisabledComponent_Properties[0]),
};

// eoc::summon::ContainerComponent (from Data.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_SummonContainerComponent_Properties[] = {
    { "Characters", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "Items", 0x08, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_SummonContainerComponent_Layout = {
    .componentName = "eoc::summon::ContainerComponent",
    .shortName = "SummonContainer",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x10,
    .properties = g_SummonContainerComponent_Properties,
    .propertyCount = sizeof(g_SummonContainerComponent_Properties) / sizeof(g_SummonContainerComponent_Properties[0]),
};

// eoc::summon::IsSummonComponent (from Data.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_IsSummonComponent_Properties[] = {
    { "Owner", 0x00, FIELD_TYPE_UINT64, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "Summoner", 0x08, FIELD_TYPE_UINT64, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_10", 0x10, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_20", 0x20, FIELD_TYPE_UINT64, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_28", 0x28, FIELD_TYPE_UINT32, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_IsSummonComponent_Layout = {
    .componentName = "eoc::summon::IsSummonComponent",
    .shortName = "IsSummon",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x2c,
    .properties = g_IsSummonComponent_Properties,
    .propertyCount = sizeof(g_IsSummonComponent_Properties) / sizeof(g_IsSummonComponent_Properties[0]),
};

// eoc::summon::LifetimeComponent (from Data.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_SummonLifetimeComponent_Properties[] = {
    { "Lifetime", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_SummonLifetimeComponent_Layout = {
    .componentName = "eoc::summon::LifetimeComponent",
    .shortName = "SummonLifetime",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x08,
    .properties = g_SummonLifetimeComponent_Properties,
    .propertyCount = sizeof(g_SummonLifetimeComponent_Properties) / sizeof(g_SummonLifetimeComponent_Properties[0]),
};

// eoc::tadpole_tree::PowerContainerComponent (from Tadpole.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_TadpolePowersComponent_Properties[] = {
    { "Powers", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_TadpolePowersComponent_Layout = {
    .componentName = "eoc::tadpole_tree::PowerContainerComponent",
    .shortName = "TadpolePowers",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x08,
    .properties = g_TadpolePowersComponent_Properties,
    .propertyCount = sizeof(g_TadpolePowersComponent_Properties) / sizeof(g_TadpolePowersComponent_Properties[0]),
};

// eoc::tadpole_tree::TreeStateComponent (from Tadpole.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_TadpoleTreeStateComponent_Properties[] = {
    { "State", 0x00, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_TadpoleTreeStateComponent_Layout = {
    .componentName = "eoc::tadpole_tree::TreeStateComponent",
    .shortName = "TadpoleTreeState",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x01,
    .properties = g_TadpoleTreeStateComponent_Properties,
    .propertyCount = sizeof(g_TadpoleTreeStateComponent_Properties) / sizeof(g_TadpoleTreeStateComponent_Properties[0]),
};

// eoc::templates::OriginalTemplateComponent (from Components.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_OriginalTemplateComponent_Properties[] = {
    { "OriginalTemplate", 0x00, FIELD_TYPE_UINT32, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "TemplateType", 0x04, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_OriginalTemplateComponent_Layout = {
    .componentName = "eoc::templates::OriginalTemplateComponent",
    .shortName = "OriginalTemplate",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x05,
    .properties = g_OriginalTemplateComponent_Properties,
    .propertyCount = sizeof(g_OriginalTemplateComponent_Properties) / sizeof(g_OriginalTemplateComponent_Properties[0]),
};

// eoc::through::ShootThroughTypeComponent (from Components.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_ShootThroughTypeComponent_Properties[] = {
    { "Type", 0x00, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_ShootThroughTypeComponent_Layout = {
    .componentName = "eoc::through::ShootThroughTypeComponent",
    .shortName = "ShootThroughType",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x01,
    .properties = g_ShootThroughTypeComponent_Properties,
    .propertyCount = sizeof(g_ShootThroughTypeComponent_Properties) / sizeof(g_ShootThroughTypeComponent_Properties[0]),
};

// eoc::trigger::TypeComponent (from Trigger.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_TriggerTypeComponent_Properties[] = {
    { "Type", 0x00, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_TriggerTypeComponent_Layout = {
    .componentName = "eoc::trigger::TypeComponent",
    .shortName = "TriggerType",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x01,
    .properties = g_TriggerTypeComponent_Properties,
    .propertyCount = sizeof(g_TriggerTypeComponent_Properties) / sizeof(g_TriggerTypeComponent_Properties[0]),
};

// eoc::unsheath::StateComponent (from Components.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_UnsheathComponent_Properties[] = {
    { "MainHandWeapon", 0x00, FIELD_TYPE_UINT64, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "OffHandWeapon", 0x08, FIELD_TYPE_UINT64, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_10", 0x10, FIELD_TYPE_INT32, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "State", 0x18, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_18", 0x20, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_19", 0x21, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_1A", 0x22, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_UnsheathComponent_Layout = {
    .componentName = "eoc::unsheath::StateComponent",
    .shortName = "Unsheath",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x23,
    .properties = g_UnsheathComponent_Properties,
    .propertyCount = sizeof(g_UnsheathComponent_Properties) / sizeof(g_UnsheathComponent_Properties[0]),
};

// eoc::use::SocketComponent (from Components.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_UseSocketComponent_Properties[] = {
    { "Sockets", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_UseSocketComponent_Layout = {
    .componentName = "eoc::use::SocketComponent",
    .shortName = "UseSocket",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x08,
    .properties = g_UseSocketComponent_Properties,
    .propertyCount = sizeof(g_UseSocketComponent_Properties) / sizeof(g_UseSocketComponent_Properties[0]),
};

// eoc::user::AvatarComponent (from Components.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_UserAvatarComponent_Properties[] = {
    { "UserID", 0x00, FIELD_TYPE_INT32, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "OwnerProfileID", 0x04, FIELD_TYPE_UINT32, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_8", 0x08, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_UserAvatarComponent_Layout = {
    .componentName = "eoc::user::AvatarComponent",
    .shortName = "UserAvatar",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x09,
    .properties = g_UserAvatarComponent_Properties,
    .propertyCount = sizeof(g_UserAvatarComponent_Properties) / sizeof(g_UserAvatarComponent_Properties[0]),
};

// eoc::user::ReservedForComponent (from Components.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_UserReservedForComponent_Properties[] = {
    { "UserID", 0x00, FIELD_TYPE_INT32, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_UserReservedForComponent_Layout = {
    .componentName = "eoc::user::ReservedForComponent",
    .shortName = "UserReservedFor",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x04,
    .properties = g_UserReservedForComponent_Properties,
    .propertyCount = sizeof(g_UserReservedForComponent_Properties) / sizeof(g_UserReservedForComponent_Properties[0]),
};

// esv::ActivationGroupContainerComponent (from ServerData.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_ServerActivationGroupContainerComponent_Properties[] = {
    { "Groups", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_ServerActivationGroupContainerComponent_Layout = {
    .componentName = "esv::ActivationGroupContainerComponent",
    .shortName = "ServerActivationGroupContainer",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x08,
    .properties = g_ServerActivationGroupContainerComponent_Properties,
    .propertyCount = sizeof(g_ServerActivationGroupContainerComponent_Properties) / sizeof(g_ServerActivationGroupContainerComponent_Properties[0]),
};

// esv::BaseDataComponent (from ServerData.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_ServerBaseDataComponent_Properties[] = {
    { "Weight", 0x00, FIELD_TYPE_INT32, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "Flags", 0x04, FIELD_TYPE_UINT32, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_ServerBaseDataComponent_Layout = {
    .componentName = "esv::BaseDataComponent",
    .shortName = "ServerBaseData",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x08,
    .properties = g_ServerBaseDataComponent_Properties,
    .propertyCount = sizeof(g_ServerBaseDataComponent_Properties) / sizeof(g_ServerBaseDataComponent_Properties[0]),
};

// esv::BaseSizeComponent (from ServerData.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_ServerBaseSizeComponent_Properties[] = {
    { "GameSize", 0x00, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "SoundSize", 0x01, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_ServerBaseSizeComponent_Layout = {
    .componentName = "esv::BaseSizeComponent",
    .shortName = "ServerBaseSize",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x02,
    .properties = g_ServerBaseSizeComponent_Properties,
    .propertyCount = sizeof(g_ServerBaseSizeComponent_Properties) / sizeof(g_ServerBaseSizeComponent_Properties[0]),
};

// esv::BaseStatsComponent (from ServerData.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_ServerBaseStatsComponent_Properties[] = {
    { "Initiative", 0x00, FIELD_TYPE_INT32, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_ServerBaseStatsComponent_Layout = {
    .componentName = "esv::BaseStatsComponent",
    .shortName = "ServerBaseStats",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x04,
    .properties = g_ServerBaseStatsComponent_Properties,
    .propertyCount = sizeof(g_ServerBaseStatsComponent_Properties) / sizeof(g_ServerBaseStatsComponent_Properties[0]),
};

// esv::BaseWeaponComponent (from ServerData.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_ServerBaseWeaponComponent_Properties[] = {
    { "DamageList", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_ServerBaseWeaponComponent_Layout = {
    .componentName = "esv::BaseWeaponComponent",
    .shortName = "ServerBaseWeapon",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x08,
    .properties = g_ServerBaseWeaponComponent_Properties,
    .propertyCount = sizeof(g_ServerBaseWeaponComponent_Properties) / sizeof(g_ServerBaseWeaponComponent_Properties[0]),
};

// esv::BreadcrumbComponent (from ServerData.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_ServerBreadcrumbComponent_Properties[] = {
    { "field_18", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_118", 0x08, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_ServerBreadcrumbComponent_Layout = {
    .componentName = "esv::BreadcrumbComponent",
    .shortName = "ServerBreadcrumb",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x10,
    .properties = g_ServerBreadcrumbComponent_Properties,
    .propertyCount = sizeof(g_ServerBreadcrumbComponent_Properties) / sizeof(g_ServerBreadcrumbComponent_Properties[0]),
};

// esv::CharacterCreationCustomIconComponent (from CharacterCreation.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_ServerCCCustomIconComponent_Properties[] = {
    { "Icon", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_ServerCCCustomIconComponent_Layout = {
    .componentName = "esv::CharacterCreationCustomIconComponent",
    .shortName = "ServerCCCustomIcon",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x08,
    .properties = g_ServerCCCustomIconComponent_Properties,
    .propertyCount = sizeof(g_ServerCCCustomIconComponent_Properties) / sizeof(g_ServerCCCustomIconComponent_Properties[0]),
};

// esv::DisplayNameListComponent (from Visual.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_ServerDisplayNameListComponent_Properties[] = {
    { "Names", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "Titles", 0x08, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "HideTitle", 0x10, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_ServerDisplayNameListComponent_Layout = {
    .componentName = "esv::DisplayNameListComponent",
    .shortName = "ServerDisplayNameList",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x11,
    .properties = g_ServerDisplayNameListComponent_Properties,
    .propertyCount = sizeof(g_ServerDisplayNameListComponent_Properties) / sizeof(g_ServerDisplayNameListComponent_Properties[0]),
};

// esv::GameTimerComponent (from ServerData.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_ServerGameTimerComponent_Properties[] = {
    { "field_18", 0x00, FIELD_TYPE_UINT32, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_20", 0x08, FIELD_TYPE_UINT64, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_28", 0x10, FIELD_TYPE_INT32, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_2C", 0x14, FIELD_TYPE_INT32, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_30", 0x18, FIELD_TYPE_INT32, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_34", 0x1c, FIELD_TYPE_INT32, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_38", 0x20, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_ServerGameTimerComponent_Layout = {
    .componentName = "esv::GameTimerComponent",
    .shortName = "ServerGameTimer",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x21,
    .properties = g_ServerGameTimerComponent_Properties,
    .propertyCount = sizeof(g_ServerGameTimerComponent_Properties) / sizeof(g_ServerGameTimerComponent_Properties[0]),
};

// esv::GameplayLightEquipmentComponent (from ServerData.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_ServerGameplayLightEquipmentComponent_Properties[] = {
    { "field_0", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_ServerGameplayLightEquipmentComponent_Layout = {
    .componentName = "esv::GameplayLightEquipmentComponent",
    .shortName = "ServerGameplayLightEquipment",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x08,
    .properties = g_ServerGameplayLightEquipmentComponent_Properties,
    .propertyCount = sizeof(g_ServerGameplayLightEquipmentComponent_Properties) / sizeof(g_ServerGameplayLightEquipmentComponent_Properties[0]),
};

// esv::IconListComponent (from Visual.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_ServerIconListComponent_Properties[] = {
    { "Icons", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_ServerIconListComponent_Layout = {
    .componentName = "esv::IconListComponent",
    .shortName = "ServerIconList",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x08,
    .properties = g_ServerIconListComponent_Properties,
    .propertyCount = sizeof(g_ServerIconListComponent_Properties) / sizeof(g_ServerIconListComponent_Properties[0]),
};

// esv::InventoryPropertyCanBePickpocketedComponent (from Inventory.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_InventoryPropertyCanBePickpocketedComponent_Properties[] = {
    { "Tag", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_InventoryPropertyCanBePickpocketedComponent_Layout = {
    .componentName = "esv::InventoryPropertyCanBePickpocketedComponent",
    .shortName = "InventoryPropertyCanBePickpocketed",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x08,
    .properties = g_InventoryPropertyCanBePickpocketedComponent_Properties,
    .propertyCount = sizeof(g_InventoryPropertyCanBePickpocketedComponent_Properties) / sizeof(g_InventoryPropertyCanBePickpocketedComponent_Properties[0]),
};

// esv::InventoryPropertyIsDroppedOnDeathComponent (from Inventory.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_InventoryPropertyIsDroppedOnDeathComponent_Properties[] = {
    { "Tag", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_InventoryPropertyIsDroppedOnDeathComponent_Layout = {
    .componentName = "esv::InventoryPropertyIsDroppedOnDeathComponent",
    .shortName = "InventoryPropertyIsDroppedOnDeath",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x08,
    .properties = g_InventoryPropertyIsDroppedOnDeathComponent_Properties,
    .propertyCount = sizeof(g_InventoryPropertyIsDroppedOnDeathComponent_Properties) / sizeof(g_InventoryPropertyIsDroppedOnDeathComponent_Properties[0]),
};

// esv::InventoryPropertyIsTradableComponent (from Inventory.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_InventoryPropertyIsTradableComponent_Properties[] = {
    { "Tag", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_InventoryPropertyIsTradableComponent_Layout = {
    .componentName = "esv::InventoryPropertyIsTradableComponent",
    .shortName = "InventoryPropertyIsTradable",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x08,
    .properties = g_InventoryPropertyIsTradableComponent_Properties,
    .propertyCount = sizeof(g_InventoryPropertyIsTradableComponent_Properties) / sizeof(g_InventoryPropertyIsTradableComponent_Properties[0]),
};

// esv::JumpFollowComponent (from ServerData.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_JumpFollowComponent_Properties[] = {
    { "field_0", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_C", 0x08, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_18", 0x10, FIELD_TYPE_INT32, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_1C", 0x14, FIELD_TYPE_INT32, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_20", 0x18, FIELD_TYPE_INT32, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_24", 0x20, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_30", 0x28, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_3C", 0x30, FIELD_TYPE_FLOAT, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_40", 0x34, FIELD_TYPE_FLOAT, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_44", 0x38, FIELD_TYPE_FLOAT, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_48", 0x3c, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_4C", 0x40, FIELD_TYPE_FLOAT, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "Spell", 0x48, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "ProjectileTerrainOffset", 0x50, FIELD_TYPE_FLOAT, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "DangerousAuras", 0x58, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_B0_AvoidArea", 0x60, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_C0_AvoidArea", 0x68, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_D0", 0x70, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_D4", 0x78, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_E0", 0x80, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_EC", 0x88, FIELD_TYPE_INT32, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_F0", 0x90, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_F8", 0x98, FIELD_TYPE_INT32, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_FC", 0xa0, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_108", 0xa8, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_114", 0xb0, FIELD_TYPE_INT32, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_118", 0xb4, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_11C", 0xb8, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_128", 0xc0, FIELD_TYPE_INT32, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_12C", 0xc4, FIELD_TYPE_INT32, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_130", 0xc8, FIELD_TYPE_UINT32, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_134", 0xcc, FIELD_TYPE_UINT32, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_138", 0xd0, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_139", 0xd1, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_13A", 0xd2, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_JumpFollowComponent_Layout = {
    .componentName = "esv::JumpFollowComponent",
    .shortName = "JumpFollow",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0xd3,
    .properties = g_JumpFollowComponent_Properties,
    .propertyCount = sizeof(g_JumpFollowComponent_Properties) / sizeof(g_JumpFollowComponent_Properties[0]),
};

// esv::LeaderComponent (from ServerData.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_ServerLeaderComponent_Properties[] = {
    { "Followers_M", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_ServerLeaderComponent_Layout = {
    .componentName = "esv::LeaderComponent",
    .shortName = "ServerLeader",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x08,
    .properties = g_ServerLeaderComponent_Properties,
    .propertyCount = sizeof(g_ServerLeaderComponent_Properties) / sizeof(g_ServerLeaderComponent_Properties[0]),
};

// esv::MusicVolumeTriggerStateComponent (from Trigger.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_ServerMusicVolumeTriggerStateComponent_Properties[] = {
    { "Triggered", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_ServerMusicVolumeTriggerStateComponent_Layout = {
    .componentName = "esv::MusicVolumeTriggerStateComponent",
    .shortName = "ServerMusicVolumeTriggerState",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x08,
    .properties = g_ServerMusicVolumeTriggerStateComponent_Properties,
    .propertyCount = sizeof(g_ServerMusicVolumeTriggerStateComponent_Properties) / sizeof(g_ServerMusicVolumeTriggerStateComponent_Properties[0]),
};

// esv::OsirisPingRequestSingletonComponent (from Data.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_ServerOsirisPingRequestSingletonComponent_Properties[] = {
    { "Pings", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_ServerOsirisPingRequestSingletonComponent_Layout = {
    .componentName = "esv::OsirisPingRequestSingletonComponent",
    .shortName = "ServerOsirisPingRequestSingleton",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x08,
    .properties = g_ServerOsirisPingRequestSingletonComponent_Properties,
    .propertyCount = sizeof(g_ServerOsirisPingRequestSingletonComponent_Properties) / sizeof(g_ServerOsirisPingRequestSingletonComponent_Properties[0]),
};

// esv::PingCooldownSingletonComponent (from Data.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_ServerPingCooldownSingletonComponent_Properties[] = {
    { "Cooldowns", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_ServerPingCooldownSingletonComponent_Layout = {
    .componentName = "esv::PingCooldownSingletonComponent",
    .shortName = "ServerPingCooldownSingleton",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x08,
    .properties = g_ServerPingCooldownSingletonComponent_Properties,
    .propertyCount = sizeof(g_ServerPingCooldownSingletonComponent_Properties) / sizeof(g_ServerPingCooldownSingletonComponent_Properties[0]),
};

// esv::PingRequestSingletonComponent (from Data.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_ServerPingRequestSingletonComponent_Properties[] = {
    { "Pings", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_ServerPingRequestSingletonComponent_Layout = {
    .componentName = "esv::PingRequestSingletonComponent",
    .shortName = "ServerPingRequestSingleton",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x08,
    .properties = g_ServerPingRequestSingletonComponent_Properties,
    .propertyCount = sizeof(g_ServerPingRequestSingletonComponent_Properties) / sizeof(g_ServerPingRequestSingletonComponent_Properties[0]),
};

// esv::SafePositionComponent (from ServerData.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_ServerSafePositionComponent_Properties[] = {
    { "Position", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_24", 0x08, FIELD_TYPE_BOOL, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_ServerSafePositionComponent_Layout = {
    .componentName = "esv::SafePositionComponent",
    .shortName = "ServerSafePosition",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x09,
    .properties = g_ServerSafePositionComponent_Properties,
    .propertyCount = sizeof(g_ServerSafePositionComponent_Properties) / sizeof(g_ServerSafePositionComponent_Properties[0]),
};

// esv::action_resource::ResourceChangeResultsSingletonComponent (from ActionResources.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_ActionResourceChangeResultsComponent_Properties[] = {
    { "Results", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_ActionResourceChangeResultsComponent_Layout = {
    .componentName = "esv::action_resource::ResourceChangeResultsSingletonComponent",
    .shortName = "ActionResourceChangeResults",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x08,
    .properties = g_ActionResourceChangeResultsComponent_Properties,
    .propertyCount = sizeof(g_ActionResourceChangeResultsComponent_Properties) / sizeof(g_ActionResourceChangeResultsComponent_Properties[0]),
};

// esv::active_roll::InProgressComponent (from Roll.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_ServerRollInProgressComponent_Properties[] = {
    { "Position", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "Entity", 0x08, FIELD_TYPE_UINT64, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_ServerRollInProgressComponent_Layout = {
    .componentName = "esv::active_roll::InProgressComponent",
    .shortName = "ServerRollInProgress",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x10,
    .properties = g_ServerRollInProgressComponent_Properties,
    .propertyCount = sizeof(g_ServerRollInProgressComponent_Properties) / sizeof(g_ServerRollInProgressComponent_Properties[0]),
};

// esv::active_roll::StartRequestOneFrameComponent (from Roll.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_ServerRollStartRequestComponent_Properties[] = {
    { "field_0", 0x00, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_10", 0x10, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_ServerRollStartRequestComponent_Layout = {
    .componentName = "esv::active_roll::StartRequestOneFrameComponent",
    .shortName = "ServerRollStartRequest",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x11,
    .properties = g_ServerRollStartRequestComponent_Properties,
    .propertyCount = sizeof(g_ServerRollStartRequestComponent_Properties) / sizeof(g_ServerRollStartRequestComponent_Properties[0]),
};

// esv::ai::combat::AiModifiersComponent (from Combat.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_ServerAiModifiersComponent_Properties[] = {
    { "field_0", 0x00, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "Modifiers", 0x08, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_ServerAiModifiersComponent_Layout = {
    .componentName = "esv::ai::combat::AiModifiersComponent",
    .shortName = "ServerAiModifiers",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x10,
    .properties = g_ServerAiModifiersComponent_Properties,
    .propertyCount = sizeof(g_ServerAiModifiersComponent_Properties) / sizeof(g_ServerAiModifiersComponent_Properties[0]),
};

// esv::ai::combat::ArchetypeComponent (from Combat.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_ServerAiArchetypeComponent_Properties[] = {
    { "field_0", 0x00, FIELD_TYPE_UINT32, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_4", 0x04, FIELD_TYPE_UINT32, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_8", 0x08, FIELD_TYPE_UINT32, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_C", 0x0c, FIELD_TYPE_UINT32, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_ServerAiArchetypeComponent_Layout = {
    .componentName = "esv::ai::combat::ArchetypeComponent",
    .shortName = "ServerAiArchetype",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x10,
    .properties = g_ServerAiArchetypeComponent_Properties,
    .propertyCount = sizeof(g_ServerAiArchetypeComponent_Properties) / sizeof(g_ServerAiArchetypeComponent_Properties[0]),
};

// esv::ai::combat::InterestedInItemsComponent (from Combat.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_ServerAiInterestedInItemsComponent_Properties[] = {
    { "Items", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_ServerAiInterestedInItemsComponent_Layout = {
    .componentName = "esv::ai::combat::InterestedInItemsComponent",
    .shortName = "ServerAiInterestedInItems",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x08,
    .properties = g_ServerAiInterestedInItemsComponent_Properties,
    .propertyCount = sizeof(g_ServerAiInterestedInItemsComponent_Properties) / sizeof(g_ServerAiInterestedInItemsComponent_Properties[0]),
};

// esv::ai::combat::InterestingItemComponent (from Combat.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_ServerAiInterestingItemComponent_Properties[] = {
    { "Items", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_ServerAiInterestingItemComponent_Layout = {
    .componentName = "esv::ai::combat::InterestingItemComponent",
    .shortName = "ServerAiInterestingItem",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x08,
    .properties = g_ServerAiInterestingItemComponent_Properties,
    .propertyCount = sizeof(g_ServerAiInterestingItemComponent_Properties) / sizeof(g_ServerAiInterestingItemComponent_Properties[0]),
};

// esv::boost::BaseComponent (from Boosts.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_ServerBoostBaseComponent_Properties[] = {
    { "field_0", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_ServerBoostBaseComponent_Layout = {
    .componentName = "esv::boost::BaseComponent",
    .shortName = "ServerBoostBase",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x08,
    .properties = g_ServerBoostBaseComponent_Properties,
    .propertyCount = sizeof(g_ServerBoostBaseComponent_Properties) / sizeof(g_ServerBoostBaseComponent_Properties[0]),
};

// esv::boost::ConditionalStateComponent (from Boosts.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_BoostConditionalStateComponent_Properties[] = {
    { "States", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_BoostConditionalStateComponent_Layout = {
    .componentName = "esv::boost::ConditionalStateComponent",
    .shortName = "BoostConditionalState",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x08,
    .properties = g_BoostConditionalStateComponent_Properties,
    .propertyCount = sizeof(g_BoostConditionalStateComponent_Properties) / sizeof(g_BoostConditionalStateComponent_Properties[0]),
};

// esv::boost::ProviderComponent (from Boosts.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_BoostProviderComponent_Properties[] = {
    { "field_0", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_10", 0x08, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_BoostProviderComponent_Layout = {
    .componentName = "esv::boost::ProviderComponent",
    .shortName = "BoostProvider",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x10,
    .properties = g_BoostProviderComponent_Properties,
    .propertyCount = sizeof(g_BoostProviderComponent_Properties) / sizeof(g_BoostProviderComponent_Properties[0]),
};

// esv::character_creation::AppearanceVisualTagComponent (from CharacterCreation.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_ServerCCAppearanceVisualTagComponent_Properties[] = {
    { "Tags", 0x00, FIELD_TYPE_GUID, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_ServerCCAppearanceVisualTagComponent_Layout = {
    .componentName = "esv::character_creation::AppearanceVisualTagComponent",
    .shortName = "ServerCCAppearanceVisualTag",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x08,
    .properties = g_ServerCCAppearanceVisualTagComponent_Properties,
    .propertyCount = sizeof(g_ServerCCAppearanceVisualTagComponent_Properties) / sizeof(g_ServerCCAppearanceVisualTagComponent_Properties[0]),
};

// esv::character_creation::GodComponent (from CharacterCreation.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_ServerCCGodComponent_Properties[] = {
    { "God", 0x00, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_ServerCCGodComponent_Layout = {
    .componentName = "esv::character_creation::GodComponent",
    .shortName = "ServerCCGod",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x10,
    .properties = g_ServerCCGodComponent_Properties,
    .propertyCount = sizeof(g_ServerCCGodComponent_Properties) / sizeof(g_ServerCCGodComponent_Properties[0]),
};

// esv::character_creation::UpdatesComponent (from CharacterCreation.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_ServerCCUpdatesComponent_Properties[] = {
    { "Updates", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_ServerCCUpdatesComponent_Layout = {
    .componentName = "esv::character_creation::UpdatesComponent",
    .shortName = "ServerCCUpdates",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x08,
    .properties = g_ServerCCUpdatesComponent_Properties,
    .propertyCount = sizeof(g_ServerCCUpdatesComponent_Properties) / sizeof(g_ServerCCUpdatesComponent_Properties[0]),
};

// esv::combat::CombatGroupMappingComponent (from Combat.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_ServerCombatGroupMappingComponent_Properties[] = {
    { "Entity", 0x00, FIELD_TYPE_UINT64, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_ServerCombatGroupMappingComponent_Layout = {
    .componentName = "esv::combat::CombatGroupMappingComponent",
    .shortName = "ServerCombatGroupMapping",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x08,
    .properties = g_ServerCombatGroupMappingComponent_Properties,
    .propertyCount = sizeof(g_ServerCombatGroupMappingComponent_Properties) / sizeof(g_ServerCombatGroupMappingComponent_Properties[0]),
};

// esv::combat::CombatSwitchedComponent (from Combat.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_CombatSwitchedComponent_Properties[] = {
    { "field_0", 0x00, FIELD_TYPE_UINT64, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_8", 0x08, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_18", 0x18, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_28", 0x28, FIELD_TYPE_UINT64, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_CombatSwitchedComponent_Layout = {
    .componentName = "esv::combat::CombatSwitchedComponent",
    .shortName = "CombatSwitched",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x30,
    .properties = g_CombatSwitchedComponent_Properties,
    .propertyCount = sizeof(g_CombatSwitchedComponent_Properties) / sizeof(g_CombatSwitchedComponent_Properties[0]),
};

// esv::combat::EnterRequestComponent (from Combat.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_ServerEnterRequestComponent_Properties[] = {
    { "EnterRequests", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_ServerEnterRequestComponent_Layout = {
    .componentName = "esv::combat::EnterRequestComponent",
    .shortName = "ServerEnterRequest",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x08,
    .properties = g_ServerEnterRequestComponent_Properties,
    .propertyCount = sizeof(g_ServerEnterRequestComponent_Properties) / sizeof(g_ServerEnterRequestComponent_Properties[0]),
};

// esv::combat::FleeRequestComponent (from Combat.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_CombatFleeRequestComponent_Properties[] = {
    { "RequestGuid", 0x00, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "UserID", 0x10, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_CombatFleeRequestComponent_Layout = {
    .componentName = "esv::combat::FleeRequestComponent",
    .shortName = "CombatFleeRequest",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x18,
    .properties = g_CombatFleeRequestComponent_Properties,
    .propertyCount = sizeof(g_CombatFleeRequestComponent_Properties) / sizeof(g_CombatFleeRequestComponent_Properties[0]),
};

// esv::combat::GlobalCombatRequests (from Combat.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_GlobalCombatRequestsComponent_Properties[] = {
    { "Requests", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_GlobalCombatRequestsComponent_Layout = {
    .componentName = "esv::combat::GlobalCombatRequests",
    .shortName = "GlobalCombatRequests",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x08,
    .properties = g_GlobalCombatRequestsComponent_Properties,
    .propertyCount = sizeof(g_GlobalCombatRequestsComponent_Properties) / sizeof(g_GlobalCombatRequestsComponent_Properties[0]),
};

// esv::combat::JoiningComponent (from Combat.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_CombatJoiningComponent_Properties[] = {
    { "field_0", 0x00, FIELD_TYPE_FLOAT, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_CombatJoiningComponent_Layout = {
    .componentName = "esv::combat::JoiningComponent",
    .shortName = "CombatJoining",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x04,
    .properties = g_CombatJoiningComponent_Properties,
    .propertyCount = sizeof(g_CombatJoiningComponent_Properties) / sizeof(g_CombatJoiningComponent_Properties[0]),
};

// esv::combat::LateJoinPenaltyComponent (from Combat.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_CombatLateJoinPenaltyComponent_Properties[] = {
    { "field_0", 0x00, FIELD_TYPE_FLOAT, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_CombatLateJoinPenaltyComponent_Layout = {
    .componentName = "esv::combat::LateJoinPenaltyComponent",
    .shortName = "CombatLateJoinPenalty",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x04,
    .properties = g_CombatLateJoinPenaltyComponent_Properties,
    .propertyCount = sizeof(g_CombatLateJoinPenaltyComponent_Properties) / sizeof(g_CombatLateJoinPenaltyComponent_Properties[0]),
};

// esv::combat::MergeComponent (from Combat.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_CombatMergeComponent_Properties[] = {
    { "Combat1", 0x00, FIELD_TYPE_UINT64, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "Combat2", 0x08, FIELD_TYPE_UINT64, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_CombatMergeComponent_Layout = {
    .componentName = "esv::combat::MergeComponent",
    .shortName = "CombatMerge",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x10,
    .properties = g_CombatMergeComponent_Properties,
    .propertyCount = sizeof(g_CombatMergeComponent_Properties) / sizeof(g_CombatMergeComponent_Properties[0]),
};

// esv::combat::SurfaceTeamSingletonComponent (from Combat.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_CombatSurfaceTeamSingletonComponent_Properties[] = {
    { "field_0", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_CombatSurfaceTeamSingletonComponent_Layout = {
    .componentName = "esv::combat::SurfaceTeamSingletonComponent",
    .shortName = "CombatSurfaceTeamSingleton",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x08,
    .properties = g_CombatSurfaceTeamSingletonComponent_Properties,
    .propertyCount = sizeof(g_CombatSurfaceTeamSingletonComponent_Properties) / sizeof(g_CombatSurfaceTeamSingletonComponent_Properties[0]),
};

// esv::death::DelayDeathCauseComponent (from Death.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_ServerDelayDeathCauseComponent_Properties[] = {
    { "DelayCount", 0x00, FIELD_TYPE_INT32, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "Reason", 0x04, FIELD_TYPE_INT32, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_8", 0x08, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_ServerDelayDeathCauseComponent_Layout = {
    .componentName = "esv::death::DelayDeathCauseComponent",
    .shortName = "ServerDelayDeathCause",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x18,
    .properties = g_ServerDelayDeathCauseComponent_Properties,
    .propertyCount = sizeof(g_ServerDelayDeathCauseComponent_Properties) / sizeof(g_ServerDelayDeathCauseComponent_Properties[0]),
};

// esv::death::DelayedDeathComponent (from Death.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_ServerDelayDeathComponent_Properties[] = {
    { "Death", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "Reason", 0x08, FIELD_TYPE_UINT32, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_88", 0x10, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_ServerDelayDeathComponent_Layout = {
    .componentName = "esv::death::DelayedDeathComponent",
    .shortName = "ServerDelayDeath",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x20,
    .properties = g_ServerDelayDeathComponent_Properties,
    .propertyCount = sizeof(g_ServerDelayDeathComponent_Properties) / sizeof(g_ServerDelayDeathComponent_Properties[0]),
};

// esv::death::KillerComponent (from Death.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_ServerKillerComponent_Properties[] = {
    { "Killers", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_ServerKillerComponent_Layout = {
    .componentName = "esv::death::KillerComponent",
    .shortName = "ServerKiller",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x08,
    .properties = g_ServerKillerComponent_Properties,
    .propertyCount = sizeof(g_ServerKillerComponent_Properties) / sizeof(g_ServerKillerComponent_Properties[0]),
};

// esv::death::StateComponent (from Death.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_ServerDeathStateComponent_Properties[] = {
    { "Flags", 0x00, FIELD_TYPE_UINT32, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_ServerDeathStateComponent_Layout = {
    .componentName = "esv::death::StateComponent",
    .shortName = "ServerDeathState",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x04,
    .properties = g_ServerDeathStateComponent_Properties,
    .propertyCount = sizeof(g_ServerDeathStateComponent_Properties) / sizeof(g_ServerDeathStateComponent_Properties[0]),
};

// esv::escort::FollowerComponent (from Party.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_EscortFollowerComponent_Properties[] = {
    { "Following", 0x00, FIELD_TYPE_UINT64, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_EscortFollowerComponent_Layout = {
    .componentName = "esv::escort::FollowerComponent",
    .shortName = "EscortFollower",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x08,
    .properties = g_EscortFollowerComponent_Properties,
    .propertyCount = sizeof(g_EscortFollowerComponent_Properties) / sizeof(g_EscortFollowerComponent_Properties[0]),
};

// esv::escort::LeaderComponent (from Party.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_EscortLeaderComponent_Properties[] = {
    { "Group", 0x00, FIELD_TYPE_UINT32, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_EscortLeaderComponent_Layout = {
    .componentName = "esv::escort::LeaderComponent",
    .shortName = "EscortLeader",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x04,
    .properties = g_EscortLeaderComponent_Properties,
    .propertyCount = sizeof(g_EscortLeaderComponent_Properties) / sizeof(g_EscortLeaderComponent_Properties[0]),
};

// esv::escort::LeaderPriorityComponent (from Party.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_EscortLeaderPriorityComponent_Properties[] = {
    { "Priorities", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_EscortLeaderPriorityComponent_Layout = {
    .componentName = "esv::escort::LeaderPriorityComponent",
    .shortName = "EscortLeaderPriority",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x08,
    .properties = g_EscortLeaderPriorityComponent_Properties,
    .propertyCount = sizeof(g_EscortLeaderPriorityComponent_Properties) / sizeof(g_EscortLeaderPriorityComponent_Properties[0]),
};

// esv::escort::MemberComponent (from Party.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_EscortMemberComponent_Properties[] = {
    { "Group", 0x00, FIELD_TYPE_UINT32, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_EscortMemberComponent_Layout = {
    .componentName = "esv::escort::MemberComponent",
    .shortName = "EscortMember",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x04,
    .properties = g_EscortMemberComponent_Properties,
    .propertyCount = sizeof(g_EscortMemberComponent_Properties) / sizeof(g_EscortMemberComponent_Properties[0]),
};

// esv::escort::StragglersTrackerComponent (from Party.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_EscortStragglersTrackerComponent_Properties[] = {
    { "Stragglers", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_10", 0x08, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_EscortStragglersTrackerComponent_Layout = {
    .componentName = "esv::escort::StragglersTrackerComponent",
    .shortName = "EscortStragglersTracker",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x10,
    .properties = g_EscortStragglersTrackerComponent_Properties,
    .propertyCount = sizeof(g_EscortStragglersTrackerComponent_Properties) / sizeof(g_EscortStragglersTrackerComponent_Properties[0]),
};

// esv::exp::ExperienceGaveOutComponent (from ServerData.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_ServerExperienceGaveOutComponent_Properties[] = {
    { "Experience", 0x00, FIELD_TYPE_INT32, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_ServerExperienceGaveOutComponent_Layout = {
    .componentName = "esv::exp::ExperienceGaveOutComponent",
    .shortName = "ServerExperienceGaveOut",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x04,
    .properties = g_ServerExperienceGaveOutComponent_Properties,
    .propertyCount = sizeof(g_ServerExperienceGaveOutComponent_Properties) / sizeof(g_ServerExperienceGaveOutComponent_Properties[0]),
};

// esv::ftb::SurfaceTeamSingletonComponent (from Combat.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_FTBSurfaceTeamSingletonComponent_Properties[] = {
    { "field_0", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_FTBSurfaceTeamSingletonComponent_Layout = {
    .componentName = "esv::ftb::SurfaceTeamSingletonComponent",
    .shortName = "FTBSurfaceTeamSingleton",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x08,
    .properties = g_FTBSurfaceTeamSingletonComponent_Properties,
    .propertyCount = sizeof(g_FTBSurfaceTeamSingletonComponent_Properties) / sizeof(g_FTBSurfaceTeamSingletonComponent_Properties[0]),
};

// esv::ftb::TimeFactorRequestsSingletonComponent (from Combat.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_FTBTimeFactorRequestsComponent_Properties[] = {
    { "Requests", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_FTBTimeFactorRequestsComponent_Layout = {
    .componentName = "esv::ftb::TimeFactorRequestsSingletonComponent",
    .shortName = "FTBTimeFactorRequests",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x08,
    .properties = g_FTBTimeFactorRequestsComponent_Properties,
    .propertyCount = sizeof(g_FTBTimeFactorRequestsComponent_Properties) / sizeof(g_FTBTimeFactorRequestsComponent_Properties[0]),
};

// esv::ftb::TimeFactorResetRequestsSingletonComponent (from Combat.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_FTBTimeFactorResetRequestsComponent_Properties[] = {
    { "Requests", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_FTBTimeFactorResetRequestsComponent_Layout = {
    .componentName = "esv::ftb::TimeFactorResetRequestsSingletonComponent",
    .shortName = "FTBTimeFactorResetRequests",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x08,
    .properties = g_FTBTimeFactorResetRequestsComponent_Properties,
    .propertyCount = sizeof(g_FTBTimeFactorResetRequestsComponent_Properties) / sizeof(g_FTBTimeFactorResetRequestsComponent_Properties[0]),
};

// esv::ftb::TurnBasedChangesRequestSingletonComponent (from Combat.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_FTBTurnBasedChangesRequestComponent_Properties[] = {
    { "Requests", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_FTBTurnBasedChangesRequestComponent_Layout = {
    .componentName = "esv::ftb::TurnBasedChangesRequestSingletonComponent",
    .shortName = "FTBTurnBasedChangesRequest",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x08,
    .properties = g_FTBTurnBasedChangesRequestComponent_Properties,
    .propertyCount = sizeof(g_FTBTurnBasedChangesRequestComponent_Properties) / sizeof(g_FTBTurnBasedChangesRequestComponent_Properties[0]),
};

// esv::ftb::ZoneComponent (from Combat.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_FTBZoneComponent_Properties[] = {
    { "Entity", 0x00, FIELD_TYPE_UINT64, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_8", 0x08, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_10", 0x10, FIELD_TYPE_UINT64, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_18", 0x18, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_1C", 0x1c, FIELD_TYPE_FLOAT, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_20", 0x20, FIELD_TYPE_UINT32, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "ZoneGuid", 0x28, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "Creator", 0x38, FIELD_TYPE_UINT64, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "ByPlayer", 0x40, FIELD_TYPE_BOOL, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "Shared", 0x41, FIELD_TYPE_BOOL, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_FTBZoneComponent_Layout = {
    .componentName = "esv::ftb::ZoneComponent",
    .shortName = "FTBZone",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x42,
    .properties = g_FTBZoneComponent_Properties,
    .propertyCount = sizeof(g_FTBZoneComponent_Properties) / sizeof(g_FTBZoneComponent_Properties[0]),
};

// esv::ftb::ZoneInstigatorComponent (from Combat.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_FTBZoneInstigatorComponent_Properties[] = {
    { "Instigator", 0x00, FIELD_TYPE_UINT64, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "Shared", 0x08, FIELD_TYPE_BOOL, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_FTBZoneInstigatorComponent_Layout = {
    .componentName = "esv::ftb::ZoneInstigatorComponent",
    .shortName = "FTBZoneInstigator",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x09,
    .properties = g_FTBZoneInstigatorComponent_Properties,
    .propertyCount = sizeof(g_FTBZoneInstigatorComponent_Properties) / sizeof(g_FTBZoneInstigatorComponent_Properties[0]),
};

// esv::history::TargetUUIDComponent (from ServerData.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_HistoryTargetUUIDComponent_Properties[] = {
    { "Target", 0x00, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_HistoryTargetUUIDComponent_Layout = {
    .componentName = "esv::history::TargetUUIDComponent",
    .shortName = "HistoryTargetUUID",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x10,
    .properties = g_HistoryTargetUUIDComponent_Properties,
    .propertyCount = sizeof(g_HistoryTargetUUIDComponent_Properties) / sizeof(g_HistoryTargetUUIDComponent_Properties[0]),
};

// esv::interrupt::ActionRequestsComponent (from Interrupt.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_ServerInterruptActionRequestsComponent_Properties[] = {
    { "StartRequests", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "StopRequests", 0x08, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "CombatLogRequests", 0x10, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_ServerInterruptActionRequestsComponent_Layout = {
    .componentName = "esv::interrupt::ActionRequestsComponent",
    .shortName = "ServerInterruptActionRequests",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x18,
    .properties = g_ServerInterruptActionRequestsComponent_Properties,
    .propertyCount = sizeof(g_ServerInterruptActionRequestsComponent_Properties) / sizeof(g_ServerInterruptActionRequestsComponent_Properties[0]),
};

// esv::interrupt::AddRemoveRequestsComponent (from Interrupt.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_ServerInterruptAddRemoveRequestsComponent_Properties[] = {
    { "Requests", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_ServerInterruptAddRemoveRequestsComponent_Layout = {
    .componentName = "esv::interrupt::AddRemoveRequestsComponent",
    .shortName = "ServerInterruptAddRemoveRequests",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x08,
    .properties = g_ServerInterruptAddRemoveRequestsComponent_Properties,
    .propertyCount = sizeof(g_ServerInterruptAddRemoveRequestsComponent_Properties) / sizeof(g_ServerInterruptAddRemoveRequestsComponent_Properties[0]),
};

// esv::interrupt::DataSingletonComponent (from Interrupt.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_ServerInterruptDataSingletonComponent_Properties[] = {
    { "Events", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "TargetHitInterrupts", 0x08, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_ServerInterruptDataSingletonComponent_Layout = {
    .componentName = "esv::interrupt::DataSingletonComponent",
    .shortName = "ServerInterruptDataSingleton",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x10,
    .properties = g_ServerInterruptDataSingletonComponent_Properties,
    .propertyCount = sizeof(g_ServerInterruptDataSingletonComponent_Properties) / sizeof(g_ServerInterruptDataSingletonComponent_Properties[0]),
};

// esv::interrupt::InitialParticipantsComponent (from Interrupt.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_ServerInterruptInitialParticipantsComponent_Properties[] = {
    { "Participants", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_ServerInterruptInitialParticipantsComponent_Layout = {
    .componentName = "esv::interrupt::InitialParticipantsComponent",
    .shortName = "ServerInterruptInitialParticipants",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x08,
    .properties = g_ServerInterruptInitialParticipantsComponent_Properties,
    .propertyCount = sizeof(g_ServerInterruptInitialParticipantsComponent_Properties) / sizeof(g_ServerInterruptInitialParticipantsComponent_Properties[0]),
};

// esv::interrupt::TurnOrderInZoneComponent (from Interrupt.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_ServerInterruptTurnOrderInZoneComponent_Properties[] = {
    { "InZone", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_ServerInterruptTurnOrderInZoneComponent_Layout = {
    .componentName = "esv::interrupt::TurnOrderInZoneComponent",
    .shortName = "ServerInterruptTurnOrderInZone",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x08,
    .properties = g_ServerInterruptTurnOrderInZoneComponent_Properties,
    .propertyCount = sizeof(g_ServerInterruptTurnOrderInZoneComponent_Properties) / sizeof(g_ServerInterruptTurnOrderInZoneComponent_Properties[0]),
};

// esv::interrupt::ZoneRequestsComponent (from Interrupt.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_ServerInterruptZoneRequestsComponent_Properties[] = {
    { "StartRequests", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "StopRequests", 0x08, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_ServerInterruptZoneRequestsComponent_Layout = {
    .componentName = "esv::interrupt::ZoneRequestsComponent",
    .shortName = "ServerInterruptZoneRequests",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x10,
    .properties = g_ServerInterruptZoneRequestsComponent_Properties,
    .propertyCount = sizeof(g_ServerInterruptZoneRequestsComponent_Properties) / sizeof(g_ServerInterruptZoneRequestsComponent_Properties[0]),
};

// esv::inventory::ContainerDataComponent (from Inventory.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_ServerInventoryContainerDataComponent_Properties[] = {
    { "Flags", 0x00, FIELD_TYPE_UINT16, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_4", 0x04, FIELD_TYPE_INT32, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_ServerInventoryContainerDataComponent_Layout = {
    .componentName = "esv::inventory::ContainerDataComponent",
    .shortName = "ServerInventoryContainerData",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x08,
    .properties = g_ServerInventoryContainerDataComponent_Properties,
    .propertyCount = sizeof(g_ServerInventoryContainerDataComponent_Properties) / sizeof(g_ServerInventoryContainerDataComponent_Properties[0]),
};

// esv::inventory::GroupCheckComponent (from Inventory.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_ServerInventoryGroupCheckComponent_Properties[] = {
    { "Conditions", 0x00, FIELD_TYPE_UINT32, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_ServerInventoryGroupCheckComponent_Layout = {
    .componentName = "esv::inventory::GroupCheckComponent",
    .shortName = "ServerInventoryGroupCheck",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x04,
    .properties = g_ServerInventoryGroupCheckComponent_Properties,
    .propertyCount = sizeof(g_ServerInventoryGroupCheckComponent_Properties) / sizeof(g_ServerInventoryGroupCheckComponent_Properties[0]),
};

// esv::inventory::ShapeshiftEquipmentHistoryComponent (from Inventory.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_ServerShapeshiftEquipmentHistoryComponent_Properties[] = {
    { "History", 0x00, FIELD_TYPE_GUID, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_ServerShapeshiftEquipmentHistoryComponent_Layout = {
    .componentName = "esv::inventory::ShapeshiftEquipmentHistoryComponent",
    .shortName = "ServerShapeshiftEquipmentHistory",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x08,
    .properties = g_ServerShapeshiftEquipmentHistoryComponent_Properties,
    .propertyCount = sizeof(g_ServerShapeshiftEquipmentHistoryComponent_Properties) / sizeof(g_ServerShapeshiftEquipmentHistoryComponent_Properties[0]),
};

// esv::item::DynamicLayerOwnerComponent (from Item.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_ServerDynamicLayerOwnerComponent_Properties[] = {
    { "Owner", 0x00, FIELD_TYPE_UINT32, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_ServerDynamicLayerOwnerComponent_Layout = {
    .componentName = "esv::item::DynamicLayerOwnerComponent",
    .shortName = "ServerDynamicLayerOwner",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x04,
    .properties = g_ServerDynamicLayerOwnerComponent_Properties,
    .propertyCount = sizeof(g_ServerDynamicLayerOwnerComponent_Properties) / sizeof(g_ServerDynamicLayerOwnerComponent_Properties[0]),
};

// esv::light::GameplayLightChangesComponent (from ServerData.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_ServerGameplayLightChangesComponent_Properties[] = {
    { "field_0", 0x00, FIELD_TYPE_UINT32, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_4", 0x04, FIELD_TYPE_UINT32, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_8", 0x08, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_9", 0x09, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_A", 0x0a, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_ServerGameplayLightChangesComponent_Layout = {
    .componentName = "esv::light::GameplayLightChangesComponent",
    .shortName = "ServerGameplayLightChanges",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x0b,
    .properties = g_ServerGameplayLightChangesComponent_Properties,
    .propertyCount = sizeof(g_ServerGameplayLightChangesComponent_Properties) / sizeof(g_ServerGameplayLightChangesComponent_Properties[0]),
};

// esv::ownership::IsCurrentOwnerComponent (from Item.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_ServerIsCurrentOwnerComponent_Properties[] = {
    { "Owner", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_ServerIsCurrentOwnerComponent_Layout = {
    .componentName = "esv::ownership::IsCurrentOwnerComponent",
    .shortName = "ServerIsCurrentOwner",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x08,
    .properties = g_ServerIsCurrentOwnerComponent_Properties,
    .propertyCount = sizeof(g_ServerIsCurrentOwnerComponent_Properties) / sizeof(g_ServerIsCurrentOwnerComponent_Properties[0]),
};

// esv::ownership::IsLatestOwnerComponent (from Item.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_ServerIsLatestOwnerComponent_Properties[] = {
    { "Owner", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_ServerIsLatestOwnerComponent_Layout = {
    .componentName = "esv::ownership::IsLatestOwnerComponent",
    .shortName = "ServerIsLatestOwner",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x08,
    .properties = g_ServerIsLatestOwnerComponent_Properties,
    .propertyCount = sizeof(g_ServerIsLatestOwnerComponent_Properties) / sizeof(g_ServerIsLatestOwnerComponent_Properties[0]),
};

// esv::ownership::IsOriginalOwnerComponent (from Item.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_ServerIsOriginalOwnerComponent_Properties[] = {
    { "Owner", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_ServerIsOriginalOwnerComponent_Layout = {
    .componentName = "esv::ownership::IsOriginalOwnerComponent",
    .shortName = "ServerIsOriginalOwner",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x08,
    .properties = g_ServerIsOriginalOwnerComponent_Properties,
    .propertyCount = sizeof(g_ServerIsOriginalOwnerComponent_Properties) / sizeof(g_ServerIsOriginalOwnerComponent_Properties[0]),
};

// esv::ownership::IsPreviousOwnerComponent (from Item.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_ServerIsPreviousOwnerComponent_Properties[] = {
    { "Owner", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_ServerIsPreviousOwnerComponent_Layout = {
    .componentName = "esv::ownership::IsPreviousOwnerComponent",
    .shortName = "ServerIsPreviousOwner",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x08,
    .properties = g_ServerIsPreviousOwnerComponent_Properties,
    .propertyCount = sizeof(g_ServerIsPreviousOwnerComponent_Properties) / sizeof(g_ServerIsPreviousOwnerComponent_Properties[0]),
};

// esv::ownership::OwneeHistoryComponent (from Item.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_ServerOwneeHistoryComponent_Properties[] = {
    { "OriginalOwner", 0x00, FIELD_TYPE_UINT64, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "LatestOwner", 0x08, FIELD_TYPE_UINT64, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "PreviousOwner", 0x10, FIELD_TYPE_UINT64, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_ServerOwneeHistoryComponent_Layout = {
    .componentName = "esv::ownership::OwneeHistoryComponent",
    .shortName = "ServerOwneeHistory",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x18,
    .properties = g_ServerOwneeHistoryComponent_Properties,
    .propertyCount = sizeof(g_ServerOwneeHistoryComponent_Properties) / sizeof(g_ServerOwneeHistoryComponent_Properties[0]),
};

// esv::ownership::OwneeRequestComponent (from Item.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_ServerOwneeRequestComponent_Properties[] = {
    { "NewCurrentOwnee", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "LatestOwner", 0x08, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "OriginalOwner", 0x10, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_ServerOwneeRequestComponent_Layout = {
    .componentName = "esv::ownership::OwneeRequestComponent",
    .shortName = "ServerOwneeRequest",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x18,
    .properties = g_ServerOwneeRequestComponent_Properties,
    .propertyCount = sizeof(g_ServerOwneeRequestComponent_Properties) / sizeof(g_ServerOwneeRequestComponent_Properties[0]),
};

// esv::passive::BaseComponent (from Passives.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_ServerPassiveBaseComponent_Properties[] = {
    { "Passives", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_ServerPassiveBaseComponent_Layout = {
    .componentName = "esv::passive::BaseComponent",
    .shortName = "ServerPassiveBase",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x08,
    .properties = g_ServerPassiveBaseComponent_Properties,
    .propertyCount = sizeof(g_ServerPassiveBaseComponent_Properties) / sizeof(g_ServerPassiveBaseComponent_Properties[0]),
};

// esv::passive::BoostsComponent (from Passives.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_ServerPassiveBoostsComponent_Properties[] = {
    { "Boosts", 0x00, FIELD_TYPE_GUID, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_ServerPassiveBoostsComponent_Layout = {
    .componentName = "esv::passive::BoostsComponent",
    .shortName = "ServerPassiveBoosts",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x08,
    .properties = g_ServerPassiveBoostsComponent_Properties,
    .propertyCount = sizeof(g_ServerPassiveBoostsComponent_Properties) / sizeof(g_ServerPassiveBoostsComponent_Properties[0]),
};

// esv::passive::PersistentDataComponent (from Passives.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_ServerPassivePersistentDataComponent_Properties[] = {
    { "field_0", 0x00, FIELD_TYPE_FLOAT, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_4", 0x04, FIELD_TYPE_FLOAT, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_ServerPassivePersistentDataComponent_Layout = {
    .componentName = "esv::passive::PersistentDataComponent",
    .shortName = "ServerPassivePersistentData",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x08,
    .properties = g_ServerPassivePersistentDataComponent_Properties,
    .propertyCount = sizeof(g_ServerPassivePersistentDataComponent_Properties) / sizeof(g_ServerPassivePersistentDataComponent_Properties[0]),
};

// esv::passive::ScriptPassivesComponent (from Passives.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_ServerScriptPassivesComponent_Properties[] = {
    { "Passives", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_ServerScriptPassivesComponent_Layout = {
    .componentName = "esv::passive::ScriptPassivesComponent",
    .shortName = "ServerScriptPassives",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x08,
    .properties = g_ServerScriptPassivesComponent_Properties,
    .propertyCount = sizeof(g_ServerScriptPassivesComponent_Properties) / sizeof(g_ServerScriptPassivesComponent_Properties[0]),
};

// esv::passive::ToggledPassivesComponent (from Passives.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_ServerToggledPassivesComponent_Properties[] = {
    { "Passives", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_ServerToggledPassivesComponent_Layout = {
    .componentName = "esv::passive::ToggledPassivesComponent",
    .shortName = "ServerToggledPassives",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x08,
    .properties = g_ServerToggledPassivesComponent_Properties,
    .propertyCount = sizeof(g_ServerToggledPassivesComponent_Properties) / sizeof(g_ServerToggledPassivesComponent_Properties[0]),
};

// esv::photo_mode::CapabilityComponent (from Dummy.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_PhotoModeCapabilityComponent_Properties[] = {
    { "field_0", 0x00, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_PhotoModeCapabilityComponent_Layout = {
    .componentName = "esv::photo_mode::CapabilityComponent",
    .shortName = "PhotoModeCapability",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x01,
    .properties = g_PhotoModeCapabilityComponent_Properties,
    .propertyCount = sizeof(g_PhotoModeCapabilityComponent_Properties) / sizeof(g_PhotoModeCapabilityComponent_Properties[0]),
};

// esv::pickpocket::PickpocketComponent (from ServerData.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_ServerPickpocketComponent_Properties[] = {
    { "Items", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_ServerPickpocketComponent_Layout = {
    .componentName = "esv::pickpocket::PickpocketComponent",
    .shortName = "ServerPickpocket",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x08,
    .properties = g_ServerPickpocketComponent_Properties,
    .propertyCount = sizeof(g_ServerPickpocketComponent_Properties) / sizeof(g_ServerPickpocketComponent_Properties[0]),
};

// esv::projectile::AttachmentComponent (from Projectile.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_ServerProjectileAttachmentComponent_Properties[] = {
    { "Attachment", 0x00, FIELD_TYPE_UINT64, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_ServerProjectileAttachmentComponent_Layout = {
    .componentName = "esv::projectile::AttachmentComponent",
    .shortName = "ServerProjectileAttachment",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x08,
    .properties = g_ServerProjectileAttachmentComponent_Properties,
    .propertyCount = sizeof(g_ServerProjectileAttachmentComponent_Properties) / sizeof(g_ServerProjectileAttachmentComponent_Properties[0]),
};

// esv::projectile::SpellComponent (from Projectile.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_ServerProjectileSpellComponent_Properties[] = {
    { "Spell", 0x00, FIELD_TYPE_UINT64, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "Target", 0x08, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "Index", 0x10, FIELD_TYPE_INT32, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_ServerProjectileSpellComponent_Layout = {
    .componentName = "esv::projectile::SpellComponent",
    .shortName = "ServerProjectileSpell",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x14,
    .properties = g_ServerProjectileSpellComponent_Properties,
    .propertyCount = sizeof(g_ServerProjectileSpellComponent_Properties) / sizeof(g_ServerProjectileSpellComponent_Properties[0]),
};

// esv::recruit::RecruitedByComponent (from ServerData.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_ServerRecruitedByComponent_Properties[] = {
    { "RecruitedBy", 0x00, FIELD_TYPE_UINT64, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_ServerRecruitedByComponent_Layout = {
    .componentName = "esv::recruit::RecruitedByComponent",
    .shortName = "ServerRecruitedBy",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x08,
    .properties = g_ServerRecruitedByComponent_Properties,
    .propertyCount = sizeof(g_ServerRecruitedByComponent_Properties) / sizeof(g_ServerRecruitedByComponent_Properties[0]),
};

// esv::replication::PeersInRangeComponent (from ServerData.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_ServerPeersInRangeComponent_Properties[] = {
    { "Peers", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_ServerPeersInRangeComponent_Layout = {
    .componentName = "esv::replication::PeersInRangeComponent",
    .shortName = "ServerPeersInRange",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x08,
    .properties = g_ServerPeersInRangeComponent_Properties,
    .propertyCount = sizeof(g_ServerPeersInRangeComponent_Properties) / sizeof(g_ServerPeersInRangeComponent_Properties[0]),
};

// esv::replication::ReplicationDependencyComponent (from Runtime.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_ServerReplicationDependencyComponent_Properties[] = {
    { "Dependency", 0x00, FIELD_TYPE_UINT64, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_ServerReplicationDependencyComponent_Layout = {
    .componentName = "esv::replication::ReplicationDependencyComponent",
    .shortName = "ServerReplicationDependency",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x08,
    .properties = g_ServerReplicationDependencyComponent_Properties,
    .propertyCount = sizeof(g_ServerReplicationDependencyComponent_Properties) / sizeof(g_ServerReplicationDependencyComponent_Properties[0]),
};

// esv::replication::ReplicationDependencyOwnerComponent (from Runtime.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_ServerReplicationDependencyOwnerComponent_Properties[] = {
    { "Dependents", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_ServerReplicationDependencyOwnerComponent_Layout = {
    .componentName = "esv::replication::ReplicationDependencyOwnerComponent",
    .shortName = "ServerReplicationDependencyOwner",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x08,
    .properties = g_ServerReplicationDependencyOwnerComponent_Properties,
    .propertyCount = sizeof(g_ServerReplicationDependencyOwnerComponent_Properties) / sizeof(g_ServerReplicationDependencyOwnerComponent_Properties[0]),
};

// esv::rest::PendingTypeComponent (from Data.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_ServerRestPendingTypeComponent_Properties[] = {
    { "CancelReason", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "Supplies", 0x08, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_ServerRestPendingTypeComponent_Layout = {
    .componentName = "esv::rest::PendingTypeComponent",
    .shortName = "ServerRestPendingType",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x10,
    .properties = g_ServerRestPendingTypeComponent_Properties,
    .propertyCount = sizeof(g_ServerRestPendingTypeComponent_Properties) / sizeof(g_ServerRestPendingTypeComponent_Properties[0]),
};

// esv::roll::RollFinishedEventOneFrameComponent (from Roll.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_ServerRollFinishedEventComponent_Properties[] = {
    { "Events", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_ServerRollFinishedEventComponent_Layout = {
    .componentName = "esv::roll::RollFinishedEventOneFrameComponent",
    .shortName = "ServerRollFinishedEvent",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x08,
    .properties = g_ServerRollFinishedEventComponent_Properties,
    .propertyCount = sizeof(g_ServerRollFinishedEventComponent_Properties) / sizeof(g_ServerRollFinishedEventComponent_Properties[0]),
};

// esv::roll::stream::StreamsComponent (from Roll.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_ServerRollStreamsComponent_Properties[] = {
    { "Streams", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "LastFrame", 0x08, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "BaseSeed", 0x10, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "RollModeType", 0x18, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "CustomRollExpectedValue", 0x20, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_ServerRollStreamsComponent_Layout = {
    .componentName = "esv::roll::stream::StreamsComponent",
    .shortName = "ServerRollStreams",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x21,
    .properties = g_ServerRollStreamsComponent_Properties,
    .propertyCount = sizeof(g_ServerRollStreamsComponent_Properties) / sizeof(g_ServerRollStreamsComponent_Properties[0]),
};

// esv::shapeshift::HealthReservationComponent (from Shapeshift.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_ShapeshiftHealthReservationComponent_Properties[] = {
    { "Reservations", 0x00, FIELD_TYPE_GUID, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_ShapeshiftHealthReservationComponent_Layout = {
    .componentName = "esv::shapeshift::HealthReservationComponent",
    .shortName = "ShapeshiftHealthReservation",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x08,
    .properties = g_ShapeshiftHealthReservationComponent_Properties,
    .propertyCount = sizeof(g_ShapeshiftHealthReservationComponent_Properties) / sizeof(g_ShapeshiftHealthReservationComponent_Properties[0]),
};

// esv::shapeshift::StatesComponent (from Shapeshift.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_ServerShapeshiftStatesComponent_Properties[] = {
    { "field_0", 0x00, FIELD_TYPE_INT32, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "States", 0x08, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_ServerShapeshiftStatesComponent_Layout = {
    .componentName = "esv::shapeshift::StatesComponent",
    .shortName = "ServerShapeshiftStates",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x10,
    .properties = g_ServerShapeshiftStatesComponent_Properties,
    .propertyCount = sizeof(g_ServerShapeshiftStatesComponent_Properties) / sizeof(g_ServerShapeshiftStatesComponent_Properties[0]),
};

// esv::sight::AggregatedDataComponent (from Components.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_ServerSightAggregatedDataComponent_Properties[] = {
    { "EntitySightData", 0x00, FIELD_TYPE_GUID, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "RemovedEntitySightData", 0x08, FIELD_TYPE_GUID, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "Entities", 0x10, FIELD_TYPE_GUID, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "RemovedEntities", 0x18, FIELD_TYPE_GUID, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "SightRanges", 0x20, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "MaxSightRange", 0x28, FIELD_TYPE_FLOAT, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_144", 0x2c, FIELD_TYPE_INT32, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "LosChecks", 0x30, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "LosCheckQueues", 0x38, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_ServerSightAggregatedDataComponent_Layout = {
    .componentName = "esv::sight::AggregatedDataComponent",
    .shortName = "ServerSightAggregatedData",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x40,
    .properties = g_ServerSightAggregatedDataComponent_Properties,
    .propertyCount = sizeof(g_ServerSightAggregatedDataComponent_Properties) / sizeof(g_ServerSightAggregatedDataComponent_Properties[0]),
};

// esv::sight::AggregatedGameplayLightDataComponent (from Components.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_ServerAggregatedGameplayLightDataComponent_Properties[] = {
    { "Ranges", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "MovedViewsheds", 0x08, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "MaxRange", 0x10, FIELD_TYPE_FLOAT, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "LosCheckQueue", 0x18, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "LightLosCheckQueues", 0x20, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_ServerAggregatedGameplayLightDataComponent_Layout = {
    .componentName = "esv::sight::AggregatedGameplayLightDataComponent",
    .shortName = "ServerAggregatedGameplayLightData",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x28,
    .properties = g_ServerAggregatedGameplayLightDataComponent_Properties,
    .propertyCount = sizeof(g_ServerAggregatedGameplayLightDataComponent_Properties) / sizeof(g_ServerAggregatedGameplayLightDataComponent_Properties[0]),
};

// esv::sight::AiGridViewshedComponent (from Components.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_ServerAiGridViewshedComponent_Properties[] = {
    { "Count", 0x00, FIELD_TYPE_UINT32, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_ServerAiGridViewshedComponent_Layout = {
    .componentName = "esv::sight::AiGridViewshedComponent",
    .shortName = "ServerAiGridViewshed",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x04,
    .properties = g_ServerAiGridViewshedComponent_Properties,
    .propertyCount = sizeof(g_ServerAiGridViewshedComponent_Properties) / sizeof(g_ServerAiGridViewshedComponent_Properties[0]),
};

// esv::sight::EntityLosCheckQueueComponent (from Components.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_ServerSightEntityLosCheckQueueComponent_Properties[] = {
    { "LosCheck", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_ServerSightEntityLosCheckQueueComponent_Layout = {
    .componentName = "esv::sight::EntityLosCheckQueueComponent",
    .shortName = "ServerSightEntityLosCheckQueue",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x08,
    .properties = g_ServerSightEntityLosCheckQueueComponent_Properties,
    .propertyCount = sizeof(g_ServerSightEntityLosCheckQueueComponent_Properties) / sizeof(g_ServerSightEntityLosCheckQueueComponent_Properties[0]),
};

// esv::sight::LightLosCheckQueueComponent (from Components.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_ServerLightLosCheckQueueComponent_Properties[] = {
    { "Checks", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "Checks2", 0x08, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_ServerLightLosCheckQueueComponent_Layout = {
    .componentName = "esv::sight::LightLosCheckQueueComponent",
    .shortName = "ServerLightLosCheckQueue",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x10,
    .properties = g_ServerLightLosCheckQueueComponent_Properties,
    .propertyCount = sizeof(g_ServerLightLosCheckQueueComponent_Properties) / sizeof(g_ServerLightLosCheckQueueComponent_Properties[0]),
};

// esv::spell::OnDamageSpellsComponent (from Spell.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_OnDamageSpellsComponent_Properties[] = {
    { "Spells", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_OnDamageSpellsComponent_Layout = {
    .componentName = "esv::spell::OnDamageSpellsComponent",
    .shortName = "OnDamageSpells",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x08,
    .properties = g_OnDamageSpellsComponent_Properties,
    .propertyCount = sizeof(g_OnDamageSpellsComponent_Properties) / sizeof(g_OnDamageSpellsComponent_Properties[0]),
};

// esv::spell_cast::CacheComponent (from SpellCast.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_ServerSpellCastCacheComponent_Properties[] = {
    { "Costs", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "TextKeyIndices", 0x08, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "TextKeyIndex", 0x10, FIELD_TYPE_UINT32, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_54", 0x14, FIELD_TYPE_INT32, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "TargetCounts", 0x18, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "MovementTransactionId", 0x20, FIELD_TYPE_UINT32, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_E0", 0x28, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "HasPathfindTemplate", 0x30, FIELD_TYPE_BOOL, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "PhaseFinished", 0x31, FIELD_TYPE_BOOL, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_ServerSpellCastCacheComponent_Layout = {
    .componentName = "esv::spell_cast::CacheComponent",
    .shortName = "ServerSpellCastCache",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x32,
    .properties = g_ServerSpellCastCacheComponent_Properties,
    .propertyCount = sizeof(g_ServerSpellCastCacheComponent_Properties) / sizeof(g_ServerSpellCastCacheComponent_Properties[0]),
};

// esv::spell_cast::CastHitDelayComponent (from SpellCast.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_ServerSpellCastHitDelayComponent_Properties[] = {
    { "Delays", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "HitDelay", 0x08, FIELD_TYPE_FLOAT, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "HitDelayRemaining", 0x0c, FIELD_TYPE_FLOAT, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_ServerSpellCastHitDelayComponent_Layout = {
    .componentName = "esv::spell_cast::CastHitDelayComponent",
    .shortName = "ServerSpellCastHitDelay",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x10,
    .properties = g_ServerSpellCastHitDelayComponent_Properties,
    .propertyCount = sizeof(g_ServerSpellCastHitDelayComponent_Properties) / sizeof(g_ServerSpellCastHitDelayComponent_Properties[0]),
};

// esv::spell_cast::CastRequestsComponent (from SpellCast.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_ServerSpellCastRequestsComponent_Properties[] = {
    { "StartRequests", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "CancelRequests", 0x08, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "ConfirmRequests", 0x10, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "PreviewSetRequests", 0x18, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_ServerSpellCastRequestsComponent_Layout = {
    .componentName = "esv::spell_cast::CastRequestsComponent",
    .shortName = "ServerSpellCastRequests",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x20,
    .properties = g_ServerSpellCastRequestsComponent_Properties,
    .propertyCount = sizeof(g_ServerSpellCastRequestsComponent_Properties) / sizeof(g_ServerSpellCastRequestsComponent_Properties[0]),
};

// esv::spell_cast::CastResponsibleComponent (from SpellCast.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_ServerSpellCastResponsibleComponent_Properties[] = {
    { "Entity", 0x00, FIELD_TYPE_UINT64, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_ServerSpellCastResponsibleComponent_Layout = {
    .componentName = "esv::spell_cast::CastResponsibleComponent",
    .shortName = "ServerSpellCastResponsible",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x08,
    .properties = g_ServerSpellCastResponsibleComponent_Properties,
    .propertyCount = sizeof(g_ServerSpellCastResponsibleComponent_Properties) / sizeof(g_ServerSpellCastResponsibleComponent_Properties[0]),
};

// esv::spell_cast::ExternalsComponent (from SpellCast.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_ServerSpellExternalsComponent_Properties[] = {
    { "Externals", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_ServerSpellExternalsComponent_Layout = {
    .componentName = "esv::spell_cast::ExternalsComponent",
    .shortName = "ServerSpellExternals",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x08,
    .properties = g_ServerSpellExternalsComponent_Properties,
    .propertyCount = sizeof(g_ServerSpellExternalsComponent_Properties) / sizeof(g_ServerSpellExternalsComponent_Properties[0]),
};

// esv::spell_cast::HitRegisterComponent (from SpellCast.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_ServerSpellHitRegisterComponent_Properties[] = {
    { "Hits", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_ServerSpellHitRegisterComponent_Layout = {
    .componentName = "esv::spell_cast::HitRegisterComponent",
    .shortName = "ServerSpellHitRegister",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x08,
    .properties = g_ServerSpellHitRegisterComponent_Properties,
    .propertyCount = sizeof(g_ServerSpellHitRegisterComponent_Properties) / sizeof(g_ServerSpellHitRegisterComponent_Properties[0]),
};

// esv::spell_cast::InterruptDataComponent (from Interrupt.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_ServerSpellCastInterruptComponent_Properties[] = {
    { "SpellCastGuid", 0x00, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "Event", 0x10, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "NextInterruptIndex", 0x18, FIELD_TYPE_INT32, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "PausedAnimationEvents", 0x20, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "AnimationInterrupts", 0x28, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "AnimationIndex", 0x30, FIELD_TYPE_INT32, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_ServerSpellCastInterruptComponent_Layout = {
    .componentName = "esv::spell_cast::InterruptDataComponent",
    .shortName = "ServerSpellCastInterrupt",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x34,
    .properties = g_ServerSpellCastInterruptComponent_Properties,
    .propertyCount = sizeof(g_ServerSpellCastInterruptComponent_Properties) / sizeof(g_ServerSpellCastInterruptComponent_Properties[0]),
};

// esv::spell_cast::InterruptRequestsComponent (from Interrupt.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_ServerSpellInterruptRequestsComponent_Properties[] = {
    { "StartRequests", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "StopRequests", 0x08, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "CombatLogRequests", 0x10, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "UpdateInterruptorsRequests", 0x18, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_ServerSpellInterruptRequestsComponent_Layout = {
    .componentName = "esv::spell_cast::InterruptRequestsComponent",
    .shortName = "ServerSpellInterruptRequests",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x20,
    .properties = g_ServerSpellInterruptRequestsComponent_Properties,
    .propertyCount = sizeof(g_ServerSpellInterruptRequestsComponent_Properties) / sizeof(g_ServerSpellInterruptRequestsComponent_Properties[0]),
};

// esv::spell_cast::InterruptResultsComponent (from Interrupt.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_ServerSpellInterruptResultsComponent_Properties[] = {
    { "Results", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "Conditionals", 0x08, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_ServerSpellInterruptResultsComponent_Layout = {
    .componentName = "esv::spell_cast::InterruptResultsComponent",
    .shortName = "ServerSpellInterruptResults",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x10,
    .properties = g_ServerSpellInterruptResultsComponent_Properties,
    .propertyCount = sizeof(g_ServerSpellInterruptResultsComponent_Properties) / sizeof(g_ServerSpellInterruptResultsComponent_Properties[0]),
};

// esv::spell_cast::MovementComponent (from SpellCast.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_ServerSpellCastMovementComponent_Properties[] = {
    { "field_0", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "IsMoving", 0x08, FIELD_TYPE_BOOL, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "Duration", 0x0c, FIELD_TYPE_FLOAT, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "Progress", 0x10, FIELD_TYPE_FLOAT, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "TextKey", 0x14, FIELD_TYPE_UINT32, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_ServerSpellCastMovementComponent_Layout = {
    .componentName = "esv::spell_cast::MovementComponent",
    .shortName = "ServerSpellCastMovement",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x18,
    .properties = g_ServerSpellCastMovementComponent_Properties,
    .propertyCount = sizeof(g_ServerSpellCastMovementComponent_Properties) / sizeof(g_ServerSpellCastMovementComponent_Properties[0]),
};

// esv::spell_cast::MovementInfoComponent (from SpellCast.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_ServerSpellCastMovementInfoComponent_Properties[] = {
    { "Settings", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "PathSettings", 0x08, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_ServerSpellCastMovementInfoComponent_Layout = {
    .componentName = "esv::spell_cast::MovementInfoComponent",
    .shortName = "ServerSpellCastMovementInfo",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x10,
    .properties = g_ServerSpellCastMovementInfoComponent_Properties,
    .propertyCount = sizeof(g_ServerSpellCastMovementInfoComponent_Properties) / sizeof(g_ServerSpellCastMovementInfoComponent_Properties[0]),
};

// esv::spell_cast::PendingRequestsComponent (from SpellCast.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_ServerSpellCastPendingRequestsComponent_Properties[] = {
    { "ConfirmRequests", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "CancelRequests", 0x08, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "PreviewSetRequests", 0x10, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_ServerSpellCastPendingRequestsComponent_Layout = {
    .componentName = "esv::spell_cast::PendingRequestsComponent",
    .shortName = "ServerSpellCastPendingRequests",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x18,
    .properties = g_ServerSpellCastPendingRequestsComponent_Properties,
    .propertyCount = sizeof(g_ServerSpellCastPendingRequestsComponent_Properties) / sizeof(g_ServerSpellCastPendingRequestsComponent_Properties[0]),
};

// esv::spell_cast::ProjectileCacheComponent (from Projectile.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_ServerProjectileCacheComponent_Properties[] = {
    { "Target", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "ProjectileDelayTimers", 0x08, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_390", 0x10, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "ExtraData", 0x18, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_ServerProjectileCacheComponent_Layout = {
    .componentName = "esv::spell_cast::ProjectileCacheComponent",
    .shortName = "ServerProjectileCache",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x20,
    .properties = g_ServerProjectileCacheComponent_Properties,
    .propertyCount = sizeof(g_ServerProjectileCacheComponent_Properties) / sizeof(g_ServerProjectileCacheComponent_Properties[0]),
};

// esv::spell_cast::ProjectilePathfindCacheComponent (from SpellCast.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_ServerSpellCastProjectilePathfindCacheComponent_Properties[] = {
    { "Targets", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "Trajectories", 0x08, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_ServerSpellCastProjectilePathfindCacheComponent_Layout = {
    .componentName = "esv::spell_cast::ProjectilePathfindCacheComponent",
    .shortName = "ServerSpellCastProjectilePathfindCache",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x10,
    .properties = g_ServerSpellCastProjectilePathfindCacheComponent_Properties,
    .propertyCount = sizeof(g_ServerSpellCastProjectilePathfindCacheComponent_Properties) / sizeof(g_ServerSpellCastProjectilePathfindCacheComponent_Properties[0]),
};

// esv::spell_cast::StateComponent (from SpellCast.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_ServerSpellCastStateComponent_Properties[] = {
    { "Phase", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_4", 0x08, FIELD_TYPE_INT32, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "Originator", 0x10, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "StoryActionId", 0x18, FIELD_TYPE_INT32, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_ServerSpellCastStateComponent_Layout = {
    .componentName = "esv::spell_cast::StateComponent",
    .shortName = "ServerSpellCastState",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x1c,
    .properties = g_ServerSpellCastStateComponent_Properties,
    .propertyCount = sizeof(g_ServerSpellCastStateComponent_Properties) / sizeof(g_ServerSpellCastStateComponent_Properties[0]),
};

// esv::spell_cast::UnsheathFallbackTimerComponent (from SpellCast.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_ServerSpellCastUnsheathFallbackTimerComponent_Properties[] = {
    { "Time", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_ServerSpellCastUnsheathFallbackTimerComponent_Layout = {
    .componentName = "esv::spell_cast::UnsheathFallbackTimerComponent",
    .shortName = "ServerSpellCastUnsheathFallbackTimer",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x08,
    .properties = g_ServerSpellCastUnsheathFallbackTimerComponent_Properties,
    .propertyCount = sizeof(g_ServerSpellCastUnsheathFallbackTimerComponent_Properties) / sizeof(g_ServerSpellCastUnsheathFallbackTimerComponent_Properties[0]),
};

// esv::spell_cast::ZoneRangeComponent (from SpellCast.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_ServerSpellCastZoneRangeComponent_Properties[] = {
    { "field_0", 0x00, FIELD_TYPE_INT32, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_4", 0x04, FIELD_TYPE_INT32, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_8", 0x08, FIELD_TYPE_INT32, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_C", 0x0c, FIELD_TYPE_INT32, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_ServerSpellCastZoneRangeComponent_Layout = {
    .componentName = "esv::spell_cast::ZoneRangeComponent",
    .shortName = "ServerSpellCastZoneRange",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x10,
    .properties = g_ServerSpellCastZoneRangeComponent_Properties,
    .propertyCount = sizeof(g_ServerSpellCastZoneRangeComponent_Properties) / sizeof(g_ServerSpellCastZoneRangeComponent_Properties[0]),
};

// esv::stats::proficiency::BaseProficiencyComponent (from ServerData.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_ServerBaseProficiencyComponent_Properties[] = {
    { "ProficiencyGroup", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "Proficiency", 0x08, FIELD_TYPE_UINT32, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_ServerBaseProficiencyComponent_Layout = {
    .componentName = "esv::stats::proficiency::BaseProficiencyComponent",
    .shortName = "ServerBaseProficiency",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x0c,
    .properties = g_ServerBaseProficiencyComponent_Properties,
    .propertyCount = sizeof(g_ServerBaseProficiencyComponent_Properties) / sizeof(g_ServerBaseProficiencyComponent_Properties[0]),
};

// esv::stats::proficiency::ProficiencyGroupStatsComponent (from ServerData.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_ServerProficiencyGroupStatsComponent_Properties[] = {
    { "Stats", 0x00, FIELD_TYPE_UINT32, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_ServerProficiencyGroupStatsComponent_Layout = {
    .componentName = "esv::stats::proficiency::ProficiencyGroupStatsComponent",
    .shortName = "ServerProficiencyGroupStats",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x04,
    .properties = g_ServerProficiencyGroupStatsComponent_Properties,
    .propertyCount = sizeof(g_ServerProficiencyGroupStatsComponent_Properties) / sizeof(g_ServerProficiencyGroupStatsComponent_Properties[0]),
};

// esv::status::CauseComponent (from Status.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_ServerStatusCauseComponent_Properties[] = {
    { "Cause", 0x00, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "StoryActionId", 0x10, FIELD_TYPE_INT32, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_ServerStatusCauseComponent_Layout = {
    .componentName = "esv::status::CauseComponent",
    .shortName = "ServerStatusCause",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x14,
    .properties = g_ServerStatusCauseComponent_Properties,
    .propertyCount = sizeof(g_ServerStatusCauseComponent_Properties) / sizeof(g_ServerStatusCauseComponent_Properties[0]),
};

// esv::status::OwnershipComponent (from Status.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_ServerStatusOwnershipComponent_Properties[] = {
    { "Owner", 0x00, FIELD_TYPE_UINT64, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_ServerStatusOwnershipComponent_Layout = {
    .componentName = "esv::status::OwnershipComponent",
    .shortName = "ServerStatusOwnership",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x08,
    .properties = g_ServerStatusOwnershipComponent_Properties,
    .propertyCount = sizeof(g_ServerStatusOwnershipComponent_Properties) / sizeof(g_ServerStatusOwnershipComponent_Properties[0]),
};

// esv::status::PerformingComponent (from Status.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_ServerStatusPerformingComponent_Properties[] = {
    { "PerformEvent", 0x00, FIELD_TYPE_UINT32, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_ServerStatusPerformingComponent_Layout = {
    .componentName = "esv::status::PerformingComponent",
    .shortName = "ServerStatusPerforming",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x04,
    .properties = g_ServerStatusPerformingComponent_Properties,
    .propertyCount = sizeof(g_ServerStatusPerformingComponent_Properties) / sizeof(g_ServerStatusPerformingComponent_Properties[0]),
};

// esv::status::StatusComponent (from Status.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_ServerStatusComponent_Properties[] = {
    { "Entity", 0x00, FIELD_TYPE_UINT64, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "StatusHandle", 0x08, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "StatusId", 0x10, FIELD_TYPE_UINT32, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "Type", 0x18, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "SpellCastSourceUuid", 0x20, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_ServerStatusComponent_Layout = {
    .componentName = "esv::status::StatusComponent",
    .shortName = "ServerStatus",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x30,
    .properties = g_ServerStatusComponent_Properties,
    .propertyCount = sizeof(g_ServerStatusComponent_Properties) / sizeof(g_ServerStatusComponent_Properties[0]),
};

// esv::status::StatusRequestsComponent (from Status.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_ServerStatusRequestsComponent_Properties[] = {
    { "Create", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "Add", 0x08, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "Destroy", 0x10, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "Deactivate", 0x18, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "Activate", 0x20, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "UnregisterMachineUpdate", 0x28, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "RegisterMachineUpdate", 0x30, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "UpdateLifetime", 0x38, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "OnEvent", 0x40, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "OnTurnStart", 0x48, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "CreatedEvent", 0x50, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "AttemptedEvent", 0x58, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "AppliedEvent", 0x60, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "Refresh", 0x68, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "DestroyedEvent", 0x70, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "ActivateStatusVisuals", 0x78, FIELD_TYPE_BOOL, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "DeactivateStatusVisuals", 0x79, FIELD_TYPE_BOOL, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_ServerStatusRequestsComponent_Layout = {
    .componentName = "esv::status::StatusRequestsComponent",
    .shortName = "ServerStatusRequests",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x7a,
    .properties = g_ServerStatusRequestsComponent_Properties,
    .propertyCount = sizeof(g_ServerStatusRequestsComponent_Properties) / sizeof(g_ServerStatusRequestsComponent_Properties[0]),
};

// esv::status::UniqueComponent (from Status.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_ServerStatusUniqueComponent_Properties[] = {
    { "Unique", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_ServerStatusUniqueComponent_Layout = {
    .componentName = "esv::status::UniqueComponent",
    .shortName = "ServerStatusUnique",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x08,
    .properties = g_ServerStatusUniqueComponent_Properties,
    .propertyCount = sizeof(g_ServerStatusUniqueComponent_Properties) / sizeof(g_ServerStatusUniqueComponent_Properties[0]),
};

// esv::status::aura::ContainerComponent (from Status.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_ServerStatusAuraContainerComponent_Properties[] = {
    { "Auras", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_ServerStatusAuraContainerComponent_Layout = {
    .componentName = "esv::status::aura::ContainerComponent",
    .shortName = "ServerStatusAuraContainer",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x08,
    .properties = g_ServerStatusAuraContainerComponent_Properties,
    .propertyCount = sizeof(g_ServerStatusAuraContainerComponent_Properties) / sizeof(g_ServerStatusAuraContainerComponent_Properties[0]),
};

// esv::status::aura::RemovedStatusAuraEffectEventOneFrameComponent (from Status.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_ServerRemovedStatusAuraEffectEventComponent_Properties[] = {
    { "StatusId", 0x00, FIELD_TYPE_UINT32, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "StoryActionId", 0x04, FIELD_TYPE_INT32, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "Source", 0x08, FIELD_TYPE_UINT64, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "Subject", 0x10, FIELD_TYPE_UINT64, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_ServerRemovedStatusAuraEffectEventComponent_Layout = {
    .componentName = "esv::status::aura::RemovedStatusAuraEffectEventOneFrameComponent",
    .shortName = "ServerRemovedStatusAuraEffectEvent",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x18,
    .properties = g_ServerRemovedStatusAuraEffectEventComponent_Properties,
    .propertyCount = sizeof(g_ServerRemovedStatusAuraEffectEventComponent_Properties) / sizeof(g_ServerRemovedStatusAuraEffectEventComponent_Properties[0]),
};

// esv::surface::SurfaceComponent (from ServerData.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_ServerSurfaceComponent_Properties[] = {
    { "field_0", 0x00, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_10", 0x10, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_ServerSurfaceComponent_Layout = {
    .componentName = "esv::surface::SurfaceComponent",
    .shortName = "ServerSurface",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x18,
    .properties = g_ServerSurfaceComponent_Properties,
    .propertyCount = sizeof(g_ServerSurfaceComponent_Properties) / sizeof(g_ServerSurfaceComponent_Properties[0]),
};

// esv::tags::AnubisTagComponent (from ServerData.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_ServerAnubisTagComponent_Properties[] = {
    { "Tags", 0x00, FIELD_TYPE_GUID, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_ServerAnubisTagComponent_Layout = {
    .componentName = "esv::tags::AnubisTagComponent",
    .shortName = "ServerAnubisTag",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x08,
    .properties = g_ServerAnubisTagComponent_Properties,
    .propertyCount = sizeof(g_ServerAnubisTagComponent_Properties) / sizeof(g_ServerAnubisTagComponent_Properties[0]),
};

// esv::tags::BoostTagComponent (from ServerData.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_ServerBoostTagComponent_Properties[] = {
    { "Tags", 0x00, FIELD_TYPE_GUID, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_ServerBoostTagComponent_Layout = {
    .componentName = "esv::tags::BoostTagComponent",
    .shortName = "ServerBoostTag",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x08,
    .properties = g_ServerBoostTagComponent_Properties,
    .propertyCount = sizeof(g_ServerBoostTagComponent_Properties) / sizeof(g_ServerBoostTagComponent_Properties[0]),
};

// esv::tags::DialogTagComponent (from ServerData.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_ServerDialogTagComponent_Properties[] = {
    { "Tags", 0x00, FIELD_TYPE_GUID, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_ServerDialogTagComponent_Layout = {
    .componentName = "esv::tags::DialogTagComponent",
    .shortName = "ServerDialogTag",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x08,
    .properties = g_ServerDialogTagComponent_Properties,
    .propertyCount = sizeof(g_ServerDialogTagComponent_Properties) / sizeof(g_ServerDialogTagComponent_Properties[0]),
};

// esv::tags::OsirisTagComponent (from Components.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_ServerOsirisTagComponent_Properties[] = {
    { "Tags", 0x00, FIELD_TYPE_GUID, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_ServerOsirisTagComponent_Layout = {
    .componentName = "esv::tags::OsirisTagComponent",
    .shortName = "ServerOsirisTag",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x08,
    .properties = g_ServerOsirisTagComponent_Properties,
    .propertyCount = sizeof(g_ServerOsirisTagComponent_Properties) / sizeof(g_ServerOsirisTagComponent_Properties[0]),
};

// esv::tags::RaceTagComponent (from ServerData.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_ServerRaceTagComponent_Properties[] = {
    { "Tags", 0x00, FIELD_TYPE_GUID, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_ServerRaceTagComponent_Layout = {
    .componentName = "esv::tags::RaceTagComponent",
    .shortName = "ServerRaceTag",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x08,
    .properties = g_ServerRaceTagComponent_Properties,
    .propertyCount = sizeof(g_ServerRaceTagComponent_Properties) / sizeof(g_ServerRaceTagComponent_Properties[0]),
};

// esv::tags::TemplateTagComponent (from ServerData.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_ServerTemplateTagComponent_Properties[] = {
    { "Tags", 0x00, FIELD_TYPE_GUID, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_ServerTemplateTagComponent_Layout = {
    .componentName = "esv::tags::TemplateTagComponent",
    .shortName = "ServerTemplateTag",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x08,
    .properties = g_ServerTemplateTagComponent_Properties,
    .propertyCount = sizeof(g_ServerTemplateTagComponent_Properties) / sizeof(g_ServerTemplateTagComponent_Properties[0]),
};

// esv::trap::DisarmAttemptComponent (from ServerData.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_ServerDisarmAttemptComponent_Properties[] = {
    { "Attempts", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_ServerDisarmAttemptComponent_Layout = {
    .componentName = "esv::trap::DisarmAttemptComponent",
    .shortName = "ServerDisarmAttempt",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x08,
    .properties = g_ServerDisarmAttemptComponent_Properties,
    .propertyCount = sizeof(g_ServerDisarmAttemptComponent_Properties) / sizeof(g_ServerDisarmAttemptComponent_Properties[0]),
};

// esv::trigger::CachedLeaveEventsComponent (from Trigger.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_ServerTriggerCachedLeaveEventsComponent_Properties[] = {
    { "Updated", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_ServerTriggerCachedLeaveEventsComponent_Layout = {
    .componentName = "esv::trigger::CachedLeaveEventsComponent",
    .shortName = "ServerTriggerCachedLeaveEvents",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x08,
    .properties = g_ServerTriggerCachedLeaveEventsComponent_Properties,
    .propertyCount = sizeof(g_ServerTriggerCachedLeaveEventsComponent_Properties) / sizeof(g_ServerTriggerCachedLeaveEventsComponent_Properties[0]),
};

// esv::trigger::EventConfigComponent (from Trigger.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_ServerTriggerEventConfigComponent_Properties[] = {
    { "Config", 0x00, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_ServerTriggerEventConfigComponent_Layout = {
    .componentName = "esv::trigger::EventConfigComponent",
    .shortName = "ServerTriggerEventConfig",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x01,
    .properties = g_ServerTriggerEventConfigComponent_Properties,
    .propertyCount = sizeof(g_ServerTriggerEventConfigComponent_Properties) / sizeof(g_ServerTriggerEventConfigComponent_Properties[0]),
};

// esv::trigger::RegisteredForComponent (from Trigger.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_ServerTriggerRegisteredForComponent_Properties[] = {
    { "RegisteredFor", 0x00, FIELD_TYPE_GUID, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_ServerTriggerRegisteredForComponent_Layout = {
    .componentName = "esv::trigger::RegisteredForComponent",
    .shortName = "ServerTriggerRegisteredFor",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x08,
    .properties = g_ServerTriggerRegisteredForComponent_Properties,
    .propertyCount = sizeof(g_ServerTriggerRegisteredForComponent_Properties) / sizeof(g_ServerTriggerRegisteredForComponent_Properties[0]),
};

// esv::trigger::RegistrationSettingsComponent (from Trigger.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_ServerRegistrationSettingsComponent_Properties[] = {
    { "Registered", 0x00, FIELD_TYPE_BOOL, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_ServerRegistrationSettingsComponent_Layout = {
    .componentName = "esv::trigger::RegistrationSettingsComponent",
    .shortName = "ServerRegistrationSettings",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x01,
    .properties = g_ServerRegistrationSettingsComponent_Properties,
    .propertyCount = sizeof(g_ServerRegistrationSettingsComponent_Properties) / sizeof(g_ServerRegistrationSettingsComponent_Properties[0]),
};

// esv::trigger::UpdatedRegisteredForComponent (from Trigger.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_ServerUpdatedRegisteredForComponent_Properties[] = {
    { "Updated", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_ServerUpdatedRegisteredForComponent_Layout = {
    .componentName = "esv::trigger::UpdatedRegisteredForComponent",
    .shortName = "ServerUpdatedRegisteredFor",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x08,
    .properties = g_ServerUpdatedRegisteredForComponent_Properties,
    .propertyCount = sizeof(g_ServerUpdatedRegisteredForComponent_Properties) / sizeof(g_ServerUpdatedRegisteredForComponent_Properties[0]),
};

// esv::trigger::UpdatedRegisteredForItemsComponent (from Trigger.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_ServerUpdatedRegisteredForItemsComponent_Properties[] = {
    { "Updated", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_ServerUpdatedRegisteredForItemsComponent_Layout = {
    .componentName = "esv::trigger::UpdatedRegisteredForItemsComponent",
    .shortName = "ServerUpdatedRegisteredForItems",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x08,
    .properties = g_ServerUpdatedRegisteredForItemsComponent_Properties,
    .propertyCount = sizeof(g_ServerUpdatedRegisteredForItemsComponent_Properties) / sizeof(g_ServerUpdatedRegisteredForItemsComponent_Properties[0]),
};

// esv::turn::SurfaceTeamSingletonComponent (from Combat.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_TurnSurfaceTeamSingletonComponent_Properties[] = {
    { "EndRound", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_TurnSurfaceTeamSingletonComponent_Layout = {
    .componentName = "esv::turn::SurfaceTeamSingletonComponent",
    .shortName = "TurnSurfaceTeamSingleton",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x08,
    .properties = g_TurnSurfaceTeamSingletonComponent_Properties,
    .propertyCount = sizeof(g_TurnSurfaceTeamSingletonComponent_Properties) / sizeof(g_TurnSurfaceTeamSingletonComponent_Properties[0]),
};

// esv::turn::SurfaceTrackingComponent (from Combat.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_TurnSurfaceTrackingComponent_Properties[] = {
    { "Surfaces", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_TurnSurfaceTrackingComponent_Layout = {
    .componentName = "esv::turn::SurfaceTrackingComponent",
    .shortName = "TurnSurfaceTracking",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x08,
    .properties = g_TurnSurfaceTrackingComponent_Properties,
    .propertyCount = sizeof(g_TurnSurfaceTrackingComponent_Properties) / sizeof(g_TurnSurfaceTrackingComponent_Properties[0]),
};

// esv::unsheath::DefaultComponent (from ServerData.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_ServerUnsheathComponent_Properties[] = {
    { "field_0", 0x00, FIELD_TYPE_INT32, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_4", 0x04, FIELD_TYPE_BOOL, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_ServerUnsheathComponent_Layout = {
    .componentName = "esv::unsheath::DefaultComponent",
    .shortName = "ServerUnsheath",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x05,
    .properties = g_ServerUnsheathComponent_Properties,
    .propertyCount = sizeof(g_ServerUnsheathComponent_Properties) / sizeof(g_ServerUnsheathComponent_Properties[0]),
};

// esv::unsheath::ScriptOverrideComponent (from ServerData.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_ServerUnsheathScriptOverrideComponent_Properties[] = {
    { "field_0", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_ServerUnsheathScriptOverrideComponent_Layout = {
    .componentName = "esv::unsheath::ScriptOverrideComponent",
    .shortName = "ServerUnsheathScriptOverride",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x08,
    .properties = g_ServerUnsheathScriptOverrideComponent_Properties,
    .propertyCount = sizeof(g_ServerUnsheathScriptOverrideComponent_Properties) / sizeof(g_ServerUnsheathScriptOverrideComponent_Properties[0]),
};

// ls::ActiveSkeletonSlotsComponent (from Data.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_ActiveSkeletonSlotsComponent_Properties[] = {
    { "Slots", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_ActiveSkeletonSlotsComponent_Layout = {
    .componentName = "ls::ActiveSkeletonSlotsComponent",
    .shortName = "ActiveSkeletonSlots",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x08,
    .properties = g_ActiveSkeletonSlotsComponent_Properties,
    .propertyCount = sizeof(g_ActiveSkeletonSlotsComponent_Properties) / sizeof(g_ActiveSkeletonSlotsComponent_Properties[0]),
};

// ls::CameraComponent (from Camera.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_CameraComponent_Properties[] = {
    { "MasterBehaviorType", 0x00, FIELD_TYPE_UINT32, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "ExposureSettingIndex", 0x04, FIELD_TYPE_INT32, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "Active", 0x08, FIELD_TYPE_BOOL, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "AcceptsInput", 0x09, FIELD_TYPE_BOOL, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "UseCameraPPSettings", 0x0a, FIELD_TYPE_BOOL, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "UseSplitScreenFov", 0x0b, FIELD_TYPE_BOOL, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "PostProcess", 0x10, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_CameraComponent_Layout = {
    .componentName = "ls::CameraComponent",
    .shortName = "Camera",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x18,
    .properties = g_CameraComponent_Properties,
    .propertyCount = sizeof(g_CameraComponent_Properties) / sizeof(g_CameraComponent_Properties[0]),
};

// ls::CullComponent (from Visual.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_CullComponent_Properties[] = {
    { "CullFlags", 0x00, FIELD_TYPE_UINT16, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_CullComponent_Layout = {
    .componentName = "ls::CullComponent",
    .shortName = "Cull",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x02,
    .properties = g_CullComponent_Properties,
    .propertyCount = sizeof(g_CullComponent_Properties) / sizeof(g_CullComponent_Properties[0]),
};

// ls::DefaultCameraBehavior (from Camera.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_DefaultCameraBehaviorComponent_Properties[] = {
    { "field_0", 0x00, FIELD_TYPE_FLOAT, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "Left", 0x04, FIELD_TYPE_FLOAT, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "Forward", 0x08, FIELD_TYPE_FLOAT, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "RotationX", 0x0c, FIELD_TYPE_FLOAT, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "RotationY", 0x10, FIELD_TYPE_FLOAT, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "Zoom", 0x14, FIELD_TYPE_FLOAT, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "CaptureInput", 0x18, FIELD_TYPE_BOOL, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_19", 0x19, FIELD_TYPE_BOOL, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_1A", 0x1a, FIELD_TYPE_BOOL, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_DefaultCameraBehaviorComponent_Layout = {
    .componentName = "ls::DefaultCameraBehavior",
    .shortName = "DefaultCameraBehavior",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x1b,
    .properties = g_DefaultCameraBehaviorComponent_Properties,
    .propertyCount = sizeof(g_DefaultCameraBehaviorComponent_Properties) / sizeof(g_DefaultCameraBehaviorComponent_Properties[0]),
};

// ls::EffectCameraBehavior (from Camera.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_EffectCameraBehaviorComponent_Properties[] = {
    { "field_0", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_EffectCameraBehaviorComponent_Layout = {
    .componentName = "ls::EffectCameraBehavior",
    .shortName = "EffectCameraBehavior",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x08,
    .properties = g_EffectCameraBehaviorComponent_Properties,
    .propertyCount = sizeof(g_EffectCameraBehaviorComponent_Properties) / sizeof(g_EffectCameraBehaviorComponent_Properties[0]),
};

// ls::GameplayEffectSetTimeFactorRequestsSingletonComponent (from Effect.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_GameplayEffectSetTimeFactorRequestsComponent_Properties[] = {
    { "SetTimeFactor", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_GameplayEffectSetTimeFactorRequestsComponent_Layout = {
    .componentName = "ls::GameplayEffectSetTimeFactorRequestsSingletonComponent",
    .shortName = "GameplayEffectSetTimeFactorRequests",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x08,
    .properties = g_GameplayEffectSetTimeFactorRequestsComponent_Properties,
    .propertyCount = sizeof(g_GameplayEffectSetTimeFactorRequestsComponent_Properties) / sizeof(g_GameplayEffectSetTimeFactorRequestsComponent_Properties[0]),
};

// ls::GameplayVFXSetPlayTimeRequestsSingletonComponent (from Effect.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_GameplayVFXSetPlayTimeRequestsComponent_Properties[] = {
    { "SetPlayTime", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_GameplayVFXSetPlayTimeRequestsComponent_Layout = {
    .componentName = "ls::GameplayVFXSetPlayTimeRequestsSingletonComponent",
    .shortName = "GameplayVFXSetPlayTimeRequests",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x08,
    .properties = g_GameplayVFXSetPlayTimeRequestsComponent_Properties,
    .propertyCount = sizeof(g_GameplayVFXSetPlayTimeRequestsComponent_Properties) / sizeof(g_GameplayVFXSetPlayTimeRequestsComponent_Properties[0]),
};

// ls::GameplayVFXSingletonComponent (from Effect.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_GameplayVFXComponent_Properties[] = {
    { "VFX", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_GameplayVFXComponent_Layout = {
    .componentName = "ls::GameplayVFXSingletonComponent",
    .shortName = "GameplayVFX",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x08,
    .properties = g_GameplayVFXComponent_Properties,
    .propertyCount = sizeof(g_GameplayVFXComponent_Properties) / sizeof(g_GameplayVFXComponent_Properties[0]),
};

// ls::LevelComponent (from Components.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_LevelComponent_Properties[] = {
    { "field_0", 0x00, FIELD_TYPE_UINT64, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "LevelName", 0x08, FIELD_TYPE_UINT32, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_LevelComponent_Layout = {
    .componentName = "ls::LevelComponent",
    .shortName = "Level",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x0c,
    .properties = g_LevelComponent_Properties,
    .propertyCount = sizeof(g_LevelComponent_Properties) / sizeof(g_LevelComponent_Properties[0]),
};

// ls::LevelInstanceComponent (from Components.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_LevelInstanceComponent_Properties[] = {
    { "LevelInstanceID", 0x00, FIELD_TYPE_UINT32, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "LevelName", 0x04, FIELD_TYPE_UINT32, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "LevelInstanceTemplate", 0x08, FIELD_TYPE_UINT32, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "LevelType", 0x0c, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "Active", 0x0d, FIELD_TYPE_BOOL, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "Platform", 0x0e, FIELD_TYPE_BOOL, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "MovingPlatform", 0x0f, FIELD_TYPE_BOOL, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "DynamicLayer", 0x10, FIELD_TYPE_BOOL, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "NeedsPhysics", 0x11, FIELD_TYPE_BOOL, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_12", 0x12, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_13", 0x13, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_14", 0x14, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_15", 0x15, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "qword18", 0x18, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "dword20", 0x20, FIELD_TYPE_INT32, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_24", 0x24, FIELD_TYPE_INT32, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_28", 0x28, FIELD_TYPE_INT32, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_2C", 0x2c, FIELD_TYPE_INT32, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_30", 0x30, FIELD_TYPE_INT32, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_34", 0x34, FIELD_TYPE_FLOAT, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_38", 0x38, FIELD_TYPE_FLOAT, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_3C", 0x3c, FIELD_TYPE_FLOAT, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_LevelInstanceComponent_Layout = {
    .componentName = "ls::LevelInstanceComponent",
    .shortName = "LevelInstance",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x40,
    .properties = g_LevelInstanceComponent_Properties,
    .propertyCount = sizeof(g_LevelInstanceComponent_Properties) / sizeof(g_LevelInstanceComponent_Properties[0]),
};

// ls::LevelInstanceStateComponent (from Components.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_LevelInstanceStateComponent_Properties[] = {
    { "field_0", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_30", 0x08, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_60", 0x10, FIELD_TYPE_INT32, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "LocalBound", 0x18, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "WorldBound", 0x20, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "MergedLevelTemplateUUID", 0x28, FIELD_TYPE_UINT32, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "LevelInstanceID", 0x2c, FIELD_TYPE_UINT32, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "LevelName", 0x30, FIELD_TYPE_UINT32, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "LevelName2", 0x34, FIELD_TYPE_UINT32, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "Destroyed", 0x38, FIELD_TYPE_BOOL, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "MovingPlatform", 0x39, FIELD_TYPE_BOOL, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_A6", 0x3a, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_A8", 0x3c, FIELD_TYPE_FLOAT, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_AC", 0x40, FIELD_TYPE_FLOAT, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_B0", 0x44, FIELD_TYPE_FLOAT, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_B4", 0x48, FIELD_TYPE_FLOAT, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_B8", 0x4c, FIELD_TYPE_FLOAT, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_BC", 0x50, FIELD_TYPE_FLOAT, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_C0", 0x54, FIELD_TYPE_FLOAT, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_C4", 0x58, FIELD_TYPE_FLOAT, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_C8", 0x5c, FIELD_TYPE_FLOAT, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_CC", 0x60, FIELD_TYPE_FLOAT, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_LevelInstanceStateComponent_Layout = {
    .componentName = "ls::LevelInstanceStateComponent",
    .shortName = "LevelInstanceState",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x64,
    .properties = g_LevelInstanceStateComponent_Properties,
    .propertyCount = sizeof(g_LevelInstanceStateComponent_Properties) / sizeof(g_LevelInstanceStateComponent_Properties[0]),
};

// ls::LevelRootComponent (from Components.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_LevelRootComponent_Properties[] = {
    { "LevelName", 0x00, FIELD_TYPE_UINT32, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_LevelRootComponent_Layout = {
    .componentName = "ls::LevelRootComponent",
    .shortName = "LevelRoot",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x04,
    .properties = g_LevelRootComponent_Properties,
    .propertyCount = sizeof(g_LevelRootComponent_Properties) / sizeof(g_LevelRootComponent_Properties[0]),
};

// ls::PhysicsComponent (from Visual.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_PhysicsComponent_Properties[] = {
    { "PhysicsGroup", 0x00, FIELD_TYPE_UINT32, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "CollidesWith", 0x04, FIELD_TYPE_UINT32, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "ExtraFlags", 0x08, FIELD_TYPE_UINT32, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "HasPhysics", 0x0c, FIELD_TYPE_BOOL, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_15", 0x0d, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "IsClustered", 0x0e, FIELD_TYPE_BOOL, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_PhysicsComponent_Layout = {
    .componentName = "ls::PhysicsComponent",
    .shortName = "Physics",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x0f,
    .properties = g_PhysicsComponent_Properties,
    .propertyCount = sizeof(g_PhysicsComponent_Properties) / sizeof(g_PhysicsComponent_Properties[0]),
};

// ls::SoundComponent (from Sound.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_SoundComponent_Properties[] = {
    { "Entity", 0x00, FIELD_TYPE_UINT64, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "Flags", 0x08, FIELD_TYPE_UINT32, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "Duration", 0x0c, FIELD_TYPE_FLOAT, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "Effect", 0x10, FIELD_TYPE_UINT32, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_1C", 0x14, FIELD_TYPE_FLOAT, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_SoundComponent_Layout = {
    .componentName = "ls::SoundComponent",
    .shortName = "Sound",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x18,
    .properties = g_SoundComponent_Properties,
    .propertyCount = sizeof(g_SoundComponent_Properties) / sizeof(g_SoundComponent_Properties[0]),
};

// ls::StaticPhysicsComponent (from Visual.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_StaticPhysicsComponent_Properties[] = {
    { "field_0", 0x00, FIELD_TYPE_UINT32, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_StaticPhysicsComponent_Layout = {
    .componentName = "ls::StaticPhysicsComponent",
    .shortName = "StaticPhysics",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x04,
    .properties = g_StaticPhysicsComponent_Properties,
    .propertyCount = sizeof(g_StaticPhysicsComponent_Properties) / sizeof(g_StaticPhysicsComponent_Properties[0]),
};

// ls::TransformComponent (from Components.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_TransformComponent_Properties[] = {
    { "Transform", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_TransformComponent_Layout = {
    .componentName = "ls::TransformComponent",
    .shortName = "Transform",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x08,
    .properties = g_TransformComponent_Properties,
    .propertyCount = sizeof(g_TransformComponent_Properties) / sizeof(g_TransformComponent_Properties[0]),
};

// ls::VisualAttachRequestOneFrameComponent (from Visual.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_VisualAttachRequestComponent_Properties[] = {
    { "Entity", 0x00, FIELD_TYPE_UINT64, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_8", 0x08, FIELD_TYPE_INT32, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_VisualAttachRequestComponent_Layout = {
    .componentName = "ls::VisualAttachRequestOneFrameComponent",
    .shortName = "VisualAttachRequest",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x0c,
    .properties = g_VisualAttachRequestComponent_Properties,
    .propertyCount = sizeof(g_VisualAttachRequestComponent_Properties) / sizeof(g_VisualAttachRequestComponent_Properties[0]),
};

// ls::VisualChangeRequestOneFrameComponent (from Visual.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_VisualChangeRequestComponent_Properties[] = {
    { "VisualTemplate", 0x00, FIELD_TYPE_UINT32, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "RenderFlags", 0x04, FIELD_TYPE_UINT16, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_VisualChangeRequestComponent_Layout = {
    .componentName = "ls::VisualChangeRequestOneFrameComponent",
    .shortName = "VisualChangeRequest",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x06,
    .properties = g_VisualChangeRequestComponent_Properties,
    .propertyCount = sizeof(g_VisualChangeRequestComponent_Properties) / sizeof(g_VisualChangeRequestComponent_Properties[0]),
};

// ls::VisualComponent (from Visual.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_VisualComponent_Properties[] = {
    { "field_8", 0x00, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "field_9", 0x01, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "NotClustered", 0x02, FIELD_TYPE_BOOL, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_VisualComponent_Layout = {
    .componentName = "ls::VisualComponent",
    .shortName = "Visual",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x03,
    .properties = g_VisualComponent_Properties,
    .propertyCount = sizeof(g_VisualComponent_Properties) / sizeof(g_VisualComponent_Properties[0]),
};

// ls::VisualLoadDesciptionComponent (from Visual.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_VisualLoadDescriptionComponent_Properties[] = {
    { "VisualTemplate", 0x00, FIELD_TYPE_UINT32, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "RenderFlags", 0x04, FIELD_TYPE_UINT16, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "RenderChannel", 0x06, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_VisualLoadDescriptionComponent_Layout = {
    .componentName = "ls::VisualLoadDesciptionComponent",
    .shortName = "VisualLoadDescription",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x07,
    .properties = g_VisualLoadDescriptionComponent_Properties,
    .propertyCount = sizeof(g_VisualLoadDescriptionComponent_Properties) / sizeof(g_VisualLoadDescriptionComponent_Properties[0]),
};

// ls::VisualLoadRequestsSingletonComponent (from Visual.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_VisualLoadRequestsComponent_Properties[] = {
    { "Requests", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_VisualLoadRequestsComponent_Layout = {
    .componentName = "ls::VisualLoadRequestsSingletonComponent",
    .shortName = "VisualLoadRequests",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x08,
    .properties = g_VisualLoadRequestsComponent_Properties,
    .propertyCount = sizeof(g_VisualLoadRequestsComponent_Properties) / sizeof(g_VisualLoadRequestsComponent_Properties[0]),
};

// ls::animation::AnimationWaterfallComponent (from Visual.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_AnimationWaterfallComponent_Properties[] = {
    { "Waterfall", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "Overrides", 0x08, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_AnimationWaterfallComponent_Layout = {
    .componentName = "ls::animation::AnimationWaterfallComponent",
    .shortName = "AnimationWaterfall",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x10,
    .properties = g_AnimationWaterfallComponent_Properties,
    .propertyCount = sizeof(g_AnimationWaterfallComponent_Properties) / sizeof(g_AnimationWaterfallComponent_Properties[0]),
};

// ls::animation::DynamicAnimationTagsComponent (from Visual.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_DynamicAnimationTagsComponent_Properties[] = {
    { "Tags", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_DynamicAnimationTagsComponent_Layout = {
    .componentName = "ls::animation::DynamicAnimationTagsComponent",
    .shortName = "DynamicAnimationTags",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x08,
    .properties = g_DynamicAnimationTagsComponent_Properties,
    .propertyCount = sizeof(g_DynamicAnimationTagsComponent_Properties) / sizeof(g_DynamicAnimationTagsComponent_Properties[0]),
};

// ls::animation::GameplayEventsSingletonComponent (from Visual.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_AnimationGameplayEventsSingletonComponent_Properties[] = {
    { "Events", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_AnimationGameplayEventsSingletonComponent_Layout = {
    .componentName = "ls::animation::GameplayEventsSingletonComponent",
    .shortName = "AnimationGameplayEventsSingleton",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x08,
    .properties = g_AnimationGameplayEventsSingletonComponent_Properties,
    .propertyCount = sizeof(g_AnimationGameplayEventsSingletonComponent_Properties) / sizeof(g_AnimationGameplayEventsSingletonComponent_Properties[0]),
};

// ls::animation::TemplateAnimationSetOverrideComponent (from Visual.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_TemplateAnimationSetOverrideComponent_Properties[] = {
    { "Overrides", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_TemplateAnimationSetOverrideComponent_Layout = {
    .componentName = "ls::animation::TemplateAnimationSetOverrideComponent",
    .shortName = "TemplateAnimationSetOverride",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x08,
    .properties = g_TemplateAnimationSetOverrideComponent_Properties,
    .propertyCount = sizeof(g_TemplateAnimationSetOverrideComponent_Properties) / sizeof(g_TemplateAnimationSetOverrideComponent_Properties[0]),
};

// ls::animation::TextKeyEventsSingletonComponent (from Visual.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_AnimationTextKeyEventsSingletonComponent_Properties[] = {
    { "Events", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_AnimationTextKeyEventsSingletonComponent_Layout = {
    .componentName = "ls::animation::TextKeyEventsSingletonComponent",
    .shortName = "AnimationTextKeyEventsSingleton",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x08,
    .properties = g_AnimationTextKeyEventsSingletonComponent_Properties,
    .propertyCount = sizeof(g_AnimationTextKeyEventsSingletonComponent_Properties) / sizeof(g_AnimationTextKeyEventsSingletonComponent_Properties[0]),
};

// ls::level::LevelInstanceTempDestroyedComponent (from Components.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_LevelInstanceTempDestroyedComponent_Properties[] = {
    { "Level", 0x00, FIELD_TYPE_UINT64, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_LevelInstanceTempDestroyedComponent_Layout = {
    .componentName = "ls::level::LevelInstanceTempDestroyedComponent",
    .shortName = "LevelInstanceTempDestroyed",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x08,
    .properties = g_LevelInstanceTempDestroyedComponent_Properties,
    .propertyCount = sizeof(g_LevelInstanceTempDestroyedComponent_Properties) / sizeof(g_LevelInstanceTempDestroyedComponent_Properties[0]),
};

// ls::trigger::AreaComponent (from Trigger.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_TriggerAreaComponent_Properties[] = {
    { "Physics", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "Bounds", 0x08, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "RotationInv", 0x10, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_TriggerAreaComponent_Layout = {
    .componentName = "ls::trigger::AreaComponent",
    .shortName = "TriggerArea",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x18,
    .properties = g_TriggerAreaComponent_Properties,
    .propertyCount = sizeof(g_TriggerAreaComponent_Properties) / sizeof(g_TriggerAreaComponent_Properties[0]),
};

// ls::trigger::ContainerComponent (from Trigger.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_TriggerContainerComponent_Properties[] = {
    { "field_0", 0x00, FIELD_TYPE_GUID, 0, false, ELEM_TYPE_UNKNOWN, 0 },
    { "Events", 0x08, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_TriggerContainerComponent_Layout = {
    .componentName = "ls::trigger::ContainerComponent",
    .shortName = "TriggerContainer",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x10,
    .properties = g_TriggerContainerComponent_Properties,
    .propertyCount = sizeof(g_TriggerContainerComponent_Properties) / sizeof(g_TriggerContainerComponent_Properties[0]),
};

// ls::trigger::IsInsideOfComponent (from Trigger.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_TriggerIsInsideOfComponent_Properties[] = {
    { "InsideOf", 0x00, FIELD_TYPE_GUID, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_TriggerIsInsideOfComponent_Layout = {
    .componentName = "ls::trigger::IsInsideOfComponent",
    .shortName = "TriggerIsInsideOf",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x08,
    .properties = g_TriggerIsInsideOfComponent_Properties,
    .propertyCount = sizeof(g_TriggerIsInsideOfComponent_Properties) / sizeof(g_TriggerIsInsideOfComponent_Properties[0]),
};

// ls::trigger::UpdatedContainerComponent (from Trigger.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_TriggerUpdatedContainerComponent_Properties[] = {
    { "Updates", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_TriggerUpdatedContainerComponent_Layout = {
    .componentName = "ls::trigger::UpdatedContainerComponent",
    .shortName = "TriggerUpdatedContainer",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x08,
    .properties = g_TriggerUpdatedContainerComponent_Properties,
    .propertyCount = sizeof(g_TriggerUpdatedContainerComponent_Properties) / sizeof(g_TriggerUpdatedContainerComponent_Properties[0]),
};

// ls::trigger::UpdatedPhysicsComponent (from Trigger.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_TriggerUpdatedPhysicsComponent_Properties[] = {
    { "Updates", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_TriggerUpdatedPhysicsComponent_Layout = {
    .componentName = "ls::trigger::UpdatedPhysicsComponent",
    .shortName = "TriggerUpdatedPhysics",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x08,
    .properties = g_TriggerUpdatedPhysicsComponent_Properties,
    .propertyCount = sizeof(g_TriggerUpdatedPhysicsComponent_Properties) / sizeof(g_TriggerUpdatedPhysicsComponent_Properties[0]),
};

// ls::uuid::Component (from Components.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_UuidComponent_Properties[] = {
    { "EntityUuid", 0x00, FIELD_TYPE_UINT8, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_UuidComponent_Layout = {
    .componentName = "ls::uuid::Component",
    .shortName = "Uuid",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x10,
    .properties = g_UuidComponent_Properties,
    .propertyCount = sizeof(g_UuidComponent_Properties) / sizeof(g_UuidComponent_Properties[0]),
};

// ls::uuid::ToHandleMappingComponent (from Components.h)
// WARNING: Offsets are ESTIMATED from Windows x64. Verify for ARM64!
static const ComponentPropertyDef g_UuidToHandleMappingComponent_Properties[] = {
    { "Mappings", 0x00, FIELD_TYPE_GUID, 0, false, ELEM_TYPE_UNKNOWN, 0 },
};

static const ComponentLayoutDef g_UuidToHandleMappingComponent_Layout = {
    .componentName = "ls::uuid::ToHandleMappingComponent",
    .shortName = "UuidToHandleMapping",
    .componentTypeIndex = 0,  // Set dynamically from TypeId
    .componentSize = 0x08,
    .properties = g_UuidToHandleMappingComponent_Properties,
    .propertyCount = sizeof(g_UuidToHandleMappingComponent_Properties) / sizeof(g_UuidToHandleMappingComponent_Properties[0]),
};

// ============================================================================
// Generated Layouts Array
// Add these to g_AllComponentLayouts[] in component_offsets.h
// ============================================================================

#define GENERATED_COMPONENT_COUNT 504

static const ComponentLayoutDef* g_GeneratedComponentLayouts[] = {
    &g_ClientCharacterIconRequestComponent_Layout,
    &g_ClientCharacterIconResultComponent_Layout,
    &g_CharacterLightComponent_Layout,
    &g_CharacterLightSingletonComponent_Layout,
    &g_ClientTimelineActorControlComponent_Layout,
    &g_ClientEquipmentVisualsComponent_Layout,
    &g_GameCameraBehaviorComponent_Layout,
    &g_ClientPaperdollComponent_Layout,
    &g_CameraCombatTargetComponent_Layout,
    &g_CameraSelectorModeComponent_Layout,
    &g_CameraTargetComponent_Layout,
    &g_ClientCCBaseDefinitionStateComponent_Layout,
    &g_ClientCCChangeAppearanceDefinitionComponent_Layout,
    &g_ClientCCCompanionDefinitionComponent_Layout,
    &g_ClientCCDefinitionStateComponent_Layout,
    &g_ClientCCDefinitionStateExComponent_Layout,
    &g_ClientCCDummyDefinitionComponent_Layout,
    &g_ClientCCFullRespecDefinitionComponent_Layout,
    &g_ClientCCLevelUpDefinitionComponent_Layout,
    &g_DummyAnimationStateComponent_Layout,
    &g_DummyAvailableAnimationsComponent_Layout,
    &g_DummyCharacterVFXInitializationComponent_Layout,
    &g_DummiesCreatedSingletonComponent_Layout,
    &g_DummyComponent_Layout,
    &g_DummyEquipmentVisualsStateComponent_Layout,
    &g_DummyFootIKStateComponent_Layout,
    &g_HasDummyComponent_Layout,
    &g_DummyOriginalTransformComponent_Layout,
    &g_DummySpellVFXInitializationComponent_Layout,
    &g_DummySplatterComponent_Layout,
    &g_DummyStoredClothComponent_Layout,
    &g_DummyTransformRequestsSingletonComponent_Layout,
    &g_DummyUnsheathComponent_Layout,
    &g_DummyVFXEntitiesComponent_Layout,
    &g_ClientVisualsDesiredStateComponent_Layout,
    &g_ClientEquipmentVisibilityStateComponent_Layout,
    &g_ClientInterruptPlayerDecisionComponent_Layout,
    &g_PhotoModeCameraOffsetComponent_Layout,
    &g_PhotoModeCameraSavedTransformComponent_Layout,
    &g_PhotoModeCameraTiltComponent_Layout,
    &g_PhotoModeCameraTrackingComponent_Layout,
    &g_PhotoModeDummyAnimationUpdateSingletonComponent_Layout,
    &g_PhotoModeDummyEquipmentSetupOneFrameComponent_Layout,
    &g_PhotoModeDummyEquipmentVisualUpdateSingletonComponent_Layout,
    &g_PhotoModeDummySplatterUpdateSingletonComponent_Layout,
    &g_PhotoModeDummyTransformUpdateSingletonComponent_Layout,
    &g_PhotoModeInvisibilityRequestSingletonComponent_Layout,
    &g_PhotoModeRequestedSingletonComponent_Layout,
    &g_ArmorComponent_Layout,
    &g_AttributeFlagsComponent_Layout,
    &g_BackgroundComponent_Layout,
    &g_BackgroundPassivesComponent_Layout,
    &g_BackgroundTagComponent_Layout,
    &g_BaseHpComponent_Layout,
    &g_BaseStatsComponent_Layout,
    &g_BlockAbilityModifierFromACBoostComponent_Layout,
    &g_BodyTypeComponent_Layout,
    &g_BoostConditionComponent_Layout,
    &g_BoostInfoComponent_Layout,
    &g_BoostsContainerComponent_Layout,
    &g_CanBeDisarmedComponent_Layout,
    &g_CanBeLootedComponent_Layout,
    &g_CanDeflectProjectilesComponent_Layout,
    &g_CanDoActionsComponent_Layout,
    &g_CanDoRestComponent_Layout,
    &g_CanInteractComponent_Layout,
    &g_CanModifyHealthComponent_Layout,
    &g_CanMoveComponent_Layout,
    &g_CanSenseComponent_Layout,
    &g_CanSpeakComponent_Layout,
    &g_CanTravelComponent_Layout,
    &g_CharacterCreationStatsComponent_Layout,
    &g_ClassTagComponent_Layout,
    &g_ClassesComponent_Layout,
    &g_CustomIconComponent_Layout,
    &g_CustomIconsStorageComponent_Layout,
    &g_CustomNameComponent_Layout,
    &g_CustomStatsComponent_Layout,
    &g_DamageReductionBoostComponent_Layout,
    &g_DarknessComponent_Layout,
    &g_DataComponent_Layout,
    &g_DetachedComponent_Layout,
    &g_DifficultyCheckComponent_Layout,
    &g_DisabledEquipmentComponent_Layout,
    &g_DisarmableComponent_Layout,
    &g_DisplayNameComponent_Layout,
    &g_DualWieldingComponent_Layout,
    &g_EquipableComponent_Layout,
    &g_FleeCapabilityComponent_Layout,
    &g_FloatingComponent_Layout,
    &g_GameObjectVisualComponent_Layout,
    &g_GameplayLightComponent_Layout,
    &g_GravityDisabledUntilMovedComponent_Layout,
    &g_HealthComponent_Layout,
    &g_HearingComponent_Layout,
    &g_IconComponent_Layout,
    &g_IncreaseMaxHPBoostComponent_Layout,
    &g_InteractionFilterComponent_Layout,
    &g_InvisibilityComponent_Layout,
    &g_ItemBoostsComponent_Layout,
    &g_EocLevelComponent_Layout,
    &g_LootComponent_Layout,
    &g_LootingStateComponent_Layout,
    &g_MaterialParameterOverrideComponent_Layout,
    &g_MovementComponent_Layout,
    &g_ObjectInteractionComponent_Layout,
    &g_ObjectSizeComponent_Layout,
    &g_OriginAppearanceTagComponent_Layout,
    &g_OriginComponent_Layout,
    &g_OriginPassivesComponent_Layout,
    &g_OriginTagComponent_Layout,
    &g_PassiveComponent_Layout,
    &g_PassiveContainerComponent_Layout,
    &g_PathingComponent_Layout,
    &g_RaceComponent_Layout,
    &g_RequestedRollComponent_Layout,
    &g_ResistancesComponent_Layout,
    &g_SpeakerComponent_Layout,
    &g_StatsComponent_Layout,
    &g_StealthComponent_Layout,
    &g_SteeringComponent_Layout,
    &g_SurfacePathInfluencesComponent_Layout,
    &g_TagComponent_Layout,
    &g_TimelineActorDataComponent_Layout,
    &g_TurnBasedComponent_Layout,
    &g_TurnOrderComponent_Layout,
    &g_UseBoostsComponent_Layout,
    &g_UseComponent_Layout,
    &g_ValueComponent_Layout,
    &g_VoiceComponent_Layout,
    &g_VoiceTagComponent_Layout,
    &g_WeaponComponent_Layout,
    &g_WeaponSetComponent_Layout,
    &g_WieldingComponent_Layout,
    &g_ActionUseConditionsComponent_Layout,
    &g_RollModifiersComponent_Layout,
    &g_ApprovalRatingsComponent_Layout,
    &g_ArmorSetStateComponent_Layout,
    &g_AttitudesToPlayersComponent_Layout,
    &g_CalendarDaysPassedComponent_Layout,
    &g_CalendarStartingDateComponent_Layout,
    &g_CampChestComponent_Layout,
    &g_CampEndTheDayStateComponent_Layout,
    &g_CampQualityComponent_Layout,
    &g_CampSettingsComponent_Layout,
    &g_CampSupplyComponent_Layout,
    &g_CampTotalSuppliesComponent_Layout,
    &g_EquipmentVisualComponent_Layout,
    &g_CharacterCreationAppearanceComponent_Layout,
    &g_CCChangeAppearanceDefinitionComponent_Layout,
    &g_CCCharacterDefinitionComponent_Layout,
    &g_CCCompanionDefinitionComponent_Layout,
    &g_CCDefinitionCommonComponent_Layout,
    &g_CCFullRespecDefinitionComponent_Layout,
    &g_CCLevelUpComponent_Layout,
    &g_CCLevelUpDefinitionComponent_Layout,
    &g_CCRespecDefinitionComponent_Layout,
    &g_CCSessionCommonComponent_Layout,
    &g_CCStateComponent_Layout,
    &g_CCCreationComponent_Layout,
    &g_CCFullRespecComponent_Layout,
    &g_CCDefinitionLevelUpComponent_Layout,
    &g_CCRespecComponent_Layout,
    &g_CanEnterChasmComponent_Layout,
    &g_IsCombatPausedComponent_Layout,
    &g_CombatIsThreatenedComponent_Layout,
    &g_CombatParticipantComponent_Layout,
    &g_CombatStateComponent_Layout,
    &g_ThreatRangeComponent_Layout,
    &g_ConcentrationComponent_Layout,
    &g_DeadByDefaultComponent_Layout,
    &g_DeathTypeComponent_Layout,
    &g_DownedComponent_Layout,
    &g_DeathStateComponent_Layout,
    &g_DialogStateComponent_Layout,
    &g_EncumbranceStateComponent_Layout,
    &g_EncumbranceStatsComponent_Layout,
    &g_AvailableLevelComponent_Layout,
    &g_ExperienceComponent_Layout,
    &g_ExpertiseComponent_Layout,
    &g_FTBParticipantComponent_Layout,
    &g_FTBZoneBlockReasonComponent_Layout,
    &g_GodComponent_Layout,
    &g_GodTagComponent_Layout,
    &g_HitAttackerComponent_Layout,
    &g_HitLifetimeComponent_Layout,
    &g_HitMetaComponent_Layout,
    &g_HitProxyComponent_Layout,
    &g_HitProxyOwnerComponent_Layout,
    &g_HitReactionComponent_Layout,
    &g_HitTargetComponent_Layout,
    &g_HitThrownObjectComponent_Layout,
    &g_HitWeaponComponent_Layout,
    &g_HotbarContainerComponent_Layout,
    &g_HotbarDecksComponent_Layout,
    &g_IdentityComponent_Layout,
    &g_OriginalIdentityComponent_Layout,
    &g_IdentityStateComponent_Layout,
    &g_ImprovisedWeaponWieldedComponent_Layout,
    &g_ImprovisedWeaponWieldingComponent_Layout,
    &g_InterruptActionStateComponent_Layout,
    &g_InterruptConditionallyDisabledComponent_Layout,
    &g_InterruptContainerComponent_Layout,
    &g_InterruptDataComponent_Layout,
    &g_InterruptDecisionComponent_Layout,
    &g_InterruptPreferencesComponent_Layout,
    &g_InterruptPreparedComponent_Layout,
    &g_InterruptZoneComponent_Layout,
    &g_InterruptZoneParticipantComponent_Layout,
    &g_InterruptZoneSourceComponent_Layout,
    &g_InventoryContainerComponent_Layout,
    &g_InventoryDataComponent_Layout,
    &g_InventoryIsOwnedComponent_Layout,
    &g_InventoryMemberComponent_Layout,
    &g_InventoryMemberTransformComponent_Layout,
    &g_InventoryOwnerComponent_Layout,
    &g_InventoryStackComponent_Layout,
    &g_InventoryStackMemberComponent_Layout,
    &g_InventoryTopOwnerComponent_Layout,
    &g_TradeBuybackDataComponent_Layout,
    &g_InventoryWeightComponent_Layout,
    &g_WieldedComponent_Layout,
    &g_WieldingHistoryComponent_Layout,
    &g_ItemDestroyedComponent_Layout,
    &g_ItemDyeComponent_Layout,
    &g_MapMarkerStyleComponent_Layout,
    &g_ItemPortalComponent_Layout,
    &g_ActionTypeComponent_Layout,
    &g_UseActionComponent_Layout,
    &g_ActiveCharacterLightComponent_Layout,
    &g_KeyComponent_Layout,
    &g_LockComponent_Layout,
    &g_MultiplayerUserComponent_Layout,
    &g_AppearanceOverrideComponent_Layout,
    &g_CharacterCreationTemplateOverrideComponent_Layout,
    &g_OwneeCurrentComponent_Layout,
    &g_PartyCompositionComponent_Layout,
    &g_PartyFollowerComponent_Layout,
    &g_PartyMemberComponent_Layout,
    &g_PartyPortalsComponent_Layout,
    &g_PartyRecipesComponent_Layout,
    &g_PartyViewComponent_Layout,
    &g_PartyWaypointsComponent_Layout,
    &g_PassiveUsageCountComponent_Layout,
    &g_PhotoModeCameraTransformComponent_Layout,
    &g_PhotoModeDummyAnimationStateComponent_Layout,
    &g_PhotoModeDummyComponent_Layout,
    &g_PhotoModeDummyEquipmentVisualComponent_Layout,
    &g_PhotoModeDummyShowSplatterComponent_Layout,
    &g_PhotoModeDummyTransformComponent_Layout,
    &g_PhotoModeSessionComponent_Layout,
    &g_PickUpRequestComponent_Layout,
    &g_ProgressionAbilityImprovementsComponent_Layout,
    &g_ProgressionFeatComponent_Layout,
    &g_LevelUpComponent_Layout,
    &g_ProgressionMetaComponent_Layout,
    &g_ProgressionPassivesComponent_Layout,
    &g_ProgressionReplicatedFeatComponent_Layout,
    &g_ProgressionSkillsComponent_Layout,
    &g_ProgressionSpellsComponent_Layout,
    &g_ProjectileSourceComponent_Layout,
    &g_RecruiterComponent_Layout,
    &g_FactionComponent_Layout,
    &g_RelationComponent_Layout,
    &g_ReposeComponent_Layout,
    &g_LongRestStateComponent_Layout,
    &g_LongRestTimelineComponent_Layout,
    &g_LongRestTimersComponent_Layout,
    &g_LongRestUsersComponent_Layout,
    &g_RestingEntitiesComponent_Layout,
    &g_RulesetComponent_Layout,
    &g_ShapeshiftAnimationComponent_Layout,
    &g_ShapeshiftRecoveryAnimationComponent_Layout,
    &g_ShapeshiftReplicatedChangesComponent_Layout,
    &g_ShapeshiftSourceCacheComponent_Layout,
    &g_ShapeshiftStateComponent_Layout,
    &g_SightComponent_Layout,
    &g_SightDataComponent_Layout,
    &g_SightEntityViewshedComponent_Layout,
    &g_IgnoreSurfacesComponent_Layout,
    &g_SpatialGridComponent_Layout,
    &g_AddedSpellsComponent_Layout,
    &g_SpellAiConditionsComponent_Layout,
    &g_AttackSpellOverrideComponent_Layout,
    &g_SpellBookComponent_Layout,
    &g_SpellBookCooldownsComponent_Layout,
    &g_SpellBookPreparesComponent_Layout,
    &g_CCPrepareSpellComponent_Layout,
    &g_SpellContainerComponent_Layout,
    &g_LearnedSpellsComponent_Layout,
    &g_PlayerPrepareSpellComponent_Layout,
    &g_ScriptedExplosionComponent_Layout,
    &g_SpellCastAnimationInfoComponent_Layout,
    &g_SpellCastCacheComponent_Layout,
    &g_SpellCastDataCacheComponent_Layout,
    &g_SpellCastExecutionTimeComponent_Layout,
    &g_SpellCastInterruptResultsComponent_Layout,
    &g_SpellCastIsCastingComponent_Layout,
    &g_SpellCastMovementComponent_Layout,
    &g_SpellCastOutcomeComponent_Layout,
    &g_SpellCastRollsComponent_Layout,
    &g_SpellCastStateComponent_Layout,
    &g_SpellSyncTargetingComponent_Layout,
    &g_ProficiencyComponent_Layout,
    &g_ProficiencyGroupComponent_Layout,
    &g_StatusCauseComponent_Layout,
    &g_StatusContainerComponent_Layout,
    &g_StatusIDComponent_Layout,
    &g_StatusIncapacitatedComponent_Layout,
    &g_StatusLifetimeComponent_Layout,
    &g_StatusLoseControlComponent_Layout,
    &g_StatusVisualDisabledComponent_Layout,
    &g_SummonContainerComponent_Layout,
    &g_IsSummonComponent_Layout,
    &g_SummonLifetimeComponent_Layout,
    &g_TadpolePowersComponent_Layout,
    &g_TadpoleTreeStateComponent_Layout,
    &g_OriginalTemplateComponent_Layout,
    &g_ShootThroughTypeComponent_Layout,
    &g_TriggerTypeComponent_Layout,
    &g_UnsheathComponent_Layout,
    &g_UseSocketComponent_Layout,
    &g_UserAvatarComponent_Layout,
    &g_UserReservedForComponent_Layout,
    &g_ServerActivationGroupContainerComponent_Layout,
    &g_ServerBaseDataComponent_Layout,
    &g_ServerBaseSizeComponent_Layout,
    &g_ServerBaseStatsComponent_Layout,
    &g_ServerBaseWeaponComponent_Layout,
    &g_ServerBreadcrumbComponent_Layout,
    &g_ServerCCCustomIconComponent_Layout,
    &g_ServerDisplayNameListComponent_Layout,
    &g_ServerGameTimerComponent_Layout,
    &g_ServerGameplayLightEquipmentComponent_Layout,
    &g_ServerIconListComponent_Layout,
    &g_InventoryPropertyCanBePickpocketedComponent_Layout,
    &g_InventoryPropertyIsDroppedOnDeathComponent_Layout,
    &g_InventoryPropertyIsTradableComponent_Layout,
    &g_JumpFollowComponent_Layout,
    &g_ServerLeaderComponent_Layout,
    &g_ServerMusicVolumeTriggerStateComponent_Layout,
    &g_ServerOsirisPingRequestSingletonComponent_Layout,
    &g_ServerPingCooldownSingletonComponent_Layout,
    &g_ServerPingRequestSingletonComponent_Layout,
    &g_ServerSafePositionComponent_Layout,
    &g_ActionResourceChangeResultsComponent_Layout,
    &g_ServerRollInProgressComponent_Layout,
    &g_ServerRollStartRequestComponent_Layout,
    &g_ServerAiModifiersComponent_Layout,
    &g_ServerAiArchetypeComponent_Layout,
    &g_ServerAiInterestedInItemsComponent_Layout,
    &g_ServerAiInterestingItemComponent_Layout,
    &g_ServerBoostBaseComponent_Layout,
    &g_BoostConditionalStateComponent_Layout,
    &g_BoostProviderComponent_Layout,
    &g_ServerCCAppearanceVisualTagComponent_Layout,
    &g_ServerCCGodComponent_Layout,
    &g_ServerCCUpdatesComponent_Layout,
    &g_ServerCombatGroupMappingComponent_Layout,
    &g_CombatSwitchedComponent_Layout,
    &g_ServerEnterRequestComponent_Layout,
    &g_CombatFleeRequestComponent_Layout,
    &g_GlobalCombatRequestsComponent_Layout,
    &g_CombatJoiningComponent_Layout,
    &g_CombatLateJoinPenaltyComponent_Layout,
    &g_CombatMergeComponent_Layout,
    &g_CombatSurfaceTeamSingletonComponent_Layout,
    &g_ServerDelayDeathCauseComponent_Layout,
    &g_ServerDelayDeathComponent_Layout,
    &g_ServerKillerComponent_Layout,
    &g_ServerDeathStateComponent_Layout,
    &g_EscortFollowerComponent_Layout,
    &g_EscortLeaderComponent_Layout,
    &g_EscortLeaderPriorityComponent_Layout,
    &g_EscortMemberComponent_Layout,
    &g_EscortStragglersTrackerComponent_Layout,
    &g_ServerExperienceGaveOutComponent_Layout,
    &g_FTBSurfaceTeamSingletonComponent_Layout,
    &g_FTBTimeFactorRequestsComponent_Layout,
    &g_FTBTimeFactorResetRequestsComponent_Layout,
    &g_FTBTurnBasedChangesRequestComponent_Layout,
    &g_FTBZoneComponent_Layout,
    &g_FTBZoneInstigatorComponent_Layout,
    &g_HistoryTargetUUIDComponent_Layout,
    &g_ServerInterruptActionRequestsComponent_Layout,
    &g_ServerInterruptAddRemoveRequestsComponent_Layout,
    &g_ServerInterruptDataSingletonComponent_Layout,
    &g_ServerInterruptInitialParticipantsComponent_Layout,
    &g_ServerInterruptTurnOrderInZoneComponent_Layout,
    &g_ServerInterruptZoneRequestsComponent_Layout,
    &g_ServerInventoryContainerDataComponent_Layout,
    &g_ServerInventoryGroupCheckComponent_Layout,
    &g_ServerShapeshiftEquipmentHistoryComponent_Layout,
    &g_ServerDynamicLayerOwnerComponent_Layout,
    &g_ServerGameplayLightChangesComponent_Layout,
    &g_ServerIsCurrentOwnerComponent_Layout,
    &g_ServerIsLatestOwnerComponent_Layout,
    &g_ServerIsOriginalOwnerComponent_Layout,
    &g_ServerIsPreviousOwnerComponent_Layout,
    &g_ServerOwneeHistoryComponent_Layout,
    &g_ServerOwneeRequestComponent_Layout,
    &g_ServerPassiveBaseComponent_Layout,
    &g_ServerPassiveBoostsComponent_Layout,
    &g_ServerPassivePersistentDataComponent_Layout,
    &g_ServerScriptPassivesComponent_Layout,
    &g_ServerToggledPassivesComponent_Layout,
    &g_PhotoModeCapabilityComponent_Layout,
    &g_ServerPickpocketComponent_Layout,
    &g_ServerProjectileAttachmentComponent_Layout,
    &g_ServerProjectileSpellComponent_Layout,
    &g_ServerRecruitedByComponent_Layout,
    &g_ServerPeersInRangeComponent_Layout,
    &g_ServerReplicationDependencyComponent_Layout,
    &g_ServerReplicationDependencyOwnerComponent_Layout,
    &g_ServerRestPendingTypeComponent_Layout,
    &g_ServerRollFinishedEventComponent_Layout,
    &g_ServerRollStreamsComponent_Layout,
    &g_ShapeshiftHealthReservationComponent_Layout,
    &g_ServerShapeshiftStatesComponent_Layout,
    &g_ServerSightAggregatedDataComponent_Layout,
    &g_ServerAggregatedGameplayLightDataComponent_Layout,
    &g_ServerAiGridViewshedComponent_Layout,
    &g_ServerSightEntityLosCheckQueueComponent_Layout,
    &g_ServerLightLosCheckQueueComponent_Layout,
    &g_OnDamageSpellsComponent_Layout,
    &g_ServerSpellCastCacheComponent_Layout,
    &g_ServerSpellCastHitDelayComponent_Layout,
    &g_ServerSpellCastRequestsComponent_Layout,
    &g_ServerSpellCastResponsibleComponent_Layout,
    &g_ServerSpellExternalsComponent_Layout,
    &g_ServerSpellHitRegisterComponent_Layout,
    &g_ServerSpellCastInterruptComponent_Layout,
    &g_ServerSpellInterruptRequestsComponent_Layout,
    &g_ServerSpellInterruptResultsComponent_Layout,
    &g_ServerSpellCastMovementComponent_Layout,
    &g_ServerSpellCastMovementInfoComponent_Layout,
    &g_ServerSpellCastPendingRequestsComponent_Layout,
    &g_ServerProjectileCacheComponent_Layout,
    &g_ServerSpellCastProjectilePathfindCacheComponent_Layout,
    &g_ServerSpellCastStateComponent_Layout,
    &g_ServerSpellCastUnsheathFallbackTimerComponent_Layout,
    &g_ServerSpellCastZoneRangeComponent_Layout,
    &g_ServerBaseProficiencyComponent_Layout,
    &g_ServerProficiencyGroupStatsComponent_Layout,
    &g_ServerStatusCauseComponent_Layout,
    &g_ServerStatusOwnershipComponent_Layout,
    &g_ServerStatusPerformingComponent_Layout,
    &g_ServerStatusComponent_Layout,
    &g_ServerStatusRequestsComponent_Layout,
    &g_ServerStatusUniqueComponent_Layout,
    &g_ServerStatusAuraContainerComponent_Layout,
    &g_ServerRemovedStatusAuraEffectEventComponent_Layout,
    &g_ServerSurfaceComponent_Layout,
    &g_ServerAnubisTagComponent_Layout,
    &g_ServerBoostTagComponent_Layout,
    &g_ServerDialogTagComponent_Layout,
    &g_ServerOsirisTagComponent_Layout,
    &g_ServerRaceTagComponent_Layout,
    &g_ServerTemplateTagComponent_Layout,
    &g_ServerDisarmAttemptComponent_Layout,
    &g_ServerTriggerCachedLeaveEventsComponent_Layout,
    &g_ServerTriggerEventConfigComponent_Layout,
    &g_ServerTriggerRegisteredForComponent_Layout,
    &g_ServerRegistrationSettingsComponent_Layout,
    &g_ServerUpdatedRegisteredForComponent_Layout,
    &g_ServerUpdatedRegisteredForItemsComponent_Layout,
    &g_TurnSurfaceTeamSingletonComponent_Layout,
    &g_TurnSurfaceTrackingComponent_Layout,
    &g_ServerUnsheathComponent_Layout,
    &g_ServerUnsheathScriptOverrideComponent_Layout,
    &g_ActiveSkeletonSlotsComponent_Layout,
    &g_CameraComponent_Layout,
    &g_CullComponent_Layout,
    &g_DefaultCameraBehaviorComponent_Layout,
    &g_EffectCameraBehaviorComponent_Layout,
    &g_GameplayEffectSetTimeFactorRequestsComponent_Layout,
    &g_GameplayVFXSetPlayTimeRequestsComponent_Layout,
    &g_GameplayVFXComponent_Layout,
    &g_LevelComponent_Layout,
    &g_LevelInstanceComponent_Layout,
    &g_LevelInstanceStateComponent_Layout,
    &g_LevelRootComponent_Layout,
    &g_PhysicsComponent_Layout,
    &g_SoundComponent_Layout,
    &g_StaticPhysicsComponent_Layout,
    &g_TransformComponent_Layout,
    &g_VisualAttachRequestComponent_Layout,
    &g_VisualChangeRequestComponent_Layout,
    &g_VisualComponent_Layout,
    &g_VisualLoadDescriptionComponent_Layout,
    &g_VisualLoadRequestsComponent_Layout,
    &g_AnimationWaterfallComponent_Layout,
    &g_DynamicAnimationTagsComponent_Layout,
    &g_AnimationGameplayEventsSingletonComponent_Layout,
    &g_TemplateAnimationSetOverrideComponent_Layout,
    &g_AnimationTextKeyEventsSingletonComponent_Layout,
    &g_LevelInstanceTempDestroyedComponent_Layout,
    &g_TriggerAreaComponent_Layout,
    &g_TriggerContainerComponent_Layout,
    &g_TriggerIsInsideOfComponent_Layout,
    &g_TriggerUpdatedContainerComponent_Layout,
    &g_TriggerUpdatedPhysicsComponent_Layout,
    &g_UuidComponent_Layout,
    &g_UuidToHandleMappingComponent_Layout,
};

#endif // GENERATED_PROPERTY_DEFS_H
