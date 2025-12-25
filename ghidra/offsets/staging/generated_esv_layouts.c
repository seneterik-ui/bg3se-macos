// Generated esv:: Component Layouts
// Cross-referenced from:
// - Windows BG3SE headers: /Users/tomdimino/Desktop/Programming/bg3se/BG3Extender/GameDefinitions/Components/
// - ARM64 sizes: /Users/tomdimino/Desktop/Programming/bg3se-macos/ghidra/offsets/components/COMPONENT_SIZES_ESV_*.md
// Auto-generated on 2025-12-24

// =============================================================================
// CORE COMPONENTS (esv::)
// =============================================================================

// esv::RecruitedByComponent - 8 bytes (0x08)
// Source: ServerData.h
static const ComponentPropertyDef g_esv_RecruitedByComponent_Properties[] = {
    { "RecruitedBy", 0x00, FIELD_TYPE_ENTITYHANDLE, 0, true },
};
static const ComponentLayoutDef g_esv_RecruitedByComponent_Layout = {
    .componentName = "esv::recruit::RecruitedByComponent",
    .shortName = "RecruitedBy",
    .componentTypeIndex = 0,
    .componentSize = 0x08,
    .properties = g_esv_RecruitedByComponent_Properties,
    .propertyCount = sizeof(g_esv_RecruitedByComponent_Properties) / sizeof(g_esv_RecruitedByComponent_Properties[0]),
};

// esv::GameTimerComponent - 40 bytes (0x28)
// Source: ServerData.h
static const ComponentPropertyDef g_esv_GameTimerComponent_Properties[] = {
    { "field_18", 0x00, FIELD_TYPE_FIXEDSTRING, 0, true },
    { "field_20", 0x08, FIELD_TYPE_ENTITYHANDLE, 0, true },
    { "field_28", 0x10, FIELD_TYPE_INT32, 0, true },
    { "field_2C", 0x14, FIELD_TYPE_INT32, 0, true },
    { "field_30", 0x18, FIELD_TYPE_INT32, 0, true },
    { "field_34", 0x1C, FIELD_TYPE_INT32, 0, true },
    { "field_38", 0x20, FIELD_TYPE_UINT8, 0, true },
};
static const ComponentLayoutDef g_esv_GameTimerComponent_Layout = {
    .componentName = "esv::GameTimerComponent",
    .shortName = "GameTimer",
    .componentTypeIndex = 0,
    .componentSize = 0x28,
    .properties = g_esv_GameTimerComponent_Properties,
    .propertyCount = sizeof(g_esv_GameTimerComponent_Properties) / sizeof(g_esv_GameTimerComponent_Properties[0]),
};

// esv::ExperienceGaveOutComponent - 4 bytes (0x04)
// Source: ServerData.h
static const ComponentPropertyDef g_esv_ExperienceGaveOutComponent_Properties[] = {
    { "Experience", 0x00, FIELD_TYPE_INT32, 0, true },
};
static const ComponentLayoutDef g_esv_ExperienceGaveOutComponent_Layout = {
    .componentName = "esv::exp::ExperienceGaveOutComponent",
    .shortName = "ExperienceGaveOut",
    .componentTypeIndex = 0,
    .componentSize = 0x04,
    .properties = g_esv_ExperienceGaveOutComponent_Properties,
    .propertyCount = sizeof(g_esv_ExperienceGaveOutComponent_Properties) / sizeof(g_esv_ExperienceGaveOutComponent_Properties[0]),
};

// esv::ActivationGroupContainerComponent - 16 bytes (0x10)
// Source: ServerData.h
static const ComponentPropertyDef g_esv_ActivationGroupContainerComponent_Properties[] = {
    { "Groups", 0x00, FIELD_TYPE_ARRAY, 0, true },  // Array<ActivationGroupData>
};
static const ComponentLayoutDef g_esv_ActivationGroupContainerComponent_Layout = {
    .componentName = "esv::ActivationGroupContainerComponent",
    .shortName = "ActivationGroupContainer",
    .componentTypeIndex = 0,
    .componentSize = 0x10,
    .properties = g_esv_ActivationGroupContainerComponent_Properties,
    .propertyCount = sizeof(g_esv_ActivationGroupContainerComponent_Properties) / sizeof(g_esv_ActivationGroupContainerComponent_Properties[0]),
};

// esv::SafePositionComponent - 16 bytes (0x10)
// Source: ServerData.h
static const ComponentPropertyDef g_esv_SafePositionComponent_Properties[] = {
    { "Position", 0x00, FIELD_TYPE_VEC3, 0, true },  // glm::vec3 (12 bytes)
    { "field_24", 0x0C, FIELD_TYPE_BOOL, 0, true },
};
static const ComponentLayoutDef g_esv_SafePositionComponent_Layout = {
    .componentName = "esv::SafePositionComponent",
    .shortName = "SafePosition",
    .componentTypeIndex = 0,
    .componentSize = 0x10,
    .properties = g_esv_SafePositionComponent_Properties,
    .propertyCount = sizeof(g_esv_SafePositionComponent_Properties) / sizeof(g_esv_SafePositionComponent_Properties[0]),
};

// esv::BaseDataComponent - 24 bytes (0x18)
// Source: ServerData.h
static const ComponentPropertyDef g_esv_BaseDataComponent_Properties[] = {
    { "Resistances", 0x00, FIELD_TYPE_ARRAY, 0, true },  // std::array<std::array<ResistanceBoostFlags, 7>, 2>
    { "Weight", 0x0E, FIELD_TYPE_INT32, 0, true },
    { "Flags", 0x12, FIELD_TYPE_UINT32, 0, true },
};
static const ComponentLayoutDef g_esv_BaseDataComponent_Layout = {
    .componentName = "esv::BaseDataComponent",
    .shortName = "BaseData",
    .componentTypeIndex = 0,
    .componentSize = 0x18,
    .properties = g_esv_BaseDataComponent_Properties,
    .propertyCount = sizeof(g_esv_BaseDataComponent_Properties) / sizeof(g_esv_BaseDataComponent_Properties[0]),
};

// esv::BaseSizeComponent - 2 bytes (0x02)
// Source: ServerData.h
static const ComponentPropertyDef g_esv_BaseSizeComponent_Properties[] = {
    { "GameSize", 0x00, FIELD_TYPE_UINT8, 0, true },
    { "SoundSize", 0x01, FIELD_TYPE_UINT8, 0, true },
};
static const ComponentLayoutDef g_esv_BaseSizeComponent_Layout = {
    .componentName = "esv::BaseSizeComponent",
    .shortName = "BaseSize",
    .componentTypeIndex = 0,
    .componentSize = 0x02,
    .properties = g_esv_BaseSizeComponent_Properties,
    .propertyCount = sizeof(g_esv_BaseSizeComponent_Properties) / sizeof(g_esv_BaseSizeComponent_Properties[0]),
};

// esv::BaseStatsComponent - 4 bytes (0x04)
// Source: ServerData.h
static const ComponentPropertyDef g_esv_BaseStatsComponent_Properties[] = {
    { "Initiative", 0x00, FIELD_TYPE_INT32, 0, true },
};
static const ComponentLayoutDef g_esv_BaseStatsComponent_Layout = {
    .componentName = "esv::BaseStatsComponent",
    .shortName = "BaseStats",
    .componentTypeIndex = 0,
    .componentSize = 0x04,
    .properties = g_esv_BaseStatsComponent_Properties,
    .propertyCount = sizeof(g_esv_BaseStatsComponent_Properties) / sizeof(g_esv_BaseStatsComponent_Properties[0]),
};

// esv::BaseWeaponComponent - 16 bytes (0x10)
// Source: ServerData.h
static const ComponentPropertyDef g_esv_BaseWeaponComponent_Properties[] = {
    { "DamageList", 0x00, FIELD_TYPE_ARRAY, 0, true },  // Array<BaseWeaponDamage>
};
static const ComponentLayoutDef g_esv_BaseWeaponComponent_Layout = {
    .componentName = "esv::BaseWeaponComponent",
    .shortName = "BaseWeapon",
    .componentTypeIndex = 0,
    .componentSize = 0x10,
    .properties = g_esv_BaseWeaponComponent_Properties,
    .propertyCount = sizeof(g_esv_BaseWeaponComponent_Properties) / sizeof(g_esv_BaseWeaponComponent_Properties[0]),
};

// esv::ExperienceComponent - 8 bytes (0x08)
// Source: COMPONENT_SIZES_ESV_CORE.md (no Windows header struct found)
static const ComponentPropertyDef g_esv_ExperienceComponent_Properties[] = {
    { "Value", 0x00, FIELD_TYPE_INT32, 0, true },  // Estimated field
};
static const ComponentLayoutDef g_esv_ExperienceComponent_Layout = {
    .componentName = "esv::ExperienceComponent",
    .shortName = "Experience",
    .componentTypeIndex = 0,
    .componentSize = 0x08,
    .properties = g_esv_ExperienceComponent_Properties,
    .propertyCount = sizeof(g_esv_ExperienceComponent_Properties) / sizeof(g_esv_ExperienceComponent_Properties[0]),
};

// esv::HealthComponent - 16 bytes (0x10)
// Source: COMPONENT_SIZES_ESV_CORE.md
static const ComponentPropertyDef g_esv_HealthComponent_Properties[] = {
    { "Hp", 0x00, FIELD_TYPE_INT32, 0, true },
    { "MaxHp", 0x04, FIELD_TYPE_INT32, 0, true },
    { "TempHp", 0x08, FIELD_TYPE_INT32, 0, true },
};
static const ComponentLayoutDef g_esv_HealthComponent_Layout = {
    .componentName = "esv::HealthComponent",
    .shortName = "Health",
    .componentTypeIndex = 0,
    .componentSize = 0x10,
    .properties = g_esv_HealthComponent_Properties,
    .propertyCount = sizeof(g_esv_HealthComponent_Properties) / sizeof(g_esv_HealthComponent_Properties[0]),
};

// esv::BaseHpComponent - 16 bytes (0x10)
// Source: COMPONENT_SIZES_ESV_CORE.md
static const ComponentPropertyDef g_esv_BaseHpComponent_Properties[] = {
    { "Hp", 0x00, FIELD_TYPE_INT32, 0, true },
    { "MaxHp", 0x04, FIELD_TYPE_INT32, 0, true },
    { "VitalityBoost", 0x08, FIELD_TYPE_INT32, 0, true },
};
static const ComponentLayoutDef g_esv_BaseHpComponent_Layout = {
    .componentName = "esv::BaseHpComponent",
    .shortName = "BaseHp",
    .componentTypeIndex = 0,
    .componentSize = 0x10,
    .properties = g_esv_BaseHpComponent_Properties,
    .propertyCount = sizeof(g_esv_BaseHpComponent_Properties) / sizeof(g_esv_BaseHpComponent_Properties[0]),
};

// esv::ArmorClassComponent - 32 bytes (0x20)
// Source: COMPONENT_SIZES_ESV_CORE.md
static const ComponentPropertyDef g_esv_ArmorClassComponent_Properties[] = {
    { "AC", 0x00, FIELD_TYPE_INT32, 0, true },
    { "ArmorType", 0x04, FIELD_TYPE_INT32, 0, true },
    { "AbilityModifierCap", 0x08, FIELD_TYPE_INT32, 0, true },
};
static const ComponentLayoutDef g_esv_ArmorClassComponent_Layout = {
    .componentName = "esv::ArmorClassComponent",
    .shortName = "ArmorClass",
    .componentTypeIndex = 0,
    .componentSize = 0x20,
    .properties = g_esv_ArmorClassComponent_Properties,
    .propertyCount = sizeof(g_esv_ArmorClassComponent_Properties) / sizeof(g_esv_ArmorClassComponent_Properties[0]),
};

// =============================================================================
// TAG COMPONENTS (1 byte)
// =============================================================================

// esv::IsMarkedForDeletionComponent - 1 byte (0x01)
static const ComponentPropertyDef g_esv_IsMarkedForDeletionComponent_Properties[] = {
    { "Value", 0x00, FIELD_TYPE_BOOL, 0, true },
};
static const ComponentLayoutDef g_esv_IsMarkedForDeletionComponent_Layout = {
    .componentName = "esv::IsMarkedForDeletionComponent",
    .shortName = "IsMarkedForDeletion",
    .componentTypeIndex = 0,
    .componentSize = 0x01,
    .properties = g_esv_IsMarkedForDeletionComponent_Properties,
    .propertyCount = sizeof(g_esv_IsMarkedForDeletionComponent_Properties) / sizeof(g_esv_IsMarkedForDeletionComponent_Properties[0]),
};

// esv::NetComponent - 1 byte (0x01)
static const ComponentPropertyDef g_esv_NetComponent_Properties[] = {
    { "Value", 0x00, FIELD_TYPE_BOOL, 0, true },
};
static const ComponentLayoutDef g_esv_NetComponent_Layout = {
    .componentName = "esv::NetComponent",
    .shortName = "Net",
    .componentTypeIndex = 0,
    .componentSize = 0x01,
    .properties = g_esv_NetComponent_Properties,
    .propertyCount = sizeof(g_esv_NetComponent_Properties) / sizeof(g_esv_NetComponent_Properties[0]),
};

// esv::ReplicationDependencyComponent - 1 byte (0x01)
static const ComponentPropertyDef g_esv_ReplicationDependencyComponent_Properties[] = {
    { "Value", 0x00, FIELD_TYPE_BOOL, 0, true },
};
static const ComponentLayoutDef g_esv_ReplicationDependencyComponent_Layout = {
    .componentName = "esv::ReplicationDependencyComponent",
    .shortName = "ReplicationDependency",
    .componentTypeIndex = 0,
    .componentSize = 0x01,
    .properties = g_esv_ReplicationDependencyComponent_Properties,
    .propertyCount = sizeof(g_esv_ReplicationDependencyComponent_Properties) / sizeof(g_esv_ReplicationDependencyComponent_Properties[0]),
};

// esv::VariableManagerComponent - 1 byte (0x01)
static const ComponentPropertyDef g_esv_VariableManagerComponent_Properties[] = {
    { "Value", 0x00, FIELD_TYPE_BOOL, 0, true },
};
static const ComponentLayoutDef g_esv_VariableManagerComponent_Layout = {
    .componentName = "esv::VariableManagerComponent",
    .shortName = "VariableManager",
    .componentTypeIndex = 0,
    .componentSize = 0x01,
    .properties = g_esv_VariableManagerComponent_Properties,
    .propertyCount = sizeof(g_esv_VariableManagerComponent_Properties) / sizeof(g_esv_VariableManagerComponent_Properties[0]),
};

// esv::SaveCompletedOneFrameComponent - 1 byte (0x01)
static const ComponentPropertyDef g_esv_SaveCompletedOneFrameComponent_Properties[] = {
    { "Value", 0x00, FIELD_TYPE_BOOL, 0, true },
};
static const ComponentLayoutDef g_esv_SaveCompletedOneFrameComponent_Layout = {
    .componentName = "esv::SaveCompletedOneFrameComponent",
    .shortName = "SaveCompletedOneFrame",
    .componentTypeIndex = 0,
    .componentSize = 0x01,
    .properties = g_esv_SaveCompletedOneFrameComponent_Properties,
    .propertyCount = sizeof(g_esv_SaveCompletedOneFrameComponent_Properties) / sizeof(g_esv_SaveCompletedOneFrameComponent_Properties[0]),
};

// esv::SaveWorldPrepareEventComponent - 1 byte (0x01)
static const ComponentPropertyDef g_esv_SaveWorldPrepareEventComponent_Properties[] = {
    { "Value", 0x00, FIELD_TYPE_BOOL, 0, true },
};
static const ComponentLayoutDef g_esv_SaveWorldPrepareEventComponent_Layout = {
    .componentName = "esv::SaveWorldPrepareEventComponent",
    .shortName = "SaveWorldPrepareEvent",
    .componentTypeIndex = 0,
    .componentSize = 0x01,
    .properties = g_esv_SaveWorldPrepareEventComponent_Properties,
    .propertyCount = sizeof(g_esv_SaveWorldPrepareEventComponent_Properties) / sizeof(g_esv_SaveWorldPrepareEventComponent_Properties[0]),
};

// esv::GravityInstigatorComponent - 1 byte (0x01)
static const ComponentPropertyDef g_esv_GravityInstigatorComponent_Properties[] = {
    { "Value", 0x00, FIELD_TYPE_BOOL, 0, true },
};
static const ComponentLayoutDef g_esv_GravityInstigatorComponent_Layout = {
    .componentName = "esv::GravityInstigatorComponent",
    .shortName = "GravityInstigator",
    .componentTypeIndex = 0,
    .componentSize = 0x01,
    .properties = g_esv_GravityInstigatorComponent_Properties,
    .propertyCount = sizeof(g_esv_GravityInstigatorComponent_Properties) / sizeof(g_esv_GravityInstigatorComponent_Properties[0]),
};

// esv::ServerReplicationDependencyOwnerComponent - 1 byte (0x01)
static const ComponentPropertyDef g_esv_ServerReplicationDependencyOwnerComponent_Properties[] = {
    { "Value", 0x00, FIELD_TYPE_BOOL, 0, true },
};
static const ComponentLayoutDef g_esv_ServerReplicationDependencyOwnerComponent_Layout = {
    .componentName = "esv::ServerReplicationDependencyOwnerComponent",
    .shortName = "ServerReplicationDependencyOwner",
    .componentTypeIndex = 0,
    .componentSize = 0x01,
    .properties = g_esv_ServerReplicationDependencyOwnerComponent_Properties,
    .propertyCount = sizeof(g_esv_ServerReplicationDependencyOwnerComponent_Properties) / sizeof(g_esv_ServerReplicationDependencyOwnerComponent_Properties[0]),
};

// =============================================================================
// SMALL COMPONENTS (4-8 bytes)
// =============================================================================

// esv::ActiveCharacterLightComponent - 4 bytes (0x04)
static const ComponentPropertyDef g_esv_ActiveCharacterLightComponent_Properties[] = {
    { "LightUUID", 0x00, FIELD_TYPE_FIXEDSTRING, 0, true },
};
static const ComponentLayoutDef g_esv_ActiveCharacterLightComponent_Layout = {
    .componentName = "esv::ActiveCharacterLightComponent",
    .shortName = "ActiveCharacterLight",
    .componentTypeIndex = 0,
    .componentSize = 0x04,
    .properties = g_esv_ActiveCharacterLightComponent_Properties,
    .propertyCount = sizeof(g_esv_ActiveCharacterLightComponent_Properties) / sizeof(g_esv_ActiveCharacterLightComponent_Properties[0]),
};

// esv::EocLevelComponent - 4 bytes (0x04)
static const ComponentPropertyDef g_esv_EocLevelComponent_Properties[] = {
    { "Level", 0x00, FIELD_TYPE_INT32, 0, true },
};
static const ComponentLayoutDef g_esv_EocLevelComponent_Layout = {
    .componentName = "esv::EocLevelComponent",
    .shortName = "EocLevel",
    .componentTypeIndex = 0,
    .componentSize = 0x04,
    .properties = g_esv_EocLevelComponent_Properties,
    .propertyCount = sizeof(g_esv_EocLevelComponent_Properties) / sizeof(g_esv_EocLevelComponent_Properties[0]),
};

// esv::FollowersComponent - 4 bytes (0x04)
static const ComponentPropertyDef g_esv_FollowersComponent_Properties[] = {
    { "Value", 0x00, FIELD_TYPE_INT32, 0, true },
};
static const ComponentLayoutDef g_esv_FollowersComponent_Layout = {
    .componentName = "esv::FollowersComponent",
    .shortName = "Followers",
    .componentTypeIndex = 0,
    .componentSize = 0x04,
    .properties = g_esv_FollowersComponent_Properties,
    .propertyCount = sizeof(g_esv_FollowersComponent_Properties) / sizeof(g_esv_FollowersComponent_Properties[0]),
};

// esv::GravityActiveTimeoutComponent - 4 bytes (0x04)
static const ComponentPropertyDef g_esv_GravityActiveTimeoutComponent_Properties[] = {
    { "Timeout", 0x00, FIELD_TYPE_FLOAT, 0, true },
};
static const ComponentLayoutDef g_esv_GravityActiveTimeoutComponent_Layout = {
    .componentName = "esv::GravityActiveTimeoutComponent",
    .shortName = "GravityActiveTimeout",
    .componentTypeIndex = 0,
    .componentSize = 0x04,
    .properties = g_esv_GravityActiveTimeoutComponent_Properties,
    .propertyCount = sizeof(g_esv_GravityActiveTimeoutComponent_Properties) / sizeof(g_esv_GravityActiveTimeoutComponent_Properties[0]),
};

// esv::IsGlobalComponent - 4 bytes (0x04)
static const ComponentPropertyDef g_esv_IsGlobalComponent_Properties[] = {
    { "Value", 0x00, FIELD_TYPE_INT32, 0, true },
};
static const ComponentLayoutDef g_esv_IsGlobalComponent_Layout = {
    .componentName = "esv::IsGlobalComponent",
    .shortName = "IsGlobal",
    .componentTypeIndex = 0,
    .componentSize = 0x04,
    .properties = g_esv_IsGlobalComponent_Properties,
    .propertyCount = sizeof(g_esv_IsGlobalComponent_Properties) / sizeof(g_esv_IsGlobalComponent_Properties[0]),
};

// esv::LevelComponent - 4 bytes (0x04)
static const ComponentPropertyDef g_esv_LevelComponent_Properties[] = {
    { "Level", 0x00, FIELD_TYPE_INT32, 0, true },
};
static const ComponentLayoutDef g_esv_LevelComponent_Layout = {
    .componentName = "esv::LevelComponent",
    .shortName = "Level",
    .componentTypeIndex = 0,
    .componentSize = 0x04,
    .properties = g_esv_LevelComponent_Properties,
    .propertyCount = sizeof(g_esv_LevelComponent_Properties) / sizeof(g_esv_LevelComponent_Properties[0]),
};

// esv::OriginalTemplateComponent - 4 bytes (0x04)
static const ComponentPropertyDef g_esv_OriginalTemplateComponent_Properties[] = {
    { "TemplateId", 0x00, FIELD_TYPE_FIXEDSTRING, 0, true },
};
static const ComponentLayoutDef g_esv_OriginalTemplateComponent_Layout = {
    .componentName = "esv::OriginalTemplateComponent",
    .shortName = "OriginalTemplate",
    .componentTypeIndex = 0,
    .componentSize = 0x04,
    .properties = g_esv_OriginalTemplateComponent_Properties,
    .propertyCount = sizeof(g_esv_OriginalTemplateComponent_Properties) / sizeof(g_esv_OriginalTemplateComponent_Properties[0]),
};

// esv::PartyMemberComponent - 4 bytes (0x04)
static const ComponentPropertyDef g_esv_PartyMemberComponent_Properties[] = {
    { "Party", 0x00, FIELD_TYPE_FIXEDSTRING, 0, true },
};
static const ComponentLayoutDef g_esv_PartyMemberComponent_Layout = {
    .componentName = "esv::PartyMemberComponent",
    .shortName = "PartyMember",
    .componentTypeIndex = 0,
    .componentSize = 0x04,
    .properties = g_esv_PartyMemberComponent_Properties,
    .propertyCount = sizeof(g_esv_PartyMemberComponent_Properties) / sizeof(g_esv_PartyMemberComponent_Properties[0]),
};

// esv::ServerDisplayNameListComponent - 4 bytes (0x04)
static const ComponentPropertyDef g_esv_ServerDisplayNameListComponent_Properties[] = {
    { "Value", 0x00, FIELD_TYPE_FIXEDSTRING, 0, true },
};
static const ComponentLayoutDef g_esv_ServerDisplayNameListComponent_Layout = {
    .componentName = "esv::ServerDisplayNameListComponent",
    .shortName = "ServerDisplayNameList",
    .componentTypeIndex = 0,
    .componentSize = 0x04,
    .properties = g_esv_ServerDisplayNameListComponent_Properties,
    .propertyCount = sizeof(g_esv_ServerDisplayNameListComponent_Properties) / sizeof(g_esv_ServerDisplayNameListComponent_Properties[0]),
};

// esv::StatusContainerComponent - 4 bytes (0x04)
static const ComponentPropertyDef g_esv_StatusContainerComponent_Properties[] = {
    { "Value", 0x00, FIELD_TYPE_INT32, 0, true },
};
static const ComponentLayoutDef g_esv_StatusContainerComponent_Layout = {
    .componentName = "esv::StatusContainerComponent",
    .shortName = "StatusContainer",
    .componentTypeIndex = 0,
    .componentSize = 0x04,
    .properties = g_esv_StatusContainerComponent_Properties,
    .propertyCount = sizeof(g_esv_StatusContainerComponent_Properties) / sizeof(g_esv_StatusContainerComponent_Properties[0]),
};

// esv::AIHintAreaTrigger - 8 bytes (0x08)
static const ComponentPropertyDef g_esv_AIHintAreaTrigger_Properties[] = {
    { "Value", 0x00, FIELD_TYPE_INT64, 0, true },
};
static const ComponentLayoutDef g_esv_AIHintAreaTrigger_Layout = {
    .componentName = "esv::AIHintAreaTrigger",
    .shortName = "AIHintAreaTrigger",
    .componentTypeIndex = 0,
    .componentSize = 0x08,
    .properties = g_esv_AIHintAreaTrigger_Properties,
    .propertyCount = sizeof(g_esv_AIHintAreaTrigger_Properties) / sizeof(g_esv_AIHintAreaTrigger_Properties[0]),
};

// esv::ActiveMusicVolumeComponent - 8 bytes (0x08)
static const ComponentPropertyDef g_esv_ActiveMusicVolumeComponent_Properties[] = {
    { "Value", 0x00, FIELD_TYPE_INT64, 0, true },
};
static const ComponentLayoutDef g_esv_ActiveMusicVolumeComponent_Layout = {
    .componentName = "esv::ActiveMusicVolumeComponent",
    .shortName = "ActiveMusicVolume",
    .componentTypeIndex = 0,
    .componentSize = 0x08,
    .properties = g_esv_ActiveMusicVolumeComponent_Properties,
    .propertyCount = sizeof(g_esv_ActiveMusicVolumeComponent_Properties) / sizeof(g_esv_ActiveMusicVolumeComponent_Properties[0]),
};

// esv::AiGridAreaTrigger - 8 bytes (0x08)
static const ComponentPropertyDef g_esv_AiGridAreaTrigger_Properties[] = {
    { "Value", 0x00, FIELD_TYPE_INT64, 0, true },
};
static const ComponentLayoutDef g_esv_AiGridAreaTrigger_Layout = {
    .componentName = "esv::AiGridAreaTrigger",
    .shortName = "AiGridAreaTrigger",
    .componentTypeIndex = 0,
    .componentSize = 0x08,
    .properties = g_esv_AiGridAreaTrigger_Properties,
    .propertyCount = sizeof(g_esv_AiGridAreaTrigger_Properties) / sizeof(g_esv_AiGridAreaTrigger_Properties[0]),
};

// esv::AtmosphereTrigger - 8 bytes (0x08)
static const ComponentPropertyDef g_esv_AtmosphereTrigger_Properties[] = {
    { "Value", 0x00, FIELD_TYPE_INT64, 0, true },
};
static const ComponentLayoutDef g_esv_AtmosphereTrigger_Layout = {
    .componentName = "esv::AtmosphereTrigger",
    .shortName = "AtmosphereTrigger",
    .componentTypeIndex = 0,
    .componentSize = 0x08,
    .properties = g_esv_AtmosphereTrigger_Properties,
    .propertyCount = sizeof(g_esv_AtmosphereTrigger_Properties) / sizeof(g_esv_AtmosphereTrigger_Properties[0]),
};

// esv::AvailableLevelComponent - 8 bytes (0x08)
static const ComponentPropertyDef g_esv_AvailableLevelComponent_Properties[] = {
    { "Level", 0x00, FIELD_TYPE_INT32, 0, true },
};
static const ComponentLayoutDef g_esv_AvailableLevelComponent_Layout = {
    .componentName = "esv::AvailableLevelComponent",
    .shortName = "AvailableLevel",
    .componentTypeIndex = 0,
    .componentSize = 0x08,
    .properties = g_esv_AvailableLevelComponent_Properties,
    .propertyCount = sizeof(g_esv_AvailableLevelComponent_Properties) / sizeof(g_esv_AvailableLevelComponent_Properties[0]),
};

// esv::BlockBronzeTimelinePlacementTrigger - 8 bytes (0x08)
static const ComponentPropertyDef g_esv_BlockBronzeTimelinePlacementTrigger_Properties[] = {
    { "Value", 0x00, FIELD_TYPE_INT64, 0, true },
};
static const ComponentLayoutDef g_esv_BlockBronzeTimelinePlacementTrigger_Layout = {
    .componentName = "esv::BlockBronzeTimelinePlacementTrigger",
    .shortName = "BlockBronzeTimelinePlacementTrigger",
    .componentTypeIndex = 0,
    .componentSize = 0x08,
    .properties = g_esv_BlockBronzeTimelinePlacementTrigger_Properties,
    .propertyCount = sizeof(g_esv_BlockBronzeTimelinePlacementTrigger_Properties) / sizeof(g_esv_BlockBronzeTimelinePlacementTrigger_Properties[0]),
};

// esv::CampChestTrigger - 8 bytes (0x08)
static const ComponentPropertyDef g_esv_CampChestTrigger_Properties[] = {
    { "Value", 0x00, FIELD_TYPE_INT64, 0, true },
};
static const ComponentLayoutDef g_esv_CampChestTrigger_Layout = {
    .componentName = "esv::CampChestTrigger",
    .shortName = "CampChestTrigger",
    .componentTypeIndex = 0,
    .componentSize = 0x08,
    .properties = g_esv_CampChestTrigger_Properties,
    .propertyCount = sizeof(g_esv_CampChestTrigger_Properties) / sizeof(g_esv_CampChestTrigger_Properties[0]),
};

// esv::CampRegionTrigger - 8 bytes (0x08)
static const ComponentPropertyDef g_esv_CampRegionTrigger_Properties[] = {
    { "Value", 0x00, FIELD_TYPE_INT64, 0, true },
};
static const ComponentLayoutDef g_esv_CampRegionTrigger_Layout = {
    .componentName = "esv::CampRegionTrigger",
    .shortName = "CampRegionTrigger",
    .componentTypeIndex = 0,
    .componentSize = 0x08,
    .properties = g_esv_CampRegionTrigger_Properties,
    .propertyCount = sizeof(g_esv_CampRegionTrigger_Properties) / sizeof(g_esv_CampRegionTrigger_Properties[0]),
};

// esv::Character - 8 bytes (0x08)
static const ComponentPropertyDef g_esv_Character_Properties[] = {
    { "CharacterPtr", 0x00, FIELD_TYPE_PTR, 0, true },  // Ptr to 0x1a8 (424b) malloc
};
static const ComponentLayoutDef g_esv_Character_Layout = {
    .componentName = "esv::Character",
    .shortName = "Character",
    .componentTypeIndex = 0,
    .componentSize = 0x08,
    .properties = g_esv_Character_Properties,
    .propertyCount = sizeof(g_esv_Character_Properties) / sizeof(g_esv_Character_Properties[0]),
};

// esv::ChasmSeederTrigger - 8 bytes (0x08)
static const ComponentPropertyDef g_esv_ChasmSeederTrigger_Properties[] = {
    { "Value", 0x00, FIELD_TYPE_INT64, 0, true },
};
static const ComponentLayoutDef g_esv_ChasmSeederTrigger_Layout = {
    .componentName = "esv::ChasmSeederTrigger",
    .shortName = "ChasmSeederTrigger",
    .componentTypeIndex = 0,
    .componentSize = 0x08,
    .properties = g_esv_ChasmSeederTrigger_Properties,
    .propertyCount = sizeof(g_esv_ChasmSeederTrigger_Properties) / sizeof(g_esv_ChasmSeederTrigger_Properties[0]),
};

// esv::CombatComponent - 8 bytes (0x08)
static const ComponentPropertyDef g_esv_CombatComponent_Properties[] = {
    { "CombatId", 0x00, FIELD_TYPE_ENTITYHANDLE, 0, true },
};
static const ComponentLayoutDef g_esv_CombatComponent_Layout = {
    .componentName = "esv::CombatComponent",
    .shortName = "Combat",
    .componentTypeIndex = 0,
    .componentSize = 0x08,
    .properties = g_esv_CombatComponent_Properties,
    .propertyCount = sizeof(g_esv_CombatComponent_Properties) / sizeof(g_esv_CombatComponent_Properties[0]),
};

// esv::CombatGroupMappingComponent - 8 bytes (0x08)
static const ComponentPropertyDef g_esv_CombatGroupMappingComponent_Properties[] = {
    { "CombatGroup", 0x00, FIELD_TYPE_ENTITYHANDLE, 0, true },
};
static const ComponentLayoutDef g_esv_CombatGroupMappingComponent_Layout = {
    .componentName = "esv::CombatGroupMappingComponent",
    .shortName = "CombatGroupMapping",
    .componentTypeIndex = 0,
    .componentSize = 0x08,
    .properties = g_esv_CombatGroupMappingComponent_Properties,
    .propertyCount = sizeof(g_esv_CombatGroupMappingComponent_Properties) / sizeof(g_esv_CombatGroupMappingComponent_Properties[0]),
};

// esv::ConstellationChildComponent - 8 bytes (0x08)
static const ComponentPropertyDef g_esv_ConstellationChildComponent_Properties[] = {
    { "Parent", 0x00, FIELD_TYPE_ENTITYHANDLE, 0, true },
};
static const ComponentLayoutDef g_esv_ConstellationChildComponent_Layout = {
    .componentName = "esv::ConstellationChildComponent",
    .shortName = "ConstellationChild",
    .componentTypeIndex = 0,
    .componentSize = 0x08,
    .properties = g_esv_ConstellationChildComponent_Properties,
    .propertyCount = sizeof(g_esv_ConstellationChildComponent_Properties) / sizeof(g_esv_ConstellationChildComponent_Properties[0]),
};

// esv::CrimeAreaTrigger - 8 bytes (0x08)
static const ComponentPropertyDef g_esv_CrimeAreaTrigger_Properties[] = {
    { "Value", 0x00, FIELD_TYPE_INT64, 0, true },
};
static const ComponentLayoutDef g_esv_CrimeAreaTrigger_Layout = {
    .componentName = "esv::CrimeAreaTrigger",
    .shortName = "CrimeAreaTrigger",
    .componentTypeIndex = 0,
    .componentSize = 0x08,
    .properties = g_esv_CrimeAreaTrigger_Properties,
    .propertyCount = sizeof(g_esv_CrimeAreaTrigger_Properties) / sizeof(g_esv_CrimeAreaTrigger_Properties[0]),
};

// esv::Effect - 8 bytes (0x08)
static const ComponentPropertyDef g_esv_Effect_Properties[] = {
    { "EffectPtr", 0x00, FIELD_TYPE_PTR, 0, true },  // Ptr to 0x70 (112b) malloc
};
static const ComponentLayoutDef g_esv_Effect_Layout = {
    .componentName = "esv::Effect",
    .shortName = "Effect",
    .componentTypeIndex = 0,
    .componentSize = 0x08,
    .properties = g_esv_Effect_Properties,
    .propertyCount = sizeof(g_esv_Effect_Properties) / sizeof(g_esv_Effect_Properties[0]),
};

// esv::InterruptPreferencesComponent - 8 bytes (0x08)
static const ComponentPropertyDef g_esv_InterruptPreferencesComponent_Properties[] = {
    { "Flags", 0x00, FIELD_TYPE_INT32, 0, true },
};
static const ComponentLayoutDef g_esv_InterruptPreferencesComponent_Layout = {
    .componentName = "esv::InterruptPreferencesComponent",
    .shortName = "InterruptPreferences",
    .componentTypeIndex = 0,
    .componentSize = 0x08,
    .properties = g_esv_InterruptPreferencesComponent_Properties,
    .propertyCount = sizeof(g_esv_InterruptPreferencesComponent_Properties) / sizeof(g_esv_InterruptPreferencesComponent_Properties[0]),
};

// esv::InterruptZoneParticipantComponent - 8 bytes (0x08)
static const ComponentPropertyDef g_esv_InterruptZoneParticipantComponent_Properties[] = {
    { "ZoneId", 0x00, FIELD_TYPE_ENTITYHANDLE, 0, true },
};
static const ComponentLayoutDef g_esv_InterruptZoneParticipantComponent_Layout = {
    .componentName = "esv::InterruptZoneParticipantComponent",
    .shortName = "InterruptZoneParticipant",
    .componentTypeIndex = 0,
    .componentSize = 0x08,
    .properties = g_esv_InterruptZoneParticipantComponent_Properties,
    .propertyCount = sizeof(g_esv_InterruptZoneParticipantComponent_Properties) / sizeof(g_esv_InterruptZoneParticipantComponent_Properties[0]),
};

// esv::Item - 8 bytes (0x08)
static const ComponentPropertyDef g_esv_Item_Properties[] = {
    { "ItemPtr", 0x00, FIELD_TYPE_PTR, 0, true },  // Ptr to 0xb0 (176b) malloc
};
static const ComponentLayoutDef g_esv_Item_Layout = {
    .componentName = "esv::Item",
    .shortName = "Item",
    .componentTypeIndex = 0,
    .componentSize = 0x08,
    .properties = g_esv_Item_Properties,
    .propertyCount = sizeof(g_esv_Item_Properties) / sizeof(g_esv_Item_Properties[0]),
};

// esv::Projectile - 8 bytes (0x08)
static const ComponentPropertyDef g_esv_Projectile_Properties[] = {
    { "ProjectilePtr", 0x00, FIELD_TYPE_PTR, 0, true },  // Ptr to 0x5b8 (1464b) malloc
};
static const ComponentLayoutDef g_esv_Projectile_Layout = {
    .componentName = "esv::Projectile",
    .shortName = "Projectile",
    .componentTypeIndex = 0,
    .componentSize = 0x08,
    .properties = g_esv_Projectile_Properties,
    .propertyCount = sizeof(g_esv_Projectile_Properties) / sizeof(g_esv_Projectile_Properties[0]),
};

// esv::StartTrigger - 8 bytes (0x08)
static const ComponentPropertyDef g_esv_StartTrigger_Properties[] = {
    { "Value", 0x00, FIELD_TYPE_INT64, 0, true },
};
static const ComponentLayoutDef g_esv_StartTrigger_Layout = {
    .componentName = "esv::StartTrigger",
    .shortName = "StartTrigger",
    .componentTypeIndex = 0,
    .componentSize = 0x08,
    .properties = g_esv_StartTrigger_Properties,
    .propertyCount = sizeof(g_esv_StartTrigger_Properties) / sizeof(g_esv_StartTrigger_Properties[0]),
};

// =============================================================================
// MEDIUM COMPONENTS (16-32 bytes)
// =============================================================================

// esv::CharacterComponent - 24 bytes (0x18)
static const ComponentPropertyDef g_esv_CharacterComponent_Properties[] = {
    { "Template", 0x00, FIELD_TYPE_FIXEDSTRING, 0, true },
    { "Flags", 0x04, FIELD_TYPE_UINT32, 0, true },
};
static const ComponentLayoutDef g_esv_CharacterComponent_Layout = {
    .componentName = "esv::CharacterComponent",
    .shortName = "CharacterComponent",
    .componentTypeIndex = 0,
    .componentSize = 0x18,
    .properties = g_esv_CharacterComponent_Properties,
    .propertyCount = sizeof(g_esv_CharacterComponent_Properties) / sizeof(g_esv_CharacterComponent_Properties[0]),
};

// esv::ItemComponent - 24 bytes (0x18)
static const ComponentPropertyDef g_esv_ItemComponent_Properties[] = {
    { "Template", 0x00, FIELD_TYPE_FIXEDSTRING, 0, true },
    { "Flags", 0x04, FIELD_TYPE_UINT32, 0, true },
};
static const ComponentLayoutDef g_esv_ItemComponent_Layout = {
    .componentName = "esv::ItemComponent",
    .shortName = "ItemComponent",
    .componentTypeIndex = 0,
    .componentSize = 0x18,
    .properties = g_esv_ItemComponent_Properties,
    .propertyCount = sizeof(g_esv_ItemComponent_Properties) / sizeof(g_esv_ItemComponent_Properties[0]),
};

// esv::StatesComponent - 24 bytes (0x18)
static const ComponentPropertyDef g_esv_StatesComponent_Properties[] = {
    { "States", 0x00, FIELD_TYPE_ARRAY, 0, true },
};
static const ComponentLayoutDef g_esv_StatesComponent_Layout = {
    .componentName = "esv::StatesComponent",
    .shortName = "States",
    .componentTypeIndex = 0,
    .componentSize = 0x18,
    .properties = g_esv_StatesComponent_Properties,
    .propertyCount = sizeof(g_esv_StatesComponent_Properties) / sizeof(g_esv_StatesComponent_Properties[0]),
};

// esv::PlayerComponent - 16 bytes (0x10)
static const ComponentPropertyDef g_esv_PlayerComponent_Properties[] = {
    { "UserId", 0x00, FIELD_TYPE_INT32, 0, true },
};
static const ComponentLayoutDef g_esv_PlayerComponent_Layout = {
    .componentName = "esv::PlayerComponent",
    .shortName = "Player",
    .componentTypeIndex = 0,
    .componentSize = 0x10,
    .properties = g_esv_PlayerComponent_Properties,
    .propertyCount = sizeof(g_esv_PlayerComponent_Properties) / sizeof(g_esv_PlayerComponent_Properties[0]),
};

// esv::IconListComponent - 16 bytes (0x10)
static const ComponentPropertyDef g_esv_IconListComponent_Properties[] = {
    { "Icons", 0x00, FIELD_TYPE_ARRAY, 0, true },
};
static const ComponentLayoutDef g_esv_IconListComponent_Layout = {
    .componentName = "esv::IconListComponent",
    .shortName = "IconList",
    .componentTypeIndex = 0,
    .componentSize = 0x10,
    .properties = g_esv_IconListComponent_Properties,
    .propertyCount = sizeof(g_esv_IconListComponent_Properties) / sizeof(g_esv_IconListComponent_Properties[0]),
};

// esv::ExplorationAwardStateComponent - 16 bytes (0x10)
static const ComponentPropertyDef g_esv_ExplorationAwardStateComponent_Properties[] = {
    { "State", 0x00, FIELD_TYPE_INT32, 0, true },
};
static const ComponentLayoutDef g_esv_ExplorationAwardStateComponent_Layout = {
    .componentName = "esv::ExplorationAwardStateComponent",
    .shortName = "ExplorationAwardState",
    .componentTypeIndex = 0,
    .componentSize = 0x10,
    .properties = g_esv_ExplorationAwardStateComponent_Properties,
    .propertyCount = sizeof(g_esv_ExplorationAwardStateComponent_Properties) / sizeof(g_esv_ExplorationAwardStateComponent_Properties[0]),
};

// esv::InterruptDataComponent - 16 bytes (0x10)
static const ComponentPropertyDef g_esv_InterruptDataComponent_Properties[] = {
    { "Data", 0x00, FIELD_TYPE_ARRAY, 0, true },
};
static const ComponentLayoutDef g_esv_InterruptDataComponent_Layout = {
    .componentName = "esv::InterruptDataComponent",
    .shortName = "InterruptData",
    .componentTypeIndex = 0,
    .componentSize = 0x10,
    .properties = g_esv_InterruptDataComponent_Properties,
    .propertyCount = sizeof(g_esv_InterruptDataComponent_Properties) / sizeof(g_esv_InterruptDataComponent_Properties[0]),
};

// esv::InventoryMemberComponent - 16 bytes (0x10)
static const ComponentPropertyDef g_esv_InventoryMemberComponent_Properties[] = {
    { "Inventory", 0x00, FIELD_TYPE_ENTITYHANDLE, 0, true },
    { "EquipmentSlot", 0x08, FIELD_TYPE_INT32, 0, true },
};
static const ComponentLayoutDef g_esv_InventoryMemberComponent_Layout = {
    .componentName = "esv::InventoryMemberComponent",
    .shortName = "InventoryMember",
    .componentTypeIndex = 0,
    .componentSize = 0x10,
    .properties = g_esv_InventoryMemberComponent_Properties,
    .propertyCount = sizeof(g_esv_InventoryMemberComponent_Properties) / sizeof(g_esv_InventoryMemberComponent_Properties[0]),
};

// esv::InventoryOwnerComponent - 16 bytes (0x10)
static const ComponentPropertyDef g_esv_InventoryOwnerComponent_Properties[] = {
    { "Inventories", 0x00, FIELD_TYPE_ARRAY, 0, true },
};
static const ComponentLayoutDef g_esv_InventoryOwnerComponent_Layout = {
    .componentName = "esv::InventoryOwnerComponent",
    .shortName = "InventoryOwner",
    .componentTypeIndex = 0,
    .componentSize = 0x10,
    .properties = g_esv_InventoryOwnerComponent_Properties,
    .propertyCount = sizeof(g_esv_InventoryOwnerComponent_Properties) / sizeof(g_esv_InventoryOwnerComponent_Properties[0]),
};

// esv::MusicVolumeTriggerStateComponent - 16 bytes (0x10)
static const ComponentPropertyDef g_esv_MusicVolumeTriggerStateComponent_Properties[] = {
    { "State", 0x00, FIELD_TYPE_INT32, 0, true },
};
static const ComponentLayoutDef g_esv_MusicVolumeTriggerStateComponent_Layout = {
    .componentName = "esv::MusicVolumeTriggerStateComponent",
    .shortName = "MusicVolumeTriggerState",
    .componentTypeIndex = 0,
    .componentSize = 0x10,
    .properties = g_esv_MusicVolumeTriggerStateComponent_Properties,
    .propertyCount = sizeof(g_esv_MusicVolumeTriggerStateComponent_Properties) / sizeof(g_esv_MusicVolumeTriggerStateComponent_Properties[0]),
};

// esv::OsirisPingRequestSingletonComponent - 16 bytes (0x10)
static const ComponentPropertyDef g_esv_OsirisPingRequestSingletonComponent_Properties[] = {
    { "Requests", 0x00, FIELD_TYPE_ARRAY, 0, true },
};
static const ComponentLayoutDef g_esv_OsirisPingRequestSingletonComponent_Layout = {
    .componentName = "esv::OsirisPingRequestSingletonComponent",
    .shortName = "OsirisPingRequestSingleton",
    .componentTypeIndex = 0,
    .componentSize = 0x10,
    .properties = g_esv_OsirisPingRequestSingletonComponent_Properties,
    .propertyCount = sizeof(g_esv_OsirisPingRequestSingletonComponent_Properties) / sizeof(g_esv_OsirisPingRequestSingletonComponent_Properties[0]),
};

// esv::PingRequestSingletonComponent - 16 bytes (0x10)
static const ComponentPropertyDef g_esv_PingRequestSingletonComponent_Properties[] = {
    { "Requests", 0x00, FIELD_TYPE_ARRAY, 0, true },
};
static const ComponentLayoutDef g_esv_PingRequestSingletonComponent_Layout = {
    .componentName = "esv::PingRequestSingletonComponent",
    .shortName = "PingRequestSingleton",
    .componentTypeIndex = 0,
    .componentSize = 0x10,
    .properties = g_esv_PingRequestSingletonComponent_Properties,
    .propertyCount = sizeof(g_esv_PingRequestSingletonComponent_Properties) / sizeof(g_esv_PingRequestSingletonComponent_Properties[0]),
};

// esv::SetGravityActiveRequestOneFrameComponent - 16 bytes (0x10)
static const ComponentPropertyDef g_esv_SetGravityActiveRequestOneFrameComponent_Properties[] = {
    { "Active", 0x00, FIELD_TYPE_BOOL, 0, true },
};
static const ComponentLayoutDef g_esv_SetGravityActiveRequestOneFrameComponent_Layout = {
    .componentName = "esv::SetGravityActiveRequestOneFrameComponent",
    .shortName = "SetGravityActiveRequestOneFrame",
    .componentTypeIndex = 0,
    .componentSize = 0x10,
    .properties = g_esv_SetGravityActiveRequestOneFrameComponent_Properties,
    .propertyCount = sizeof(g_esv_SetGravityActiveRequestOneFrameComponent_Properties) / sizeof(g_esv_SetGravityActiveRequestOneFrameComponent_Properties[0]),
};

// esv::TurnStartedEventOneFrameComponent - 16 bytes (0x10)
static const ComponentPropertyDef g_esv_TurnStartedEventOneFrameComponent_Properties[] = {
    { "CombatId", 0x00, FIELD_TYPE_ENTITYHANDLE, 0, true },
};
static const ComponentLayoutDef g_esv_TurnStartedEventOneFrameComponent_Layout = {
    .componentName = "esv::TurnStartedEventOneFrameComponent",
    .shortName = "TurnStartedEventOneFrame",
    .componentTypeIndex = 0,
    .componentSize = 0x10,
    .properties = g_esv_TurnStartedEventOneFrameComponent_Properties,
    .propertyCount = sizeof(g_esv_TurnStartedEventOneFrameComponent_Properties) / sizeof(g_esv_TurnStartedEventOneFrameComponent_Properties[0]),
};

// esv::UseSocketComponent - 16 bytes (0x10)
static const ComponentPropertyDef g_esv_UseSocketComponent_Properties[] = {
    { "Socket", 0x00, FIELD_TYPE_ENTITYHANDLE, 0, true },
};
static const ComponentLayoutDef g_esv_UseSocketComponent_Layout = {
    .componentName = "esv::UseSocketComponent",
    .shortName = "UseSocket",
    .componentTypeIndex = 0,
    .componentSize = 0x10,
    .properties = g_esv_UseSocketComponent_Properties,
    .propertyCount = sizeof(g_esv_UseSocketComponent_Properties) / sizeof(g_esv_UseSocketComponent_Properties[0]),
};

// esv::ConstellationHelperComponent - 24 bytes (0x18)
static const ComponentPropertyDef g_esv_ConstellationHelperComponent_Properties[] = {
    { "Data", 0x00, FIELD_TYPE_ARRAY, 0, true },
};
static const ComponentLayoutDef g_esv_ConstellationHelperComponent_Layout = {
    .componentName = "esv::ConstellationHelperComponent",
    .shortName = "ConstellationHelper",
    .componentTypeIndex = 0,
    .componentSize = 0x18,
    .properties = g_esv_ConstellationHelperComponent_Properties,
    .propertyCount = sizeof(g_esv_ConstellationHelperComponent_Properties) / sizeof(g_esv_ConstellationHelperComponent_Properties[0]),
};

// esv::IdentifiedComponent - 24 bytes (0x18)
static const ComponentPropertyDef g_esv_IdentifiedComponent_Properties[] = {
    { "Identified", 0x00, FIELD_TYPE_BOOL, 0, true },
};
static const ComponentLayoutDef g_esv_IdentifiedComponent_Layout = {
    .componentName = "esv::IdentifiedComponent",
    .shortName = "Identified",
    .componentTypeIndex = 0,
    .componentSize = 0x18,
    .properties = g_esv_IdentifiedComponent_Properties,
    .propertyCount = sizeof(g_esv_IdentifiedComponent_Properties) / sizeof(g_esv_IdentifiedComponent_Properties[0]),
};

// esv::InventoryPropertyCanBePickpocketedComponent - 24 bytes (0x18)
static const ComponentPropertyDef g_esv_InventoryPropertyCanBePickpocketedComponent_Properties[] = {
    { "CanBePickpocketed", 0x00, FIELD_TYPE_BOOL, 0, true },
};
static const ComponentLayoutDef g_esv_InventoryPropertyCanBePickpocketedComponent_Layout = {
    .componentName = "esv::InventoryPropertyCanBePickpocketedComponent",
    .shortName = "InventoryPropertyCanBePickpocketed",
    .componentTypeIndex = 0,
    .componentSize = 0x18,
    .properties = g_esv_InventoryPropertyCanBePickpocketedComponent_Properties,
    .propertyCount = sizeof(g_esv_InventoryPropertyCanBePickpocketedComponent_Properties) / sizeof(g_esv_InventoryPropertyCanBePickpocketedComponent_Properties[0]),
};

// esv::InventoryPropertyIsDroppedOnDeathComponent - 24 bytes (0x18)
static const ComponentPropertyDef g_esv_InventoryPropertyIsDroppedOnDeathComponent_Properties[] = {
    { "IsDroppedOnDeath", 0x00, FIELD_TYPE_BOOL, 0, true },
};
static const ComponentLayoutDef g_esv_InventoryPropertyIsDroppedOnDeathComponent_Layout = {
    .componentName = "esv::InventoryPropertyIsDroppedOnDeathComponent",
    .shortName = "InventoryPropertyIsDroppedOnDeath",
    .componentTypeIndex = 0,
    .componentSize = 0x18,
    .properties = g_esv_InventoryPropertyIsDroppedOnDeathComponent_Properties,
    .propertyCount = sizeof(g_esv_InventoryPropertyIsDroppedOnDeathComponent_Properties) / sizeof(g_esv_InventoryPropertyIsDroppedOnDeathComponent_Properties[0]),
};

// esv::InventoryPropertyIsTradableComponent - 24 bytes (0x18)
static const ComponentPropertyDef g_esv_InventoryPropertyIsTradableComponent_Properties[] = {
    { "IsTradable", 0x00, FIELD_TYPE_BOOL, 0, true },
};
static const ComponentLayoutDef g_esv_InventoryPropertyIsTradableComponent_Layout = {
    .componentName = "esv::InventoryPropertyIsTradableComponent",
    .shortName = "InventoryPropertyIsTradable",
    .componentTypeIndex = 0,
    .componentSize = 0x18,
    .properties = g_esv_InventoryPropertyIsTradableComponent_Properties,
    .propertyCount = sizeof(g_esv_InventoryPropertyIsTradableComponent_Properties) / sizeof(g_esv_InventoryPropertyIsTradableComponent_Properties[0]),
};

// esv::SafePositionUpdatedEventOneFrameComponent - 24 bytes (0x18)
static const ComponentPropertyDef g_esv_SafePositionUpdatedEventOneFrameComponent_Properties[] = {
    { "Entity", 0x00, FIELD_TYPE_ENTITYHANDLE, 0, true },
};
static const ComponentLayoutDef g_esv_SafePositionUpdatedEventOneFrameComponent_Layout = {
    .componentName = "esv::SafePositionUpdatedEventOneFrameComponent",
    .shortName = "SafePositionUpdatedEventOneFrame",
    .componentTypeIndex = 0,
    .componentSize = 0x18,
    .properties = g_esv_SafePositionUpdatedEventOneFrameComponent_Properties,
    .propertyCount = sizeof(g_esv_SafePositionUpdatedEventOneFrameComponent_Properties) / sizeof(g_esv_SafePositionUpdatedEventOneFrameComponent_Properties[0]),
};

// esv::SummonContainerComponent - 24 bytes (0x18)
static const ComponentPropertyDef g_esv_SummonContainerComponent_Properties[] = {
    { "Summons", 0x00, FIELD_TYPE_ARRAY, 0, true },
};
static const ComponentLayoutDef g_esv_SummonContainerComponent_Layout = {
    .componentName = "esv::SummonContainerComponent",
    .shortName = "SummonContainer",
    .componentTypeIndex = 0,
    .componentSize = 0x18,
    .properties = g_esv_SummonContainerComponent_Properties,
    .propertyCount = sizeof(g_esv_SummonContainerComponent_Properties) / sizeof(g_esv_SummonContainerComponent_Properties[0]),
};

// esv::SurfacePathInfluencesComponent - 24 bytes (0x18)
static const ComponentPropertyDef g_esv_SurfacePathInfluencesComponent_Properties[] = {
    { "PathInfluences", 0x00, FIELD_TYPE_ARRAY, 0, true },
};
static const ComponentLayoutDef g_esv_SurfacePathInfluencesComponent_Layout = {
    .componentName = "esv::SurfacePathInfluencesComponent",
    .shortName = "SurfacePathInfluences",
    .componentTypeIndex = 0,
    .componentSize = 0x18,
    .properties = g_esv_SurfacePathInfluencesComponent_Properties,
    .propertyCount = sizeof(g_esv_SurfacePathInfluencesComponent_Properties) / sizeof(g_esv_SurfacePathInfluencesComponent_Properties[0]),
};

// esv::UserReservedComponent - 24 bytes (0x18)
static const ComponentPropertyDef g_esv_UserReservedComponent_Properties[] = {
    { "UserID", 0x00, FIELD_TYPE_INT32, 0, true },
};
static const ComponentLayoutDef g_esv_UserReservedComponent_Layout = {
    .componentName = "esv::UserReservedComponent",
    .shortName = "UserReserved",
    .componentTypeIndex = 0,
    .componentSize = 0x18,
    .properties = g_esv_UserReservedComponent_Properties,
    .propertyCount = sizeof(g_esv_UserReservedComponent_Properties) / sizeof(g_esv_UserReservedComponent_Properties[0]),
};

// esv::CustomStatsComponent - 40 bytes (0x28)
static const ComponentPropertyDef g_esv_CustomStatsComponent_Properties[] = {
    { "Stats", 0x00, FIELD_TYPE_ARRAY, 0, true },
};
static const ComponentLayoutDef g_esv_CustomStatsComponent_Layout = {
    .componentName = "esv::CustomStatsComponent",
    .shortName = "CustomStats",
    .componentTypeIndex = 0,
    .componentSize = 0x28,
    .properties = g_esv_CustomStatsComponent_Properties,
    .propertyCount = sizeof(g_esv_CustomStatsComponent_Properties) / sizeof(g_esv_CustomStatsComponent_Properties[0]),
};

// esv::DisplayNameListComponent - 40 bytes (0x28)
static const ComponentPropertyDef g_esv_DisplayNameListComponent_Properties[] = {
    { "Names", 0x00, FIELD_TYPE_ARRAY, 0, true },
};
static const ComponentLayoutDef g_esv_DisplayNameListComponent_Layout = {
    .componentName = "esv::DisplayNameListComponent",
    .shortName = "DisplayNameList",
    .componentTypeIndex = 0,
    .componentSize = 0x28,
    .properties = g_esv_DisplayNameListComponent_Properties,
    .propertyCount = sizeof(g_esv_DisplayNameListComponent_Properties) / sizeof(g_esv_DisplayNameListComponent_Properties[0]),
};

// esv::LockComponent - 40 bytes (0x28)
static const ComponentPropertyDef g_esv_LockComponent_Properties[] = {
    { "Key", 0x00, FIELD_TYPE_GUID, 0, true },
    { "LockDC", 0x10, FIELD_TYPE_INT32, 0, true },
};
static const ComponentLayoutDef g_esv_LockComponent_Layout = {
    .componentName = "esv::LockComponent",
    .shortName = "Lock",
    .componentTypeIndex = 0,
    .componentSize = 0x28,
    .properties = g_esv_LockComponent_Properties,
    .propertyCount = sizeof(g_esv_LockComponent_Properties) / sizeof(g_esv_LockComponent_Properties[0]),
};

// esv::StealthComponent - 40 bytes (0x28)
static const ComponentPropertyDef g_esv_StealthComponent_Properties[] = {
    { "Seeking", 0x00, FIELD_TYPE_BOOL, 0, true },
    { "SeekHiddenFlag", 0x01, FIELD_TYPE_BOOL, 0, true },
};
static const ComponentLayoutDef g_esv_StealthComponent_Layout = {
    .componentName = "esv::StealthComponent",
    .shortName = "Stealth",
    .componentTypeIndex = 0,
    .componentSize = 0x28,
    .properties = g_esv_StealthComponent_Properties,
    .propertyCount = sizeof(g_esv_StealthComponent_Properties) / sizeof(g_esv_StealthComponent_Properties[0]),
};

// esv::UseComponent - 40 bytes (0x28)
static const ComponentPropertyDef g_esv_UseComponent_Properties[] = {
    { "Charges", 0x00, FIELD_TYPE_INT32, 0, true },
    { "MaxCharges", 0x04, FIELD_TYPE_INT32, 0, true },
};
static const ComponentLayoutDef g_esv_UseComponent_Layout = {
    .componentName = "esv::UseComponent",
    .shortName = "Use",
    .componentTypeIndex = 0,
    .componentSize = 0x28,
    .properties = g_esv_UseComponent_Properties,
    .propertyCount = sizeof(g_esv_UseComponent_Properties) / sizeof(g_esv_UseComponent_Properties[0]),
};

// esv::InventoryDataComponent - 32 bytes (0x20)
static const ComponentPropertyDef g_esv_InventoryDataComponent_Properties[] = {
    { "Flags", 0x00, FIELD_TYPE_UINT32, 0, true },
};
static const ComponentLayoutDef g_esv_InventoryDataComponent_Layout = {
    .componentName = "esv::InventoryDataComponent",
    .shortName = "InventoryData",
    .componentTypeIndex = 0,
    .componentSize = 0x20,
    .properties = g_esv_InventoryDataComponent_Properties,
    .propertyCount = sizeof(g_esv_InventoryDataComponent_Properties) / sizeof(g_esv_InventoryDataComponent_Properties[0]),
};

// esv::CombatParticipantComponent - 48 bytes (0x30)
static const ComponentPropertyDef g_esv_CombatParticipantComponent_Properties[] = {
    { "CombatHandle", 0x00, FIELD_TYPE_ENTITYHANDLE, 0, true },
    { "CombatGroupId", 0x08, FIELD_TYPE_GUID, 0, true },
};
static const ComponentLayoutDef g_esv_CombatParticipantComponent_Layout = {
    .componentName = "esv::CombatParticipantComponent",
    .shortName = "CombatParticipant",
    .componentTypeIndex = 0,
    .componentSize = 0x30,
    .properties = g_esv_CombatParticipantComponent_Properties,
    .propertyCount = sizeof(g_esv_CombatParticipantComponent_Properties) / sizeof(g_esv_CombatParticipantComponent_Properties[0]),
};

// esv::ChasmDataComponent - 48 bytes (0x30)
static const ComponentPropertyDef g_esv_ChasmDataComponent_Properties[] = {
    { "Data", 0x00, FIELD_TYPE_ARRAY, 0, true },
};
static const ComponentLayoutDef g_esv_ChasmDataComponent_Layout = {
    .componentName = "esv::ChasmDataComponent",
    .shortName = "ChasmData",
    .componentTypeIndex = 0,
    .componentSize = 0x30,
    .properties = g_esv_ChasmDataComponent_Properties,
    .propertyCount = sizeof(g_esv_ChasmDataComponent_Properties) / sizeof(g_esv_ChasmDataComponent_Properties[0]),
};

// =============================================================================
// COMBAT COMPONENTS (esv::combat::)
// =============================================================================

// esv::combat::CanStartCombatComponent - 1 byte (0x01)
static const ComponentPropertyDef g_esv_combat_CanStartCombatComponent_Properties[] = {
    { "Value", 0x00, FIELD_TYPE_BOOL, 0, true },
};
static const ComponentLayoutDef g_esv_combat_CanStartCombatComponent_Layout = {
    .componentName = "esv::combat::CanStartCombatComponent",
    .shortName = "CanStartCombat",
    .componentTypeIndex = 0,
    .componentSize = 0x01,
    .properties = g_esv_combat_CanStartCombatComponent_Properties,
    .propertyCount = sizeof(g_esv_combat_CanStartCombatComponent_Properties) / sizeof(g_esv_combat_CanStartCombatComponent_Properties[0]),
};

// esv::combat::FleeBlockedComponent - 1 byte (0x01)
static const ComponentPropertyDef g_esv_combat_FleeBlockedComponent_Properties[] = {
    { "Value", 0x00, FIELD_TYPE_BOOL, 0, true },
};
static const ComponentLayoutDef g_esv_combat_FleeBlockedComponent_Layout = {
    .componentName = "esv::combat::FleeBlockedComponent",
    .shortName = "FleeBlocked",
    .componentTypeIndex = 0,
    .componentSize = 0x01,
    .properties = g_esv_combat_FleeBlockedComponent_Properties,
    .propertyCount = sizeof(g_esv_combat_FleeBlockedComponent_Properties) / sizeof(g_esv_combat_FleeBlockedComponent_Properties[0]),
};

// esv::combat::ImmediateJoinComponent - 1 byte (0x01)
static const ComponentPropertyDef g_esv_combat_ImmediateJoinComponent_Properties[] = {
    { "Value", 0x00, FIELD_TYPE_BOOL, 0, true },
};
static const ComponentLayoutDef g_esv_combat_ImmediateJoinComponent_Layout = {
    .componentName = "esv::combat::ImmediateJoinComponent",
    .shortName = "ImmediateJoin",
    .componentTypeIndex = 0,
    .componentSize = 0x01,
    .properties = g_esv_combat_ImmediateJoinComponent_Properties,
    .propertyCount = sizeof(g_esv_combat_ImmediateJoinComponent_Properties) / sizeof(g_esv_combat_ImmediateJoinComponent_Properties[0]),
};

// esv::combat::LeaveRequestComponent - 1 byte (0x01)
static const ComponentPropertyDef g_esv_combat_LeaveRequestComponent_Properties[] = {
    { "Value", 0x00, FIELD_TYPE_BOOL, 0, true },
};
static const ComponentLayoutDef g_esv_combat_LeaveRequestComponent_Layout = {
    .componentName = "esv::combat::LeaveRequestComponent",
    .shortName = "LeaveRequest",
    .componentTypeIndex = 0,
    .componentSize = 0x01,
    .properties = g_esv_combat_LeaveRequestComponent_Properties,
    .propertyCount = sizeof(g_esv_combat_LeaveRequestComponent_Properties) / sizeof(g_esv_combat_LeaveRequestComponent_Properties[0]),
};

// esv::combat::JoiningComponent - 4 bytes (0x04)
static const ComponentPropertyDef g_esv_combat_JoiningComponent_Properties[] = {
    { "State", 0x00, FIELD_TYPE_INT32, 0, true },
};
static const ComponentLayoutDef g_esv_combat_JoiningComponent_Layout = {
    .componentName = "esv::combat::JoiningComponent",
    .shortName = "Joining",
    .componentTypeIndex = 0,
    .componentSize = 0x04,
    .properties = g_esv_combat_JoiningComponent_Properties,
    .propertyCount = sizeof(g_esv_combat_JoiningComponent_Properties) / sizeof(g_esv_combat_JoiningComponent_Properties[0]),
};

// esv::combat::LateJoinPenaltyComponent - 4 bytes (0x04)
static const ComponentPropertyDef g_esv_combat_LateJoinPenaltyComponent_Properties[] = {
    { "Penalty", 0x00, FIELD_TYPE_FLOAT, 0, true },
};
static const ComponentLayoutDef g_esv_combat_LateJoinPenaltyComponent_Layout = {
    .componentName = "esv::combat::LateJoinPenaltyComponent",
    .shortName = "LateJoinPenalty",
    .componentTypeIndex = 0,
    .componentSize = 0x04,
    .properties = g_esv_combat_LateJoinPenaltyComponent_Properties,
    .propertyCount = sizeof(g_esv_combat_LateJoinPenaltyComponent_Properties) / sizeof(g_esv_combat_LateJoinPenaltyComponent_Properties[0]),
};

// esv::combat::CombatStateComponent - 24 bytes (0x18)
static const ComponentPropertyDef g_esv_combat_CombatStateComponent_Properties[] = {
    { "State", 0x00, FIELD_TYPE_INT32, 0, true },
    { "Initiative", 0x04, FIELD_TYPE_INT32, 0, true },
};
static const ComponentLayoutDef g_esv_combat_CombatStateComponent_Layout = {
    .componentName = "esv::combat::CombatStateComponent",
    .shortName = "CombatState",
    .componentTypeIndex = 0,
    .componentSize = 0x18,
    .properties = g_esv_combat_CombatStateComponent_Properties,
    .propertyCount = sizeof(g_esv_combat_CombatStateComponent_Properties) / sizeof(g_esv_combat_CombatStateComponent_Properties[0]),
};

// esv::combat::IsInCombatComponent - 24 bytes (0x18)
static const ComponentPropertyDef g_esv_combat_IsInCombatComponent_Properties[] = {
    { "CombatId", 0x00, FIELD_TYPE_ENTITYHANDLE, 0, true },
};
static const ComponentLayoutDef g_esv_combat_IsInCombatComponent_Layout = {
    .componentName = "esv::combat::IsInCombatComponent",
    .shortName = "IsInCombat",
    .componentTypeIndex = 0,
    .componentSize = 0x18,
    .properties = g_esv_combat_IsInCombatComponent_Properties,
    .propertyCount = sizeof(g_esv_combat_IsInCombatComponent_Properties) / sizeof(g_esv_combat_IsInCombatComponent_Properties[0]),
};

// esv::combat::LeftEventOneFrameComponent - 24 bytes (0x18)
static const ComponentPropertyDef g_esv_combat_LeftEventOneFrameComponent_Properties[] = {
    { "CombatId", 0x00, FIELD_TYPE_ENTITYHANDLE, 0, true },
};
static const ComponentLayoutDef g_esv_combat_LeftEventOneFrameComponent_Layout = {
    .componentName = "esv::combat::LeftEventOneFrameComponent",
    .shortName = "LeftEventOneFrame",
    .componentTypeIndex = 0,
    .componentSize = 0x18,
    .properties = g_esv_combat_LeftEventOneFrameComponent_Properties,
    .propertyCount = sizeof(g_esv_combat_LeftEventOneFrameComponent_Properties) / sizeof(g_esv_combat_LeftEventOneFrameComponent_Properties[0]),
};

// esv::combat::EnterRequestComponent - 48 bytes (0x30)
static const ComponentPropertyDef g_esv_combat_EnterRequestComponent_Properties[] = {
    { "CombatId", 0x00, FIELD_TYPE_ENTITYHANDLE, 0, true },
    { "Position", 0x08, FIELD_TYPE_VEC3, 0, true },
};
static const ComponentLayoutDef g_esv_combat_EnterRequestComponent_Layout = {
    .componentName = "esv::combat::EnterRequestComponent",
    .shortName = "EnterRequest",
    .componentTypeIndex = 0,
    .componentSize = 0x30,
    .properties = g_esv_combat_EnterRequestComponent_Properties,
    .propertyCount = sizeof(g_esv_combat_EnterRequestComponent_Properties) / sizeof(g_esv_combat_EnterRequestComponent_Properties[0]),
};

// esv::combat::CombatSwitchedComponent - 48 bytes (0x30)
static const ComponentPropertyDef g_esv_combat_CombatSwitchedComponent_Properties[] = {
    { "FromCombat", 0x00, FIELD_TYPE_ENTITYHANDLE, 0, true },
    { "ToCombat", 0x08, FIELD_TYPE_ENTITYHANDLE, 0, true },
};
static const ComponentLayoutDef g_esv_combat_CombatSwitchedComponent_Layout = {
    .componentName = "esv::combat::CombatSwitchedComponent",
    .shortName = "CombatSwitched",
    .componentTypeIndex = 0,
    .componentSize = 0x30,
    .properties = g_esv_combat_CombatSwitchedComponent_Properties,
    .propertyCount = sizeof(g_esv_combat_CombatSwitchedComponent_Properties) / sizeof(g_esv_combat_CombatSwitchedComponent_Properties[0]),
};

// =============================================================================
// INVENTORY COMPONENTS (esv::inventory::)
// =============================================================================

// esv::inventory::CharacterHasGeneratedTradeTreasureComponent - 1 byte (0x01)
static const ComponentPropertyDef g_esv_inventory_CharacterHasGeneratedTradeTreasureComponent_Properties[] = {
    { "Value", 0x00, FIELD_TYPE_BOOL, 0, true },
};
static const ComponentLayoutDef g_esv_inventory_CharacterHasGeneratedTradeTreasureComponent_Layout = {
    .componentName = "esv::inventory::CharacterHasGeneratedTradeTreasureComponent",
    .shortName = "CharacterHasGeneratedTradeTreasure",
    .componentTypeIndex = 0,
    .componentSize = 0x01,
    .properties = g_esv_inventory_CharacterHasGeneratedTradeTreasureComponent_Properties,
    .propertyCount = sizeof(g_esv_inventory_CharacterHasGeneratedTradeTreasureComponent_Properties) / sizeof(g_esv_inventory_CharacterHasGeneratedTradeTreasureComponent_Properties[0]),
};

// esv::inventory::EntityHasGeneratedTreasureComponent - 1 byte (0x01)
static const ComponentPropertyDef g_esv_inventory_EntityHasGeneratedTreasureComponent_Properties[] = {
    { "Value", 0x00, FIELD_TYPE_BOOL, 0, true },
};
static const ComponentLayoutDef g_esv_inventory_EntityHasGeneratedTreasureComponent_Layout = {
    .componentName = "esv::inventory::EntityHasGeneratedTreasureComponent",
    .shortName = "EntityHasGeneratedTreasure",
    .componentTypeIndex = 0,
    .componentSize = 0x01,
    .properties = g_esv_inventory_EntityHasGeneratedTreasureComponent_Properties,
    .propertyCount = sizeof(g_esv_inventory_EntityHasGeneratedTreasureComponent_Properties) / sizeof(g_esv_inventory_EntityHasGeneratedTreasureComponent_Properties[0]),
};

// esv::inventory::IsReplicatedComponent - 1 byte (0x01)
static const ComponentPropertyDef g_esv_inventory_IsReplicatedComponent_Properties[] = {
    { "Value", 0x00, FIELD_TYPE_BOOL, 0, true },
};
static const ComponentLayoutDef g_esv_inventory_IsReplicatedComponent_Layout = {
    .componentName = "esv::inventory::IsReplicatedComponent",
    .shortName = "IsReplicated",
    .componentTypeIndex = 0,
    .componentSize = 0x01,
    .properties = g_esv_inventory_IsReplicatedComponent_Properties,
    .propertyCount = sizeof(g_esv_inventory_IsReplicatedComponent_Properties) / sizeof(g_esv_inventory_IsReplicatedComponent_Properties[0]),
};

// esv::inventory::IsReplicatedWithComponent - 1 byte (0x01)
static const ComponentPropertyDef g_esv_inventory_IsReplicatedWithComponent_Properties[] = {
    { "Value", 0x00, FIELD_TYPE_BOOL, 0, true },
};
static const ComponentLayoutDef g_esv_inventory_IsReplicatedWithComponent_Layout = {
    .componentName = "esv::inventory::IsReplicatedWithComponent",
    .shortName = "IsReplicatedWith",
    .componentTypeIndex = 0,
    .componentSize = 0x01,
    .properties = g_esv_inventory_IsReplicatedWithComponent_Properties,
    .propertyCount = sizeof(g_esv_inventory_IsReplicatedWithComponent_Properties) / sizeof(g_esv_inventory_IsReplicatedWithComponent_Properties[0]),
};

// esv::inventory::MemberIsReplicatedWithComponent - 1 byte (0x01)
static const ComponentPropertyDef g_esv_inventory_MemberIsReplicatedWithComponent_Properties[] = {
    { "Value", 0x00, FIELD_TYPE_BOOL, 0, true },
};
static const ComponentLayoutDef g_esv_inventory_MemberIsReplicatedWithComponent_Layout = {
    .componentName = "esv::inventory::MemberIsReplicatedWithComponent",
    .shortName = "MemberIsReplicatedWith",
    .componentTypeIndex = 0,
    .componentSize = 0x01,
    .properties = g_esv_inventory_MemberIsReplicatedWithComponent_Properties,
    .propertyCount = sizeof(g_esv_inventory_MemberIsReplicatedWithComponent_Properties) / sizeof(g_esv_inventory_MemberIsReplicatedWithComponent_Properties[0]),
};

// esv::inventory::ReturnToOwnerComponent - 1 byte (0x01)
static const ComponentPropertyDef g_esv_inventory_ReturnToOwnerComponent_Properties[] = {
    { "Value", 0x00, FIELD_TYPE_BOOL, 0, true },
};
static const ComponentLayoutDef g_esv_inventory_ReturnToOwnerComponent_Layout = {
    .componentName = "esv::inventory::ReturnToOwnerComponent",
    .shortName = "ReturnToOwner",
    .componentTypeIndex = 0,
    .componentSize = 0x01,
    .properties = g_esv_inventory_ReturnToOwnerComponent_Properties,
    .propertyCount = sizeof(g_esv_inventory_ReturnToOwnerComponent_Properties) / sizeof(g_esv_inventory_ReturnToOwnerComponent_Properties[0]),
};

// esv::inventory::StackBlockedDuringTradeComponent - 1 byte (0x01)
static const ComponentPropertyDef g_esv_inventory_StackBlockedDuringTradeComponent_Properties[] = {
    { "Value", 0x00, FIELD_TYPE_BOOL, 0, true },
};
static const ComponentLayoutDef g_esv_inventory_StackBlockedDuringTradeComponent_Layout = {
    .componentName = "esv::inventory::StackBlockedDuringTradeComponent",
    .shortName = "StackBlockedDuringTrade",
    .componentTypeIndex = 0,
    .componentSize = 0x01,
    .properties = g_esv_inventory_StackBlockedDuringTradeComponent_Properties,
    .propertyCount = sizeof(g_esv_inventory_StackBlockedDuringTradeComponent_Properties) / sizeof(g_esv_inventory_StackBlockedDuringTradeComponent_Properties[0]),
};

// esv::inventory::GroupCheckComponent - 4 bytes (0x04)
// Source: Inventory.h
static const ComponentPropertyDef g_esv_inventory_GroupCheckComponent_Properties[] = {
    { "Conditions", 0x00, FIELD_TYPE_UINT32, 0, true },
};
static const ComponentLayoutDef g_esv_inventory_GroupCheckComponent_Layout = {
    .componentName = "esv::inventory::GroupCheckComponent",
    .shortName = "GroupCheck",
    .componentTypeIndex = 0,
    .componentSize = 0x04,
    .properties = g_esv_inventory_GroupCheckComponent_Properties,
    .propertyCount = sizeof(g_esv_inventory_GroupCheckComponent_Properties) / sizeof(g_esv_inventory_GroupCheckComponent_Properties[0]),
};

// esv::inventory::ContainerDataComponent - 8 bytes (0x08)
// Source: Inventory.h
static const ComponentPropertyDef g_esv_inventory_ContainerDataComponent_Properties[] = {
    { "Flags", 0x00, FIELD_TYPE_UINT16, 0, true },
    { "field_4", 0x04, FIELD_TYPE_INT32, 0, true },
};
static const ComponentLayoutDef g_esv_inventory_ContainerDataComponent_Layout = {
    .componentName = "esv::inventory::ContainerDataComponent",
    .shortName = "ContainerData",
    .componentTypeIndex = 0,
    .componentSize = 0x08,
    .properties = g_esv_inventory_ContainerDataComponent_Properties,
    .propertyCount = sizeof(g_esv_inventory_ContainerDataComponent_Properties) / sizeof(g_esv_inventory_ContainerDataComponent_Properties[0]),
};

// esv::inventory::MemberRemovedEventOneFrameComponent - 16 bytes (0x10)
static const ComponentPropertyDef g_esv_inventory_MemberRemovedEventOneFrameComponent_Properties[] = {
    { "Member", 0x00, FIELD_TYPE_ENTITYHANDLE, 0, true },
};
static const ComponentLayoutDef g_esv_inventory_MemberRemovedEventOneFrameComponent_Layout = {
    .componentName = "esv::inventory::MemberRemovedEventOneFrameComponent",
    .shortName = "MemberRemovedEventOneFrame",
    .componentTypeIndex = 0,
    .componentSize = 0x10,
    .properties = g_esv_inventory_MemberRemovedEventOneFrameComponent_Properties,
    .propertyCount = sizeof(g_esv_inventory_MemberRemovedEventOneFrameComponent_Properties) / sizeof(g_esv_inventory_MemberRemovedEventOneFrameComponent_Properties[0]),
};

// esv::inventory::ShapeshiftAddedEquipmentComponent - 16 bytes (0x10)
static const ComponentPropertyDef g_esv_inventory_ShapeshiftAddedEquipmentComponent_Properties[] = {
    { "Equipment", 0x00, FIELD_TYPE_ARRAY, 0, true },
};
static const ComponentLayoutDef g_esv_inventory_ShapeshiftAddedEquipmentComponent_Layout = {
    .componentName = "esv::inventory::ShapeshiftAddedEquipmentComponent",
    .shortName = "ShapeshiftAddedEquipment",
    .componentTypeIndex = 0,
    .componentSize = 0x10,
    .properties = g_esv_inventory_ShapeshiftAddedEquipmentComponent_Properties,
    .propertyCount = sizeof(g_esv_inventory_ShapeshiftAddedEquipmentComponent_Properties) / sizeof(g_esv_inventory_ShapeshiftAddedEquipmentComponent_Properties[0]),
};

// esv::inventory::ShapeshiftEquipmentHistoryComponent - 16 bytes (0x10)
// Source: Inventory.h
static const ComponentPropertyDef g_esv_inventory_ShapeshiftEquipmentHistoryComponent_Properties[] = {
    { "History", 0x00, FIELD_TYPE_ARRAY, 0, true },
};
static const ComponentLayoutDef g_esv_inventory_ShapeshiftEquipmentHistoryComponent_Layout = {
    .componentName = "esv::inventory::ShapeshiftEquipmentHistoryComponent",
    .shortName = "ShapeshiftEquipmentHistory",
    .componentTypeIndex = 0,
    .componentSize = 0x10,
    .properties = g_esv_inventory_ShapeshiftEquipmentHistoryComponent_Properties,
    .propertyCount = sizeof(g_esv_inventory_ShapeshiftEquipmentHistoryComponent_Properties) / sizeof(g_esv_inventory_ShapeshiftEquipmentHistoryComponent_Properties[0]),
};

// esv::inventory::ShapeshiftUnequippedEquipmentComponent - 16 bytes (0x10)
static const ComponentPropertyDef g_esv_inventory_ShapeshiftUnequippedEquipmentComponent_Properties[] = {
    { "Equipment", 0x00, FIELD_TYPE_ARRAY, 0, true },
};
static const ComponentLayoutDef g_esv_inventory_ShapeshiftUnequippedEquipmentComponent_Layout = {
    .componentName = "esv::inventory::ShapeshiftUnequippedEquipmentComponent",
    .shortName = "ShapeshiftUnequippedEquipment",
    .componentTypeIndex = 0,
    .componentSize = 0x10,
    .properties = g_esv_inventory_ShapeshiftUnequippedEquipmentComponent_Properties,
    .propertyCount = sizeof(g_esv_inventory_ShapeshiftUnequippedEquipmentComponent_Properties) / sizeof(g_esv_inventory_ShapeshiftUnequippedEquipmentComponent_Properties[0]),
};

// =============================================================================
// ITEM COMPONENTS (esv::item::)
// =============================================================================

// esv::item::DestroyingEventOneFrameComponent - 1 byte (0x01)
static const ComponentPropertyDef g_esv_item_DestroyingEventOneFrameComponent_Properties[] = {
    { "Value", 0x00, FIELD_TYPE_BOOL, 0, true },
};
static const ComponentLayoutDef g_esv_item_DestroyingEventOneFrameComponent_Layout = {
    .componentName = "esv::item::DestroyingEventOneFrameComponent",
    .shortName = "DestroyingEventOneFrame",
    .componentTypeIndex = 0,
    .componentSize = 0x01,
    .properties = g_esv_item_DestroyingEventOneFrameComponent_Properties,
    .propertyCount = sizeof(g_esv_item_DestroyingEventOneFrameComponent_Properties) / sizeof(g_esv_item_DestroyingEventOneFrameComponent_Properties[0]),
};

// esv::item::EntityMovingComponent - 1 byte (0x01)
static const ComponentPropertyDef g_esv_item_EntityMovingComponent_Properties[] = {
    { "Value", 0x00, FIELD_TYPE_BOOL, 0, true },
};
static const ComponentLayoutDef g_esv_item_EntityMovingComponent_Layout = {
    .componentName = "esv::item::EntityMovingComponent",
    .shortName = "EntityMoving",
    .componentTypeIndex = 0,
    .componentSize = 0x01,
    .properties = g_esv_item_EntityMovingComponent_Properties,
    .propertyCount = sizeof(g_esv_item_EntityMovingComponent_Properties) / sizeof(g_esv_item_EntityMovingComponent_Properties[0]),
};

// esv::item::MarkEntityForDestructionComponent - 1 byte (0x01)
static const ComponentPropertyDef g_esv_item_MarkEntityForDestructionComponent_Properties[] = {
    { "Value", 0x00, FIELD_TYPE_BOOL, 0, true },
};
static const ComponentLayoutDef g_esv_item_MarkEntityForDestructionComponent_Layout = {
    .componentName = "esv::item::MarkEntityForDestructionComponent",
    .shortName = "MarkEntityForDestruction",
    .componentTypeIndex = 0,
    .componentSize = 0x01,
    .properties = g_esv_item_MarkEntityForDestructionComponent_Properties,
    .propertyCount = sizeof(g_esv_item_MarkEntityForDestructionComponent_Properties) / sizeof(g_esv_item_MarkEntityForDestructionComponent_Properties[0]),
};

// esv::item::TransformedOnDestroyEventOneFrameComponent - 1 byte (0x01)
static const ComponentPropertyDef g_esv_item_TransformedOnDestroyEventOneFrameComponent_Properties[] = {
    { "Value", 0x00, FIELD_TYPE_BOOL, 0, true },
};
static const ComponentLayoutDef g_esv_item_TransformedOnDestroyEventOneFrameComponent_Layout = {
    .componentName = "esv::item::TransformedOnDestroyEventOneFrameComponent",
    .shortName = "TransformedOnDestroyEventOneFrame",
    .componentTypeIndex = 0,
    .componentSize = 0x01,
    .properties = g_esv_item_TransformedOnDestroyEventOneFrameComponent_Properties,
    .propertyCount = sizeof(g_esv_item_TransformedOnDestroyEventOneFrameComponent_Properties) / sizeof(g_esv_item_TransformedOnDestroyEventOneFrameComponent_Properties[0]),
};

// esv::item::DestroyingWaitingForDeactivationComponent - 2 bytes (0x02)
static const ComponentPropertyDef g_esv_item_DestroyingWaitingForDeactivationComponent_Properties[] = {
    { "Value", 0x00, FIELD_TYPE_UINT16, 0, true },
};
static const ComponentLayoutDef g_esv_item_DestroyingWaitingForDeactivationComponent_Layout = {
    .componentName = "esv::item::DestroyingWaitingForDeactivationComponent",
    .shortName = "DestroyingWaitingForDeactivation",
    .componentTypeIndex = 0,
    .componentSize = 0x02,
    .properties = g_esv_item_DestroyingWaitingForDeactivationComponent_Properties,
    .propertyCount = sizeof(g_esv_item_DestroyingWaitingForDeactivationComponent_Properties) / sizeof(g_esv_item_DestroyingWaitingForDeactivationComponent_Properties[0]),
};

// esv::item::DynamicLayerOwnerComponent - 4 bytes (0x04)
static const ComponentPropertyDef g_esv_item_DynamicLayerOwnerComponent_Properties[] = {
    { "Owner", 0x00, FIELD_TYPE_FIXEDSTRING, 0, true },
};
static const ComponentLayoutDef g_esv_item_DynamicLayerOwnerComponent_Layout = {
    .componentName = "esv::item::DynamicLayerOwnerComponent",
    .shortName = "DynamicLayerOwner",
    .componentTypeIndex = 0,
    .componentSize = 0x04,
    .properties = g_esv_item_DynamicLayerOwnerComponent_Properties,
    .propertyCount = sizeof(g_esv_item_DynamicLayerOwnerComponent_Properties) / sizeof(g_esv_item_DynamicLayerOwnerComponent_Properties[0]),
};

// esv::item::DestroyingWaitingForEffectComponent - 4 bytes (0x04)
static const ComponentPropertyDef g_esv_item_DestroyingWaitingForEffectComponent_Properties[] = {
    { "Value", 0x00, FIELD_TYPE_INT32, 0, true },
};
static const ComponentLayoutDef g_esv_item_DestroyingWaitingForEffectComponent_Layout = {
    .componentName = "esv::item::DestroyingWaitingForEffectComponent",
    .shortName = "DestroyingWaitingForEffect",
    .componentTypeIndex = 0,
    .componentSize = 0x04,
    .properties = g_esv_item_DestroyingWaitingForEffectComponent_Properties,
    .propertyCount = sizeof(g_esv_item_DestroyingWaitingForEffectComponent_Properties) / sizeof(g_esv_item_DestroyingWaitingForEffectComponent_Properties[0]),
};

// =============================================================================
// STATUS COMPONENTS (esv::status::)
// =============================================================================

// esv::status::PerformingComponent - 4 bytes (0x04)
static const ComponentPropertyDef g_esv_status_PerformingComponent_Properties[] = {
    { "StatusId", 0x00, FIELD_TYPE_FIXEDSTRING, 0, true },
};
static const ComponentLayoutDef g_esv_status_PerformingComponent_Layout = {
    .componentName = "esv::status::PerformingComponent",
    .shortName = "Performing",
    .componentTypeIndex = 0,
    .componentSize = 0x04,
    .properties = g_esv_status_PerformingComponent_Properties,
    .propertyCount = sizeof(g_esv_status_PerformingComponent_Properties) / sizeof(g_esv_status_PerformingComponent_Properties[0]),
};

// esv::status::OwnershipComponent - 8 bytes (0x08)
static const ComponentPropertyDef g_esv_status_OwnershipComponent_Properties[] = {
    { "Owner", 0x00, FIELD_TYPE_ENTITYHANDLE, 0, true },
};
static const ComponentLayoutDef g_esv_status_OwnershipComponent_Layout = {
    .componentName = "esv::status::OwnershipComponent",
    .shortName = "Ownership",
    .componentTypeIndex = 0,
    .componentSize = 0x08,
    .properties = g_esv_status_OwnershipComponent_Properties,
    .propertyCount = sizeof(g_esv_status_OwnershipComponent_Properties) / sizeof(g_esv_status_OwnershipComponent_Properties[0]),
};

// esv::status::LifeTimeComponent - 16 bytes (0x10)
static const ComponentPropertyDef g_esv_status_LifeTimeComponent_Properties[] = {
    { "Duration", 0x00, FIELD_TYPE_FLOAT, 0, true },
    { "TurnTimer", 0x04, FIELD_TYPE_FLOAT, 0, true },
};
static const ComponentLayoutDef g_esv_status_LifeTimeComponent_Layout = {
    .componentName = "esv::status::LifeTimeComponent",
    .shortName = "LifeTime",
    .componentTypeIndex = 0,
    .componentSize = 0x10,
    .properties = g_esv_status_LifeTimeComponent_Properties,
    .propertyCount = sizeof(g_esv_status_LifeTimeComponent_Properties) / sizeof(g_esv_status_LifeTimeComponent_Properties[0]),
};

// esv::status::StatusIDComponent - 16 bytes (0x10)
static const ComponentPropertyDef g_esv_status_StatusIDComponent_Properties[] = {
    { "ID", 0x00, FIELD_TYPE_GUID, 0, true },
};
static const ComponentLayoutDef g_esv_status_StatusIDComponent_Layout = {
    .componentName = "esv::status::StatusIDComponent",
    .shortName = "StatusID",
    .componentTypeIndex = 0,
    .componentSize = 0x10,
    .properties = g_esv_status_StatusIDComponent_Properties,
    .propertyCount = sizeof(g_esv_status_StatusIDComponent_Properties) / sizeof(g_esv_status_StatusIDComponent_Properties[0]),
};

// esv::status::StatusComponent - 40 bytes (0x28)
static const ComponentPropertyDef g_esv_status_StatusComponent_Properties[] = {
    { "StatusId", 0x00, FIELD_TYPE_FIXEDSTRING, 0, true },
    { "Flags", 0x04, FIELD_TYPE_UINT32, 0, true },
};
static const ComponentLayoutDef g_esv_status_StatusComponent_Layout = {
    .componentName = "esv::status::StatusComponent",
    .shortName = "Status",
    .componentTypeIndex = 0,
    .componentSize = 0x28,
    .properties = g_esv_status_StatusComponent_Properties,
    .propertyCount = sizeof(g_esv_status_StatusComponent_Properties) / sizeof(g_esv_status_StatusComponent_Properties[0]),
};

// =============================================================================
// AI COMPONENTS (esv::ai::)
// =============================================================================

// esv::ai::AiComponent - 1 byte (0x01)
static const ComponentPropertyDef g_esv_ai_AiComponent_Properties[] = {
    { "Value", 0x00, FIELD_TYPE_BOOL, 0, true },
};
static const ComponentLayoutDef g_esv_ai_AiComponent_Layout = {
    .componentName = "esv::ai::AiComponent",
    .shortName = "Ai",
    .componentTypeIndex = 0,
    .componentSize = 0x01,
    .properties = g_esv_ai_AiComponent_Properties,
    .propertyCount = sizeof(g_esv_ai_AiComponent_Properties) / sizeof(g_esv_ai_AiComponent_Properties[0]),
};

// Total: 113 component layouts generated
