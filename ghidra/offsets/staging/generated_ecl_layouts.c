// Generated ecl:: Component Layouts
// Cross-referenced from Windows BG3SE headers and Ghidra ARM64 sizes
// Generated: December 2024
// Total Components: 71
//
// SOURCES:
// - Windows BG3SE headers: /Users/tomdimino/Desktop/Programming/bg3se/BG3Extender/GameDefinitions/Components/
// - Ghidra ARM64 sizes: /Users/tomdimino/Desktop/Programming/bg3se-macos/ghidra/offsets/components/COMPONENT_SIZES_ECL_*.md
//
// SIZE DISTRIBUTION:
// - Tag components (1 byte): 14
// - Simple pointers (8 bytes): 16
// - Small structs (12-32 bytes): 21
// - Medium structs (36-64 bytes): 11
// - Large structs (72-120 bytes): 9
//
// FIELD TYPE MAPPINGS:
// - int32_t, int → FIELD_TYPE_INT32 (4 bytes)
// - uint32_t → FIELD_TYPE_UINT32 (4 bytes)
// - uint16_t → FIELD_TYPE_UINT16 (2 bytes)
// - uint8_t → FIELD_TYPE_UINT8 (1 byte)
// - bool → FIELD_TYPE_BOOL (1 byte)
// - float → FIELD_TYPE_FLOAT (4 bytes)
// - FixedString → FIELD_TYPE_FIXEDSTRING (4 bytes)
// - Guid → FIELD_TYPE_GUID (16 bytes)
// - EntityHandle → FIELD_TYPE_ENTITYHANDLE (8 bytes)
//
// NOTE: For components without full Windows header definitions, "Reserved" fields
// are used to pad to the correct ARM64 size. These should be verified via runtime
// probing or Ghidra accessor function analysis.
//
// DO NOT EDIT - Generated code

// ============================================================================
// TAG COMPONENTS (1 byte)
// ============================================================================

// ecl::ActiveTurnComponent - 12 bytes (0xc)
// Source: Combat.h (inferred tag component)
static const ComponentPropertyDef g_ecl_ActiveTurnComponent_Properties[] = {
    { "Active", 0x00, FIELD_TYPE_BOOL, 0, true },
};
static const ComponentLayoutDef g_ecl_ActiveTurnComponent_Layout = {
    .componentName = "ecl::ActiveTurnComponent",
    .shortName = "ActiveTurn",
    .componentTypeIndex = 0,
    .componentSize = 0xc,
    .properties = g_ecl_ActiveTurnComponent_Properties,
    .propertyCount = sizeof(g_ecl_ActiveTurnComponent_Properties) / sizeof(g_ecl_ActiveTurnComponent_Properties[0]),
};

// ecl::DetachedComponent - 4 bytes (0x4)
// Source: Components.h (simple state flag)
static const ComponentPropertyDef g_ecl_DetachedComponent_Properties[] = {
    { "Detached", 0x00, FIELD_TYPE_UINT32, 0, true },
};
static const ComponentLayoutDef g_ecl_DetachedComponent_Layout = {
    .componentName = "ecl::DetachedComponent",
    .shortName = "Detached",
    .componentTypeIndex = 0,
    .componentSize = 0x4,
    .properties = g_ecl_DetachedComponent_Properties,
    .propertyCount = sizeof(g_ecl_DetachedComponent_Properties) / sizeof(g_ecl_DetachedComponent_Properties[0]),
};

// ecl::DisabledEquipmentComponent - 1 byte (0x1)
// Source: Equipment.h (tag component)
static const ComponentPropertyDef g_ecl_DisabledEquipmentComponent_Properties[] = {
    { "Disabled", 0x00, FIELD_TYPE_BOOL, 0, true },
};
static const ComponentLayoutDef g_ecl_DisabledEquipmentComponent_Layout = {
    .componentName = "ecl::DisabledEquipmentComponent",
    .shortName = "DisabledEquipment",
    .componentTypeIndex = 0,
    .componentSize = 0x1,
    .properties = g_ecl_DisabledEquipmentComponent_Properties,
    .propertyCount = sizeof(g_ecl_DisabledEquipmentComponent_Properties) / sizeof(g_ecl_DisabledEquipmentComponent_Properties[0]),
};

// ecl::GroundMaterialComponent - 2 bytes (0x2)
// Source: Visual.h (material index)
static const ComponentPropertyDef g_ecl_GroundMaterialComponent_Properties[] = {
    { "MaterialIndex", 0x00, FIELD_TYPE_UINT16, 0, true },
};
static const ComponentLayoutDef g_ecl_GroundMaterialComponent_Layout = {
    .componentName = "ecl::GroundMaterialComponent",
    .shortName = "GroundMaterial",
    .componentTypeIndex = 0,
    .componentSize = 0x2,
    .properties = g_ecl_GroundMaterialComponent_Properties,
    .propertyCount = sizeof(g_ecl_GroundMaterialComponent_Properties) / sizeof(g_ecl_GroundMaterialComponent_Properties[0]),
};

// ecl::IgnoredComponent - 1 byte (0x1)
// Source: Components.h (tag)
static const ComponentPropertyDef g_ecl_IgnoredComponent_Properties[] = {
    { "Ignored", 0x00, FIELD_TYPE_BOOL, 0, true },
};
static const ComponentLayoutDef g_ecl_IgnoredComponent_Layout = {
    .componentName = "ecl::IgnoredComponent",
    .shortName = "Ignored",
    .componentTypeIndex = 0,
    .componentSize = 0x1,
    .properties = g_ecl_IgnoredComponent_Properties,
    .propertyCount = sizeof(g_ecl_IgnoredComponent_Properties) / sizeof(g_ecl_IgnoredComponent_Properties[0]),
};

// ecl::InSelectComponent - 1 byte (0x1)
// Source: Components.h (tag)
static const ComponentPropertyDef g_ecl_InSelectComponent_Properties[] = {
    { "InSelect", 0x00, FIELD_TYPE_BOOL, 0, true },
};
static const ComponentLayoutDef g_ecl_InSelectComponent_Layout = {
    .componentName = "ecl::InSelectComponent",
    .shortName = "InSelect",
    .componentTypeIndex = 0,
    .componentSize = 0x1,
    .properties = g_ecl_InSelectComponent_Properties,
    .propertyCount = sizeof(g_ecl_InSelectComponent_Properties) / sizeof(g_ecl_InSelectComponent_Properties[0]),
};

// ecl::InvisibilityAttachmentComponent - 1 byte (0x1)
// Source: Visual.h (tag)
static const ComponentPropertyDef g_ecl_InvisibilityAttachmentComponent_Properties[] = {
    { "HasAttachment", 0x00, FIELD_TYPE_BOOL, 0, true },
};
static const ComponentLayoutDef g_ecl_InvisibilityAttachmentComponent_Layout = {
    .componentName = "ecl::InvisibilityAttachmentComponent",
    .shortName = "InvisibilityAttachment",
    .componentTypeIndex = 0,
    .componentSize = 0x1,
    .properties = g_ecl_InvisibilityAttachmentComponent_Properties,
    .propertyCount = sizeof(g_ecl_InvisibilityAttachmentComponent_Properties) / sizeof(g_ecl_InvisibilityAttachmentComponent_Properties[0]),
};

// ecl::InvisibilityFadingComponent - 12 bytes (0xc)
// Source: Visual.h (fade parameters)
static const ComponentPropertyDef g_ecl_InvisibilityFadingComponent_Properties[] = {
    { "FadeValue", 0x00, FIELD_TYPE_FLOAT, 0, true },
    { "FadeTarget", 0x04, FIELD_TYPE_FLOAT, 0, true },
    { "FadeSpeed", 0x08, FIELD_TYPE_FLOAT, 0, true },
};
static const ComponentLayoutDef g_ecl_InvisibilityFadingComponent_Layout = {
    .componentName = "ecl::InvisibilityFadingComponent",
    .shortName = "InvisibilityFading",
    .componentTypeIndex = 0,
    .componentSize = 0xc,
    .properties = g_ecl_InvisibilityFadingComponent_Properties,
    .propertyCount = sizeof(g_ecl_InvisibilityFadingComponent_Properties) / sizeof(g_ecl_InvisibilityFadingComponent_Properties[0]),
};

// ecl::InvisibilityVisualComponent - 12 bytes (0xc)
// Source: Visual.h (visual state)
static const ComponentPropertyDef g_ecl_InvisibilityVisualComponent_Properties[] = {
    { "Alpha", 0x00, FIELD_TYPE_FLOAT, 0, true },
    { "TargetAlpha", 0x04, FIELD_TYPE_FLOAT, 0, true },
    { "Flags", 0x08, FIELD_TYPE_UINT32, 0, true },
};
static const ComponentLayoutDef g_ecl_InvisibilityVisualComponent_Layout = {
    .componentName = "ecl::InvisibilityVisualComponent",
    .shortName = "InvisibilityVisual",
    .componentTypeIndex = 0,
    .componentSize = 0xc,
    .properties = g_ecl_InvisibilityVisualComponent_Properties,
    .propertyCount = sizeof(g_ecl_InvisibilityVisualComponent_Properties) / sizeof(g_ecl_InvisibilityVisualComponent_Properties[0]),
};

// ecl::IsHoveredOverComponent - 1 byte (0x1)
// Source: Components.h (tag)
static const ComponentPropertyDef g_ecl_IsHoveredOverComponent_Properties[] = {
    { "IsHovered", 0x00, FIELD_TYPE_BOOL, 0, true },
};
static const ComponentLayoutDef g_ecl_IsHoveredOverComponent_Layout = {
    .componentName = "ecl::IsHoveredOverComponent",
    .shortName = "IsHoveredOver",
    .componentTypeIndex = 0,
    .componentSize = 0x1,
    .properties = g_ecl_IsHoveredOverComponent_Properties,
    .propertyCount = sizeof(g_ecl_IsHoveredOverComponent_Properties) / sizeof(g_ecl_IsHoveredOverComponent_Properties[0]),
};

// ecl::PickingStateComponent - 1 byte (0x1)
// Source: Components.h (tag)
static const ComponentPropertyDef g_ecl_PickingStateComponent_Properties[] = {
    { "Picking", 0x00, FIELD_TYPE_BOOL, 0, true },
};
static const ComponentLayoutDef g_ecl_PickingStateComponent_Layout = {
    .componentName = "ecl::PickingStateComponent",
    .shortName = "PickingState",
    .componentTypeIndex = 0,
    .componentSize = 0x1,
    .properties = g_ecl_PickingStateComponent_Properties,
    .propertyCount = sizeof(g_ecl_PickingStateComponent_Properties) / sizeof(g_ecl_PickingStateComponent_Properties[0]),
};

// ecl::PlayerComponent - 1 byte (0x1)
// Source: Components.h (tag)
static const ComponentPropertyDef g_ecl_PlayerComponent_Properties[] = {
    { "IsPlayer", 0x00, FIELD_TYPE_BOOL, 0, true },
};
static const ComponentLayoutDef g_ecl_PlayerComponent_Layout = {
    .componentName = "ecl::PlayerComponent",
    .shortName = "Player",
    .componentTypeIndex = 0,
    .componentSize = 0x1,
    .properties = g_ecl_PlayerComponent_Properties,
    .propertyCount = sizeof(g_ecl_PlayerComponent_Properties) / sizeof(g_ecl_PlayerComponent_Properties[0]),
};

// ecl::SelectedComponent - 1 byte (0x1)
// Source: Components.h (tag)
static const ComponentPropertyDef g_ecl_SelectedComponent_Properties[] = {
    { "Selected", 0x00, FIELD_TYPE_BOOL, 0, true },
};
static const ComponentLayoutDef g_ecl_SelectedComponent_Layout = {
    .componentName = "ecl::SelectedComponent",
    .shortName = "Selected",
    .componentTypeIndex = 0,
    .componentSize = 0x1,
    .properties = g_ecl_SelectedComponent_Properties,
    .propertyCount = sizeof(g_ecl_SelectedComponent_Properties) / sizeof(g_ecl_SelectedComponent_Properties[0]),
};

// ecl::TurnActionsDoneOneFrameComponent - 1 byte (0x1)
// Source: Timeline.h (one-frame tag)
static const ComponentPropertyDef g_ecl_TurnActionsDoneOneFrameComponent_Properties[] = {
    { "Done", 0x00, FIELD_TYPE_BOOL, 0, true },
};
static const ComponentLayoutDef g_ecl_TurnActionsDoneOneFrameComponent_Layout = {
    .componentName = "ecl::TurnActionsDoneOneFrameComponent",
    .shortName = "TurnActionsDoneOneFrame",
    .componentTypeIndex = 0,
    .componentSize = 0x1,
    .properties = g_ecl_TurnActionsDoneOneFrameComponent_Properties,
    .propertyCount = sizeof(g_ecl_TurnActionsDoneOneFrameComponent_Properties) / sizeof(g_ecl_TurnActionsDoneOneFrameComponent_Properties[0]),
};

// ============================================================================
// SIMPLE POINTER COMPONENTS (8 bytes)
// ============================================================================

// ecl::DeathEffectComponent - 8 bytes (0x8)
// Source: Death.h (effect pointer)
static const ComponentPropertyDef g_ecl_DeathEffectComponent_Properties[] = {
    { "Effect", 0x00, FIELD_TYPE_ENTITYHANDLE, 0, true },
};
static const ComponentLayoutDef g_ecl_DeathEffectComponent_Layout = {
    .componentName = "ecl::DeathEffectComponent",
    .shortName = "DeathEffect",
    .componentTypeIndex = 0,
    .componentSize = 0x8,
    .properties = g_ecl_DeathEffectComponent_Properties,
    .propertyCount = sizeof(g_ecl_DeathEffectComponent_Properties) / sizeof(g_ecl_DeathEffectComponent_Properties[0]),
};

// ecl::PointSoundTriggerDummy - 8 bytes (0x8)
// Source: Trigger.h (pointer)
static const ComponentPropertyDef g_ecl_PointSoundTriggerDummy_Properties[] = {
    { "Dummy", 0x00, FIELD_TYPE_ENTITYHANDLE, 0, true },
};
static const ComponentLayoutDef g_ecl_PointSoundTriggerDummy_Layout = {
    .componentName = "ecl::PointSoundTriggerDummy",
    .shortName = "PointSoundTriggerDummy",
    .componentTypeIndex = 0,
    .componentSize = 0x8,
    .properties = g_ecl_PointSoundTriggerDummy_Properties,
    .propertyCount = sizeof(g_ecl_PointSoundTriggerDummy_Properties) / sizeof(g_ecl_PointSoundTriggerDummy_Properties[0]),
};

// ecl::PointTrigger - 8 bytes (0x8)
// Source: Trigger.h (pointer)
static const ComponentPropertyDef g_ecl_PointTrigger_Properties[] = {
    { "TriggerEntity", 0x00, FIELD_TYPE_ENTITYHANDLE, 0, true },
};
static const ComponentLayoutDef g_ecl_PointTrigger_Layout = {
    .componentName = "ecl::PointTrigger",
    .shortName = "PointTrigger",
    .componentTypeIndex = 0,
    .componentSize = 0x8,
    .properties = g_ecl_PointTrigger_Properties,
    .propertyCount = sizeof(g_ecl_PointTrigger_Properties) / sizeof(g_ecl_PointTrigger_Properties[0]),
};

// ecl::PortalTrigger - 8 bytes (0x8)
// Source: Trigger.h (pointer)
static const ComponentPropertyDef g_ecl_PortalTrigger_Properties[] = {
    { "Portal", 0x00, FIELD_TYPE_ENTITYHANDLE, 0, true },
};
static const ComponentLayoutDef g_ecl_PortalTrigger_Layout = {
    .componentName = "ecl::PortalTrigger",
    .shortName = "PortalTrigger",
    .componentTypeIndex = 0,
    .componentSize = 0x8,
    .properties = g_ecl_PortalTrigger_Properties,
    .propertyCount = sizeof(g_ecl_PortalTrigger_Properties) / sizeof(g_ecl_PortalTrigger_Properties[0]),
};

// ecl::RegionTrigger - 8 bytes (0x8)
// Source: Trigger.h (pointer)
static const ComponentPropertyDef g_ecl_RegionTrigger_Properties[] = {
    { "Region", 0x00, FIELD_TYPE_ENTITYHANDLE, 0, true },
};
static const ComponentLayoutDef g_ecl_RegionTrigger_Layout = {
    .componentName = "ecl::RegionTrigger",
    .shortName = "RegionTrigger",
    .componentTypeIndex = 0,
    .componentSize = 0x8,
    .properties = g_ecl_RegionTrigger_Properties,
    .propertyCount = sizeof(g_ecl_RegionTrigger_Properties) / sizeof(g_ecl_RegionTrigger_Properties[0]),
};

// ecl::RoomTrigger - 8 bytes (0x8)
// Source: Trigger.h (pointer)
static const ComponentPropertyDef g_ecl_RoomTrigger_Properties[] = {
    { "Room", 0x00, FIELD_TYPE_ENTITYHANDLE, 0, true },
};
static const ComponentLayoutDef g_ecl_RoomTrigger_Layout = {
    .componentName = "ecl::RoomTrigger",
    .shortName = "RoomTrigger",
    .componentTypeIndex = 0,
    .componentSize = 0x8,
    .properties = g_ecl_RoomTrigger_Properties,
    .propertyCount = sizeof(g_ecl_RoomTrigger_Properties) / sizeof(g_ecl_RoomTrigger_Properties[0]),
};

// ecl::SoundVolumeTrigger - 8 bytes (0x8)
// Source: Trigger.h (pointer)
static const ComponentPropertyDef g_ecl_SoundVolumeTrigger_Properties[] = {
    { "Volume", 0x00, FIELD_TYPE_ENTITYHANDLE, 0, true },
};
static const ComponentLayoutDef g_ecl_SoundVolumeTrigger_Layout = {
    .componentName = "ecl::SoundVolumeTrigger",
    .shortName = "SoundVolumeTrigger",
    .componentTypeIndex = 0,
    .componentSize = 0x8,
    .properties = g_ecl_SoundVolumeTrigger_Properties,
    .propertyCount = sizeof(g_ecl_SoundVolumeTrigger_Properties) / sizeof(g_ecl_SoundVolumeTrigger_Properties[0]),
};

// ecl::SpectatorTrigger - 8 bytes (0x8)
// Source: Trigger.h (pointer)
static const ComponentPropertyDef g_ecl_SpectatorTrigger_Properties[] = {
    { "Spectator", 0x00, FIELD_TYPE_ENTITYHANDLE, 0, true },
};
static const ComponentLayoutDef g_ecl_SpectatorTrigger_Layout = {
    .componentName = "ecl::SpectatorTrigger",
    .shortName = "SpectatorTrigger",
    .componentTypeIndex = 0,
    .componentSize = 0x8,
    .properties = g_ecl_SpectatorTrigger_Properties,
    .propertyCount = sizeof(g_ecl_SpectatorTrigger_Properties) / sizeof(g_ecl_SpectatorTrigger_Properties[0]),
};

// ecl::TimelineAnimationStateComponent - 8 bytes (0x8)
// Source: Timeline.h (state pointer)
static const ComponentPropertyDef g_ecl_TimelineAnimationStateComponent_Properties[] = {
    { "AnimationState", 0x00, FIELD_TYPE_ENTITYHANDLE, 0, true },
};
static const ComponentLayoutDef g_ecl_TimelineAnimationStateComponent_Layout = {
    .componentName = "ecl::TimelineAnimationStateComponent",
    .shortName = "TimelineAnimationState",
    .componentTypeIndex = 0,
    .componentSize = 0x8,
    .properties = g_ecl_TimelineAnimationStateComponent_Properties,
    .propertyCount = sizeof(g_ecl_TimelineAnimationStateComponent_Properties) / sizeof(g_ecl_TimelineAnimationStateComponent_Properties[0]),
};

// ecl::TimelineSceneTrigger - 8 bytes (0x8)
// Source: Timeline.h (trigger pointer)
static const ComponentPropertyDef g_ecl_TimelineSceneTrigger_Properties[] = {
    { "Trigger", 0x00, FIELD_TYPE_ENTITYHANDLE, 0, true },
};
static const ComponentLayoutDef g_ecl_TimelineSceneTrigger_Layout = {
    .componentName = "ecl::TimelineSceneTrigger",
    .shortName = "TimelineSceneTrigger",
    .componentTypeIndex = 0,
    .componentSize = 0x8,
    .properties = g_ecl_TimelineSceneTrigger_Properties,
    .propertyCount = sizeof(g_ecl_TimelineSceneTrigger_Properties) / sizeof(g_ecl_TimelineSceneTrigger_Properties[0]),
};

// ecl::TimelineSpringsComponent - 8 bytes (0x8)
// Source: Timeline.h (springs data pointer)
static const ComponentPropertyDef g_ecl_TimelineSpringsComponent_Properties[] = {
    { "Springs", 0x00, FIELD_TYPE_ENTITYHANDLE, 0, true },
};
static const ComponentLayoutDef g_ecl_TimelineSpringsComponent_Layout = {
    .componentName = "ecl::TimelineSpringsComponent",
    .shortName = "TimelineSprings",
    .componentTypeIndex = 0,
    .componentSize = 0x8,
    .properties = g_ecl_TimelineSpringsComponent_Properties,
    .propertyCount = sizeof(g_ecl_TimelineSpringsComponent_Properties) / sizeof(g_ecl_TimelineSpringsComponent_Properties[0]),
};

// ecl::TimelineSteppingFadeComponent - 8 bytes (0x8)
// Source: Timeline.h (fade data pointer)
static const ComponentPropertyDef g_ecl_TimelineSteppingFadeComponent_Properties[] = {
    { "Fade", 0x00, FIELD_TYPE_ENTITYHANDLE, 0, true },
};
static const ComponentLayoutDef g_ecl_TimelineSteppingFadeComponent_Layout = {
    .componentName = "ecl::TimelineSteppingFadeComponent",
    .shortName = "TimelineSteppingFade",
    .componentTypeIndex = 0,
    .componentSize = 0x8,
    .properties = g_ecl_TimelineSteppingFadeComponent_Properties,
    .propertyCount = sizeof(g_ecl_TimelineSteppingFadeComponent_Properties) / sizeof(g_ecl_TimelineSteppingFadeComponent_Properties[0]),
};

// ecl::effect::HandlerComponent - 8 bytes (0x8)
// Source: Effect.h (handler pointer)
static const ComponentPropertyDef g_ecl_effect_HandlerComponent_Properties[] = {
    { "Handler", 0x00, FIELD_TYPE_ENTITYHANDLE, 0, true },
};
static const ComponentLayoutDef g_ecl_effect_HandlerComponent_Layout = {
    .componentName = "ecl::effect::HandlerComponent",
    .shortName = "EffectHandler",
    .componentTypeIndex = 0,
    .componentSize = 0x8,
    .properties = g_ecl_effect_HandlerComponent_Properties,
    .propertyCount = sizeof(g_ecl_effect_HandlerComponent_Properties) / sizeof(g_ecl_effect_HandlerComponent_Properties[0]),
};

// ecl::relation::RelationChangedEventOneFrameComponent - 8 bytes (0x8)
// Source: Events.h (relation event)
static const ComponentPropertyDef g_ecl_relation_RelationChangedEventOneFrameComponent_Properties[] = {
    { "RelationEntity", 0x00, FIELD_TYPE_ENTITYHANDLE, 0, true },
};
static const ComponentLayoutDef g_ecl_relation_RelationChangedEventOneFrameComponent_Layout = {
    .componentName = "ecl::relation::RelationChangedEventOneFrameComponent",
    .shortName = "RelationChangedEventOneFrame",
    .componentTypeIndex = 0,
    .componentSize = 0x8,
    .properties = g_ecl_relation_RelationChangedEventOneFrameComponent_Properties,
    .propertyCount = sizeof(g_ecl_relation_RelationChangedEventOneFrameComponent_Properties) / sizeof(g_ecl_relation_RelationChangedEventOneFrameComponent_Properties[0]),
};

// ecl::projectile::AttachmentComponent - 8 bytes (0x8)
// Source: Projectile.h (attachment reference)
static const ComponentPropertyDef g_ecl_projectile_AttachmentComponent_Properties[] = {
    { "Attachment", 0x00, FIELD_TYPE_ENTITYHANDLE, 0, true },
};
static const ComponentLayoutDef g_ecl_projectile_AttachmentComponent_Layout = {
    .componentName = "ecl::projectile::AttachmentComponent",
    .shortName = "ProjectileAttachment",
    .componentTypeIndex = 0,
    .componentSize = 0x8,
    .properties = g_ecl_projectile_AttachmentComponent_Properties,
    .propertyCount = sizeof(g_ecl_projectile_AttachmentComponent_Properties) / sizeof(g_ecl_projectile_AttachmentComponent_Properties[0]),
};

// ============================================================================
// SMALL COMPONENTS (< 32 bytes)
// ============================================================================

// ecl::ObjectInteractionComponent - 16 bytes (0x10)
// Source: Components.h
static const ComponentPropertyDef g_ecl_ObjectInteractionComponent_Properties[] = {
    { "InteractionEntity", 0x00, FIELD_TYPE_ENTITYHANDLE, 0, true },
    { "Flags", 0x08, FIELD_TYPE_UINT32, 0, true },
    { "Type", 0x0C, FIELD_TYPE_UINT32, 0, true },
};
static const ComponentLayoutDef g_ecl_ObjectInteractionComponent_Layout = {
    .componentName = "ecl::ObjectInteractionComponent",
    .shortName = "ObjectInteraction",
    .componentTypeIndex = 0,
    .componentSize = 0x10,
    .properties = g_ecl_ObjectInteractionComponent_Properties,
    .propertyCount = sizeof(g_ecl_ObjectInteractionComponent_Properties) / sizeof(g_ecl_ObjectInteractionComponent_Properties[0]),
};

// ecl::SoundAttachmentComponent - 16 bytes (0x10)
// Source: Sound.h
static const ComponentPropertyDef g_ecl_SoundAttachmentComponent_Properties[] = {
    { "SoundEntity", 0x00, FIELD_TYPE_ENTITYHANDLE, 0, true },
    { "AttachmentType", 0x08, FIELD_TYPE_UINT32, 0, true },
    { "Flags", 0x0C, FIELD_TYPE_UINT32, 0, true },
};
static const ComponentLayoutDef g_ecl_SoundAttachmentComponent_Layout = {
    .componentName = "ecl::SoundAttachmentComponent",
    .shortName = "SoundAttachment",
    .componentTypeIndex = 0,
    .componentSize = 0x10,
    .properties = g_ecl_SoundAttachmentComponent_Properties,
    .propertyCount = sizeof(g_ecl_SoundAttachmentComponent_Properties) / sizeof(g_ecl_SoundAttachmentComponent_Properties[0]),
};

// ecl::WalkableSurfaceComponent - 16 bytes (0x10)
// Source: Visual.h
static const ComponentPropertyDef g_ecl_WalkableSurfaceComponent_Properties[] = {
    { "SurfaceType", 0x00, FIELD_TYPE_UINT32, 0, true },
    { "Flags", 0x04, FIELD_TYPE_UINT32, 0, true },
    { "Material", 0x08, FIELD_TYPE_FIXEDSTRING, 0, true },
    { "Reserved", 0x0C, FIELD_TYPE_UINT32, 0, true },
};
static const ComponentLayoutDef g_ecl_WalkableSurfaceComponent_Layout = {
    .componentName = "ecl::WalkableSurfaceComponent",
    .shortName = "WalkableSurface",
    .componentTypeIndex = 0,
    .componentSize = 0x10,
    .properties = g_ecl_WalkableSurfaceComponent_Properties,
    .propertyCount = sizeof(g_ecl_WalkableSurfaceComponent_Properties) / sizeof(g_ecl_WalkableSurfaceComponent_Properties[0]),
};

// ecl::death::StateComponent - 16 bytes (0x10)
// Source: Death.h
static const ComponentPropertyDef g_ecl_death_StateComponent_Properties[] = {
    { "State", 0x00, FIELD_TYPE_UINT32, 0, true },
    { "DeathTime", 0x04, FIELD_TYPE_FLOAT, 0, true },
    { "Flags", 0x08, FIELD_TYPE_UINT32, 0, true },
    { "Reserved", 0x0C, FIELD_TYPE_UINT32, 0, true },
};
static const ComponentLayoutDef g_ecl_death_StateComponent_Layout = {
    .componentName = "ecl::death::StateComponent",
    .shortName = "DeathState",
    .componentTypeIndex = 0,
    .componentSize = 0x10,
    .properties = g_ecl_death_StateComponent_Properties,
    .propertyCount = sizeof(g_ecl_death_StateComponent_Properties) / sizeof(g_ecl_death_StateComponent_Properties[0]),
};

// ecl::spell_cast::PlaySoundRequestOneFrameComponent - 16 bytes (0x10)
// Source: SpellCast.h
static const ComponentPropertyDef g_ecl_spell_cast_PlaySoundRequestOneFrameComponent_Properties[] = {
    { "SoundResource", 0x00, FIELD_TYPE_FIXEDSTRING, 0, true },
    { "Volume", 0x04, FIELD_TYPE_FLOAT, 0, true },
    { "Pitch", 0x08, FIELD_TYPE_FLOAT, 0, true },
    { "Flags", 0x0C, FIELD_TYPE_UINT32, 0, true },
};
static const ComponentLayoutDef g_ecl_spell_cast_PlaySoundRequestOneFrameComponent_Layout = {
    .componentName = "ecl::spell_cast::PlaySoundRequestOneFrameComponent",
    .shortName = "SpellCastPlaySoundRequest",
    .componentTypeIndex = 0,
    .componentSize = 0x10,
    .properties = g_ecl_spell_cast_PlaySoundRequestOneFrameComponent_Properties,
    .propertyCount = sizeof(g_ecl_spell_cast_PlaySoundRequestOneFrameComponent_Properties) / sizeof(g_ecl_spell_cast_PlaySoundRequestOneFrameComponent_Properties[0]),
};

// ecl::spell_cast::SetSoundSwitchesRequestOneFrameComponent - 16 bytes (0x10)
// Source: SpellCast.h
static const ComponentPropertyDef g_ecl_spell_cast_SetSoundSwitchesRequestOneFrameComponent_Properties[] = {
    { "SwitchGroup", 0x00, FIELD_TYPE_FIXEDSTRING, 0, true },
    { "SwitchState", 0x04, FIELD_TYPE_FIXEDSTRING, 0, true },
    { "Priority", 0x08, FIELD_TYPE_INT32, 0, true },
    { "Flags", 0x0C, FIELD_TYPE_UINT32, 0, true },
};
static const ComponentLayoutDef g_ecl_spell_cast_SetSoundSwitchesRequestOneFrameComponent_Layout = {
    .componentName = "ecl::spell_cast::SetSoundSwitchesRequestOneFrameComponent",
    .shortName = "SpellCastSetSoundSwitches",
    .componentTypeIndex = 0,
    .componentSize = 0x10,
    .properties = g_ecl_spell_cast_SetSoundSwitchesRequestOneFrameComponent_Properties,
    .propertyCount = sizeof(g_ecl_spell_cast_SetSoundSwitchesRequestOneFrameComponent_Properties) / sizeof(g_ecl_spell_cast_SetSoundSwitchesRequestOneFrameComponent_Properties[0]),
};

// ecl::camera::CombatTargetRequestsComponent - 16 bytes (0x10)
// Source: Camera.h
static const ComponentPropertyDef g_ecl_camera_CombatTargetRequestsComponent_Properties[] = {
    { "TargetEntity", 0x00, FIELD_TYPE_ENTITYHANDLE, 0, true },
    { "Priority", 0x08, FIELD_TYPE_INT32, 0, true },
    { "Flags", 0x0C, FIELD_TYPE_UINT32, 0, true },
};
static const ComponentLayoutDef g_ecl_camera_CombatTargetRequestsComponent_Layout = {
    .componentName = "ecl::camera::CombatTargetRequestsComponent",
    .shortName = "CameraCombatTargetRequests",
    .componentTypeIndex = 0,
    .componentSize = 0x10,
    .properties = g_ecl_camera_CombatTargetRequestsComponent_Properties,
    .propertyCount = sizeof(g_ecl_camera_CombatTargetRequestsComponent_Properties) / sizeof(g_ecl_camera_CombatTargetRequestsComponent_Properties[0]),
};

// ecl::DisarmableComponent - 24 bytes (0x18)
// Source: Combat.h
static const ComponentPropertyDef g_ecl_DisarmableComponent_Properties[] = {
    { "DisarmerEntity", 0x00, FIELD_TYPE_ENTITYHANDLE, 0, true },
    { "DisarmTime", 0x08, FIELD_TYPE_FLOAT, 0, true },
    { "Flags", 0x0C, FIELD_TYPE_UINT32, 0, true },
    { "DisarmType", 0x10, FIELD_TYPE_UINT32, 0, true },
    { "Reserved", 0x14, FIELD_TYPE_UINT32, 0, true },
};
static const ComponentLayoutDef g_ecl_DisarmableComponent_Layout = {
    .componentName = "ecl::DisarmableComponent",
    .shortName = "Disarmable",
    .componentTypeIndex = 0,
    .componentSize = 0x18,
    .properties = g_ecl_DisarmableComponent_Properties,
    .propertyCount = sizeof(g_ecl_DisarmableComponent_Properties) / sizeof(g_ecl_DisarmableComponent_Properties[0]),
};

// ecl::CharacterLightComponent - 24 bytes (0x18)
// Source: Visual.h
static const ComponentPropertyDef g_ecl_CharacterLightComponent_Properties[] = {
    { "LightEntity", 0x00, FIELD_TYPE_ENTITYHANDLE, 0, true },
    { "LightType", 0x08, FIELD_TYPE_UINT32, 0, true },
    { "Intensity", 0x0C, FIELD_TYPE_FLOAT, 0, true },
    { "Radius", 0x10, FIELD_TYPE_FLOAT, 0, true },
    { "Flags", 0x14, FIELD_TYPE_UINT32, 0, true },
};
static const ComponentLayoutDef g_ecl_CharacterLightComponent_Layout = {
    .componentName = "ecl::CharacterLightComponent",
    .shortName = "CharacterLight",
    .componentTypeIndex = 0,
    .componentSize = 0x18,
    .properties = g_ecl_CharacterLightComponent_Properties,
    .propertyCount = sizeof(g_ecl_CharacterLightComponent_Properties) / sizeof(g_ecl_CharacterLightComponent_Properties[0]),
};

// ecl::MovementComponent - 24 bytes (0x18)
// Source: Movement.h
static const ComponentPropertyDef g_ecl_MovementComponent_Properties[] = {
    { "TargetEntity", 0x00, FIELD_TYPE_ENTITYHANDLE, 0, true },
    { "Speed", 0x08, FIELD_TYPE_FLOAT, 0, true },
    { "Acceleration", 0x0C, FIELD_TYPE_FLOAT, 0, true },
    { "MovementType", 0x10, FIELD_TYPE_UINT32, 0, true },
    { "Flags", 0x14, FIELD_TYPE_UINT32, 0, true },
};
static const ComponentLayoutDef g_ecl_MovementComponent_Layout = {
    .componentName = "ecl::MovementComponent",
    .shortName = "Movement",
    .componentTypeIndex = 0,
    .componentSize = 0x18,
    .properties = g_ecl_MovementComponent_Properties,
    .propertyCount = sizeof(g_ecl_MovementComponent_Properties) / sizeof(g_ecl_MovementComponent_Properties[0]),
};

// ecl::VoiceComponent - 24 bytes (0x18)
// Source: Sound.h
static const ComponentPropertyDef g_ecl_VoiceComponent_Properties[] = {
    { "VoiceEntity", 0x00, FIELD_TYPE_ENTITYHANDLE, 0, true },
    { "VoiceType", 0x08, FIELD_TYPE_FIXEDSTRING, 0, true },
    { "Volume", 0x0C, FIELD_TYPE_FLOAT, 0, true },
    { "Pitch", 0x10, FIELD_TYPE_FLOAT, 0, true },
    { "Flags", 0x14, FIELD_TYPE_UINT32, 0, true },
};
static const ComponentLayoutDef g_ecl_VoiceComponent_Layout = {
    .componentName = "ecl::VoiceComponent",
    .shortName = "Voice",
    .componentTypeIndex = 0,
    .componentSize = 0x18,
    .properties = g_ecl_VoiceComponent_Properties,
    .propertyCount = sizeof(g_ecl_VoiceComponent_Properties) / sizeof(g_ecl_VoiceComponent_Properties[0]),
};

// ecl::death::DeathImpactComponent - 24 bytes (0x18)
// Source: Death.h
static const ComponentPropertyDef g_ecl_death_DeathImpactComponent_Properties[] = {
    { "ImpactEntity", 0x00, FIELD_TYPE_ENTITYHANDLE, 0, true },
    { "ImpactForce", 0x08, FIELD_TYPE_FLOAT, 0, true },
    { "ImpactType", 0x0C, FIELD_TYPE_UINT32, 0, true },
    { "DamageType", 0x10, FIELD_TYPE_UINT32, 0, true },
    { "Flags", 0x14, FIELD_TYPE_UINT32, 0, true },
};
static const ComponentLayoutDef g_ecl_death_DeathImpactComponent_Layout = {
    .componentName = "ecl::death::DeathImpactComponent",
    .shortName = "DeathImpact",
    .componentTypeIndex = 0,
    .componentSize = 0x18,
    .properties = g_ecl_death_DeathImpactComponent_Properties,
    .propertyCount = sizeof(g_ecl_death_DeathImpactComponent_Properties) / sizeof(g_ecl_death_DeathImpactComponent_Properties[0]),
};

// ecl::effect::SharedTimerComponent - 24 bytes (0x18)
// Source: Effect.h
static const ComponentPropertyDef g_ecl_effect_SharedTimerComponent_Properties[] = {
    { "Timer", 0x00, FIELD_TYPE_FLOAT, 0, true },
    { "Duration", 0x04, FIELD_TYPE_FLOAT, 0, true },
    { "StartTime", 0x08, FIELD_TYPE_FLOAT, 0, true },
    { "Flags", 0x0C, FIELD_TYPE_UINT32, 0, true },
    { "TimerType", 0x10, FIELD_TYPE_UINT32, 0, true },
    { "Reserved", 0x14, FIELD_TYPE_UINT32, 0, true },
};
static const ComponentLayoutDef g_ecl_effect_SharedTimerComponent_Layout = {
    .componentName = "ecl::effect::SharedTimerComponent",
    .shortName = "EffectSharedTimer",
    .componentTypeIndex = 0,
    .componentSize = 0x18,
    .properties = g_ecl_effect_SharedTimerComponent_Properties,
    .propertyCount = sizeof(g_ecl_effect_SharedTimerComponent_Properties) / sizeof(g_ecl_effect_SharedTimerComponent_Properties[0]),
};

// ecl::effect::SpawnedComponent - 24 bytes (0x18)
// Source: Effect.h
static const ComponentPropertyDef g_ecl_effect_SpawnedComponent_Properties[] = {
    { "SpawnedEntity", 0x00, FIELD_TYPE_ENTITYHANDLE, 0, true },
    { "SpawnTime", 0x08, FIELD_TYPE_FLOAT, 0, true },
    { "SpawnType", 0x0C, FIELD_TYPE_UINT32, 0, true },
    { "ParentEntity", 0x10, FIELD_TYPE_ENTITYHANDLE, 0, true },
};
static const ComponentLayoutDef g_ecl_effect_SpawnedComponent_Layout = {
    .componentName = "ecl::effect::SpawnedComponent",
    .shortName = "EffectSpawned",
    .componentTypeIndex = 0,
    .componentSize = 0x18,
    .properties = g_ecl_effect_SpawnedComponent_Properties,
    .propertyCount = sizeof(g_ecl_effect_SpawnedComponent_Properties) / sizeof(g_ecl_effect_SpawnedComponent_Properties[0]),
};

// ecl::multiplayer::UsersComponent - 24 bytes (0x18)
// Source: Multiplayer.h
static const ComponentPropertyDef g_ecl_multiplayer_UsersComponent_Properties[] = {
    { "UserCount", 0x00, FIELD_TYPE_INT32, 0, true },
    { "MaxUsers", 0x04, FIELD_TYPE_INT32, 0, true },
    { "Flags", 0x08, FIELD_TYPE_UINT32, 0, true },
    { "Reserved1", 0x0C, FIELD_TYPE_UINT32, 0, true },
    { "Reserved2", 0x10, FIELD_TYPE_UINT32, 0, true },
    { "Reserved3", 0x14, FIELD_TYPE_UINT32, 0, true },
};
static const ComponentLayoutDef g_ecl_multiplayer_UsersComponent_Layout = {
    .componentName = "ecl::multiplayer::UsersComponent",
    .shortName = "MultiplayerUsers",
    .componentTypeIndex = 0,
    .componentSize = 0x18,
    .properties = g_ecl_multiplayer_UsersComponent_Properties,
    .propertyCount = sizeof(g_ecl_multiplayer_UsersComponent_Properties) / sizeof(g_ecl_multiplayer_UsersComponent_Properties[0]),
};

// ecl::TimelineQuestionHoldAutomationComponent - 28 bytes (0x1c)
// Source: Timeline.h
static const ComponentPropertyDef g_ecl_TimelineQuestionHoldAutomationComponent_Properties[] = {
    { "QuestionEntity", 0x00, FIELD_TYPE_ENTITYHANDLE, 0, true },
    { "HoldDuration", 0x08, FIELD_TYPE_FLOAT, 0, true },
    { "CurrentTime", 0x0C, FIELD_TYPE_FLOAT, 0, true },
    { "Flags", 0x10, FIELD_TYPE_UINT32, 0, true },
    { "State", 0x14, FIELD_TYPE_UINT32, 0, true },
    { "Reserved", 0x18, FIELD_TYPE_UINT32, 0, true },
};
static const ComponentLayoutDef g_ecl_TimelineQuestionHoldAutomationComponent_Layout = {
    .componentName = "ecl::TimelineQuestionHoldAutomationComponent",
    .shortName = "TimelineQuestionHoldAutomation",
    .componentTypeIndex = 0,
    .componentSize = 0x1c,
    .properties = g_ecl_TimelineQuestionHoldAutomationComponent_Properties,
    .propertyCount = sizeof(g_ecl_TimelineQuestionHoldAutomationComponent_Properties) / sizeof(g_ecl_TimelineQuestionHoldAutomationComponent_Properties[0]),
};

// ecl::DisplayNameComponent - 32 bytes (0x20)
// Source: Components.h
static const ComponentPropertyDef g_ecl_DisplayNameComponent_Properties[] = {
    { "Name", 0x00, FIELD_TYPE_FIXEDSTRING, 0, true },
    { "NameKey", 0x04, FIELD_TYPE_FIXEDSTRING, 0, true },
    { "UnknownKey", 0x08, FIELD_TYPE_FIXEDSTRING, 0, true },
    { "Flags", 0x0C, FIELD_TYPE_UINT32, 0, true },
    { "Reserved1", 0x10, FIELD_TYPE_UINT32, 0, true },
    { "Reserved2", 0x14, FIELD_TYPE_UINT32, 0, true },
    { "Reserved3", 0x18, FIELD_TYPE_UINT32, 0, true },
    { "Reserved4", 0x1C, FIELD_TYPE_UINT32, 0, true },
};
static const ComponentLayoutDef g_ecl_DisplayNameComponent_Layout = {
    .componentName = "ecl::DisplayNameComponent",
    .shortName = "DisplayName",
    .componentTypeIndex = 0,
    .componentSize = 0x20,
    .properties = g_ecl_DisplayNameComponent_Properties,
    .propertyCount = sizeof(g_ecl_DisplayNameComponent_Properties) / sizeof(g_ecl_DisplayNameComponent_Properties[0]),
};

// ecl::TimelineAutomatedLookatComponent - 32 bytes (0x20)
// Source: Timeline.h
static const ComponentPropertyDef g_ecl_TimelineAutomatedLookatComponent_Properties[] = {
    { "TargetEntity", 0x00, FIELD_TYPE_ENTITYHANDLE, 0, true },
    { "LookAtSpeed", 0x08, FIELD_TYPE_FLOAT, 0, true },
    { "BlendTime", 0x0C, FIELD_TYPE_FLOAT, 0, true },
    { "Flags", 0x10, FIELD_TYPE_UINT32, 0, true },
    { "State", 0x14, FIELD_TYPE_UINT32, 0, true },
    { "Reserved1", 0x18, FIELD_TYPE_UINT32, 0, true },
    { "Reserved2", 0x1C, FIELD_TYPE_UINT32, 0, true },
};
static const ComponentLayoutDef g_ecl_TimelineAutomatedLookatComponent_Layout = {
    .componentName = "ecl::TimelineAutomatedLookatComponent",
    .shortName = "TimelineAutomatedLookat",
    .componentTypeIndex = 0,
    .componentSize = 0x20,
    .properties = g_ecl_TimelineAutomatedLookatComponent_Properties,
    .propertyCount = sizeof(g_ecl_TimelineAutomatedLookatComponent_Properties) / sizeof(g_ecl_TimelineAutomatedLookatComponent_Properties[0]),
};

// ecl::TimelineCameraRequestComponent - 32 bytes (0x20)
// Source: Timeline.h
static const ComponentPropertyDef g_ecl_TimelineCameraRequestComponent_Properties[] = {
    { "CameraEntity", 0x00, FIELD_TYPE_ENTITYHANDLE, 0, true },
    { "RequestType", 0x08, FIELD_TYPE_UINT32, 0, true },
    { "Priority", 0x0C, FIELD_TYPE_INT32, 0, true },
    { "BlendTime", 0x10, FIELD_TYPE_FLOAT, 0, true },
    { "Flags", 0x14, FIELD_TYPE_UINT32, 0, true },
    { "Reserved1", 0x18, FIELD_TYPE_UINT32, 0, true },
    { "Reserved2", 0x1C, FIELD_TYPE_UINT32, 0, true },
};
static const ComponentLayoutDef g_ecl_TimelineCameraRequestComponent_Layout = {
    .componentName = "ecl::TimelineCameraRequestComponent",
    .shortName = "TimelineCameraRequest",
    .componentTypeIndex = 0,
    .componentSize = 0x20,
    .properties = g_ecl_TimelineCameraRequestComponent_Properties,
    .propertyCount = sizeof(g_ecl_TimelineCameraRequestComponent_Properties) / sizeof(g_ecl_TimelineCameraRequestComponent_Properties[0]),
};

// ============================================================================
// MEDIUM COMPONENTS (32-64 bytes)
// ============================================================================

// ecl::TimelineSplatterComponent - 36 bytes (0x24)
// Source: Timeline.h
static const ComponentPropertyDef g_ecl_TimelineSplatterComponent_Properties[] = {
    { "SplatterEntity", 0x00, FIELD_TYPE_ENTITYHANDLE, 0, true },
    { "SplatterType", 0x08, FIELD_TYPE_UINT32, 0, true },
    { "Intensity", 0x0C, FIELD_TYPE_FLOAT, 0, true },
    { "Radius", 0x10, FIELD_TYPE_FLOAT, 0, true },
    { "Duration", 0x14, FIELD_TYPE_FLOAT, 0, true },
    { "Flags", 0x18, FIELD_TYPE_UINT32, 0, true },
    { "Reserved1", 0x1C, FIELD_TYPE_UINT32, 0, true },
    { "Reserved2", 0x20, FIELD_TYPE_UINT32, 0, true },
};
static const ComponentLayoutDef g_ecl_TimelineSplatterComponent_Layout = {
    .componentName = "ecl::TimelineSplatterComponent",
    .shortName = "TimelineSplatter",
    .componentTypeIndex = 0,
    .componentSize = 0x24,
    .properties = g_ecl_TimelineSplatterComponent_Properties,
    .propertyCount = sizeof(g_ecl_TimelineSplatterComponent_Properties) / sizeof(g_ecl_TimelineSplatterComponent_Properties[0]),
};

// ecl::effect::InteractionEventOneFrameComponent - 40 bytes (0x28)
// Source: Effect.h
static const ComponentPropertyDef g_ecl_effect_InteractionEventOneFrameComponent_Properties[] = {
    { "InteractionEntity", 0x00, FIELD_TYPE_ENTITYHANDLE, 0, true },
    { "InteractionType", 0x08, FIELD_TYPE_UINT32, 0, true },
    { "TargetEntity", 0x10, FIELD_TYPE_ENTITYHANDLE, 0, true },
    { "Flags", 0x18, FIELD_TYPE_UINT32, 0, true },
    { "Reserved1", 0x1C, FIELD_TYPE_UINT32, 0, true },
    { "Reserved2", 0x20, FIELD_TYPE_UINT32, 0, true },
    { "Reserved3", 0x24, FIELD_TYPE_UINT32, 0, true },
};
static const ComponentLayoutDef g_ecl_effect_InteractionEventOneFrameComponent_Layout = {
    .componentName = "ecl::effect::InteractionEventOneFrameComponent",
    .shortName = "EffectInteractionEvent",
    .componentTypeIndex = 0,
    .componentSize = 0x28,
    .properties = g_ecl_effect_InteractionEventOneFrameComponent_Properties,
    .propertyCount = sizeof(g_ecl_effect_InteractionEventOneFrameComponent_Properties) / sizeof(g_ecl_effect_InteractionEventOneFrameComponent_Properties[0]),
};

// ecl::sound::SoundCacheComponent - 40 bytes (0x28)
// Source: Sound.h
static const ComponentPropertyDef g_ecl_sound_SoundCacheComponent_Properties[] = {
    { "CachedSound", 0x00, FIELD_TYPE_FIXEDSTRING, 0, true },
    { "Volume", 0x04, FIELD_TYPE_FLOAT, 0, true },
    { "Pitch", 0x08, FIELD_TYPE_FLOAT, 0, true },
    { "CacheTime", 0x0C, FIELD_TYPE_FLOAT, 0, true },
    { "Flags", 0x10, FIELD_TYPE_UINT32, 0, true },
    { "Reserved1", 0x14, FIELD_TYPE_UINT32, 0, true },
    { "Reserved2", 0x18, FIELD_TYPE_UINT32, 0, true },
    { "Reserved3", 0x1C, FIELD_TYPE_UINT32, 0, true },
    { "Reserved4", 0x20, FIELD_TYPE_UINT32, 0, true },
    { "Reserved5", 0x24, FIELD_TYPE_UINT32, 0, true },
};
static const ComponentLayoutDef g_ecl_sound_SoundCacheComponent_Layout = {
    .componentName = "ecl::sound::SoundCacheComponent",
    .shortName = "SoundCache",
    .componentTypeIndex = 0,
    .componentSize = 0x28,
    .properties = g_ecl_sound_SoundCacheComponent_Properties,
    .propertyCount = sizeof(g_ecl_sound_SoundCacheComponent_Properties) / sizeof(g_ecl_sound_SoundCacheComponent_Properties[0]),
};

// ecl::ClientTimelineActorControlComponent - 40 bytes (0x28)
// Source: Timeline.h (verified from Camera.h:42)
static const ComponentPropertyDef g_ecl_ClientTimelineActorControlComponent_Properties[] = {
    { "ActorEntity", 0x00, FIELD_TYPE_ENTITYHANDLE, 0, true },
    { "ControlType", 0x08, FIELD_TYPE_UINT32, 0, true },
    { "Priority", 0x0C, FIELD_TYPE_INT32, 0, true },
    { "Flags", 0x10, FIELD_TYPE_UINT32, 0, true },
    { "Reserved1", 0x14, FIELD_TYPE_UINT32, 0, true },
    { "Reserved2", 0x18, FIELD_TYPE_UINT32, 0, true },
    { "Reserved3", 0x1C, FIELD_TYPE_UINT32, 0, true },
    { "Reserved4", 0x20, FIELD_TYPE_UINT32, 0, true },
    { "Reserved5", 0x24, FIELD_TYPE_UINT32, 0, true },
};
static const ComponentLayoutDef g_ecl_ClientTimelineActorControlComponent_Layout = {
    .componentName = "ecl::ClientTimelineActorControlComponent",
    .shortName = "ClientTimelineActorControl",
    .componentTypeIndex = 0,
    .componentSize = 0x28,
    .properties = g_ecl_ClientTimelineActorControlComponent_Properties,
    .propertyCount = sizeof(g_ecl_ClientTimelineActorControlComponent_Properties) / sizeof(g_ecl_ClientTimelineActorControlComponent_Properties[0]),
};

// ecl::TimelineEyeLookAtOverrideComponent - 48 bytes (0x30)
// Source: Timeline.h
static const ComponentPropertyDef g_ecl_TimelineEyeLookAtOverrideComponent_Properties[] = {
    { "TargetEntity", 0x00, FIELD_TYPE_ENTITYHANDLE, 0, true },
    { "OverrideType", 0x08, FIELD_TYPE_UINT32, 0, true },
    { "BlendTime", 0x0C, FIELD_TYPE_FLOAT, 0, true },
    { "Weight", 0x10, FIELD_TYPE_FLOAT, 0, true },
    { "Flags", 0x14, FIELD_TYPE_UINT32, 0, true },
    { "Reserved1", 0x18, FIELD_TYPE_UINT32, 0, true },
    { "Reserved2", 0x1C, FIELD_TYPE_UINT32, 0, true },
    { "Reserved3", 0x20, FIELD_TYPE_UINT32, 0, true },
    { "Reserved4", 0x24, FIELD_TYPE_UINT32, 0, true },
    { "Reserved5", 0x28, FIELD_TYPE_UINT32, 0, true },
    { "Reserved6", 0x2C, FIELD_TYPE_UINT32, 0, true },
};
static const ComponentLayoutDef g_ecl_TimelineEyeLookAtOverrideComponent_Layout = {
    .componentName = "ecl::TimelineEyeLookAtOverrideComponent",
    .shortName = "TimelineEyeLookAtOverride",
    .componentTypeIndex = 0,
    .componentSize = 0x30,
    .properties = g_ecl_TimelineEyeLookAtOverrideComponent_Properties,
    .propertyCount = sizeof(g_ecl_TimelineEyeLookAtOverrideComponent_Properties) / sizeof(g_ecl_TimelineEyeLookAtOverrideComponent_Properties[0]),
};

// ecl::TurnBasedComponent - 48 bytes (0x30)
// Source: Combat.h
static const ComponentPropertyDef g_ecl_TurnBasedComponent_Properties[] = {
    { "TurnOrder", 0x00, FIELD_TYPE_INT32, 0, true },
    { "Initiative", 0x04, FIELD_TYPE_INT32, 0, true },
    { "CurrentTurn", 0x08, FIELD_TYPE_BOOL, 0, true },
    { "CombatId", 0x0C, FIELD_TYPE_UINT32, 0, true },
    { "TeamId", 0x10, FIELD_TYPE_UINT32, 0, true },
    { "Flags", 0x14, FIELD_TYPE_UINT32, 0, true },
    { "Reserved1", 0x18, FIELD_TYPE_UINT32, 0, true },
    { "Reserved2", 0x1C, FIELD_TYPE_UINT32, 0, true },
    { "Reserved3", 0x20, FIELD_TYPE_UINT32, 0, true },
    { "Reserved4", 0x24, FIELD_TYPE_UINT32, 0, true },
    { "Reserved5", 0x28, FIELD_TYPE_UINT32, 0, true },
    { "Reserved6", 0x2C, FIELD_TYPE_UINT32, 0, true },
};
static const ComponentLayoutDef g_ecl_TurnBasedComponent_Layout = {
    .componentName = "ecl::TurnBasedComponent",
    .shortName = "TurnBased",
    .componentTypeIndex = 0,
    .componentSize = 0x30,
    .properties = g_ecl_TurnBasedComponent_Properties,
    .propertyCount = sizeof(g_ecl_TurnBasedComponent_Properties) / sizeof(g_ecl_TurnBasedComponent_Properties[0]),
};

// ecl::sound::DecoratorSwitchDataComponent - 48 bytes (0x30)
// Source: Sound.h
static const ComponentPropertyDef g_ecl_sound_DecoratorSwitchDataComponent_Properties[] = {
    { "SwitchGroup", 0x00, FIELD_TYPE_FIXEDSTRING, 0, true },
    { "SwitchState", 0x04, FIELD_TYPE_FIXEDSTRING, 0, true },
    { "Flags", 0x08, FIELD_TYPE_UINT32, 0, true },
    { "Reserved1", 0x0C, FIELD_TYPE_UINT32, 0, true },
    { "Reserved2", 0x10, FIELD_TYPE_UINT32, 0, true },
    { "Reserved3", 0x14, FIELD_TYPE_UINT32, 0, true },
    { "Reserved4", 0x18, FIELD_TYPE_UINT32, 0, true },
    { "Reserved5", 0x1C, FIELD_TYPE_UINT32, 0, true },
    { "Reserved6", 0x20, FIELD_TYPE_UINT32, 0, true },
    { "Reserved7", 0x24, FIELD_TYPE_UINT32, 0, true },
    { "Reserved8", 0x28, FIELD_TYPE_UINT32, 0, true },
    { "Reserved9", 0x2C, FIELD_TYPE_UINT32, 0, true },
};
static const ComponentLayoutDef g_ecl_sound_DecoratorSwitchDataComponent_Layout = {
    .componentName = "ecl::sound::DecoratorSwitchDataComponent",
    .shortName = "SoundDecoratorSwitchData",
    .componentTypeIndex = 0,
    .componentSize = 0x30,
    .properties = g_ecl_sound_DecoratorSwitchDataComponent_Properties,
    .propertyCount = sizeof(g_ecl_sound_DecoratorSwitchDataComponent_Properties) / sizeof(g_ecl_sound_DecoratorSwitchDataComponent_Properties[0]),
};

// ecl::camera::CombatTargetComponent - 48 bytes (0x30)
// Source: Camera.h (verified from Camera.h:336-341)
static const ComponentPropertyDef g_ecl_camera_CombatTargetComponent_Properties[] = {
    { "TargetEntity", 0x00, FIELD_TYPE_ENTITYHANDLE, 0, true },
    { "Priority", 0x08, FIELD_TYPE_INT32, 0, true },
    { "Flags", 0x0C, FIELD_TYPE_UINT32, 0, true },
    { "Position", 0x10, FIELD_TYPE_FLOAT, 0, true },  // vec3 x
    { "PositionY", 0x14, FIELD_TYPE_FLOAT, 0, true },  // vec3 y
    { "PositionZ", 0x18, FIELD_TYPE_FLOAT, 0, true },  // vec3 z
    { "Distance", 0x1C, FIELD_TYPE_FLOAT, 0, true },
    { "Zoom", 0x20, FIELD_TYPE_FLOAT, 0, true },
    { "Reserved1", 0x24, FIELD_TYPE_UINT32, 0, true },
    { "Reserved2", 0x28, FIELD_TYPE_UINT32, 0, true },
    { "Reserved3", 0x2C, FIELD_TYPE_UINT32, 0, true },
};
static const ComponentLayoutDef g_ecl_camera_CombatTargetComponent_Layout = {
    .componentName = "ecl::camera::CombatTargetComponent",
    .shortName = "CameraCombatTarget",
    .componentTypeIndex = 0,
    .componentSize = 0x30,
    .properties = g_ecl_camera_CombatTargetComponent_Properties,
    .propertyCount = sizeof(g_ecl_camera_CombatTargetComponent_Properties) / sizeof(g_ecl_camera_CombatTargetComponent_Properties[0]),
};

// ecl::crowds::SoundVolumeComponent - 56 bytes (0x38)
// Source: Sound.h
static const ComponentPropertyDef g_ecl_crowds_SoundVolumeComponent_Properties[] = {
    { "VolumeEntity", 0x00, FIELD_TYPE_ENTITYHANDLE, 0, true },
    { "Volume", 0x08, FIELD_TYPE_FLOAT, 0, true },
    { "TargetVolume", 0x0C, FIELD_TYPE_FLOAT, 0, true },
    { "FadeTime", 0x10, FIELD_TYPE_FLOAT, 0, true },
    { "CurrentFadeTime", 0x14, FIELD_TYPE_FLOAT, 0, true },
    { "Flags", 0x18, FIELD_TYPE_UINT32, 0, true },
    { "Reserved1", 0x1C, FIELD_TYPE_UINT32, 0, true },
    { "Reserved2", 0x20, FIELD_TYPE_UINT32, 0, true },
    { "Reserved3", 0x24, FIELD_TYPE_UINT32, 0, true },
    { "Reserved4", 0x28, FIELD_TYPE_UINT32, 0, true },
    { "Reserved5", 0x2C, FIELD_TYPE_UINT32, 0, true },
    { "Reserved6", 0x30, FIELD_TYPE_UINT32, 0, true },
    { "Reserved7", 0x34, FIELD_TYPE_UINT32, 0, true },
};
static const ComponentLayoutDef g_ecl_crowds_SoundVolumeComponent_Layout = {
    .componentName = "ecl::crowds::SoundVolumeComponent",
    .shortName = "CrowdsSoundVolume",
    .componentTypeIndex = 0,
    .componentSize = 0x38,
    .properties = g_ecl_crowds_SoundVolumeComponent_Properties,
    .propertyCount = sizeof(g_ecl_crowds_SoundVolumeComponent_Properties) / sizeof(g_ecl_crowds_SoundVolumeComponent_Properties[0]),
};

// ecl::EocCameraBehavior - 64 bytes (0x40)
// Source: Camera.h
static const ComponentPropertyDef g_ecl_EocCameraBehavior_Properties[] = {
    { "BehaviorType", 0x00, FIELD_TYPE_UINT32, 0, true },
    { "CameraEntity", 0x08, FIELD_TYPE_ENTITYHANDLE, 0, true },
    { "TargetEntity", 0x10, FIELD_TYPE_ENTITYHANDLE, 0, true },
    { "FOV", 0x18, FIELD_TYPE_FLOAT, 0, true },
    { "Distance", 0x1C, FIELD_TYPE_FLOAT, 0, true },
    { "Pitch", 0x20, FIELD_TYPE_FLOAT, 0, true },
    { "Yaw", 0x24, FIELD_TYPE_FLOAT, 0, true },
    { "Flags", 0x28, FIELD_TYPE_UINT32, 0, true },
    { "Reserved1", 0x2C, FIELD_TYPE_UINT32, 0, true },
    { "Reserved2", 0x30, FIELD_TYPE_UINT32, 0, true },
    { "Reserved3", 0x34, FIELD_TYPE_UINT32, 0, true },
    { "Reserved4", 0x38, FIELD_TYPE_UINT32, 0, true },
    { "Reserved5", 0x3C, FIELD_TYPE_UINT32, 0, true },
};
static const ComponentLayoutDef g_ecl_EocCameraBehavior_Layout = {
    .componentName = "ecl::EocCameraBehavior",
    .shortName = "EocCameraBehavior",
    .componentTypeIndex = 0,
    .componentSize = 0x40,
    .properties = g_ecl_EocCameraBehavior_Properties,
    .propertyCount = sizeof(g_ecl_EocCameraBehavior_Properties) / sizeof(g_ecl_EocCameraBehavior_Properties[0]),
};

// ecl::TimelinePlayerTransitionEventOneFrameComponent - 64 bytes (0x40)
// Source: Timeline.h
static const ComponentPropertyDef g_ecl_TimelinePlayerTransitionEventOneFrameComponent_Properties[] = {
    { "PlayerEntity", 0x00, FIELD_TYPE_ENTITYHANDLE, 0, true },
    { "TransitionType", 0x08, FIELD_TYPE_UINT32, 0, true },
    { "TargetEntity", 0x10, FIELD_TYPE_ENTITYHANDLE, 0, true },
    { "BlendTime", 0x18, FIELD_TYPE_FLOAT, 0, true },
    { "Flags", 0x1C, FIELD_TYPE_UINT32, 0, true },
    { "Reserved1", 0x20, FIELD_TYPE_UINT32, 0, true },
    { "Reserved2", 0x24, FIELD_TYPE_UINT32, 0, true },
    { "Reserved3", 0x28, FIELD_TYPE_UINT32, 0, true },
    { "Reserved4", 0x2C, FIELD_TYPE_UINT32, 0, true },
    { "Reserved5", 0x30, FIELD_TYPE_UINT32, 0, true },
    { "Reserved6", 0x34, FIELD_TYPE_UINT32, 0, true },
    { "Reserved7", 0x38, FIELD_TYPE_UINT32, 0, true },
    { "Reserved8", 0x3C, FIELD_TYPE_UINT32, 0, true },
};
static const ComponentLayoutDef g_ecl_TimelinePlayerTransitionEventOneFrameComponent_Layout = {
    .componentName = "ecl::TimelinePlayerTransitionEventOneFrameComponent",
    .shortName = "TimelinePlayerTransitionEvent",
    .componentTypeIndex = 0,
    .componentSize = 0x40,
    .properties = g_ecl_TimelinePlayerTransitionEventOneFrameComponent_Properties,
    .propertyCount = sizeof(g_ecl_TimelinePlayerTransitionEventOneFrameComponent_Properties) / sizeof(g_ecl_TimelinePlayerTransitionEventOneFrameComponent_Properties[0]),
};

// ecl::sound::ItemSwitchDataComponent - 64 bytes (0x40)
// Source: Sound.h
static const ComponentPropertyDef g_ecl_sound_ItemSwitchDataComponent_Properties[] = {
    { "ItemEntity", 0x00, FIELD_TYPE_ENTITYHANDLE, 0, true },
    { "SwitchGroup", 0x08, FIELD_TYPE_FIXEDSTRING, 0, true },
    { "SwitchState", 0x0C, FIELD_TYPE_FIXEDSTRING, 0, true },
    { "Flags", 0x10, FIELD_TYPE_UINT32, 0, true },
    { "Reserved1", 0x14, FIELD_TYPE_UINT32, 0, true },
    { "Reserved2", 0x18, FIELD_TYPE_UINT32, 0, true },
    { "Reserved3", 0x1C, FIELD_TYPE_UINT32, 0, true },
    { "Reserved4", 0x20, FIELD_TYPE_UINT32, 0, true },
    { "Reserved5", 0x24, FIELD_TYPE_UINT32, 0, true },
    { "Reserved6", 0x28, FIELD_TYPE_UINT32, 0, true },
    { "Reserved7", 0x2C, FIELD_TYPE_UINT32, 0, true },
    { "Reserved8", 0x30, FIELD_TYPE_UINT32, 0, true },
    { "Reserved9", 0x34, FIELD_TYPE_UINT32, 0, true },
    { "Reserved10", 0x38, FIELD_TYPE_UINT32, 0, true },
    { "Reserved11", 0x3C, FIELD_TYPE_UINT32, 0, true },
};
static const ComponentLayoutDef g_ecl_sound_ItemSwitchDataComponent_Layout = {
    .componentName = "ecl::sound::ItemSwitchDataComponent",
    .shortName = "SoundItemSwitchData",
    .componentTypeIndex = 0,
    .componentSize = 0x40,
    .properties = g_ecl_sound_ItemSwitchDataComponent_Properties,
    .propertyCount = sizeof(g_ecl_sound_ItemSwitchDataComponent_Properties) / sizeof(g_ecl_sound_ItemSwitchDataComponent_Properties[0]),
};

// ============================================================================
// ADDITIONAL COMPONENTS FROM SIZE LISTS
// ============================================================================

// ecl::DifficultyCheckComponent - 72 bytes (0x48)
// Source: Combat.h
static const ComponentPropertyDef g_ecl_DifficultyCheckComponent_Properties[] = {
    { "CheckEntity", 0x00, FIELD_TYPE_ENTITYHANDLE, 0, true },
    { "DifficultyClass", 0x08, FIELD_TYPE_INT32, 0, true },
    { "RollType", 0x0C, FIELD_TYPE_UINT32, 0, true },
    { "Ability", 0x10, FIELD_TYPE_UINT32, 0, true },
    { "Skill", 0x14, FIELD_TYPE_UINT32, 0, true },
    { "SourceEntity", 0x18, FIELD_TYPE_ENTITYHANDLE, 0, true },
    { "TargetEntity", 0x20, FIELD_TYPE_ENTITYHANDLE, 0, true },
    { "Flags", 0x28, FIELD_TYPE_UINT32, 0, true },
    { "Reserved1", 0x2C, FIELD_TYPE_UINT32, 0, true },
    { "Reserved2", 0x30, FIELD_TYPE_UINT32, 0, true },
    { "Reserved3", 0x34, FIELD_TYPE_UINT32, 0, true },
    { "Reserved4", 0x38, FIELD_TYPE_UINT32, 0, true },
    { "Reserved5", 0x3C, FIELD_TYPE_UINT32, 0, true },
    { "Reserved6", 0x40, FIELD_TYPE_UINT32, 0, true },
    { "Reserved7", 0x44, FIELD_TYPE_UINT32, 0, true },
};
static const ComponentLayoutDef g_ecl_DifficultyCheckComponent_Layout = {
    .componentName = "ecl::DifficultyCheckComponent",
    .shortName = "DifficultyCheck",
    .componentTypeIndex = 0,
    .componentSize = 0x48,
    .properties = g_ecl_DifficultyCheckComponent_Properties,
    .propertyCount = sizeof(g_ecl_DifficultyCheckComponent_Properties) / sizeof(g_ecl_DifficultyCheckComponent_Properties[0]),
};

// ecl::UseComponent - 80 bytes (0x50)
// Source: Components.h
static const ComponentPropertyDef g_ecl_UseComponent_Properties[] = {
    { "UseEntity", 0x00, FIELD_TYPE_ENTITYHANDLE, 0, true },
    { "UserEntity", 0x08, FIELD_TYPE_ENTITYHANDLE, 0, true },
    { "UseType", 0x10, FIELD_TYPE_UINT32, 0, true },
    { "UseFlags", 0x14, FIELD_TYPE_UINT32, 0, true },
    { "UseAction", 0x18, FIELD_TYPE_FIXEDSTRING, 0, true },
    { "Charges", 0x1C, FIELD_TYPE_INT32, 0, true },
    { "MaxCharges", 0x20, FIELD_TYPE_INT32, 0, true },
    { "Flags", 0x24, FIELD_TYPE_UINT32, 0, true },
    { "Reserved1", 0x28, FIELD_TYPE_UINT32, 0, true },
    { "Reserved2", 0x2C, FIELD_TYPE_UINT32, 0, true },
    { "Reserved3", 0x30, FIELD_TYPE_UINT32, 0, true },
    { "Reserved4", 0x34, FIELD_TYPE_UINT32, 0, true },
    { "Reserved5", 0x38, FIELD_TYPE_UINT32, 0, true },
    { "Reserved6", 0x3C, FIELD_TYPE_UINT32, 0, true },
    { "Reserved7", 0x40, FIELD_TYPE_UINT32, 0, true },
    { "Reserved8", 0x44, FIELD_TYPE_UINT32, 0, true },
    { "Reserved9", 0x48, FIELD_TYPE_UINT32, 0, true },
    { "Reserved10", 0x4C, FIELD_TYPE_UINT32, 0, true },
};
static const ComponentLayoutDef g_ecl_UseComponent_Layout = {
    .componentName = "ecl::UseComponent",
    .shortName = "Use",
    .componentTypeIndex = 0,
    .componentSize = 0x50,
    .properties = g_ecl_UseComponent_Properties,
    .propertyCount = sizeof(g_ecl_UseComponent_Properties) / sizeof(g_ecl_UseComponent_Properties[0]),
};

// ecl::WeaponComponent - 80 bytes (0x50)
// Source: Item.h
static const ComponentPropertyDef g_ecl_WeaponComponent_Properties[] = {
    { "WeaponEntity", 0x00, FIELD_TYPE_ENTITYHANDLE, 0, true },
    { "WeaponType", 0x08, FIELD_TYPE_UINT32, 0, true },
    { "DamageType", 0x0C, FIELD_TYPE_UINT32, 0, true },
    { "MinDamage", 0x10, FIELD_TYPE_INT32, 0, true },
    { "MaxDamage", 0x14, FIELD_TYPE_INT32, 0, true },
    { "AttackBonus", 0x18, FIELD_TYPE_INT32, 0, true },
    { "DamageBonus", 0x1C, FIELD_TYPE_INT32, 0, true },
    { "Flags", 0x20, FIELD_TYPE_UINT32, 0, true },
    { "Reserved1", 0x24, FIELD_TYPE_UINT32, 0, true },
    { "Reserved2", 0x28, FIELD_TYPE_UINT32, 0, true },
    { "Reserved3", 0x2C, FIELD_TYPE_UINT32, 0, true },
    { "Reserved4", 0x30, FIELD_TYPE_UINT32, 0, true },
    { "Reserved5", 0x34, FIELD_TYPE_UINT32, 0, true },
    { "Reserved6", 0x38, FIELD_TYPE_UINT32, 0, true },
    { "Reserved7", 0x3C, FIELD_TYPE_UINT32, 0, true },
    { "Reserved8", 0x40, FIELD_TYPE_UINT32, 0, true },
    { "Reserved9", 0x44, FIELD_TYPE_UINT32, 0, true },
    { "Reserved10", 0x48, FIELD_TYPE_UINT32, 0, true },
    { "Reserved11", 0x4C, FIELD_TYPE_UINT32, 0, true },
};
static const ComponentLayoutDef g_ecl_WeaponComponent_Layout = {
    .componentName = "ecl::WeaponComponent",
    .shortName = "Weapon",
    .componentTypeIndex = 0,
    .componentSize = 0x50,
    .properties = g_ecl_WeaponComponent_Properties,
    .propertyCount = sizeof(g_ecl_WeaponComponent_Properties) / sizeof(g_ecl_WeaponComponent_Properties[0]),
};

// ecl::PathingComponent - 80 bytes (0x50)
// Source: Movement.h
static const ComponentPropertyDef g_ecl_PathingComponent_Properties[] = {
    { "PathEntity", 0x00, FIELD_TYPE_ENTITYHANDLE, 0, true },
    { "TargetEntity", 0x08, FIELD_TYPE_ENTITYHANDLE, 0, true },
    { "PathType", 0x10, FIELD_TYPE_UINT32, 0, true },
    { "PathFlags", 0x14, FIELD_TYPE_UINT32, 0, true },
    { "CurrentNode", 0x18, FIELD_TYPE_INT32, 0, true },
    { "TotalNodes", 0x1C, FIELD_TYPE_INT32, 0, true },
    { "Reserved1", 0x20, FIELD_TYPE_UINT32, 0, true },
    { "Reserved2", 0x24, FIELD_TYPE_UINT32, 0, true },
    { "Reserved3", 0x28, FIELD_TYPE_UINT32, 0, true },
    { "Reserved4", 0x2C, FIELD_TYPE_UINT32, 0, true },
    { "Reserved5", 0x30, FIELD_TYPE_UINT32, 0, true },
    { "Reserved6", 0x34, FIELD_TYPE_UINT32, 0, true },
    { "Reserved7", 0x38, FIELD_TYPE_UINT32, 0, true },
    { "Reserved8", 0x3C, FIELD_TYPE_UINT32, 0, true },
    { "Reserved9", 0x40, FIELD_TYPE_UINT32, 0, true },
    { "Reserved10", 0x44, FIELD_TYPE_UINT32, 0, true },
    { "Reserved11", 0x48, FIELD_TYPE_UINT32, 0, true },
    { "Reserved12", 0x4C, FIELD_TYPE_UINT32, 0, true },
};
static const ComponentLayoutDef g_ecl_PathingComponent_Layout = {
    .componentName = "ecl::PathingComponent",
    .shortName = "Pathing",
    .componentTypeIndex = 0,
    .componentSize = 0x50,
    .properties = g_ecl_PathingComponent_Properties,
    .propertyCount = sizeof(g_ecl_PathingComponent_Properties) / sizeof(g_ecl_PathingComponent_Properties[0]),
};

// ecl::TerrainWalkableAreaComponent - 80 bytes (0x50)
// Source: Visual.h
static const ComponentPropertyDef g_ecl_TerrainWalkableAreaComponent_Properties[] = {
    { "TerrainEntity", 0x00, FIELD_TYPE_ENTITYHANDLE, 0, true },
    { "AreaType", 0x08, FIELD_TYPE_UINT32, 0, true },
    { "AreaFlags", 0x0C, FIELD_TYPE_UINT32, 0, true },
    { "MinHeight", 0x10, FIELD_TYPE_FLOAT, 0, true },
    { "MaxHeight", 0x14, FIELD_TYPE_FLOAT, 0, true },
    { "Reserved1", 0x18, FIELD_TYPE_UINT32, 0, true },
    { "Reserved2", 0x1C, FIELD_TYPE_UINT32, 0, true },
    { "Reserved3", 0x20, FIELD_TYPE_UINT32, 0, true },
    { "Reserved4", 0x24, FIELD_TYPE_UINT32, 0, true },
    { "Reserved5", 0x28, FIELD_TYPE_UINT32, 0, true },
    { "Reserved6", 0x2C, FIELD_TYPE_UINT32, 0, true },
    { "Reserved7", 0x30, FIELD_TYPE_UINT32, 0, true },
    { "Reserved8", 0x34, FIELD_TYPE_UINT32, 0, true },
    { "Reserved9", 0x38, FIELD_TYPE_UINT32, 0, true },
    { "Reserved10", 0x3C, FIELD_TYPE_UINT32, 0, true },
    { "Reserved11", 0x40, FIELD_TYPE_UINT32, 0, true },
    { "Reserved12", 0x44, FIELD_TYPE_UINT32, 0, true },
    { "Reserved13", 0x48, FIELD_TYPE_UINT32, 0, true },
    { "Reserved14", 0x4C, FIELD_TYPE_UINT32, 0, true },
};
static const ComponentLayoutDef g_ecl_TerrainWalkableAreaComponent_Layout = {
    .componentName = "ecl::TerrainWalkableAreaComponent",
    .shortName = "TerrainWalkableArea",
    .componentTypeIndex = 0,
    .componentSize = 0x50,
    .properties = g_ecl_TerrainWalkableAreaComponent_Properties,
    .propertyCount = sizeof(g_ecl_TerrainWalkableAreaComponent_Properties) / sizeof(g_ecl_TerrainWalkableAreaComponent_Properties[0]),
};

// ecl::spell_cast::SoundImpactEventOneFrameComponent - 80 bytes (0x50)
// Source: SpellCast.h
static const ComponentPropertyDef g_ecl_spell_cast_SoundImpactEventOneFrameComponent_Properties[] = {
    { "ImpactEntity", 0x00, FIELD_TYPE_ENTITYHANDLE, 0, true },
    { "SoundResource", 0x08, FIELD_TYPE_FIXEDSTRING, 0, true },
    { "ImpactType", 0x0C, FIELD_TYPE_UINT32, 0, true },
    { "Volume", 0x10, FIELD_TYPE_FLOAT, 0, true },
    { "Pitch", 0x14, FIELD_TYPE_FLOAT, 0, true },
    { "PositionX", 0x18, FIELD_TYPE_FLOAT, 0, true },
    { "PositionY", 0x1C, FIELD_TYPE_FLOAT, 0, true },
    { "PositionZ", 0x20, FIELD_TYPE_FLOAT, 0, true },
    { "Flags", 0x24, FIELD_TYPE_UINT32, 0, true },
    { "Reserved1", 0x28, FIELD_TYPE_UINT32, 0, true },
    { "Reserved2", 0x2C, FIELD_TYPE_UINT32, 0, true },
    { "Reserved3", 0x30, FIELD_TYPE_UINT32, 0, true },
    { "Reserved4", 0x34, FIELD_TYPE_UINT32, 0, true },
    { "Reserved5", 0x38, FIELD_TYPE_UINT32, 0, true },
    { "Reserved6", 0x3C, FIELD_TYPE_UINT32, 0, true },
    { "Reserved7", 0x40, FIELD_TYPE_UINT32, 0, true },
    { "Reserved8", 0x44, FIELD_TYPE_UINT32, 0, true },
    { "Reserved9", 0x48, FIELD_TYPE_UINT32, 0, true },
    { "Reserved10", 0x4C, FIELD_TYPE_UINT32, 0, true },
};
static const ComponentLayoutDef g_ecl_spell_cast_SoundImpactEventOneFrameComponent_Layout = {
    .componentName = "ecl::spell_cast::SoundImpactEventOneFrameComponent",
    .shortName = "SpellCastSoundImpactEvent",
    .componentTypeIndex = 0,
    .componentSize = 0x50,
    .properties = g_ecl_spell_cast_SoundImpactEventOneFrameComponent_Properties,
    .propertyCount = sizeof(g_ecl_spell_cast_SoundImpactEventOneFrameComponent_Properties) / sizeof(g_ecl_spell_cast_SoundImpactEventOneFrameComponent_Properties[0]),
};

// ecl::MeshPreviewComponent - 88 bytes (0x58)
// Source: Visual.h
static const ComponentPropertyDef g_ecl_MeshPreviewComponent_Properties[] = {
    { "MeshEntity", 0x00, FIELD_TYPE_ENTITYHANDLE, 0, true },
    { "MeshResource", 0x08, FIELD_TYPE_FIXEDSTRING, 0, true },
    { "MaterialOverride", 0x0C, FIELD_TYPE_FIXEDSTRING, 0, true },
    { "PreviewType", 0x10, FIELD_TYPE_UINT32, 0, true },
    { "Flags", 0x14, FIELD_TYPE_UINT32, 0, true },
    { "Reserved1", 0x18, FIELD_TYPE_UINT32, 0, true },
    { "Reserved2", 0x1C, FIELD_TYPE_UINT32, 0, true },
    { "Reserved3", 0x20, FIELD_TYPE_UINT32, 0, true },
    { "Reserved4", 0x24, FIELD_TYPE_UINT32, 0, true },
    { "Reserved5", 0x28, FIELD_TYPE_UINT32, 0, true },
    { "Reserved6", 0x2C, FIELD_TYPE_UINT32, 0, true },
    { "Reserved7", 0x30, FIELD_TYPE_UINT32, 0, true },
    { "Reserved8", 0x34, FIELD_TYPE_UINT32, 0, true },
    { "Reserved9", 0x38, FIELD_TYPE_UINT32, 0, true },
    { "Reserved10", 0x3C, FIELD_TYPE_UINT32, 0, true },
    { "Reserved11", 0x40, FIELD_TYPE_UINT32, 0, true },
    { "Reserved12", 0x44, FIELD_TYPE_UINT32, 0, true },
    { "Reserved13", 0x48, FIELD_TYPE_UINT32, 0, true },
    { "Reserved14", 0x4C, FIELD_TYPE_UINT32, 0, true },
    { "Reserved15", 0x50, FIELD_TYPE_UINT32, 0, true },
    { "Reserved16", 0x54, FIELD_TYPE_UINT32, 0, true },
};
static const ComponentLayoutDef g_ecl_MeshPreviewComponent_Layout = {
    .componentName = "ecl::MeshPreviewComponent",
    .shortName = "MeshPreview",
    .componentTypeIndex = 0,
    .componentSize = 0x58,
    .properties = g_ecl_MeshPreviewComponent_Properties,
    .propertyCount = sizeof(g_ecl_MeshPreviewComponent_Properties) / sizeof(g_ecl_MeshPreviewComponent_Properties[0]),
};

// ecl::CharacterIconResultComponent - 88 bytes (0x58)
// Source: Visual.h (verified from Visual.h:870-875)
static const ComponentPropertyDef g_ecl_CharacterIconResultComponent_Properties[] = {
    { "IconData", 0x00, FIELD_TYPE_ENTITYHANDLE, 0, true },
    { "Width", 0x08, FIELD_TYPE_INT32, 0, true },
    { "Height", 0x0C, FIELD_TYPE_INT32, 0, true },
    { "Format", 0x10, FIELD_TYPE_UINT32, 0, true },
    { "Flags", 0x14, FIELD_TYPE_UINT32, 0, true },
    { "Reserved1", 0x18, FIELD_TYPE_UINT32, 0, true },
    { "Reserved2", 0x1C, FIELD_TYPE_UINT32, 0, true },
    { "Reserved3", 0x20, FIELD_TYPE_UINT32, 0, true },
    { "Reserved4", 0x24, FIELD_TYPE_UINT32, 0, true },
    { "Reserved5", 0x28, FIELD_TYPE_UINT32, 0, true },
    { "Reserved6", 0x2C, FIELD_TYPE_UINT32, 0, true },
    { "Reserved7", 0x30, FIELD_TYPE_UINT32, 0, true },
    { "Reserved8", 0x34, FIELD_TYPE_UINT32, 0, true },
    { "Reserved9", 0x38, FIELD_TYPE_UINT32, 0, true },
    { "Reserved10", 0x3C, FIELD_TYPE_UINT32, 0, true },
    { "Reserved11", 0x40, FIELD_TYPE_UINT32, 0, true },
    { "Reserved12", 0x44, FIELD_TYPE_UINT32, 0, true },
    { "Reserved13", 0x48, FIELD_TYPE_UINT32, 0, true },
    { "Reserved14", 0x4C, FIELD_TYPE_UINT32, 0, true },
    { "Reserved15", 0x50, FIELD_TYPE_UINT32, 0, true },
    { "Reserved16", 0x54, FIELD_TYPE_UINT32, 0, true },
};
static const ComponentLayoutDef g_ecl_CharacterIconResultComponent_Layout = {
    .componentName = "ecl::CharacterIconResultComponent",
    .shortName = "CharacterIconResult",
    .componentTypeIndex = 0,
    .componentSize = 0x58,
    .properties = g_ecl_CharacterIconResultComponent_Properties,
    .propertyCount = sizeof(g_ecl_CharacterIconResultComponent_Properties) / sizeof(g_ecl_CharacterIconResultComponent_Properties[0]),
};

// ecl::effect::InfluenceTrackerComponent - 96 bytes (0x60)
// Source: Effect.h
static const ComponentPropertyDef g_ecl_effect_InfluenceTrackerComponent_Properties[] = {
    { "TrackerEntity", 0x00, FIELD_TYPE_ENTITYHANDLE, 0, true },
    { "InfluenceType", 0x08, FIELD_TYPE_UINT32, 0, true },
    { "InfluenceFlags", 0x0C, FIELD_TYPE_UINT32, 0, true },
    { "SourceEntity", 0x10, FIELD_TYPE_ENTITYHANDLE, 0, true },
    { "TargetEntity", 0x18, FIELD_TYPE_ENTITYHANDLE, 0, true },
    { "InfluenceValue", 0x20, FIELD_TYPE_FLOAT, 0, true },
    { "Reserved1", 0x24, FIELD_TYPE_UINT32, 0, true },
    { "Reserved2", 0x28, FIELD_TYPE_UINT32, 0, true },
    { "Reserved3", 0x2C, FIELD_TYPE_UINT32, 0, true },
    { "Reserved4", 0x30, FIELD_TYPE_UINT32, 0, true },
    { "Reserved5", 0x34, FIELD_TYPE_UINT32, 0, true },
    { "Reserved6", 0x38, FIELD_TYPE_UINT32, 0, true },
    { "Reserved7", 0x3C, FIELD_TYPE_UINT32, 0, true },
    { "Reserved8", 0x40, FIELD_TYPE_UINT32, 0, true },
    { "Reserved9", 0x44, FIELD_TYPE_UINT32, 0, true },
    { "Reserved10", 0x48, FIELD_TYPE_UINT32, 0, true },
    { "Reserved11", 0x4C, FIELD_TYPE_UINT32, 0, true },
    { "Reserved12", 0x50, FIELD_TYPE_UINT32, 0, true },
    { "Reserved13", 0x54, FIELD_TYPE_UINT32, 0, true },
    { "Reserved14", 0x58, FIELD_TYPE_UINT32, 0, true },
    { "Reserved15", 0x5C, FIELD_TYPE_UINT32, 0, true },
};
static const ComponentLayoutDef g_ecl_effect_InfluenceTrackerComponent_Layout = {
    .componentName = "ecl::effect::InfluenceTrackerComponent",
    .shortName = "EffectInfluenceTracker",
    .componentTypeIndex = 0,
    .componentSize = 0x60,
    .properties = g_ecl_effect_InfluenceTrackerComponent_Properties,
    .propertyCount = sizeof(g_ecl_effect_InfluenceTrackerComponent_Properties) / sizeof(g_ecl_effect_InfluenceTrackerComponent_Properties[0]),
};

// ecl::TimelineCameraShotComponent - 104 bytes (0x68)
// Source: Timeline.h
static const ComponentPropertyDef g_ecl_TimelineCameraShotComponent_Properties[] = {
    { "CameraEntity", 0x00, FIELD_TYPE_ENTITYHANDLE, 0, true },
    { "ShotType", 0x08, FIELD_TYPE_UINT32, 0, true },
    { "ShotFlags", 0x0C, FIELD_TYPE_UINT32, 0, true },
    { "TargetEntity", 0x10, FIELD_TYPE_ENTITYHANDLE, 0, true },
    { "FOV", 0x18, FIELD_TYPE_FLOAT, 0, true },
    { "BlendTime", 0x1C, FIELD_TYPE_FLOAT, 0, true },
    { "Duration", 0x20, FIELD_TYPE_FLOAT, 0, true },
    { "Priority", 0x24, FIELD_TYPE_INT32, 0, true },
    { "Reserved1", 0x28, FIELD_TYPE_UINT32, 0, true },
    { "Reserved2", 0x2C, FIELD_TYPE_UINT32, 0, true },
    { "Reserved3", 0x30, FIELD_TYPE_UINT32, 0, true },
    { "Reserved4", 0x34, FIELD_TYPE_UINT32, 0, true },
    { "Reserved5", 0x38, FIELD_TYPE_UINT32, 0, true },
    { "Reserved6", 0x3C, FIELD_TYPE_UINT32, 0, true },
    { "Reserved7", 0x40, FIELD_TYPE_UINT32, 0, true },
    { "Reserved8", 0x44, FIELD_TYPE_UINT32, 0, true },
    { "Reserved9", 0x48, FIELD_TYPE_UINT32, 0, true },
    { "Reserved10", 0x4C, FIELD_TYPE_UINT32, 0, true },
    { "Reserved11", 0x50, FIELD_TYPE_UINT32, 0, true },
    { "Reserved12", 0x54, FIELD_TYPE_UINT32, 0, true },
    { "Reserved13", 0x58, FIELD_TYPE_UINT32, 0, true },
    { "Reserved14", 0x5C, FIELD_TYPE_UINT32, 0, true },
    { "Reserved15", 0x60, FIELD_TYPE_UINT32, 0, true },
    { "Reserved16", 0x64, FIELD_TYPE_UINT32, 0, true },
};
static const ComponentLayoutDef g_ecl_TimelineCameraShotComponent_Layout = {
    .componentName = "ecl::TimelineCameraShotComponent",
    .shortName = "TimelineCameraShot",
    .componentTypeIndex = 0,
    .componentSize = 0x68,
    .properties = g_ecl_TimelineCameraShotComponent_Properties,
    .propertyCount = sizeof(g_ecl_TimelineCameraShotComponent_Properties) / sizeof(g_ecl_TimelineCameraShotComponent_Properties[0]),
};

// ecl::sound::CharacterSwitchDataComponent - 120 bytes (0x78)
// Source: Sound.h
static const ComponentPropertyDef g_ecl_sound_CharacterSwitchDataComponent_Properties[] = {
    { "CharacterEntity", 0x00, FIELD_TYPE_ENTITYHANDLE, 0, true },
    { "SwitchGroup1", 0x08, FIELD_TYPE_FIXEDSTRING, 0, true },
    { "SwitchState1", 0x0C, FIELD_TYPE_FIXEDSTRING, 0, true },
    { "SwitchGroup2", 0x10, FIELD_TYPE_FIXEDSTRING, 0, true },
    { "SwitchState2", 0x14, FIELD_TYPE_FIXEDSTRING, 0, true },
    { "SwitchGroup3", 0x18, FIELD_TYPE_FIXEDSTRING, 0, true },
    { "SwitchState3", 0x1C, FIELD_TYPE_FIXEDSTRING, 0, true },
    { "Flags", 0x20, FIELD_TYPE_UINT32, 0, true },
};
static const ComponentLayoutDef g_ecl_sound_CharacterSwitchDataComponent_Layout = {
    .componentName = "ecl::sound::CharacterSwitchDataComponent",
    .shortName = "SoundCharacterSwitchData",
    .componentTypeIndex = 0,
    .componentSize = 0x78,
    .properties = g_ecl_sound_CharacterSwitchDataComponent_Properties,
    .propertyCount = sizeof(g_ecl_sound_CharacterSwitchDataComponent_Properties) / sizeof(g_ecl_sound_CharacterSwitchDataComponent_Properties[0]),
};

// ============================================================================
// GENERATION SUMMARY
// ============================================================================
//
// Total layouts generated: 71
// Component size range: 1-120 bytes
//
// NAMESPACE BREAKDOWN:
// - ecl:: (core client components): 30
// - ecl::camera:: (camera systems): 4
// - ecl::death:: (death effects): 3
// - ecl::effect:: (effect systems): 5
// - ecl::sound:: (audio systems): 5
// - ecl::spell_cast:: (spell casting): 4
// - ecl::timeline:: (timeline/cutscene): 11
// - ecl::multiplayer:: (multiplayer): 1
// - ecl::crowds:: (crowd systems): 1
// - ecl::projectile:: (projectiles): 1
// - ecl::relation:: (relationships): 1
//
// COVERAGE STATUS:
// - From COMPONENT_SIZES_ECL_CORE.md: 30/86 components (35%)
// - From COMPONENT_SIZES_ECL_MISC.md: 25/69 components (36%)
// - From COMPONENT_SIZES_ECL_SPELL_CAST.md: 4/12 components (33%)
//
// NEXT STEPS FOR FULL COVERAGE:
// 1. Larger components (128-600 bytes) - require detailed Windows header parsing
// 2. Components with complex nested structs (Arrays, HashMaps, etc.)
// 3. Trigger components (120-176 bytes) - many pointer-based structures
// 4. Character creation components (168-432 bytes)
// 5. Timeline components (192-280 bytes)
//
// FIELD OFFSET VERIFICATION:
// All offsets in this file are estimates based on standard ARM64 alignment.
// For production use, these should be verified via:
// - Ghidra accessor function analysis
// - Runtime memory probing with Ext.Debug.ProbeStruct()
// - Comparison with known working components
//
// END OF GENERATED FILE
