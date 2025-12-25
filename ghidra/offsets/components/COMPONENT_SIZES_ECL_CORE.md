# ecl::core:: Components - ARM64 Sizes

Extracted via Ghidra MCP decompilation of `AddComponent<T>` functions.

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| ecl::ActiveTurnComponent | 0xc | 12 |  |
| ecl::AiSeederTrigger | 0x78 | 120 | AI seeder trigger |
| ecl::AtmosphereTrigger | 0x90 | 144 | Atmosphere trigger |
| ecl::CameraBlockerTrigger | 0x78 | 120 | Camera blocker |
| ecl::CameraLockTrigger | 0x80 | 128 | Camera lock |
| ecl::Character | 0x158 | 344 | Character (inline) |
| ecl::Character (no template) | 0x158 | 344 | No template param variant |
| ecl::CharacterIconRequestComponent | 432 | 0x1b0 | GetComponent<ecl::CharacterIconRequestComponent,false> |
| ecl::CharacterIconResultComponent | 0x58 | 88 | Character icon result |
| ecl::CharacterLightComponent | 0x18 | 24 | Character lighting |
| ecl::CinematicArenaTrigger | 0xb0 | 176 | Cinematic arena |
| ecl::ClientTimelineActorControlComponent | 0x28 | 40 | Timeline control |
| ecl::ClientTimelineControlComponent | 0x88 | 136 | Client timeline control |
| ecl::CombatTimelineDataComponent | 352 | `* 0x160` at 0x103741d18 |  |
| ecl::CullTrigger | 0x78 | 120 | Cull trigger |
| ecl::DeathDetachEffectRequestOneFrameComponent | 0x01 | 1 | OneFrame tag |
| ecl::DeathEffectComponent | `0x8` | 8 | Has destructor (PTR___invoke_1083fe360) |
| ecl::DetachedComponent | 0x04 | 4 | Detached state |
| ecl::DifficultyCheckComponent | 0x48 | 72 | Difficulty check |
| ecl::DisabledEquipmentComponent | 0x01 | 1 | Tag - disabled equip |
| ecl::DisarmableComponent | 0x18 | 24 | Disarmable state |
| ecl::DisplayNameComponent | 0x20 | 32 | Display name |
| ecl::EocCameraBehavior | 0x40 | 64 | EOC camera behavior |
| ecl::EquipmentVisualsComponent | 0x48 | 72 | Equipment visuals |
| ecl::FadeTrigger | 0x80 | 128 | Fade trigger |
| ecl::FloorTrigger | 0x80 | 128 | Floor trigger |
| ecl::GameCameraBehavior | 0x258 | 600 | Game camera (largest ecl!) |
| ecl::GroundMaterialComponent | 0x2 | 2 |  |
| ecl::IgnoredComponent | 0x01 | 1 | Tag - ignored |
| ecl::InSelectComponent | 0x01 | 1 | Tag - in selection |
| ecl::InvisibilityAttachmentComponent | 0x01 | 1 | Tag |
| ecl::InvisibilityFadingComponent | 0xc | 12 |  |
| ecl::InvisibilityVisualComponent | 0xc | 12 |  |
| ecl::IsHoveredOverComponent | 0x01 | 1 | Tag - hovered |
| ecl::Item | 0x70 | 112 | Item (inline) |
| ecl::Item (no template) | 0x8 | 8 | Pointer storage |
| ecl::LightingTrigger | 0x90 | 144 | Lighting trigger |
| ecl::MeshPreviewComponent | 0x58 | 88 | Mesh preview |
| ecl::MovementComponent | 0x18 | 24 | Movement state |
| ecl::NavigationCloudTrigger | 0x78 | 120 | Navigation cloud |
| ecl::ObjectInteractionComponent | 0x10 | 16 | Object interaction |
| ecl::PaperdollComponent | 0x10 | 16 | Paperdoll UI |
| ecl::PathingComponent | 0x50 | 80 | Pathing (largest core) |
| ecl::PickingStateComponent | 0x01 | 1 | Tag - picking state |
| ecl::PlayerComponent | 0x01 | 1 | Tag - player |
| ecl::PointSoundTrigger | 0xa8 | 168 | Point sound trigger |
| ecl::PointSoundTriggerDummy | 0x8 | 8 | Pointer storage |
| ecl::PointTrigger | 0x8 | 8 | Pointer storage |
| ecl::PortalTrigger | 0x8 | 8 | Pointer storage |
| ecl::Projectile | 0x240 | 576 | Projectile (largest!) |
| ecl::RegionTrigger | 0x8 | 8 | Pointer storage |
| ecl::RoomTrigger | 0x8 | 8 | Pointer storage |
| ecl::SceneCameraBehavior | 0x108 | 264 | Scene camera behavior |
| ecl::Scenery | 0x40 | 64 | Scenery (inline) |
| ecl::SelectedComponent | 0x01 | 1 | Tag - selected |
| ecl::ServerControlledEffectDestroyRequestOneFrameComponent | 0x01 | 1 | OneFrame tag |
| ecl::ServerControlledEffectForgetRequestOneFrameComponent | `0x1` | 1 | No destructor (NULL), OneFrame component |
| ecl::SoundAttachmentComponent | `0x10` | 16 | Has destructor (PTR___invoke_1083fe3a0) |
| ecl::SoundVolumeTrigger | 0x8 | 8 | Pointer storage |
| ecl::SpectatorCameraBehavior | 0x88 | 136 | Spectator camera |
| ecl::SpectatorTrigger | 0x8 | 8 | Pointer storage |
| ecl::SurfaceLightComponent | 64 (0x40) | GetComponent<ecl::SurfaceLightComponent,false> @ 0x1031f6550 |  |
| ecl::SyncedTimelineControlComponent | 0xf8 | 248 | Synced timeline control (large!) |
| ecl::TLPreviewDummy | 0xC0 | 192 | Timeline preview dummy (malloc alloc) |
| ecl::TerrainWalkableAreaComponent | 0x50 | 80 | Terrain walkable area |
| ecl::TimelineAnimationStateComponent | 0x08 | 8 | Animation state |
| ecl::TimelineAutomatedLookatComponent | 0x20 | 32 | Automated lookat |
| ecl::TimelineCameraRequestComponent | 0x20 | 32 | Camera request |
| ecl::TimelineCameraShotComponent | 0x68 | 104 | Timeline camera shot data |
| ecl::TimelineEmotionMaterialComponent | 0x90 | 144 | Emotion material (large!) |
| ecl::TimelineEyeLookAtOverrideComponent | 0x30 | 48 | Eye lookat override |
| ecl::TimelineMaterialComponent | 0x80 | 128 | Material component |
| ecl::TimelinePlayerTransitionEventOneFrameComponent | 0x40 | 64 | One-frame event data |
| ecl::TimelineQuestionHoldAutomationComponent | 0x1c | 28 | Question hold automation |
| ecl::TimelineSceneTrigger | 0x8 | 8 | Pointer storage |
| ecl::TimelineShapeShiftComponent | 0x04 | 4 | Shapeshift |
| ecl::TimelineSplatterComponent | 0x24 | 36 | Splatter effect |
| ecl::TimelineSpringsComponent | 0x08 | 8 | Springs data |
| ecl::TimelineSteppingFadeComponent | 0x08 | 8 | Stepping fade |
| ecl::TimelineTransformComponent | 0x118 | 280 | Transform (largest timeline!) |
| ecl::TurnActionsDoneOneFrameComponent | 0x1 | 1 | One-frame flag |
| ecl::TurnBasedComponent | 0x30 | 48 | Turn-based state |
| ecl::UseComponent | 0x50 | 80 | Use interaction data |
| ecl::VoiceComponent | 0x18 | 24 | Voice data |
| ecl::WalkableSurfaceComponent | 0x10 | 16 | Walkable surface |
| ecl::WeaponComponent | 0x50 | 80 | Weapon state |

**Total: 86 components**
