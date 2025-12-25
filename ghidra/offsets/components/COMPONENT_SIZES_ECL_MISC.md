# ecl:: Miscellaneous Components - ARM64 Sizes

Extracted via Ghidra MCP decompilation of `AddComponent<T>` functions.

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| ecl::camera::CombatTargetComponent | 0x30 | 48 | Combat target (verified Dec 2025) |
| ecl::camera::CombatTargetRequestsComponent | 0x10 | 16 | Combat target requests (verified Dec 2025) |
| ecl::character::CharacterUpdateConfigComponent | 0xc | 12 |  |
| ecl::character_creation::ChangesPreviewComponent | 8 (ptr) |  |  |
| ecl::character_creation::CommandQueueComponent | 32 |  |  |
| ecl::character_creation::DefinitionStateComponent | 0xc8 | 200 | Definition state |
| ecl::character_creation::DefinitionStateExComponent | 40 | 0x28 | GetComponent<ecl::character_creation::DefinitionStateExComponent,false> |
| ecl::character_creation::DummyComponent | 24 |  |  |
| ecl::character_creation::DummyDefinitionComponent | `0x1b0` | 432 | Has destructor (PTR___invoke_1083fe2d0), Largest ecl:: component |
| ecl::character_creation::FullRespecDefinitionComponent | 168 |  |  |
| ecl::character_creation::SessionStateComponent | 40 |  |  |
| ecl::character_creation::TargetVisualComponent | 240 |  |  |
| ecl::container::OngoingExplorationComponent | 16 |  |  |
| ecl::crowds::SoundVolumeComponent | 0x38 | 56 | Sound volume |
| ecl::death::DeathImpactComponent | 0x18 | 24 | Death impact |
| ecl::death::SetVisualImmediateRequestOneFrameComponent | 0x01 | 1 | OneFrame tag |
| ecl::death::StateComponent | `0x10` | 16 | Has destructor (PTR___invoke_1083fe568) |
| ecl::dialog::BlockAfterGroupPrepareComponent | 0x01 | 1 | Tag - block after group |
| ecl::dialog::DialogTimelineUpdateStateComponent | 0x04 | 4 | Timeline update state |
| ecl::dialog::IsInDialogComponent | 0x01 | 1 | Tag - in dialog |
| ecl::dummy::DummiesCreatedSingletonComponent | 64 | 0x40 | TryGetSingleton<...DummiesCreatedSingletonComponent...> |
| ecl::dummy::DummyComponent | 8 |  |  |
| ecl::dummy::EquipmentVisualsStateComponent | Not found | No GetComponent/AddComponent function |  |
| ecl::dummy::FootIKStateComponent | Not found | No GetComponent function |  |
| ecl::dummy::HasDummyComponent | 8 | GetComponent | `>> 0xd & 0x7fff8` pattern = 8 bytes |
| ecl::dummy::OriginalTransformComponent | 48 (0x30) | Struct analysis | Transform = 48 bytes (3x vec3 + padding) |
| ecl::dummy::TransformRequestsSingletonComponent | ecl::dummy | Singleton component |  |
| ecl::dummy::UnsheathComponent | ecl::dummy | Character equipment state |  |
| ecl::dummy::VFXEntitiesComponent | ecl::dummy | Has destructor showing internal structure 0x48+ |  |
| ecl::effect::DistributorTrackerComponent | 0x88 | 136 | Distributor tracker |
| ecl::effect::HandlerComponent | 0x08 | 8 | Effect handler ptr |
| ecl::effect::InfluenceTrackerComponent | 0x60 | 96 | Influence tracker |
| ecl::effect::InteractionEventOneFrameComponent | 0x28 | 40 | Interaction event |
| ecl::effect::SharedTimerComponent | 0x18 | 24 | Shared timer |
| ecl::effect::SpawnedComponent | 0x18 | 24 | Spawned effect |
| ecl::equipment::VisualsDesiredStateComponent | ecl::equipment | Equipment visuals |  |
| ecl::equipment::VisualsVisibilityStateComponent | ecl::equipment | Equipment visibility |  |
| ecl::ftb::BlockedFTBToggleRequestOneFrameComponent | 0x04 | 4 | FTB toggle request |
| ecl::hit::HitVFXComponent | 0x240 | 576 | Hit VFX (large - malloc alloc) |
| ecl::interrupt::PlayerDecisionComponent | 64 (0x40) | Struct analysis | HashMap<EntityHandle, uint8_t> = 64 bytes |
| ecl::inventory::ExamineInventoryComponent | 0x01 | 1 | Tag - examine inventory |
| ecl::item::animation::StateComponent | 6 |  |  |
| ecl::multiplayer::UsersComponent | 0x18 | 24 | Users component |
| ecl::photo_mode::InvisibilityRequestSingletonComponent | Not found | Singleton - may not have standard allocation |  |
| ecl::player_management::UserComponent | 2 |  |  |
| ecl::projectile::AttachmentComponent | 0x08 | 8 | Projectile attachment ref |
| ecl::projectile::SpellComponent | unknown | No AddComponent/GetComponent found |  |
| ecl::relation::RelationChangedEventOneFrameComponent | 0x08 | 8 | Relation changed event |
| ecl::sound::AutoFoleyDataComponent | 8 (ptr) |  |  |
| ecl::sound::CharacterSwitchDataComponent | 0x78 | 120 | Character switch data |
| ecl::sound::DecoratorSwitchDataComponent | 0x30 | 48 | Decorator switch data |
| ecl::sound::DistantSoundStateTrackerComponent | 8 |  |  |
| ecl::sound::ItemSwitchDataComponent | 0x40 | 64 | Item switch data |
| ecl::sound::SoundCacheComponent | 0x28 | 40 | Sound cache |
| ecl::spell_preview::EffectsComponent | 8 (ptr) |  |  |
| ecl::spell_preview::ProjectilePathComponent | 24 |  |  |
| ecl::spell_preview::SurfaceTilesComponent | 16 |  |  |
| ecl::spell_preview::TargetingComponent | 56 |  |  |
| ecl::splitscreen::FullscreenTurnActiveComponent | 4 |  |  |
| ecl::tag::SpellCheckedTagComponent | 0x01 | 1 | Tag - spell checked |
| ecl::thrown::DummyAttachmentComponent | 8 (ptr) |  |  |
| ecl::timeline::ArenaTriggerHasPlayersComponent | 4 |  |  |
| ecl::timeline::CameraShotComponent | 0x68 | 104 | Camera shot |
| ecl::timeline::PlayerTransitionEventOneFrameComponent | 0x40 | 64 | Player transition event |
| ecl::timeline::QuestionHoldAutomationComponent | 0x1c | 28 | Question hold automation |
| ecl::timeline::TurnActionsDoneOneFrameComponent | 0x01 | 1 | Turn actions done tag |
| ecl::timeline::VisualFXViewComponent | 0x88 | 136 | Visual FX view |
| ecl::trigger::SightHelperComponent | 1 |  |  |
| ecl::unsheath::VisualStateComponent | 8 |  |  |

**Total: 69 components**
