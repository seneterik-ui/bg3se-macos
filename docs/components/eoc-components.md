# eoc:: Components (Engine of Combat)

701 total components in the `eoc::` namespace. **276 have property layouts** parsed from Windows BG3SE headers.

## Components with Property Layouts

These components have property definitions available via `tools/parse_component_headers.py`:

| Component | Full Name | Properties |
|-----------|-----------|------------|
| Armor | eoc::ArmorComponent | 5 |
| AttributeFlags | eoc::AttributeFlagsComponent | 1 |
| Background | eoc::BackgroundComponent | 1 |
| BackgroundPassives | eoc::BackgroundPassivesComponent | 1 |
| BackgroundTag | eoc::BackgroundTagComponent | 1 |
| BaseHp | eoc::BaseHpComponent | 2 |
| BaseStats | eoc::BaseStatsComponent | 1 |
| BodyType | eoc::BodyTypeComponent | 2 |
| BoostCondition | eoc::BoostConditionComponent | 2 |
| BoostInfo | eoc::BoostInfoComponent | 7 |
| BoostsContainer | eoc::BoostsContainerComponent | 1 |
| CanBeDisarmed | eoc::CanBeDisarmedComponent | 1 |
| CanBeLooted | eoc::CanBeLootedComponent | 1 |
| CanDeflectProjectiles | eoc::CanDeflectProjectilesComponent | 1 |
| CanDoActions | eoc::CanDoActionsComponent | 1 |
| CanDoRest | eoc::CanDoRestComponent | 3 |
| CanInteract | eoc::CanInteractComponent | 2 |
| CanModifyHealth | eoc::CanModifyHealthComponent | 1 |
| CanMove | eoc::CanMoveComponent | 3 |
| CanSense | eoc::CanSenseComponent | 1 |
| CanSpeak | eoc::CanSpeakComponent | 1 |
| CanTravel | eoc::CanTravelComponent | 3 |
| CharacterCreationAppearance | eoc::character_creation::AppearanceComponent | 7 |
| CharacterCreationStats | eoc::CharacterCreationStatsComponent | 7 |
| Classes | eoc::ClassesComponent | 1 |
| ClassTag | eoc::ClassTagComponent | 1 |
| CombatParticipant | eoc::combat::ParticipantComponent | 5 |
| CombatState | eoc::combat::StateComponent | 11 |
| Concentration | eoc::concentration::ConcentrationComponent | 3 |
| CustomIcon | eoc::CustomIconComponent | 2 |
| CustomName | eoc::CustomNameComponent | 1 |
| CustomStats | eoc::CustomStatsComponent | 1 |
| DamageReductionBoost | eoc::DamageReductionBoostComponent | 4 |
| Darkness | eoc::DarknessComponent | 7 |
| Data | eoc::DataComponent | 3 |
| DeadByDefault | eoc::death::DeadByDefaultComponent | 1 |
| DeathState | eoc::death::StateComponent | 1 |
| DeathType | eoc::death::DeathTypeComponent | 1 |
| Detached | eoc::DetachedComponent | 1 |
| DialogState | eoc::dialog::StateComponent | 5 |
| DifficultyCheck | eoc::DifficultyCheckComponent | 6 |
| DisabledEquipment | eoc::DisabledEquipmentComponent | 1 |
| Disarmable | eoc::DisarmableComponent | 3 |
| DisplayName | eoc::DisplayNameComponent | 2 |
| Downed | eoc::death::DownedComponent | 2 |
| DualWielding | eoc::DualWieldingComponent | 7 |
| EncumbranceState | eoc::encumbrance::StateComponent | 1 |
| EncumbranceStats | eoc::encumbrance::StatsComponent | 3 |
| Equipable | eoc::EquipableComponent | 2 |
| EquipmentVisual | eoc::character::EquipmentVisualComponent | 1 |
| Experience | eoc::exp::ExperienceComponent | 4 |
| AvailableLevel | eoc::exp::AvailableLevelComponent | 1 |
| Expertise | eoc::expertise::ExpertiseComponent | 1 |
| Faction | eoc::relation::FactionComponent | 4 |
| FleeCapability | eoc::FleeCapabilityComponent | 3 |
| Floating | eoc::FloatingComponent | 2 |
| FTBParticipant | eoc::ftb::ParticipantComponent | 1 |
| GameObjectVisual | eoc::GameObjectVisualComponent | 5 |
| GameplayLight | eoc::GameplayLightComponent | 15 |
| God | eoc::god::GodComponent | 2 |
| GodTag | eoc::god::TagComponent | 1 |
| GravityDisabledUntilMoved | eoc::GravityDisabledUntilMovedComponent | 1 |
| Health | eoc::HealthComponent | 6 |
| Hearing | eoc::HearingComponent | 1 |
| HitAttacker | eoc::hit::AttackerComponent | 1 |
| HitLifetime | eoc::hit::LifetimeComponent | 2 |
| HitMeta | eoc::hit::MetaComponent | 1 |
| HitProxy | eoc::hit::ProxyComponent | 2 |
| HitProxyOwner | eoc::hit::ProxyOwnerComponent | 1 |
| HitReaction | eoc::hit::ReactionComponent | 1 |
| HitTarget | eoc::hit::TargetComponent | 3 |
| HitThrownObject | eoc::hit::ThrownObjectComponent | 1 |
| HitWeapon | eoc::hit::WeaponComponent | 1 |
| HotbarContainer | eoc::hotbar::ContainerComponent | 1 |
| HotbarDecks | eoc::hotbar::CurrentDecksComponent | 1 |
| Icon | eoc::IconComponent | 1 |
| Identity | eoc::identity::IdentityComponent | 1 |
| IdentityState | eoc::identity::StateComponent | 1 |
| IncreaseMaxHPBoost | eoc::IncreaseMaxHPBoostComponent | 2 |
| InteractionFilter | eoc::InteractionFilterComponent | 3 |
| InterruptActionState | eoc::interrupt::ActionStateComponent | 3 |
| InterruptContainer | eoc::interrupt::ContainerComponent | 1 |
| InterruptData | eoc::interrupt::DataComponent | 5 |
| InterruptDecision | eoc::interrupt::DecisionComponent | 1 |
| InterruptPreferences | eoc::interrupt::PreferencesComponent | 1 |
| InterruptPrepared | eoc::interrupt::PreparedComponent | 1 |
| InterruptZone | eoc::interrupt::ZoneComponent | 1 |
| InterruptZoneParticipant | eoc::interrupt::ZoneParticipantComponent | 1 |
| InterruptZoneSource | eoc::interrupt::ZoneSourceComponent | 1 |
| InventoryContainer | eoc::inventory::ContainerComponent | 1 |
| InventoryData | eoc::inventory::DataComponent | 2 |
| InventoryIsOwned | eoc::inventory::IsOwnedComponent | 1 |
| InventoryMember | eoc::inventory::MemberComponent | 2 |
| InventoryMemberTransform | eoc::inventory::MemberTransformComponent | 1 |
| InventoryOwner | eoc::inventory::OwnerComponent | 2 |
| InventoryStack | eoc::inventory::StackComponent | 2 |
| InventoryStackMember | eoc::inventory::StackMemberComponent | 1 |
| InventoryTopOwner | eoc::inventory::TopOwnerComponent | 1 |
| InventoryWeight | eoc::inventory::WeightComponent | 1 |
| Invisibility | eoc::InvisibilityComponent | 3 |
| IsSummon | eoc::summon::IsSummonComponent | 5 |
| ItemBoosts | eoc::ItemBoostsComponent | 1 |
| ItemDestroyed | eoc::item::DestroyedComponent | 1 |
| ItemDye | eoc::item::DyeComponent | 1 |
| ItemPortal | eoc::item::PortalComponent | 2 |
| Key | eoc::lock::KeyComponent | 1 |
| EocLevel | eoc::LevelComponent | 1 |
| LevelUp | eoc::progression::LevelUpComponent | 1 |
| Lock | eoc::lock::LockComponent | 4 |
| Loot | eoc::LootComponent | 2 |
| LootingState | eoc::LootingStateComponent | 3 |
| MaterialParameterOverride | eoc::MaterialParameterOverrideComponent | 2 |
| Movement | eoc::MovementComponent | 4 |
| ObjectInteraction | eoc::ObjectInteractionComponent | 1 |
| ObjectSize | eoc::ObjectSizeComponent | 2 |
| Origin | eoc::OriginComponent | 2 |
| OriginAppearanceTag | eoc::OriginAppearanceTagComponent | 1 |
| OriginPassives | eoc::OriginPassivesComponent | 1 |
| OriginTag | eoc::OriginTagComponent | 1 |
| OwneeCurrent | eoc::ownership::OwneeCurrentComponent | 1 |
| PartyComposition | eoc::party::CompositionComponent | 3 |
| PartyFollower | eoc::party::FollowerComponent | 1 |
| PartyMember | eoc::party::MemberComponent | 5 |
| PartyPortals | eoc::party::PortalsComponent | 1 |
| PartyRecipes | eoc::party::RecipesComponent | 1 |
| PartyView | eoc::party::ViewComponent | 3 |
| PartyWaypoints | eoc::party::WaypointsComponent | 1 |
| Passive | eoc::PassiveComponent | 7 |
| PassiveContainer | eoc::PassiveContainerComponent | 1 |
| PassiveUsageCount | eoc::passive::UsageCountComponent | 1 |
| Pathing | eoc::PathingComponent | 11 |
| PhotoModeCameraTransform | eoc::photo_mode::CameraTransformComponent | 1 |
| PhotoModeDummy | eoc::photo_mode::DummyComponent | 2 |
| PhotoModeDummyAnimationState | eoc::photo_mode::DummyAnimationStateComponent | 8 |
| PhotoModeDummyEquipmentVisual | eoc::photo_mode::DummyEquipmentVisualComponent | 1 |
| PhotoModeDummyShowSplatter | eoc::photo_mode::DummyShowSplatterComponent | 1 |
| PhotoModeDummyTransform | eoc::photo_mode::DummyTransformComponent | 1 |
| PhotoModeSession | eoc::photo_mode::SessionComponent | 1 |
| PickUpRequest | eoc::pickup::PickUpRequestComponent | 2 |
| Proficiency | eoc::stats::proficiency::ProficiencyComponent | 1 |
| ProficiencyGroup | eoc::stats::proficiency::ProficiencyGroupComponent | 1 |
| ProgressionAbilityImprovements | eoc::progression::AbilityImprovementsComponent | 2 |
| ProgressionFeat | eoc::progression::FeatComponent | 8 |
| ProgressionMeta | eoc::progression::MetaComponent | 8 |
| ProgressionPassives | eoc::progression::PassivesComponent | 2 |
| ProgressionReplicatedFeat | eoc::progression::ReplicatedFeatComponent | 3 |
| ProgressionSkills | eoc::progression::SkillsComponent | 2 |
| ProgressionSpells | eoc::progression::SpellsComponent | 2 |
| ProjectileSource | eoc::projectile::SourceInfoComponent | 2 |
| Race | eoc::RaceComponent | 1 |
| Recruiter | eoc::recruit::RecruiterComponent | 1 |
| Relation | eoc::relation::RelationComponent | 7 |
| Repose | eoc::repose::StateComponent | 5 |
| RequestedRoll | eoc::RequestedRollComponent | 38 |
| Resistances | eoc::ResistancesComponent | 5 |
| LongRestState | eoc::rest::LongRestState | 7 |
| LongRestTimeline | eoc::rest::LongRestTimeline | 1 |
| LongRestTimers | eoc::rest::LongRestTimers | 1 |
| LongRestUsers | eoc::rest::LongRestUsers | 3 |
| RestingEntities | eoc::rest::RestingEntities | 5 |
| RollModifiers | eoc::active_roll::ModifiersComponent | 11 |
| Ruleset | eoc::ruleset::RulesetComponent | 2 |
| ShapeshiftAnimation | eoc::shapeshift::AnimationComponent | 2 |
| ShapeshiftRecoveryAnimation | eoc::shapeshift::RecoveryAnimationComponent | 1 |
| ShapeshiftReplicatedChanges | eoc::shapeshift::ReplicatedChangesComponent | 12 |
| ShapeshiftSourceCache | eoc::shapeshift::SourceCacheComponent | 1 |
| ShapeshiftState | eoc::shapeshift::StateComponent | 3 |
| Sight | eoc::sight::BaseComponent | 4 |
| SightData | eoc::sight::DataComponent | 7 |
| SightEntityViewshed | eoc::sight::EntityViewshedComponent | 1 |
| IgnoreSurfaces | eoc::sight::IgnoreSurfacesComponent | 1 |
| SpatialGrid | eoc::spatial_grid::DataComponent | 3 |
| Speaker | eoc::SpeakerComponent | 1 |
| SpellAiConditions | eoc::spell::AiConditionsComponent | 1 |
| AttackSpellOverride | eoc::spell::AttackSpellOverrideComponent | 1 |
| SpellBook | eoc::spell::BookComponent | 2 |
| SpellBookCooldowns | eoc::spell::BookCooldownsComponent | 1 |
| SpellBookPrepares | eoc::spell::BookPreparesComponent | 3 |
| CCPrepareSpell | eoc::spell::CCPrepareSpellComponent | 1 |
| SpellContainer | eoc::spell::ContainerComponent | 1 |
| LearnedSpells | eoc::spell::LearnedSpellsComponent | 1 |
| PlayerPrepareSpell | eoc::spell::PlayerPrepareSpellComponent | 2 |
| ScriptedExplosion | eoc::spell::ScriptedExplosionComponent | 1 |
| AddedSpells | eoc::spell::AddedSpellsComponent | 1 |
| SpellCastAnimationInfo | eoc::spell_cast::AnimationInfoComponent | 11 |
| SpellCastCache | eoc::spell_cast::CacheComponent | 2 |
| SpellCastDataCache | eoc::spell_cast::DataCacheSingletonComponent | 1 |
| SpellCastExecutionTime | eoc::spell_cast::ExecutionTimeComponent | 1 |
| SpellCastInterruptResults | eoc::spell_cast::InterruptResultsComponent | 2 |
| SpellCastIsCasting | eoc::spell_cast::IsCastingComponent | 1 |
| SpellCastMovement | eoc::spell_cast::MovementComponent | 3 |
| SpellCastOutcome | eoc::spell_cast::OutcomeComponent | 1 |
| SpellCastRolls | eoc::spell_cast::RollsComponent | 1 |
| SpellCastState | eoc::spell_cast::StateComponent | 12 |
| SpellSyncTargeting | eoc::spell_cast::SyncTargetingComponent | 9 |
| Stats | eoc::StatsComponent | 12 |
| StatusCause | eoc::status::CauseComponent | 1 |
| StatusContainer | eoc::status::ContainerComponent | 1 |
| StatusID | eoc::status::IDComponent | 1 |
| StatusIncapacitated | eoc::status::IncapacitatedComponent | 2 |
| StatusLifetime | eoc::status::LifetimeComponent | 2 |
| StatusLoseControl | eoc::status::LoseControlComponent | 1 |
| StatusVisualDisabled | eoc::status::visual::DisabledComponent | 1 |
| Stealth | eoc::StealthComponent | 7 |
| Steering | eoc::SteeringComponent | 6 |
| SummonContainer | eoc::summon::ContainerComponent | 2 |
| SummonLifetime | eoc::summon::LifetimeComponent | 1 |
| SurfacePathInfluences | eoc::SurfacePathInfluencesComponent | 1 |
| TadpolePowers | eoc::tadpole_tree::PowerContainerComponent | 1 |
| TadpoleTreeState | eoc::tadpole_tree::TreeStateComponent | 1 |
| Tag | eoc::TagComponent | 1 |
| OriginalTemplate | eoc::templates::OriginalTemplateComponent | 2 |
| ShootThroughType | eoc::through::ShootThroughTypeComponent | 1 |
| ThreatRange | eoc::combat::ThreatRangeComponent | 3 |
| TimelineActorData | eoc::TimelineActorDataComponent | 5 |
| TradeBuybackData | eoc::inventory::TradeBuybackDataComponent | 3 |
| TriggerType | eoc::trigger::TypeComponent | 1 |
| TurnBased | eoc::TurnBasedComponent | 11 |
| TurnOrder | eoc::TurnOrderComponent | 8 |
| Unsheath | eoc::unsheath::StateComponent | 7 |
| Use | eoc::UseComponent | 10 |
| UseAction | eoc::item_template::UseActionComponent | 1 |
| ActionType | eoc::item_template::ActionTypeComponent | 1 |
| UseBoosts | eoc::UseBoostsComponent | 1 |
| UseSocket | eoc::use::SocketComponent | 1 |
| UserAvatar | eoc::user::AvatarComponent | 3 |
| UserReservedFor | eoc::user::ReservedForComponent | 1 |
| Value | eoc::ValueComponent | 3 |
| Voice | eoc::VoiceComponent | 1 |
| VoiceTag | eoc::VoiceTagComponent | 1 |
| Weapon | eoc::WeaponComponent | 8 |
| WeaponSet | eoc::WeaponSetComponent | 1 |
| Wielded | eoc::inventory::WieldedComponent | 1 |
| Wielding | eoc::WieldingComponent | 1 |
| WieldingHistory | eoc::inventory::WieldingHistoryComponent | 1 |

## Verified ARM64 Layouts

These components have property layouts verified on ARM64 macOS via Ghidra decompilation and runtime testing (Dec 2025):

| Component | Size (ARM64) | Bytes | Key Properties | Runtime ✓ |
|-----------|--------------|-------|----------------|-----------|
| **Core Character** | | | | |
| Health | 0x28 | 40 | Hp, MaxHp, TemporaryHp, IsInvulnerable | ✓ |
| Armor | 0x10 | 16 | ArmorType, ArmorClass, AbilityModifierCap | |
| Stats | 0xa0 | 160 | InitiativeBonus, Abilities[7]*, Skills[18] | ✓ |
| Resistances | 0x68 | 104 | Resistances[14], AC | ✓ |
| Experience | 0x18 | 24 | CurrentLevelExperience, TotalExperience | |
| Level | 0x04 | 4 | Level (int32) | |
| Classes | 0x10 | 16 | Classes (DynamicArray) | |
| **Identity** | | | | |
| Origin | 0x18 | 24 | Origin FixedString | ✓ |
| Background | 0x10 | 16 | Background GUID | ✓ |
| Race | 0x10 | 16 | Race GUID | ✓ |
| God | 0x28 | 40 | God GUID, HasGodOverride | ✓ |
| DisplayName | 0x40 | 64 | Name, Title (TranslatedStrings) | ✓ |
| Tag | 0x10 | 16 | Tags (DynamicArray<Guid>) | ✓ |
| Data | 0x0c | 12 | Weight, StatsId, StepsType | ✓ |
| **Capabilities** | | | | |
| CanDoActions | 0x02 | 2 | ActionFlags (bitfield) | |
| CanMove | 0x06 | 6 | MovementFlags, Distance | |
| CanSpeak | 0x02 | 2 | SpeakFlags (bitfield) | |
| FleeCapability | 0x0c | 12 | FleeFlags, Conditions | |
| **Movement/Combat** | | | | |
| Movement | 0x18 | 24 | Direction, Acceleration, Speed | |
| TurnBased | 0x30 | 48 | IsActiveCombatTurn, RequestedEndTurn | ✓ |
| **Equipment/Items** | | | | |
| Weapon | 0x50 | 80 | WeaponRange, DamageRange, WeaponProperties | |
| Value | 0x08 | 8 | Value, Rarity, Unique | |
| Use | 0x50 | 80 | UseBoosts, Charges, RequirementsData | |
| DisabledEquipment | 0x01 | 1 | IsDisabled (flag) | |
| **Containers** | | | | |
| ActionResources | 0x40 | 64 | Resources (HashMap<Guid, DynamicArray>) | ✓ |
| PassiveContainer | 0x10 | 16 | Passives (DynamicArray) | ✓ |
| BoostsContainer | 0x10 | 16 | Boosts (DynamicArray) | ✓ |

*\*Stats.Abilities[7]: Index [1]=None, [2]=STR, [3]=DEX, [4]=CON, [5]=INT, [6]=WIS, [7]=CHA*

### Verification Process

Component sizes are verified by decompiling `AddComponent<T>` functions in Ghidra, which call:
```c
ComponentFrameStorageAllocRaw(allocator, SIZE, ...)
```
Where SIZE is the actual ARM64 component size.

**Key Finding:** HealthComponent differs from Windows - ARM64 has 4 extra bytes of padding (0x28 vs 0x24). This validates the importance of Ghidra verification for ARM64.

### Verification Stats

- **27 components** verified via Ghidra AddComponent<> decompilation
- **1 size correction** found (HealthComponent: 0x24 → 0x28)
- **Pattern: Capability components are minimal** (2-6 bytes, bitfield flags)
- **Pattern: Container components use DynamicArray** (0x10 base size)

## Usage

```lua
local entity = Ext.Entity.Get("GUID")

-- Check for component
if entity:HasComponent("eoc::HealthComponent") then
    local health = entity.Health
    Ext.Print("HP: " .. health.Hp .. "/" .. health.MaxHp)
end

-- Access armor stats
local armor = entity.Armor
if armor then
    Ext.Print("AC: " .. armor.ArmorClass)
end
```
