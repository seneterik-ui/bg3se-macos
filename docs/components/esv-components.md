# esv:: Components (Server-Side)

596 total components in the `esv::` namespace. **146 have property layouts** parsed from Windows BG3SE headers.

## Components with Property Layouts

Run `python3 tools/parse_component_headers.py --list 2>/dev/null | grep "esv::"` to see all 146 components.

### Key Categories

| Category | Examples | Count |
|----------|----------|-------|
| Combat | CombatState, CombatGroupMapping, FleeRequest | ~15 |
| AI | AiModifiers, AiArchetype, InterestedInItems | ~5 |
| Character Creation | CCAppearanceVisualTag, CCGod, CCUpdates | ~3 |
| Death | DelayDeath, Killer, StateComponent | ~4 |
| Escort | EscortFollower, EscortLeader | ~3 |
| Inventory | PropertyCanBePickpocketed, IsTradable, IsDroppedOnDeath | ~3 |
| Level | LevelData, LevelUpQueue | ~5 |
| Story | StoryDialogHistory, StoryCrime | ~10 |
| Templates | TemplateInfo, TemplateTag | ~5 |
| Trade | TradeRequest, Trader, TraderService | ~5 |

### Notable Components

| Component | Full Name | Properties |
|-----------|-----------|------------|
| ServerGameTimer | esv::GameTimerComponent | 7 |
| JumpFollow | esv::JumpFollowComponent | 35 |
| ServerAiArchetype | esv::ai::combat::ArchetypeComponent | 4 |
| CombatSwitched | esv::combat::CombatSwitchedComponent | 4 |
| ServerStatusMachine | esv::status::StatusMachineComponent | 2 |
| ServerLevelData | esv::level::LevelDataComponent | 4 |

## Usage

Server components are typically accessed in server-side scripts (BootstrapServer.lua):

```lua
-- Server context only
Ext.Osiris.RegisterListener("EnteredCombat", 2, "after", function(char, combatGuid)
    local entity = Ext.Entity.Get(char)
    if entity then
        local combat = entity["esv::combat::ParticipantComponent"]
        if combat then
            -- Access combat state
        end
    end
end)
```

## Note

Many esv:: components are internal server state and may not be directly useful for modding. Focus on eoc:: components for gameplay modifications.
