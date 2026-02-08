# Plan: Comprehensive Test Suite for BG3SE-macOS (Minoan Swarm)

## Context

BG3SE-macOS has ~350 Lua API functions across ~20 namespaces, but the `!test` command only covers 8 basic assertions. We just fixed 3 bugs that the existing tests missed (wrong type check, wrong Events API, missing lifetime scope in console dispatch). A comprehensive suite would have caught all of these.

The goal: expand `!test` to cover every implemented API to a reasonable depth — existence checks, basic functionality, no-crash guarantees, and return type validation. This is a regression suite, not an exhaustive correctness test.

## Critical Constraint: 4095-Char ISO C99 String Literal Limit

The existing code (line 1032-1033 of `lua_ext.c`) already documents this:
```c
// Register built-in console commands (split into smaller chunks to avoid
// exceeding the 4095 char limit that ISO C99 requires compilers to support)
```

Each C string literal must stay under 4095 chars. The test suite will be split across **multiple C string variables**, each loaded sequentially via `luaL_dostring()`. Tests use a **global `BG3SE_Tests` table** pattern so they can be defined across separate string chunks but run together.

## Architecture: Multi-String Test Framework

### String Layout (11 variables total)

```
console_cmd_test_framework   (~800 chars)  -- BG3SE_Tests table, BG3SE_AddTest, BG3SE_RunTests
console_cmd_test_core        (~3500 chars) -- Core, Json, Helpers (14 tests)
console_cmd_test_stats       (~3500 chars) -- Stats (10 tests)
console_cmd_test_timer       (~2500 chars) -- Timer (8 tests)
console_cmd_test_events      (~2000 chars) -- Events (5 tests)
console_cmd_test_debug       (~3500 chars) -- Debug (10 tests)
console_cmd_test_types       (~2500 chars) -- Types, Enums (9 tests)
console_cmd_test_misc        (~3000 chars) -- IO, Memory, Mod, Vars, Osi (15 tests)
console_cmd_test_register    (~500 chars)  -- Register !test command (calls BG3SE_RunTests)
console_cmd_test_ingame      (~3500 chars) -- Tier 2: Entity, Level, Audio, Net, IMGUI, etc.
console_cmd_test_ingame_reg  (~500 chars)  -- Register !test_ingame command
```

### Framework String (loaded first)

```lua
BG3SE_Tests = BG3SE_Tests or {tier1 = {}, tier2 = {}}
function BG3SE_AddTest(tier, name, fn)
  local t = (tier == 2) and BG3SE_Tests.tier2 or BG3SE_Tests.tier1
  t[#t+1] = {name=name, fn=fn}
end
function BG3SE_RunTests(tier, filter)
  local t = (tier == 2) and BG3SE_Tests.tier2 or BG3SE_Tests.tier1
  local passed, failed, skipped = 0, 0, 0
  local label = (tier == 2) and 'In-Game' or 'General'
  Ext.Print('\n=== BG3SE ' .. label .. ' Test Suite ===')
  for _, test in ipairs(t) do
    if not filter or test.name:find(filter) then
      local ok, err = pcall(test.fn)
      if ok then passed = passed + 1; Ext.Print('  PASS: ' .. test.name)
      else failed = failed + 1; Ext.Print('  FAIL: ' .. test.name .. ' - ' .. tostring(err)) end
    else skipped = skipped + 1 end
  end
  Ext.Print(string.format('\nResults: %d passed, %d failed, %d skipped', passed, failed, skipped))
  if failed > 0 then Ext.Print('SOME TESTS FAILED') else Ext.Print('ALL TESTS PASSED') end
end
```

### Registration Strings (loaded last)

```lua
-- !test registers Tier 1
Ext.RegisterConsoleCommand('test', function(cmd, filter)
  BG3SE_RunTests(1, filter ~= '' and filter or nil)
end)

-- !test_ingame registers Tier 2
Ext.RegisterConsoleCommand('test_ingame', function(cmd, filter)
  BG3SE_RunTests(2, filter ~= '' and filter or nil)
end)
```

## File to Modify

**`src/lua/lua_ext.c`** — Replace current `console_cmd_test` (lines 1126-1192) with 11 string variables, and update the `console_cmds[]` array (lines 1210-1214) to include them all.

No other files need changes.

## Test Inventory (Verified API Signatures)

### Tier 1: `!test` (always works, ~72 tests)

**Ext Core (6 tests)**
- `Core.Print` — `Ext.Print('test')` no crash
- `Core.GetVersion` — returns string matching `%d+%.%d+`
- `Core.IsServer` — returns boolean (false in client)
- `Core.IsClient` — returns boolean (true in client)
- `Core.GetContext` — returns string ("Client" or "Server")
- `Core.RegisterConsoleCommand` — `type(Ext.RegisterConsoleCommand) == 'function'`

**Ext.Json (4 tests)**
- `Json.Parse` — `Ext.Json.Parse('{"a":1}')` returns table with `t.a == 1`
- `Json.ParseArray` — `Ext.Json.Parse('[1,2]')` returns table with `t[1] == 1`
- `Json.Roundtrip` — Stringify then Parse roundtrip preserves values
- `Json.ParseInvalid` — `Ext.Json.Parse('not json')` returns nil, no crash

**Global Helpers (5 tests)**
- `Helpers.Print` — `_P('test')` no crash
- `Helpers.Hex` — `_H(255) == '0xff'`
- `Helpers.Dump` — `_D({a=1})` no crash
- `Helpers.DumpShallow` — `_DS({a=1})` no crash
- `Helpers.PrintError` — `_PE('err')` no crash

**Ext.Stats (10 tests)** *(Verified: Get returns userdata or nil, GetAll returns string table)*
- `Stats.Get` — `type(Ext.Stats.Get('WPN_Longsword')) == 'userdata'`
- `Stats.GetName` — `.Name == 'WPN_Longsword'`
- `Stats.GetProperty` — `.Damage` readable, `.Type` readable
- `Stats.GetNonexistent` — `Ext.Stats.Get('NONEXISTENT_STAT') == nil`
- `Stats.GetAll` — returns table with `#t > 0`
- `Stats.GetAllFiltered` — `Ext.Stats.GetAll('Weapon')` returns table
- `Stats.IsReady` — `Ext.Stats.IsReady() == true`
- `Stats.Sync` — modify + sync no crash (use Projectile_FireBolt)
- `Stats.EnumIndexToLabel` — returns string or nil, no crash
- `Stats.EnumLabelToIndex` — returns number or nil, no crash

**Ext.Timer (8 tests)** *(Verified: Pause/Resume return boolean, MonotonicTime returns ms)*
- `Timer.WaitFor` — returns number handle
- `Timer.Cancel` — cancel valid handle, no crash
- `Timer.PauseResume` — Pause returns true, IsPaused returns true, Resume returns true
- `Timer.MonotonicTime` — returns number > 0
- `Timer.MicrosecTime` — returns number > 0
- `Timer.GameTime` — returns number >= 0
- `Timer.DeltaTime` — returns number >= 0
- `Timer.Ticks` — returns number >= 0

**Ext.Events (5 tests)** *(Verified: Subscribe returns number ID, accepts options table)*
- `Events.TickSubscribe` — `Ext.Events.Tick:Subscribe(fn)` returns number
- `Events.TickUnsubscribe` — Unsubscribe(id) no crash
- `Events.SessionLoaded` — Subscribe returns number
- `Events.OnNextTick` — `type(Ext.OnNextTick) == 'function'`
- `Events.SubscribeOptions` — `Ext.Events.Tick:Subscribe(fn, {Priority=50, Once=true})` returns number

**Ext.Debug (10 tests)** *(Verified: ClassifyPointer returns table with .type field)*
- `Debug.ReadPtr` — `Ext.Debug.ReadPtr(0) == nil`
- `Debug.ReadU32` — `Ext.Debug.ReadU32(0) == nil`
- `Debug.ReadI32` — `Ext.Debug.ReadI32(0) == nil`
- `Debug.ReadFloat` — `Ext.Debug.ReadFloat(0) == nil`
- `Debug.IsValidPointer` — `Ext.Debug.IsValidPointer(0) == false`
- `Debug.ClassifyNull` — returns table with `.type == 'null'`
- `Debug.ClassifySmallInt` — `Ext.Debug.ClassifyPointer(42)` → `.type == 'small_int'`
- `Debug.Time` — returns string matching `%d+:%d+:%d+`
- `Debug.Timestamp` — returns number > 0
- `Debug.SessionAge` — returns number >= 0

**Ext.Types (6 tests)**
- `Types.GetAllTypes` — returns table with `#t > 1000`
- `Types.GetTypeInfo` — `Ext.Types.GetTypeInfo('Weapon')` returns non-nil
- `Types.GetAllLayouts` — returns table
- `Types.GetComponentLayout` — no crash on known component name
- `Types.TypeOf` — returns string for stats userdata
- `Types.GenerateIdeHelpers` — is a function (don't call)

**Ext.Enums (3 tests)**
- `Enums.DamageType` — exists
- `Enums.DamageTypeFire` — `Ext.Enums.DamageType.Fire` exists
- `Enums.AbilityId` — exists

**Ext.IO (3 tests)**
- `IO.LoadFile` — is a function
- `IO.SaveFile` — is a function
- `IO.AddPathOverride` — is a function

**Ext.Memory (3 tests)**
- `Memory.GetModuleBase` — returns number or nil, no crash
- `Memory.ReadInvalid` — `Ext.Memory.Read(0, 8)` returns nil, no crash
- `Memory.Search` — is a function

**Ext.Mod (4 tests)**
- `Mod.GetLoadOrder` — returns table
- `Mod.GetBaseMod` — returns non-nil
- `Mod.IsModLoaded` — `Ext.Mod.IsModLoaded('00000000-0000-0000-0000-000000000000')` returns false
- `Mod.GetModManager` — is a function

**Ext.Vars (2 tests)**
- `Vars.Exists` — `type(Ext.Vars) == 'table'`
- `Vars.ReloadPersistentVars` — is a function

**Osi.* Dispatch (3 tests)**
- `Osi.Exists` — `type(Osi) == 'table'`
- `Osi.GetHostCharacter` — accessing via metatable doesn't crash
- `Osi.SafeCall` — `pcall(Osi.AddGold, nil, 1)` no crash

### Tier 2: `!test_ingame` (needs loaded save, ~22 tests)

Each guarded with readiness checks.

**Ext.Entity (5)** — Get, GetByHandle, host char lookup, component access, module exists
**Ext.Level (5)** — IsReady, GetCurrentLevel, GetPhysicsScene, GetAiGrid, GetHeightsAt
**Ext.Audio (4)** — IsReady, GetSoundObjectId, PostEvent, SetState (function checks)
**Ext.Net (4)** — IsReady, IsHost, Version, PostMessageToServer (function check)
**Ext.IMGUI (2)** — IsReady, NewWindow (function check)
**Ext.StaticData (2)** — IsReady, GetTypes returns table

## Minoan Swarm Team: `kaptaru-test-forge`

### Why a Team

The test suite spans ~72 Tier 1 + ~22 Tier 2 tests across ~20 namespaces, each needing careful C string segmentation under the 4095-char limit. Two builders working in parallel on different tiers with a coordinator for build/verification is efficient:

- **kaptaru** writes Tier 1 strings (7 variables) — the bulk of the work
- **sassuratu** writes Tier 2 strings (2 variables) — smaller but needs ingame API knowledge
- **athirat** writes framework + registration + assembles final array + builds

### Team Structure

| Name | Role | Agent Type | Model | Owns |
|------|------|-----------|-------|------|
| **athirat-lead** | Coordinator | general-purpose | opus | Framework string, registration strings, `console_cmds[]` array, build |
| **kaptaru** | Tier 1 builder | general-purpose | sonnet | 7 test string variables (core, stats, timer, events, debug, types, misc) |
| **sassuratu** | Tier 2 builder | general-purpose | sonnet | 2 test string variables (ingame tests, ingame registration) |

### File Ownership

All three touch `src/lua/lua_ext.c` but in **non-overlapping line ranges**:

| Agent | Lines | Content |
|-------|-------|---------|
| athirat | 1126-1135 | `console_cmd_test_framework` variable |
| kaptaru | 1136-1220 (approx) | 7 Tier 1 `console_cmd_test_*` variables |
| sassuratu | after kaptaru | 2 Tier 2 variables |
| athirat | after sassuratu | Registration strings + `console_cmds[]` update |

### Execution Pipeline

```
Phase 1 (parallel):
  kaptaru:   Write 7 Tier 1 test strings
  sassuratu: Write 2 Tier 2 test strings

Phase 2 (athirat, after both complete):
  1. Write framework string (console_cmd_test_framework)
  2. Write registration strings (console_cmd_test_register, console_cmd_test_ingame_reg)
  3. Update console_cmds[] array to include all 11 variables
  4. Build: cd build && cmake .. && cmake --build .
  5. Report build status

Phase 3 (user):
  1. Launch game
  2. Run !test — target ~72/72 PASS
  3. Load save, run !test_ingame — target ~22/22 PASS
```

### Agent Prompts

**kaptaru prompt:**
> You are kaptaru, the Tier 1 test builder for BG3SE-macOS. Read `src/lua/lua_ext.c` and replace the existing `console_cmd_test` variable (lines 1126-1192) with 7 new C string variables. Each must be under 4095 characters. Follow the test inventory in the plan for exact assertions. Use `BG3SE_AddTest(1, 'Name', function() ... end)` pattern. Variables: `console_cmd_test_core`, `console_cmd_test_stats`, `console_cmd_test_timer`, `console_cmd_test_events`, `console_cmd_test_debug`, `console_cmd_test_types`, `console_cmd_test_misc`. Do NOT touch the `console_cmds[]` array — athirat handles that.

**sassuratu prompt:**
> You are sassuratu, the Tier 2 test builder for BG3SE-macOS. After kaptaru finishes, add 2 C string variables after the Tier 1 strings: `console_cmd_test_ingame` and `console_cmd_test_ingame_reg`. Each under 4095 chars. Guard every test with readiness checks (`Ext.Level.IsReady()`, etc.). Use `BG3SE_AddTest(2, 'Name', function() ... end)` pattern. Do NOT touch the `console_cmds[]` array.

**athirat prompt:**
> You are athirat-lead, coordinator for the test suite swarm. After kaptaru and sassuratu finish: (1) Add `console_cmd_test_framework` before all test strings. (2) Add `console_cmd_test_register` and `console_cmd_test_ingame_reg` registration strings. (3) Update the `console_cmds[]` array to include all 11 variables in order. (4) Build and report.

## Verification

1. **Build**: `cd build && cmake .. && cmake --build .`
2. **Launch game** (main menu): `./scripts/launch_bg3.sh`
3. **Run Tier 1**: `echo '!test' | nc -U /tmp/bg3se.sock` — target ~72/72 PASS
4. **Filter test**: `echo '!test Stats' | nc -U /tmp/bg3se.sock` — runs only Stats.* tests
5. **Load a save**, then: `echo '!test_ingame' | nc -U /tmp/bg3se.sock` — target ~22/22 PASS
6. **Verify**: All original 8 tests subsumed by the new suite (same assertions, better names)
7. **Update log**: `echo '!status' | nc -U /tmp/bg3se.sock` should show both commands registered
