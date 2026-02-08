# Minoan Swarm Plan: Issue #67 Test Suite Fixes + Osi.* Dispatch Verification

**Team Name:** Qedeshot (Phase Completion template)
**Date:** 2026-02-07
**Scope:** Fix 4 test failures, 2 unresolved TypeIds, verify Osi.* dispatch end-to-end

---

## Context

### Issue #67 — Test Suite Failures (v0.36.39)

The `!test` command reports 4/8 failures:

| # | Test | Root Cause | Fix |
|---|------|-----------|-----|
| 1 | `Stats.Get returns table` | Test checks `type(s) == 'table'` but `push_stats_object` returns **userdata** | Change to `'userdata'` |
| 2 | `Stats.Get property access` | Console wraps each `!command` in `lifetime_lua_begin_scope/end_scope`. The `!test` command registers a function via `Ext.RegisterConsoleCommand` — but the test closure captures locals that are invalidated when the lifetime scope ends between test registration and execution. **However**, the actual issue is that `Ext.Stats.Get` returns a userdata whose metatable `__index` checks lifetime validity, and the lifetime scope is still active during `!test` execution (the entire command runs in one scope). The real problem is likely the same as #1: `s.Damage` and `s.Type` may need the correct property name or the stats object lacks those fields for `WPN_Longsword`. | Investigate at runtime — may be a stats property name issue |
| 3 | `Stats.Sync no crash` | Same lifetime scope as #2 — `Ext.Stats.Get` returns userdata, then `s.Damage = '2d6'` tries to set via `__newindex`. If the stats object doesn't support `Damage` as a writable field, this fails. | Investigate at runtime |
| 4 | `Events.Subscribe returns ID` | Wrong API: `Ext.Events.Subscribe('Tick', fn)` — but `Events` is a table of event objects, each with `:Subscribe(fn)` method. Correct: `Ext.Events.Tick:Subscribe(fn)` | Fix API call in test |

Additionally, 2 TypeIds failed to resolve:
- `esv::TurnStartedEventOneFrameComponent` (rawValue=187116264)
- `esv::TurnEndedEventOneFrameComponent` (rawValue=187116280)

### Osi.* Dispatch Verification (ShaiLaric blocker)

ShaiLaric reported crashes calling `Osi.AddGold` and `Osi.TemplateAddTo` on v0.36.38. The v0.36.39 fix corrected type reading (+0x28), key reading (+0x2C), and handle caching. We need to **actually test** these calls in-game to confirm they work before telling ShaiLaric to rebuild.

---

## Team Structure

### Why a team (vs solo fixes)

The test fixes are simple code changes, but:
1. **Runtime verification requires the game running** — testing Osi.* calls and stats property access needs live console interaction
2. **TypeId investigation needs Ghidra** — checking why 2 addresses don't resolve requires decompilation
3. **These are independent workstreams** — can run in parallel

### Teammates

| Name | Role | Agent Type | Model | Files Owned |
|------|------|-----------|-------|-------------|
| **qedesha-lead** | Coordinator | general-purpose | opus | (none — delegates only) |
| **kaptaru** | Test fixer | general-purpose | sonnet | `src/lua/lua_ext.c` (test suite only, lines 1126-1192) |
| **devorah** | TypeId investigator | Explore | haiku | `src/entity/generated_typeids.h` (read-only), Ghidra MCP |
| **sassuratu** | Live tester | general-purpose | sonnet | Console commands only (nc -U /tmp/bg3se.sock) |

### File Ownership Matrix

| File | kaptaru | devorah | sassuratu |
|------|---------|---------|-----------|
| `src/lua/lua_ext.c` | WRITE (lines 1126-1192) | - | - |
| `src/entity/generated_typeids.h` | - | READ | - |
| Console socket | - | - | WRITE |
| `docs/CHANGELOG.md` | - | - | - |

---

## Tasks

### Task 1: Fix test type assertion (kaptaru)
**File:** `src/lua/lua_ext.c:1132`
**Change:** `type(s) == 'table'` → `type(s) == 'userdata'`
**Why:** `push_stats_object()` in `lua_stats.c:44-56` creates userdata with metatable, not a plain table.

### Task 2: Fix Events.Subscribe API (kaptaru)
**File:** `src/lua/lua_ext.c:1161-1164`
**Change:**
```lua
-- OLD (wrong):
local id = Ext.Events.Subscribe('Tick', function() end)
assert(type(id) == 'number', 'Expected number ID')
Ext.Events.Unsubscribe('Tick', id)

-- NEW (correct):
local id = Ext.Events.Tick:Subscribe(function() end)
assert(type(id) == 'number', 'Expected number ID')
Ext.Events.Tick:Unsubscribe(id)
```
**Why:** `lua_events.c:758-770` creates per-event objects. `Subscribe` is a method on `Ext.Events.Tick`, not a function on `Ext.Events`.

### Task 3: Investigate Stats property tests (sassuratu)
**Method:** Run these commands via console while game is loaded:
```lua
local s = Ext.Stats.Get('WPN_Longsword')
_P(type(s))
_D(s)
_P('Damage=' .. tostring(s.Damage))
_P('Type=' .. tostring(s.Type))
```
If properties fail, determine correct field names. Report back to kaptaru for test fixes.

### Task 4: Test Osi.* dispatch (sassuratu)
**Method:** Run these commands via console in a loaded save:
```lua
-- Test basic Osi call
local host = Osi.GetHostCharacter()
_P('Host: ' .. tostring(host))

-- Test AddGold (ShaiLaric's crash case)
Osi.AddGold(host, 1)
_P('AddGold succeeded')

-- Test query
local x, y, z = Osi.GetPosition(host)
_P(string.format('Position: %.1f, %.1f, %.1f', x or 0, y or 0, z or 0))
```
**Expected:** No crash. If crash occurs, check crash.log and ring buffer.

### Task 5: Investigate unresolved TypeIds (devorah)
**TypeIds:**
- `esv::TurnStartedEventOneFrameComponent` — rawValue=187116264 (0xB276F78)
- `esv::TurnEndedEventOneFrameComponent` — rawValue=187116280 (0xB276F88)

**Method:**
1. Check if these addresses are valid in the BG3 binary
2. Check if the TypeId global is a pointer-to-pointer (needs double deref)
3. Compare with nearby working TypeIds to see if the address pattern differs

### Task 6: Build, test, and close (qedesha-lead)
After kaptaru's fixes:
1. Build: `cd build && cmake .. && cmake --build .`
2. User relaunches game
3. sassuratu runs `!test` — target 8/8 pass
4. sassuratu runs Osi.* dispatch tests
5. Update Issue #67 with results
6. If all pass, comment on Issue #66 confirming Osi.* works

---

## Execution Order

```
Phase 1 (parallel):
  kaptaru: Tasks 1+2 (code fixes)
  devorah: Task 5 (TypeId research)

Phase 2 (after build + game reload):
  sassuratu: Tasks 3+4 (live testing)

Phase 3:
  qedesha-lead: Task 6 (verify + close)
```

---

## Decision: Solo vs Swarm

**Recommendation: Execute solo (no swarm needed).**

After writing this plan, it's clear the work is:
- 2 one-line code fixes (Tasks 1-2) — trivial
- 2 console test sessions (Tasks 3-4) — requires game running, sequential
- 1 Ghidra lookup (Task 5) — quick if Ghidra is running, otherwise deferred

A Minoan Swarm team adds coordination overhead that exceeds the work itself. The fixes can be done in ~5 minutes of editing + one build + one test cycle. The TypeId investigation can happen after.

**Proceed with direct execution instead.**
