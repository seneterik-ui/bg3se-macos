# Final Issue Coverage Review

**Date:** December 22, 2025

## Coverage Confirmation: All Windows BG3SE Features Tracked

### Windows BG3SE Modules → Issue Mapping

| Windows Module | Context | macOS Status | Tracking Issue |
|----------------|---------|--------------|----------------|
| **Ext.Utils** | Both | ✅ 100% | Implemented |
| **Ext.Entity** | Both | ✅ 77% | #52 (expansion) |
| **Ext.Stats** | Both | ✅ 95% | #53 (functors) |
| **Ext.Json** | Both | ✅ 100% | Implemented |
| **Ext.Level** | Both | ❌ 0% | **#37** |
| **Ext.Math** | Both | ⚠️ 8% | **#47** |
| **Ext.Timer** | Both | ⚠️ 46% | **#50** |
| **Ext.Log** | Both | ✅ 100% | Implemented |
| **Ext.IO** | Both | ⚠️ 50% | **#49** |
| **Ext.Types** | Both | ⚠️ 29% | **#48** |
| **Ext.Debug** | Both | ✅ 212% | Extended for macOS |
| **Ext.Mod** | Both | ⚠️ 60% | Minor gaps |
| **Ext.Loca** | Both | ✅ 100% | Implemented |
| **Ext.Vars** | Both | ⚠️ 50% | Minor gaps |
| **Ext.StaticData** | Both | ✅ 100% | Implemented |
| **Ext.Resource** | Both | ✅ 100% | Implemented |
| **Ext.Table** | Both | ✅ 100% | Implemented |
| **Ext.Net** (Server) | Server | ❌ 0% | **#6** |
| **Ext.Net** (Client) | Client | ❌ 0% | **#6** |
| **Ext.Template** (Server) | Server | ✅ 91% | Implemented |
| **Ext.Template** (Client) | Client | ✅ 91% | Implemented |
| **Ext.Audio** | Client | ❌ 0% | **#38** |
| **Ext.Input** | Client | ⚠️ 50% | Minor gaps |
| **Ext.UI** | Client | ❌ 0% | **#35** |
| **Ext.IMGUI** | Client | ❌ 0% | **#36** |
| **Events System** | Both | ⚠️ 40% | **#51** |

### Additional Tracked Items

| Feature | Tracking Issue |
|---------|----------------|
| Component Coverage | **#52** |
| IDE/Type System | **#7** |
| VS Code Debugger | **#42** |
| Technical Debt | **#8** |
| Context Annotations | **#46** |

✅ **CONFIRMED: All Windows BG3SE features are now tracked by issues.**

---

## Issue Relationships & Dependencies

```
                    ┌─────────────────────────────────────┐
                    │     FOUNDATION LAYER                │
                    │  (No dependencies, do anytime)      │
                    ├─────────────────────────────────────┤
                    │ #47 Ext.Math    #49 Ext.IO          │
                    │ #50 Ext.Timer   #46 Context Docs    │
                    │ #8 Tech Debt                        │
                    └─────────────────────────────────────┘
                                    │
                    ┌───────────────┴───────────────┐
                    ▼                               ▼
        ┌───────────────────────┐     ┌───────────────────────┐
        │   CORE EXPANSION      │     │   TYPE SYSTEM         │
        ├───────────────────────┤     ├───────────────────────┤
        │ #51 Ext.Events        │     │ #48 Ext.Types         │
        │ #52 Components        │     │ #7 IDE Integration    │
        │ #53 Stats Functors    │     └───────────┬───────────┘
        └───────────┬───────────┘                 │
                    │                             │
                    └──────────────┬──────────────┘
                                   ▼
                    ┌─────────────────────────────────────┐
                    │     CLIENT FEATURES                 │
                    │  (Benefit from core expansion)      │
                    ├─────────────────────────────────────┤
                    │ #36 Ext.IMGUI (standalone ok)       │
                    │ #38 Ext.Audio (standalone ok)       │
                    │ #42 Debugger (benefits from #7,#48) │
                    └─────────────────────────────────────┘
                                    │
                                    ▼
                    ┌─────────────────────────────────────┐
                    │     COMPLEX INTEGRATIONS            │
                    │  (Need significant RE work)         │
                    ├─────────────────────────────────────┤
                    │ #37 Ext.Level (physics engine)      │
                    │ #35 Ext.UI (Noesis deep hooks)      │
                    │ #6 Ext.Net (network stack)          │
                    └─────────────────────────────────────┘
```

### Direct Dependencies

| Issue | Depends On | Notes |
|-------|------------|-------|
| #42 Debugger | #48, #7 | Benefits from type introspection |
| #53 Functors | #51 | Events needed for BeforeDamage hooks |
| #6 NetChannel | None | But #51 helps with network events |
| #35 Ext.UI | #36 | IMGUI experience helps UI patterns |

### Synergies (Shared Work)

| Issues | Shared Component |
|--------|------------------|
| #51 + #52 | Both need game engine hooks |
| #36 + #38 | Both need client-side hooks |
| #47 + #37 | Math needed for physics |
| #48 + #7 | Type introspection shared |

---

## Recommended Implementation Sequence

### Phase 1: Quick Wins (1-2 days each)

| Order | Issue | Acceleration | Effort | Why First |
|-------|-------|--------------|--------|-----------|
| 1 | **#49 Ext.IO** | 90% | LOW | 2 functions, pure C |
| 2 | **#47 Ext.Math** | 85% | MEDIUM | Pure math, no RE |
| 3 | **#50 Ext.Timer** | 80% | LOW | Extend existing system |
| 4 | **#46 Context Docs** | 95% | LOW | Documentation only |

### Phase 2: Core Expansion (1-2 weeks each)

| Order | Issue | Acceleration | Effort | Why This Order |
|-------|-------|--------------|--------|----------------|
| 5 | **#48 Ext.Types** | 70% | MEDIUM | Unlocks debugger/IDE |
| 6 | **#51 Ext.Events** | 60% | HIGH | Unlocks functors |
| 7 | **#52 Components** | 80% | HIGH | Accelerated workflow exists |
| 8 | **#53 Functors** | 50% | HIGH | Needs #51 events |

### Phase 3: Client Features (1-3 weeks each)

| Order | Issue | Acceleration | Effort | Why This Order |
|-------|-------|--------------|--------|----------------|
| 9 | **#36 Ext.IMGUI** | 70% | MEDIUM | Official Metal backend |
| 10 | **#38 Ext.Audio** | 45% | MEDIUM | WWise documented |
| 11 | **#42 Debugger** | 60% | HIGH | DAP reference exists |
| 12 | **#7 IDE Types** | 50% | MEDIUM | Builds on #48 |

### Phase 4: Complex Integrations (2-4 weeks each)

| Order | Issue | Acceleration | Effort | Why Last |
|-------|-------|--------------|--------|----------|
| 13 | **#37 Ext.Level** | 50% | HIGH | Physics RE needed |
| 14 | **#35 Ext.UI** | 25% | VERY HIGH | Deep Noesis hooks |
| 15 | **#6 Ext.Net** | 30% | VERY HIGH | Network stack RE |

---

## Acceleration Analysis (from agent_docs/acceleration.md)

### Highest Acceleration (70-90%) - Do First

| Issue | Acceleration | Key Technique |
|-------|--------------|---------------|
| **#49 Ext.IO** | 90% | Pure C, 2 functions |
| **#47 Ext.Math** | 85% | GLM-style, no dependencies |
| **#52 Components** | 80% | TypeId extraction tools exist |
| **#50 Ext.Timer** | 80% | Extend existing timer system |

### Medium Acceleration (50-70%)

| Issue | Acceleration | Key Technique |
|-------|--------------|---------------|
| **#48 Ext.Types** | 70% | Port Types.inl patterns |
| **#36 Ext.IMGUI** | 70% | Official Metal backend |
| **#51 Ext.Events** | 60% | Hook game event dispatch |
| **#42 Debugger** | 60% | DAP protocol references |
| **#53 Functors** | 50% | Windows code portable |
| **#37 Ext.Level** | 50% | LevelLib.inl portable |

### Lower Acceleration (25-45%) - Complex

| Issue | Acceleration | Key Technique |
|-------|--------------|---------------|
| **#38 Ext.Audio** | 45% | WWise documented but complex |
| **#6 Ext.Net** | 30% | Lua wrappers portable, C bridge complex |
| **#35 Ext.UI** | 25% | Deep Noesis integration required |

---

## Easiest Issues (Acceleratable)

### Tier 1: Can Complete in 1-2 Days

1. **#49 Ext.IO** - Just 2 functions: `AddPathOverride`, `GetPathOverride`
2. **#46 Context Annotations** - Documentation only, no code
3. **#50 Ext.Timer** - 7 functions, extend existing `src/timer/`

### Tier 2: Can Complete in 3-5 Days

4. **#47 Ext.Math** - 47 functions but pure math, no RE
5. **#48 Ext.Types** - Port from Windows Types.inl

### Tier 3: Week-Long with Acceleration

6. **#52 Components** - Tools exist (`extract_typeids.py`, `generate_component_stubs.py`)
7. **#36 Ext.IMGUI** - Official ImGui Metal backend available

---

## Summary: 17 Open Issues

| Priority | Issues | Combined Parity Impact |
|----------|--------|------------------------|
| Quick Wins | #49, #50, #46, #47 | +5.5% |
| Core | #48, #51, #52, #53 | +13% |
| Client | #36, #38, #42, #7 | +11.8% |
| Complex | #37, #35, #6 | +15.2% |
| Meta | #8, #24 | - |

**If all issues completed: 76% → ~100% parity**

---

## Recommended Starting Point

Based on acceleration analysis, start with:

1. **#49 Ext.IO** (90% acceleration, 1 day)
2. **#47 Ext.Math** (85% acceleration, 3-5 days)
3. **#50 Ext.Timer** (80% acceleration, 1-2 days)

These three can be done in parallel and provide immediate parity gains with minimal RE work.
