# Component Extraction Plan: 1,030 → 1,500

## Goal
Extract ~470 more ARM64 component sizes via Ghidra MCP to reach 1,500 verified components (75% coverage).

## Current State (Dec 23, 2025)
- **1,030 components** size-verified (51.5% of 1,999 total)
- **Target:** 1,500 components (75% coverage)
- **Gap:** ~470 components needed

### Wave 8 Progress
| Agent | Status | Components | Notes |
|-------|--------|------------|-------|
| FOXTROT | Partial | 10/79 | Context limit hit |
| GOLF | ✅ Complete | 40/40 | Successfully wrote staging file |
| HOTEL | ❌ Failed | 0 | "Prompt too long" before start |
| INDIA | Pending | - | Not yet launched |
| JULIET | Pending | - | Not yet launched |

**Direct extraction in progress:** 12 additional esv:: components extracted manually

### Namespace Coverage Analysis

| Namespace | Documented | Total Available | Remaining | Priority |
|-----------|------------|-----------------|-----------|----------|
| esv:: | 160 | 596 | **436** | HIGH |
| ecl:: | 99 | 429 | **330** | HIGH |
| ls:: | 106 | 233 | **127** | MEDIUM |
| eoc:: | 648 | 701 | 53 | LOW (near complete) |
| navcloud:: | 17 | 13 | 0 | DONE |

**Strategy:** Focus on esv:: and ecl:: for maximum yield.

---

## Naming Convention

### Agent Names
Use NATO phonetic alphabet + wave number:
```
Wave 8:  FOXTROT, GOLF, HOTEL, INDIA, JULIET
Wave 9:  KILO, LIMA, MIKE, NOVEMBER, OSCAR
Wave 10: PAPA, QUEBEC, ROMEO, SIERRA, TANGO
```

### Staging File Names
Pattern: `{agent}_{namespace}_{offset-range}.md`

Examples:
```
foxtrot_esv_0-100.md
golf_esv_100-200.md
hotel_ecl_0-100.md
india_ecl_100-200.md
juliet_ls_0-100.md
```

### Staging Directory
All agent output goes to: `ghidra/offsets/staging/`

---

## Wave 8: Server Components (esv::) - Target: +200 components

**Focus:** esv:: namespace has 436 undocumented components - biggest opportunity.

| Agent | Namespace | Offset Range | Focus Area |
|-------|-----------|--------------|------------|
| FOXTROT | esv:: | 0-100 | Core server components |
| GOLF | esv:: | 100-200 | Triggers, AI |
| HOTEL | esv:: | 200-300 | Camp, Timeline |
| INDIA | esv:: | 300-400 | Character, Replication |
| JULIET | esv:: | 400-500 | Remaining server |

**Batch execution:**
- Batch 8A: FOXTROT + GOLF + HOTEL (3 parallel)
- Batch 8B: INDIA + JULIET (2 parallel)

---

## Wave 9: Client Components (ecl::) - Target: +150 components

**Focus:** ecl:: namespace has 330 undocumented components.

| Agent | Namespace | Offset Range | Focus Area |
|-------|-----------|--------------|------------|
| KILO | ecl:: | 0-100 | Visual, Effect |
| LIMA | ecl:: | 100-200 | Sound, Dialog |
| MIKE | ecl:: | 200-300 | Timeline, Inventory |
| NOVEMBER | ecl:: | 300-400 | Remaining client |

**Batch execution:**
- Batch 9A: KILO + LIMA + MIKE (3 parallel)
- Batch 9B: NOVEMBER (1 agent)

---

## Wave 10: Engine + Cleanup - Target: +120 components

| Agent | Namespace | Offset Range | Focus Area |
|-------|-----------|--------------|------------|
| OSCAR | ls:: | 100-200 | Remaining engine |
| PAPA | esv:: AddComponentUnchecked | all | Unchecked variants |
| QUEBEC | ecl:: AddComponentUnchecked | all | Unchecked variants |
| ROMEO | RemoveComponent | all | Name discovery |

**Batch execution:**
- Batch 10A: OSCAR + PAPA + QUEBEC (3 parallel)
- Batch 10B: ROMEO (cross-reference pass)

---

## Agent Prompt Template

```markdown
You are agent {AGENT_NAME}. Extract component sizes from {NAMESPACE} namespace.

**Ghidra MCP Workflow:**
1. search_functions_by_name("AddComponent<{NAMESPACE}", limit=50, offset={OFFSET})
2. For each result, decompile_function_by_address(address)
3. Extract SIZE from: ComponentFrameStorageAllocRaw(..., SIZE, ...)
4. Skip failures silently (not all functions decompile)

**Output format:**
| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|

**IMPORTANT:** Write your final results to:
`ghidra/offsets/staging/{agent}_{namespace}_{offset-range}.md`

Example filename: `foxtrot_esv_0-100.md`

Return confirmation when complete.
```

---

## Consolidation Workflow

After each wave:
1. Retrieve agent results via TaskOutput (or read staging files)
2. Deduplicate against existing documentation
3. Add new components to appropriate namespace file
4. Update statistics in COMPONENT_SIZES.md
5. Clean up staging files after consolidation

---

## Success Metrics

| Wave | Target | Cumulative | Coverage |
|------|--------|------------|----------|
| Wave 8 Complete | +200 | 1,230 | 61.5% |
| Wave 9 Complete | +150 | 1,380 | 69% |
| Wave 10 Complete | +120 | 1,500 | **75%** |

---

## Files to Modify

| File | Changes |
|------|---------|
| `ghidra/offsets/COMPONENT_SIZES.md` | Update total count, namespace breakdown |
| `ghidra/offsets/COMPONENT_SIZES_ESV.md` | Add ~200 server components |
| `ghidra/offsets/COMPONENT_SIZES_ECL.md` | Add ~150 client components |
| `ghidra/offsets/COMPONENT_SIZES_LS.md` | Add ~50 engine components |

---

## Execution Notes

1. **Launch 2-3 agents at a time** to avoid rate limits
2. **Agents write to staging/** to survive context compaction
3. **Use decompile_function_by_address** when names have special characters
4. **Skip Ghidra timeouts** silently - move to next function
5. **Consolidate after each wave** before launching next

---

## Lessons Learned (Wave 8A)

### Context Accumulation Problem
Subagents inherit accumulated conversation context, causing "Prompt is too long" errors:
- FOXTROT: Hit limit after 10 components
- HOTEL: Failed before starting (inherited too much context)
- GOLF: Succeeded (smaller inherited context at launch time)

### Mitigation Strategies

1. **Smaller batches**: Use `limit=25` instead of `limit=50-100` in search queries
2. **Minimal prompts**: Reduce agent prompt template to essential instructions only
3. **Staging directory works**: Partial results are preserved even when agents fail
4. **Direct extraction fallback**: When agents fail, extract directly in main session
5. **Fresh session advantage**: Launch agents early in session before context grows

### Updated Agent Prompt (Minimal)
```
Extract {NAMESPACE} component sizes (offset {OFFSET}-{END}).
Workflow: search_functions_by_name → decompile_function_by_address → extract SIZE
Write results to: ghidra/offsets/staging/{agent}_{namespace}_{range}.md
```

### Hybrid Approach
- Use subagents for fresh sessions with minimal context
- Fall back to direct extraction when context is large
- Always consolidate staging files before next wave

---

## Estimated Timeline

- Wave 8: 1-2 sessions (5 agents + consolidation)
- Wave 9: 1 session (4 agents + consolidation)
- Wave 10: 1 session (4 agents + consolidation)

**Total: 3-4 sessions to reach 1,500 components**
