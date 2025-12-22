# Comprehensive BG3SE Feature Parity Audit

**Completed:** December 22, 2025

## Executive Summary

**Parity: 76% (feature-weighted methodology)**

Comprehensive audit of Windows BG3SE (250+ functions, 16 namespaces) vs macOS BG3SE (82+ functions, 18 namespaces). The 76% figure uses feature-weighted methodology prioritizing high-mod-usage APIs; raw function count would be ~51%.

## Audit Results

### Windows BG3SE: ~253 functions
- Shared libraries: ~198 functions (16 namespaces)
- Client-only: ~41 functions (6 namespaces)
- Server-only: ~14 functions (2 namespaces)

### macOS BG3SE: ~123 functions
- Core functions: ~83
- Dynamic Osi.*: ~40+

## Created Issues (7)

| Issue | Title | Priority | Parity Impact |
|-------|-------|----------|---------------|
| #47 | Ext.Math - Full Vector/Matrix Library | HIGH | +3% |
| #48 | Ext.Types - Full Reflection System | MEDIUM | +2% |
| #49 | Ext.IO - File Handle Operations | LOW | +0.5% |
| #50 | Ext.Timer - Persistent/Realtime Timers | MEDIUM | +1% |
| #51 | Ext.Events - Engine Events Expansion | HIGH | +4% |
| #52 | Component Coverage Expansion | HIGH | +5% |
| #53 | Stats Functor System | MEDIUM | +2% |

## Total Open Issues: 17

### By Priority
- **CRITICAL**: #6 (Ext.Net - blocks multiplayer)
- **HIGH**: #35, #37, #47, #51, #52
- **MEDIUM**: #7, #36, #38, #42, #48, #50, #53
- **LOW**: #8, #46, #49
- **N/A**: #24 (community Q&A)

## Parity Calculation Methodology

The 76% parity uses weighted scoring by namespace importance:
- Ext.Stats, Ext.Entity, Ext.Osiris: 42% weight (core mod APIs)
- Ext.Events, Ext.Vars, Ext.Timer: 20% weight (common utilities)
- Ext.Net, Ext.UI, Ext.Level: 18% weight (advanced features, 0% implemented)
- Other: 20% weight

Raw function count would yield ~51% parity.
