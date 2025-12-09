# Plan: In-Game Console, Structured Logging, and Ext.Input API

## Overview

This plan addresses three interconnected enhancements:
1. **In-Game Console Research** - Investigate overlay approaches, recommend implementation
2. **Structured Logging System** - Log levels, JSON output, module filtering, colors
3. **Ext.Input API** - Full keyboard/mouse event handling with hotkey support

## Key Discovery: macOS Has No SDL2

BG3 on macOS uses **native AppKit/Metal** (not SDL2 like Windows). This requires:
- NSEvent hooking instead of SDL_PollEvent hooking
- CGEventPost for input injection instead of SDL_PushEvent
- Method swizzling instead of Detours

---

## Part 1: In-Game Console (Research First)

### Recommended Approach: Phased Implementation

| Phase | Approach | Risk | Effort | Value |
|-------|----------|------|--------|-------|
| **1** | Unix Socket Console | Low | 2-3 hrs | High |
| **2** | NSWindow Overlay | Medium | 1-2 days | Medium |
| **3** | Metal/ImGui Overlay | High | 3-5 days | High |

### Phase 1: Socket Console (Implement First)

Enhance existing file-based console with bidirectional socket communication.

**New Files:**
- Extend `src/console/console.c` with socket server
- Create `tools/bg3se-console.c` - standalone readline client

**Architecture:**
```
Game Process                     Terminal
    ↓                               ↓
Unix Socket Server ←──────→ bg3se-console client
/tmp/bg3se.sock                 (readline)
```

**Features:**
- Real-time bidirectional I/O
- Command history (readline)
- ANSI color output for errors
- Output capture (Ext.Print → socket)

### Phase 2: NSWindow Overlay (Optional)

Create floating transparent window over game.

**New Files:**
- `src/overlay/overlay.h` - API declarations
- `src/overlay/overlay.m` - NSWindow management (Objective-C)

**Approach:**
```objc
NSWindow *overlay at NSScreenSaverWindowLevel
Toggle with hotkey (requires Phase 3: Ext.Input)
```

### Phase 3: Metal/ImGui (Future/Advanced)

Hook rendering pipeline for true in-game overlay.

**Investigation Required:**
1. Hook `[CAMetalLayer nextDrawable]` via method swizzling
2. Integrate ImGui Metal backend
3. Test stability across game states

**POC Experiments:**
- POC 1: Socket console works with BG3 (1-2 hours)
- POC 2: NSWindow visible over fullscreen BG3 (2-3 hours)
- POC 3: Metal hook doesn't crash BG3 (4-6 hours)

---

## Part 2: Structured Logging System

### Design Summary

Replace single-level `log_message()` with multi-level, module-aware system.

### Log Levels

```c
typedef enum {
    LOG_LEVEL_DEBUG = 0,  // Verbose (off in release)
    LOG_LEVEL_INFO  = 1,  // Normal operations
    LOG_LEVEL_WARN  = 2,  // Potential issues
    LOG_LEVEL_ERROR = 3,  // Serious failures
    LOG_LEVEL_NONE  = 4   // Suppress all
} LogLevel;
```

### Log Modules

```c
typedef enum {
    LOG_MODULE_CORE = 0,
    LOG_MODULE_CONSOLE,
    LOG_MODULE_LUA,
    LOG_MODULE_OSIRIS,
    LOG_MODULE_ENTITY,
    LOG_MODULE_EVENTS,
    LOG_MODULE_STATS,
    LOG_MODULE_TIMER,
    LOG_MODULE_HOOKS,
    LOG_MODULE_MOD,
    LOG_MODULE_PAK,
    LOG_MODULE_MEMORY,
    LOG_MODULE_INPUT,  // NEW for Ext.Input
    LOG_MODULE_MAX
} LogModule;
```

### API

**Macros (Primary Interface):**
```c
LOG_DEBUG(module, fmt, ...)
LOG_INFO(module, fmt, ...)
LOG_WARN(module, fmt, ...)
LOG_ERROR(module, fmt, ...)

// Module-specific shortcuts
LOG_LUA_INFO("Loaded %s", path)
LOG_STATS_DEBUG("Property %s = %s", name, value)
```

**Configuration:**
```c
log_set_global_level(LOG_LEVEL_INFO);
log_set_module_level(LOG_MODULE_STATS, LOG_LEVEL_DEBUG);
log_set_format(LOG_FORMAT_JSON);  // or LOG_FORMAT_HUMAN
log_set_color_enabled(true);
```

**Environment Variables:**
```bash
BG3SE_LOG_LEVEL=DEBUG
BG3SE_LOG_FORMAT=json
BG3SE_LOG_COLOR=1
BG3SE_LOG_MODULES=Stats:DEBUG,Lua:DEBUG
```

### Output Formats

**Human-Readable:**
```
[2025-12-06 12:30:45.123] [INFO ] [Stats ] Loaded 15774 stats
[2025-12-06 12:30:45.124] [ERROR] [Lua   ] Failed to load mod
```

**JSON (for grep/jq):**
```json
{"ts":"2025-12-06T12:30:45.123Z","level":"INFO","module":"Stats","msg":"Loaded 15774 stats"}
```

### ANSI Colors

| Level | Color |
|-------|-------|
| DEBUG | Cyan |
| INFO | White |
| WARN | Yellow |
| ERROR | Red (bold) |

### Files to Modify/Create

| File | Action |
|------|--------|
| `src/core/logging.h` | Rewrite with new API |
| `src/core/logging.c` | Rewrite implementation |
| `src/core/log_format.c` | NEW: Human/JSON formatters |
| `src/lua/lua_log.c` | NEW: Ext.Log Lua bindings |

### Migration

Existing `log_message("[Module] msg")` calls → `LOG_INFO(LOG_MODULE_X, "msg")`

**~220 call sites** across:
- `main.c` (~180 calls)
- `console.c` (~25 calls)
- `lua_events.c`, `stats_manager.c`, etc.

Backward-compatible wrapper preserved:
```c
void log_message(const char *format, ...) {
    // Maps to LOG_INFO(LOG_MODULE_CORE, ...)
}
```

---

## Part 3: Ext.Input API

### Key Discovery: No SDL2

macOS BG3 uses AppKit, not SDL2. Need NSEvent hooking.

### Architecture

```
src/input/
├── input_hooks.h      // Public API
├── input_hooks.m      // NSEvent hooking (Objective-C)
├── input_manager.c    // State management
├── input_inject.c     // CGEventPost injection
├── keycode_map.c      // macOS → SDL scan codes
└── lua_input.c        // Ext.Input Lua bindings
```

### NSEvent Hook (Method Swizzling)

```objc
// Swizzle [NSApplication sendEvent:]
@implementation NSApplication (BG3SEInput)
- (void)bg3se_sendEvent:(NSEvent *)event {
    bg3se_process_event(event);  // Process for BG3SE
    [self bg3se_sendEvent:event]; // Call original
}
@end
```

### Lua API

```lua
-- Event subscription
Ext.Events.KeyInput:Subscribe(function(e)
    e.Event      -- "KeyDown" / "KeyUp"
    e.Key        -- Scan code (SDL-compatible)
    e.Modifiers  -- Ctrl, Shift, Alt, Cmd flags
    e.Pressed    -- boolean
    e.Repeat     -- Key repeat flag
end)

-- Input injection
Ext.Input.InjectKeyPress(key, [modifiers])
Ext.Input.InjectKeyDown(key)
Ext.Input.InjectKeyUp(key)
```

### New Event Types (extend lua_events.h)

```c
typedef enum {
    // Existing...
    EVENT_KEY_INPUT,
    EVENT_MOUSE_BUTTON,
    EVENT_MOUSE_WHEEL,
    EVENT_MAX
} EventType;
```

### Hotkey System

Built-in hotkeys:
- `Ctrl+`` or `Ctrl+F12` → Toggle console

```c
typedef struct {
    uint16_t key;
    uint32_t modifiers;
    void (*callback)(void);
} HotkeyEntry;
```

### CMake Changes

```cmake
# Add Objective-C sources
set(INPUT_SOURCES
    src/input/input_hooks.m
    src/input/input_manager.c
    src/input/lua_input.c
)

# Link frameworks
target_link_libraries(bg3se
    "-framework AppKit"
    "-framework CoreGraphics"
)
```

---

## Implementation Order

### Week 1: Structured Logging
1. Rewrite `logging.h/c` with levels, modules, config
2. Add JSON formatter
3. Add ANSI color support
4. Migrate existing calls (incremental)

### Week 2: Socket Console
1. Add Unix socket server to `console.c`
2. Create `bg3se-console` readline client
3. Capture Ext.Print output to socket
4. Test bidirectional communication

### Week 3: Ext.Input Foundation
1. Create `input_hooks.m` with NSEvent swizzling
2. Create `input_manager.c` for state tracking
3. Add `keycode_map.c` for macOS→SDL mapping

### Week 4: Ext.Input Lua Bindings
1. Create `lua_input.c` with Ext.Input namespace
2. Extend `lua_events.c` with KeyInput event
3. Implement input injection via CGEventPost

### Week 5: Hotkey System & Console Toggle
1. Implement hotkey registry
2. Add Ctrl+` console toggle
3. Integrate with socket console (or overlay if ready)

### Week 6: Polish & Documentation
1. Update ROADMAP.md with new parity percentages
2. Add console command help
3. Test all features together

---

## Critical Files Summary

### Logging
- `src/core/logging.h` - Rewrite
- `src/core/logging.c` - Rewrite
- `src/core/log_format.c` - NEW

### Console
- `src/console/console.c` - Extend with socket
- `tools/bg3se-console.c` - NEW client

### Input
- `src/input/input_hooks.m` - NEW (Objective-C)
- `src/input/input_manager.c` - NEW
- `src/input/lua_input.c` - NEW
- `src/lua/lua_events.h` - Extend with input events
- `src/lua/lua_events.c` - Extend with input dispatch

### Build
- `CMakeLists.txt` - Add new sources, frameworks

---

## Success Criteria

### Logging
- [ ] `LOG_DEBUG/INFO/WARN/ERROR` macros work
- [ ] Per-module level filtering works
- [ ] JSON output with `BG3SE_LOG_FORMAT=json`
- [ ] ANSI colors in terminal
- [ ] Backward-compatible `log_message()` still works

### Console
- [ ] `bg3se-console` connects to running game
- [ ] Lua commands execute with output returned
- [ ] Command history with arrow keys
- [ ] Errors displayed in red

### Ext.Input
- [ ] `Ext.Events.KeyInput` fires on key press
- [ ] `Ext.Input.InjectKeyPress()` works
- [ ] Ctrl+` toggles console visibility
- [ ] No game crashes from input hooks

---

## Risk Mitigation

| Risk | Mitigation |
|------|------------|
| NSEvent hook crashes game | Test with logging-only hook first |
| Performance overhead | Lazy formatting, level filtering |
| Thread safety issues | pthread_mutex on all shared state |
| Game updates break hooks | Use method swizzling (stable) |
