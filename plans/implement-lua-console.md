# feat: Implement Interactive Lua Console (Phase 5)

**Issue**: #5 - Debug Console
**Priority**: HIGH
**Status**: Ready for Implementation

---

## Overview

Implement a real-time Lua REPL accessible during gameplay for testing and debugging. This is critical for developer iteration speed - currently testing FixedString resolution and other features requires restarting the entire game.

The console will use a Unix domain socket architecture where the game hosts a socket server, and an external terminal client connects to send commands and receive output.

## Problem Statement / Motivation

**Current Pain Points:**
1. Testing Lua code requires full game restart
2. No way to inspect runtime state during gameplay
3. Debugging GlobalStringTable and other systems is extremely slow
4. Cannot iterate on mod code without restart cycle

**User Quote** (from current session):
> "It's not efficient for me to continuously open this damn game over and over"

## Proposed Solution

### Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    Game Process (BG3)                    │
│  ┌─────────────────────────────────────────────────────┐│
│  │                 BG3SE Dylib (Injected)               ││
│  │  ┌──────────────┐   ┌──────────────────────────────┐││
│  │  │ Console      │   │ Lua State (L)                │││
│  │  │ Server       │──▶│ - Execute commands           │││
│  │  │ (socket)     │   │ - Capture output             │││
│  │  └──────────────┘   └──────────────────────────────┘││
│  │         │                                            ││
│  │         │ /tmp/bg3se-console.sock                   ││
│  └─────────│────────────────────────────────────────────┘│
└────────────│────────────────────────────────────────────┘
             │
             ▼
┌─────────────────────────────────────────────────────────┐
│                 External Terminal                        │
│  ┌─────────────────────────────────────────────────────┐│
│  │              bg3se-console (client)                  ││
│  │  - readline for input editing                       ││
│  │  - command history                                  ││
│  │  - output display                                   ││
│  └─────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────┘
```

### Key Design Decisions

1. **Unix Domain Socket** - Best performance for local IPC on macOS
2. **Single Client** - One terminal at a time (simpler, matches Windows BG3SE)
3. **Server-Only Context** - Defer client/server switching until Issue #15 (dual Lua states)
4. **Main Thread Execution** - Commands queued and executed in game loop (thread safe)
5. **Newline Protocol** - Simple text-based protocol for easy debugging

---

## Technical Approach

### Phase 1: Minimal Console (MVP)

**Goal**: Execute Lua commands during gameplay with basic input/output.

#### 1.1 Create Console Module

**Files:**
```
src/console/
├── console.h          # Public API
├── console.c          # Socket server, command queue
└── console_client.c   # Standalone terminal client
```

**console.h**:
```c
#ifndef CONSOLE_H
#define CONSOLE_H

#include <stdbool.h>

// Initialize console socket server
// Returns true on success
bool console_init(void);

// Shutdown console and cleanup socket
void console_shutdown(void);

// Poll for incoming commands (call from game loop)
// Executes any queued commands on the Lua state
void console_poll(lua_State *L);

// Send output to connected client
void console_print(const char *msg);

// Check if client is connected
bool console_is_connected(void);

#endif
```

**console.c Core Structure**:
```c
// Socket file path
#define CONSOLE_SOCKET_PATH "/tmp/bg3se-console.sock"

// Command queue (circular buffer)
#define MAX_QUEUED_COMMANDS 64
#define MAX_COMMAND_LENGTH 4096

static int g_server_fd = -1;
static int g_client_fd = -1;
static char g_command_queue[MAX_QUEUED_COMMANDS][MAX_COMMAND_LENGTH];
static int g_queue_head = 0;
static int g_queue_tail = 0;

bool console_init(void) {
    // 1. Remove stale socket
    unlink(CONSOLE_SOCKET_PATH);

    // 2. Create Unix socket
    g_server_fd = socket(AF_UNIX, SOCK_STREAM, 0);

    // 3. Bind to path
    struct sockaddr_un addr = {0};
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, CONSOLE_SOCKET_PATH, sizeof(addr.sun_path) - 1);
    bind(g_server_fd, (struct sockaddr*)&addr, sizeof(addr));

    // 4. Listen (single client)
    listen(g_server_fd, 1);

    // 5. Set non-blocking
    fcntl(g_server_fd, F_SETFL, O_NONBLOCK);

    return true;
}

void console_poll(lua_State *L) {
    // 1. Accept new connection (non-blocking)
    if (g_client_fd < 0) {
        g_client_fd = accept(g_server_fd, NULL, NULL);
        if (g_client_fd >= 0) {
            fcntl(g_client_fd, F_SETFL, O_NONBLOCK);
            console_print("BG3SE-macOS Lua Console\nType 'help' for commands.\n>> ");
        }
    }

    // 2. Read commands (non-blocking)
    if (g_client_fd >= 0) {
        char buf[MAX_COMMAND_LENGTH];
        ssize_t n = recv(g_client_fd, buf, sizeof(buf) - 1, 0);
        if (n > 0) {
            buf[n] = '\0';
            queue_command(buf);
        } else if (n == 0) {
            // Client disconnected
            close(g_client_fd);
            g_client_fd = -1;
        }
    }

    // 3. Execute queued commands
    while (g_queue_head != g_queue_tail) {
        char *cmd = g_command_queue[g_queue_head];
        execute_lua_command(L, cmd);
        g_queue_head = (g_queue_head + 1) % MAX_QUEUED_COMMANDS;
    }
}
```

#### 1.2 Integrate with Game Loop

**In main.c**, add console polling to `fake_Event()`:

```c
// src/injector/main.c - in fake_Event()
static int event_count = 0;
event_count++;

// Poll console every 10 events (~every frame)
if (event_count % 10 == 0 && L != NULL) {
    console_poll(L);
}
```

#### 1.3 Create Terminal Client

**console_client.c** (standalone binary):
```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <editline/readline.h>

#define SOCKET_PATH "/tmp/bg3se-console.sock"

int main(void) {
    int sock = socket(AF_UNIX, SOCK_STREAM, 0);

    struct sockaddr_un addr = {0};
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, SOCKET_PATH, sizeof(addr.sun_path) - 1);

    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("Cannot connect to BG3SE console");
        return 1;
    }

    printf("Connected to BG3SE console.\n");

    // Receive welcome message
    char buf[4096];
    ssize_t n = recv(sock, buf, sizeof(buf) - 1, 0);
    if (n > 0) {
        buf[n] = '\0';
        printf("%s", buf);
    }

    // Input loop with readline
    char *line;
    while ((line = readline("")) != NULL) {
        if (strlen(line) > 0) {
            add_history(line);

            // Send command
            send(sock, line, strlen(line), 0);
            send(sock, "\n", 1, 0);

            // Receive response
            n = recv(sock, buf, sizeof(buf) - 1, 0);
            if (n > 0) {
                buf[n] = '\0';
                printf("%s", buf);
            } else if (n == 0) {
                printf("Server disconnected.\n");
                break;
            }
        }
        free(line);
    }

    close(sock);
    return 0;
}
```

#### 1.4 Build System Integration

**CMakeLists.txt additions**:
```cmake
# Console module
set(CONSOLE_SOURCES
    src/console/console.c
)

# Add to main library
target_sources(bg3se PRIVATE ${CONSOLE_SOURCES})

# Console client (standalone binary)
add_executable(bg3se-console src/console/console_client.c)
target_link_libraries(bg3se-console edit)  # libedit for readline
```

---

### Phase 2: Feature Parity with Windows BG3SE

**Goal**: Match Windows BG3SE console functionality.

#### 2.1 Special Commands

| Command | Action |
|---------|--------|
| `help` | Show available commands |
| `reset` | Reload Lua VM and re-run mod scripts |
| `clear` | Clear output buffer |
| `exit` | Close console session |
| `!<cmd> <args>` | Trigger ConsoleCommand event |

**Implementation in console.c**:
```c
static void handle_command(lua_State *L, const char *cmd) {
    // Trim whitespace
    while (*cmd == ' ' || *cmd == '\t') cmd++;

    if (strcmp(cmd, "help") == 0) {
        console_print("Commands:\n");
        console_print("  help  - Show this help\n");
        console_print("  reset - Reload Lua VM\n");
        console_print("  clear - Clear screen\n");
        console_print("  exit  - Close console\n");
        console_print("  !cmd  - Trigger ConsoleCommand event\n");
        console_print("\nAnything else is executed as Lua code.\n");
    } else if (strcmp(cmd, "reset") == 0) {
        // TODO: Implement Lua VM reset
        console_print("Reset not yet implemented.\n");
    } else if (strcmp(cmd, "exit") == 0) {
        close(g_client_fd);
        g_client_fd = -1;
    } else if (cmd[0] == '!') {
        // Custom command - trigger event
        fire_console_command_event(L, cmd + 1);
    } else {
        // Execute as Lua
        execute_lua_command(L, cmd);
    }
}
```

#### 2.2 Multiline Input

Support `--[[` to start multiline, `]]--` to end:

```c
static bool g_multiline_mode = false;
static char g_multiline_buffer[MAX_COMMAND_LENGTH * 10];

static void process_line(lua_State *L, const char *line) {
    if (!g_multiline_mode) {
        if (strcmp(line, "--[[") == 0) {
            g_multiline_mode = true;
            g_multiline_buffer[0] = '\0';
            console_print("-->> ");
            return;
        }
        handle_command(L, line);
    } else {
        if (strcmp(line, "]]--") == 0) {
            g_multiline_mode = false;
            handle_command(L, g_multiline_buffer);
        } else {
            strncat(g_multiline_buffer, line, sizeof(g_multiline_buffer) - strlen(g_multiline_buffer) - 2);
            strcat(g_multiline_buffer, "\n");
            console_print("-->> ");
        }
    }
}
```

#### 2.3 Output Capture

Intercept `Ext.Print` and forward to console:

```c
// In lua_ext.c - modify lua_ext_print
static int lua_ext_print(lua_State *L) {
    // ... existing implementation ...

    // Also send to console
    if (console_is_connected()) {
        console_print(output);
        console_print("\n");
    }

    return 0;
}
```

#### 2.4 Pretty Printing

Implement `_D()` for table/entity dumping:

```lua
-- Register in init_lua()
function _D(value, depth)
    depth = depth or 0
    local indent = string.rep("  ", depth)

    if type(value) == "table" then
        local mt = getmetatable(value)
        if mt and mt.__tostring then
            return tostring(value)
        end

        local lines = {"{"}
        local count = 0
        for k, v in pairs(value) do
            count = count + 1
            if count > 20 then
                table.insert(lines, indent .. "  ...")
                break
            end
            local key = type(k) == "string" and k or "[" .. tostring(k) .. "]"
            local val = depth < 3 and _D(v, depth + 1) or tostring(v)
            table.insert(lines, indent .. "  " .. key .. " = " .. val)
        end
        table.insert(lines, indent .. "}")
        return table.concat(lines, "\n")
    else
        return tostring(value)
    end
end
```

---

### Phase 3: Advanced Features (Future)

#### 3.1 Command Timeout

Prevent infinite loops from freezing game:

```c
#include <lua.h>
#include <lualib.h>

static int g_instruction_count = 0;
#define MAX_INSTRUCTIONS 10000000  // ~1 second of Lua

static void timeout_hook(lua_State *L, lua_Debug *ar) {
    g_instruction_count++;
    if (g_instruction_count > MAX_INSTRUCTIONS) {
        luaL_error(L, "Command timed out (infinite loop?)");
    }
}

static void execute_lua_command(lua_State *L, const char *cmd) {
    g_instruction_count = 0;
    lua_sethook(L, timeout_hook, LUA_MASKCOUNT, 10000);

    int result = luaL_dostring(L, cmd);

    lua_sethook(L, NULL, 0, 0);

    if (result != LUA_OK) {
        const char *err = lua_tostring(L, -1);
        console_print("Error: ");
        console_print(err);
        console_print("\n");
        lua_pop(L, 1);
    }
}
```

#### 3.2 TAB Completion (Future)

Send completion request, receive candidates from server.

#### 3.3 Client/Server Context (Future - Issue #15)

Requires implementing separate client Lua state first.

---

## Acceptance Criteria

### Phase 1 (MVP) - Must Have

- [ ] Socket server starts at game initialization
- [ ] Terminal client can connect to socket
- [ ] Execute arbitrary Lua code during gameplay
- [ ] See output from `Ext.Print()` in console
- [ ] Basic error messages for failed commands
- [ ] `exit` command closes connection cleanly
- [ ] Socket cleaned up on game shutdown

### Phase 2 (Feature Parity) - Should Have

- [ ] `help` command shows available commands
- [ ] `reset` command reloads Lua VM
- [ ] Multiline input with `--[[` / `]]--`
- [ ] `!cmd` triggers ConsoleCommand event
- [ ] `_D()` function for table/entity dumping
- [ ] Command history (arrow keys via readline)

### Phase 3 (Polish) - Nice to Have

- [ ] Command timeout prevents infinite loops
- [ ] TAB completion for Lua globals
- [ ] Color-coded output (errors in red)
- [ ] Multiple simultaneous clients

---

## Success Metrics

1. **Iteration Speed**: Developer can test Lua code without game restart
2. **Response Time**: Command execution completes in <100ms for simple commands
3. **Reliability**: No crashes from console commands (errors contained)
4. **Compatibility**: Works with existing BG3SE mods

---

## Dependencies & Prerequisites

### Required Before Starting

- [x] Lua state accessible from game loop (`L` global in main.c)
- [x] Game hook points identified (`fake_Event` runs every frame)
- [x] macOS socket APIs available (standard POSIX)

### Blocks Other Work

- Issue #5 (Debug Console) - This plan implements it
- GlobalStringTable discovery - Console enables faster iteration

### Affected by Other Work

- Issue #15 (Client Lua State) - Would enable client/server switching

---

## Risk Analysis & Mitigation

| Risk | Likelihood | Impact | Mitigation |
|------|------------|--------|------------|
| Lua state corruption from threading | Medium | High | All execution on main thread via queue |
| Game freeze from infinite loop | Medium | High | Instruction count timeout hook |
| Socket file left behind on crash | High | Low | atexit() handler + stale detection |
| Client disconnects mid-command | Low | Low | Graceful error handling |

---

## References & Research

### Internal References

- `src/injector/main.c:279` - Global Lua state `L`
- `src/injector/main.c:1654` - Example of `luaL_dostring()` usage
- `src/injector/main.c:2034` - `fake_Event()` hook (game loop integration point)
- `src/lua/lua_ext.c` - Ext.Print implementation to intercept
- `ROADMAP.md:49` - Console listed as Phase 5

### Windows BG3SE Reference

- `/Users/tomdimino/Desktop/Programming/bg3se/BG3Extender/Extender/Shared/Console.h:10-37` - DebugConsole class
- `/Users/tomdimino/Desktop/Programming/bg3se/BG3Extender/Extender/Shared/Console.cpp:97-129` - ExecLuaCommand
- `/Users/tomdimino/Desktop/Programming/bg3se/BG3Extender/Extender/Shared/Console.cpp:131-168` - HandleCommand
- `/Users/tomdimino/Desktop/Programming/bg3se/BG3Extender/Extender/Shared/Console.cpp:201-254` - InputLoop

### External Documentation

- [Unix Domain Socket Programming](https://systemprogrammingatntu.github.io/mp2/unix_socket.html)
- [Lua 5.4 Debug Interface](https://www.lua.org/manual/5.4/manual.html#4.7)
- [libedit/editline for macOS](https://thrysoee.dk/editline/)

### GitHub Issues

- Issue #5 - Implement debug console and REPL (Phase 5)
- Issue #15 - Client Lua State (related - enables context switching)

---

## Implementation Checklist

### Setup

- [ ] Create `src/console/` directory
- [ ] Add console.h and console.c
- [ ] Update CMakeLists.txt

### Phase 1 Implementation

- [ ] Implement `console_init()` - socket creation
- [ ] Implement `console_poll()` - non-blocking I/O
- [ ] Implement `console_print()` - output to client
- [ ] Implement `console_shutdown()` - cleanup
- [ ] Add poll call to `fake_Event()`
- [ ] Build standalone client binary
- [ ] Test basic command execution

### Phase 2 Implementation

- [ ] Add special command handling (help, reset, exit)
- [ ] Implement multiline mode
- [ ] Hook `Ext.Print` output to console
- [ ] Add `_D()` pretty-print function
- [ ] Test all special commands

### Testing

- [ ] Test connection/disconnection
- [ ] Test error handling (syntax errors, runtime errors)
- [ ] Test multiline input
- [ ] Test with existing BG3SE mods
- [ ] Test socket cleanup on crash

---

## Estimated Effort

| Phase | Tasks | Complexity |
|-------|-------|------------|
| Phase 1 (MVP) | Socket server, client, basic execution | Medium |
| Phase 2 (Features) | Special commands, multiline, pretty-print | Medium |
| Phase 3 (Polish) | Timeout, completion, colors | Low-Medium |

**Recommended approach**: Implement Phase 1 first (2-3 hours), validate it works for debugging GlobalStringTable, then add Phase 2 features as needed.
