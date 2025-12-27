/**
 * functor_hooks.h - Stats Functor Hook System
 *
 * Hooks for intercepting functor execution to fire Lua events.
 * Implements ExecuteFunctor, AfterExecuteFunctor, and damage events.
 */

#ifndef FUNCTOR_HOOKS_H
#define FUNCTOR_HOOKS_H

#include <stdbool.h>
#include <lua.h>

/**
 * Initialize the functor hook system.
 * Must be called after Dobby is ready and game module is loaded.
 *
 * @param L Lua state for event dispatch
 * @return true on success
 */
bool functor_hooks_init(lua_State* L);

/**
 * Shutdown the functor hook system.
 * Removes all installed hooks.
 */
void functor_hooks_shutdown(void);

/**
 * Check if functor hooks are active.
 */
bool functor_hooks_is_active(void);

/**
 * Get count of functor events fired.
 */
uint64_t functor_hooks_get_event_count(void);

#endif // FUNCTOR_HOOKS_H
