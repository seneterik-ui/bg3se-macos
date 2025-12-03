/**
 * stats_manager.h - Stats System Manager for BG3SE-macOS
 *
 * Provides access to the game's RPGStats system for reading and modifying
 * game statistics (weapons, armor, spells, statuses, passives, etc.)
 *
 * Architecture:
 *   RPGStats::m_ptr (global) -> RPGStats instance -> CNamedElementManager<Object>
 *   Objects manager contains stat entries with properties stored as indices
 *   into global property pools (strings, floats, ints, GUIDs).
 */

#ifndef STATS_MANAGER_H
#define STATS_MANAGER_H

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

// Opaque handle for stat objects
typedef void* StatsObjectPtr;

// Forward declaration for internal types
typedef struct RPGStats RPGStats;
typedef struct StatsObject StatsObject;

// ============================================================================
// Initialization
// ============================================================================

/**
 * Initialize the stats manager.
 * Must be called after the game binary is loaded.
 *
 * @param main_binary_base Base address of the main game binary (for offset calculation)
 */
void stats_manager_init(void *main_binary_base);

/**
 * Called at SessionLoaded to verify stats system is ready.
 * Logs diagnostic information about the stats pointer state.
 */
void stats_manager_on_session_loaded(void);

/**
 * Check if the stats system is ready (RPGStats::m_ptr is non-null).
 *
 * @return true if stats system is initialized and accessible
 */
bool stats_manager_ready(void);

/**
 * Get the raw RPGStats pointer (for debugging).
 *
 * @return Pointer to RPGStats instance, or NULL if not ready
 */
void* stats_manager_get_raw(void);

// ============================================================================
// Stat Object Access
// ============================================================================

/**
 * Get a stat object by name.
 *
 * @param name Stat entry name (e.g., "Weapon_Longsword", "Armor_Leather")
 * @return Opaque pointer to stat object, or NULL if not found
 */
StatsObjectPtr stats_get(const char *name);

/**
 * Get the type (ModifierList name) of a stat object.
 *
 * @param obj Stat object pointer from stats_get()
 * @return Type name (e.g., "Weapon", "Armor", "SpellData"), or NULL on error
 */
const char* stats_get_type(StatsObjectPtr obj);

/**
 * Get the name of a stat object.
 *
 * @param obj Stat object pointer from stats_get()
 * @return Stat entry name, or NULL on error
 */
const char* stats_get_name(StatsObjectPtr obj);

/**
 * Get the level of a stat object.
 *
 * @param obj Stat object pointer from stats_get()
 * @return Level value, or -1 on error
 */
int stats_get_level(StatsObjectPtr obj);

/**
 * Get the parent stat name (Using field).
 *
 * @param obj Stat object pointer from stats_get()
 * @return Parent stat name, or NULL if no parent or on error
 */
const char* stats_get_using(StatsObjectPtr obj);

// ============================================================================
// Property Access (Read)
// ============================================================================

/**
 * Get a string property value.
 *
 * @param obj Stat object pointer
 * @param prop Property name (e.g., "Damage", "DamageType")
 * @return String value, or NULL if property not found or wrong type
 */
const char* stats_get_string(StatsObjectPtr obj, const char *prop);

/**
 * Get an integer property value.
 *
 * @param obj Stat object pointer
 * @param prop Property name
 * @param out_value Output parameter for the value
 * @return true if successful, false on error
 */
bool stats_get_int(StatsObjectPtr obj, const char *prop, int64_t *out_value);

/**
 * Get a float property value.
 *
 * @param obj Stat object pointer
 * @param prop Property name
 * @param out_value Output parameter for the value
 * @return true if successful, false on error
 */
bool stats_get_float(StatsObjectPtr obj, const char *prop, float *out_value);

// ============================================================================
// Property Access (Write) - Phase 4
// ============================================================================

/**
 * Set a string property value.
 *
 * @param obj Stat object pointer
 * @param prop Property name
 * @param value New string value
 * @return true if successful, false on error
 */
bool stats_set_string(StatsObjectPtr obj, const char *prop, const char *value);

/**
 * Set an integer property value.
 *
 * @param obj Stat object pointer
 * @param prop Property name
 * @param value New integer value
 * @return true if successful, false on error
 */
bool stats_set_int(StatsObjectPtr obj, const char *prop, int64_t value);

/**
 * Set a float property value.
 *
 * @param obj Stat object pointer
 * @param prop Property name
 * @param value New float value
 * @return true if successful, false on error
 */
bool stats_set_float(StatsObjectPtr obj, const char *prop, float value);

// ============================================================================
// Sync and Persistence - Phase 4
// ============================================================================

/**
 * Sync a modified stat to the game engine.
 * This propagates changes to prototypes and recalculates derived values.
 *
 * @param name Stat entry name to sync
 * @return true if successful, false on error
 */
bool stats_sync(const char *name);

// ============================================================================
// Enumeration
// ============================================================================

/**
 * Get the count of stats of a given type.
 *
 * @param type Type name (e.g., "Weapon", "Armor", NULL for all)
 * @return Number of stats, or -1 on error
 */
int stats_get_count(const char *type);

/**
 * Get the name of a stat at a given index.
 *
 * @param type Type name (or NULL for all)
 * @param index Index into the filtered list
 * @return Stat name, or NULL if out of bounds
 */
const char* stats_get_name_at(const char *type, int index);

// ============================================================================
// Stat Creation - Phase 5
// ============================================================================

/**
 * Create a new stat object.
 *
 * @param name Name for the new stat
 * @param type Type (ModifierList name)
 * @param template_name Optional template stat to copy from (NULL for default)
 * @return New stat object pointer, or NULL on error
 */
StatsObjectPtr stats_create(const char *name, const char *type, const char *template_name);

// ============================================================================
// Debugging
// ============================================================================

/**
 * Dump stat object details to log.
 *
 * @param obj Stat object pointer
 */
void stats_dump(StatsObjectPtr obj);

/**
 * Dump all available stat types to log.
 */
void stats_dump_types(void);

#endif // STATS_MANAGER_H
