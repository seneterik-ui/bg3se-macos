/**
 * stats_manager.c - Stats System Manager for BG3SE-macOS
 *
 * Provides access to the game's RPGStats system for reading and modifying
 * game statistics (weapons, armor, spells, statuses, passives, etc.)
 *
 * The stats system uses CNamedElementManager<T> templates to store:
 * - ModifierValueLists (RPGEnumeration) - Type definitions and enums
 * - ModifierLists - Stat types (Weapon, Armor, SpellData, etc.)
 * - Objects - Actual stat entries with properties
 *
 * Properties are stored as indices into global pools (FixedStrings, Floats, etc.)
 */

#include "stats_manager.h"
#include "logging.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <dlfcn.h>
#include <mach/mach.h>
#include <mach-o/dyld.h>

// ============================================================================
// Logging Helper
// ============================================================================

static void log_stats(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
static void log_stats(const char *fmt, ...) {
    char buf[1024];
    va_list args;
    va_start(args, fmt);
    vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);
    log_message("[Stats] %s", buf);
}

// ============================================================================
// Memory Safety
// ============================================================================

// Safely read memory using mach_vm_read (won't crash on bad addresses)
static bool safe_read_ptr(void *addr, void **out_value) {
    if (!addr || !out_value) return false;

    vm_size_t size = sizeof(void*);
    vm_offset_t data;
    kern_return_t kr = vm_read(mach_task_self(), (vm_address_t)addr,
                               size, &data, (mach_msg_type_number_t*)&size);
    if (kr != KERN_SUCCESS) return false;

    *out_value = *(void**)data;
    vm_deallocate(mach_task_self(), data, size);
    return true;
}

static bool safe_read_u32(void *addr, uint32_t *out_value) {
    if (!addr || !out_value) return false;

    vm_size_t size = sizeof(uint32_t);
    vm_offset_t data;
    kern_return_t kr = vm_read(mach_task_self(), (vm_address_t)addr,
                               size, &data, (mach_msg_type_number_t*)&size);
    if (kr != KERN_SUCCESS) return false;

    *out_value = *(uint32_t*)data;
    vm_deallocate(mach_task_self(), data, size);
    return true;
}

static bool safe_read_i32(void *addr, int32_t *out_value) {
    if (!addr || !out_value) return false;

    vm_size_t size = sizeof(int32_t);
    vm_offset_t data;
    kern_return_t kr = vm_read(mach_task_self(), (vm_address_t)addr,
                               size, &data, (mach_msg_type_number_t*)&size);
    if (kr != KERN_SUCCESS) return false;

    *out_value = *(int32_t*)data;
    vm_deallocate(mach_task_self(), data, size);
    return true;
}

// ============================================================================
// Symbol Resolution
// ============================================================================

// RPGStats::m_ptr mangled symbol name
#define RPGSTATS_M_PTR_SYMBOL "__ZN8RPGStats5m_ptrE"

// Ghidra offset (for fallback if dlsym fails)
#define GHIDRA_BASE_ADDRESS 0x100000000ULL
#define OFFSET_RPGSTATS_M_PTR 0x1089c5730ULL

// ============================================================================
// Structure Offsets (from Windows BG3SE + ARM64 alignment)
// These need to be verified with Ghidra analysis
// ============================================================================

// RPGStats structure offsets
// CNamedElementManager has: VMT(8) + Values(24) + NameToHandle(~48) + NextHandle(4)
// Approximate size per manager: ~80-88 bytes

// For ARM64, we assume 8-byte alignment
// struct RPGStats {
//     VMT;                             // +0x00 (8 bytes)
//     CNamedElementManager ModifierValueLists;  // +0x08
//     CNamedElementManager ModifierLists;       // +0x??
//     CNamedElementManager Objects;             // +0x??
//     ...
// }

// CNamedElementManager<T> offsets (ARM64)
// From BG3SE Common.h - CNamedElementManager has:
//   VMT (8 bytes) - virtual destructor
//   Array<T*> Values (16 bytes: buf_[8] + capacity_[4] + size_[4])
//   HashMap<FixedString, int32_t> NameToHandle (~48 bytes)
//   int32_t NextHandle (4 bytes)
// Total: ~80 bytes per manager

#define CNEM_OFFSET_VMT           0x00
#define CNEM_OFFSET_VALUES_BUF    0x08   // Array.buf_ (pointer to T*)
#define CNEM_OFFSET_VALUES_CAP    0x10   // Array.capacity_
#define CNEM_OFFSET_VALUES_SIZE   0x14   // Array.size_
#define CNEM_OFFSET_NAMETOHASH    0x18   // HashMap start
// NextHandle offset varies, determined at runtime

// RPGStats offsets - empirically determined from runtime probing
// The runtime probing found valid stat data at offset 0x88
#define RPGSTATS_OFFSET_OBJECTS             0x88   // CNamedElementManager<Object> Objects
#define RPGSTATS_OFFSET_MODIFIER_LISTS      0x58   // CNamedElementManager<ModifierList> ModifierLists

// Array<T*> offsets within CNamedElementManager
#define ARRAY_OFFSET_BUFFER       0x00
#define ARRAY_OFFSET_CAPACITY     0x08
#define ARRAY_OFFSET_SIZE         0x0C

// stats::Object offsets (from BG3SE Common.h lines 190-211)
// struct Object {
//   void* VMT;                    // +0x00
//   Vector<int32_t> IndexedProperties;  // +0x08 (24 bytes: buf[8]+cap[4]+size[4]+pad[8]?)
//   FixedString Name;             // +0x20
//   HashMap Functors;             // +0x28
//   HashMap RollConditions;       // +??
//   FixedString AIFlags;          // +??
//   Array Requirements;           // +??
//   ... more fields ...
//   int32_t Using;                // near end
//   uint32_t ModifierListIndex;
//   uint32_t Level;
// }
#define OBJECT_OFFSET_VMT              0x00
#define OBJECT_OFFSET_INDEXED_PROPS    0x08
#define OBJECT_OFFSET_NAME             0x20   // FixedString Name

// These need runtime discovery - placeholders for now
// From BG3SE: Using, ModifierListIndex, Level are near end of Object struct
// Object struct is quite large (~200+ bytes), we'll probe to find these
#define OBJECT_OFFSET_USING            0xC0   // Placeholder - int32_t Using (parent index)
#define OBJECT_OFFSET_MODIFIERLIST_IDX 0xC4   // Placeholder - uint32_t ModifierListIndex
#define OBJECT_OFFSET_LEVEL            0xC8   // Placeholder - uint32_t Level

// FixedString structure
// FixedString is typically just a const char* pointer in Larian's engine
// On ARM64 it's 8 bytes
#define FIXEDSTRING_SIZE 8

// ============================================================================
// Global State
// ============================================================================

static void *g_MainBinaryBase = NULL;
static void **g_pRPGStatsPtr = NULL;   // Pointer to RPGStats::m_ptr
static bool g_Initialized = false;

// Forward declarations for internal helpers
static void* get_objects_manager(void);
static int get_manager_count(void *manager);
static void* get_manager_element(void *manager, int index);
static const char* read_fixed_string(void *addr);

// ============================================================================
// Initialization
// ============================================================================

void stats_manager_init(void *main_binary_base) {
    if (g_Initialized) {
        log_stats("Already initialized");
        return;
    }

    g_MainBinaryBase = main_binary_base;

    log_stats("=== Stats Manager Initialization ===");
    log_stats("Main binary base: %p", main_binary_base);

    // Try to resolve RPGStats::m_ptr via dlsym
    // The symbol is exported in the main binary's symbol table
    void *handle = dlopen(NULL, RTLD_NOW);  // Get handle to main executable
    if (handle) {
        g_pRPGStatsPtr = (void**)dlsym(handle, RPGSTATS_M_PTR_SYMBOL);
        if (g_pRPGStatsPtr) {
            log_stats("Resolved %s via dlsym: %p", RPGSTATS_M_PTR_SYMBOL, (void*)g_pRPGStatsPtr);
        } else {
            log_stats("dlsym failed for %s: %s", RPGSTATS_M_PTR_SYMBOL, dlerror());
        }
    }

    // Fallback: Calculate from Ghidra offset
    if (!g_pRPGStatsPtr && main_binary_base) {
        uintptr_t runtime_addr = (uintptr_t)main_binary_base +
                                  (OFFSET_RPGSTATS_M_PTR - GHIDRA_BASE_ADDRESS);
        g_pRPGStatsPtr = (void**)runtime_addr;
        log_stats("Using Ghidra offset: %p (base %p + offset 0x%llx)",
                  (void*)g_pRPGStatsPtr, main_binary_base,
                  (unsigned long long)(OFFSET_RPGSTATS_M_PTR - GHIDRA_BASE_ADDRESS));
    }

    g_Initialized = true;

    // Check if stats system is ready yet
    if (stats_manager_ready()) {
        log_stats("Stats system is READY");
        void *rpgstats = stats_manager_get_raw();
        log_stats("RPGStats instance: %p", rpgstats);
    } else {
        log_stats("Stats system not yet ready (m_ptr is NULL - will retry at SessionLoaded)");
    }
}

void stats_manager_on_session_loaded(void) {
    log_stats("=== SessionLoaded: Checking Stats System ===");

    if (!g_Initialized) {
        log_stats("ERROR: Stats manager not initialized");
        return;
    }

    if (!g_pRPGStatsPtr) {
        log_stats("ERROR: g_pRPGStatsPtr is NULL");
        return;
    }

    // Read the pointer value
    void *stats_ptr = NULL;
    if (!safe_read_ptr(g_pRPGStatsPtr, &stats_ptr)) {
        log_stats("ERROR: Failed to read m_ptr (bad address?)");
        return;
    }

    if (!stats_ptr) {
        log_stats("WARNING: m_ptr is still NULL after SessionLoaded");
        return;
    }

    log_stats("Stats system pointer: %p", stats_ptr);

    // Get the Objects manager
    void *objects_mgr = get_objects_manager();
    if (!objects_mgr) {
        log_stats("ERROR: Failed to get Objects manager");
        return;
    }
    log_stats("Objects manager at: %p (RPGStats+0x%02x)", objects_mgr, RPGSTATS_OFFSET_OBJECTS);

    // Read raw buffer pointer and count
    void *buf_ptr = NULL;
    if (safe_read_ptr((char*)objects_mgr + CNEM_OFFSET_VALUES_BUF, &buf_ptr)) {
        log_stats("  Values.buf_: %p", buf_ptr);
    }
    uint32_t capacity = 0, size = 0;
    safe_read_u32((char*)objects_mgr + CNEM_OFFSET_VALUES_CAP, &capacity);
    safe_read_u32((char*)objects_mgr + CNEM_OFFSET_VALUES_SIZE, &size);
    log_stats("  Values.capacity_: %u, Values.size_: %u", capacity, size);

    // Get count
    int count = get_manager_count(objects_mgr);
    log_stats("Stats Objects count: %d", count);

    if (count <= 0 || count > 100000) {
        log_stats("ERROR: Invalid count - offsets may be wrong");
        return;
    }

    // Try to read first stat name as a sanity check
    void *first_obj = get_manager_element(objects_mgr, 0);
    log_stats("First element ptr: %p", first_obj);
    if (first_obj) {
        const char *name = read_fixed_string((char*)first_obj + OBJECT_OFFSET_NAME);
        if (name) {
            log_stats("First stat: \"%s\"", name);
        } else {
            log_stats("First stat: (name read failed at +0x%02x)", OBJECT_OFFSET_NAME);
        }
    } else {
        log_stats("ERROR: Could not read first element from buffer");
    }

    log_stats("Stats system READY with %d entries", count);
}

bool stats_manager_ready(void) {
    if (!g_Initialized || !g_pRPGStatsPtr) {
        return false;
    }

    // Read the pointer value safely
    void *stats_ptr = NULL;
    if (!safe_read_ptr(g_pRPGStatsPtr, &stats_ptr)) {
        return false;
    }

    return stats_ptr != NULL;
}

void* stats_manager_get_raw(void) {
    if (!g_pRPGStatsPtr) return NULL;

    void *stats_ptr = NULL;
    if (!safe_read_ptr(g_pRPGStatsPtr, &stats_ptr)) {
        return NULL;
    }

    return stats_ptr;
}

// ============================================================================
// Internal Helpers
// ============================================================================

// Get the Objects manager from RPGStats
// RPGStats layout: VMT(?), ModifierValueLists, ModifierLists, Objects, ...
// Based on runtime probing: Objects.NextHandle at +0x0E0
static void* get_objects_manager(void) {
    void *rpgstats = stats_manager_get_raw();
    if (!rpgstats) return NULL;

    // Objects is the 3rd CNamedElementManager
    // From runtime probing, NextHandle (count) is at +0x0E0
    // Working backwards: CNEM starts ~0x58 before NextHandle
    return (char*)rpgstats + RPGSTATS_OFFSET_OBJECTS;
}

// Get the ModifierLists manager from RPGStats
static void* get_modifier_lists_manager(void) {
    void *rpgstats = stats_manager_get_raw();
    if (!rpgstats) return NULL;

    // ModifierLists is the 2nd CNamedElementManager
    return (char*)rpgstats + RPGSTATS_OFFSET_MODIFIER_LISTS;
}

// Read FixedString (just a const char* in Larian's engine)
static const char* read_fixed_string(void *addr) {
    if (!addr) return NULL;

    void *str_ptr = NULL;
    if (!safe_read_ptr(addr, &str_ptr)) {
        return NULL;
    }

    return (const char*)str_ptr;
}

// Get count of elements in a CNamedElementManager
// Use Array.size_ which is more reliable than NextHandle
static int get_manager_count(void *manager) {
    if (!manager) return -1;

    // Read Values.size_ (at offset +0x14 from manager start)
    // Manager layout: VMT(8) + Values.buf_(8) + Values.cap_(4) + Values.size_(4)
    uint32_t size = 0;
    void *size_addr = (char*)manager + CNEM_OFFSET_VALUES_SIZE;
    if (!safe_read_u32(size_addr, &size)) {
        return -1;
    }

    return (int)size;
}

// Get element at index from CNamedElementManager
static void* get_manager_element(void *manager, int index) {
    if (!manager || index < 0) return NULL;

    // Read Values.buf_ pointer directly (at offset +0x08 from manager start)
    // Manager layout: VMT(8) + Values.buf_(8) + Values.cap_(4) + Values.size_(4)
    void *buffer = NULL;
    if (!safe_read_ptr((char*)manager + CNEM_OFFSET_VALUES_BUF, &buffer)) {
        return NULL;
    }

    if (!buffer) return NULL;

    // Read element at index (array of pointers)
    void *element_ptr_addr = (char*)buffer + (index * sizeof(void*));
    void *element = NULL;
    if (!safe_read_ptr(element_ptr_addr, &element)) {
        return NULL;
    }

    return element;
}

// ============================================================================
// Stat Object Access
// ============================================================================

StatsObjectPtr stats_get(const char *name) {
    if (!name || !stats_manager_ready()) {
        return NULL;
    }

    void *objects = get_objects_manager();
    if (!objects) {
        log_stats("Failed to get Objects manager");
        return NULL;
    }

    // Linear search through all objects (inefficient but safe for now)
    // TODO: Implement hash table lookup for performance
    int count = get_manager_count(objects);
    if (count <= 0) {
        log_stats("No stats objects found (count: %d)", count);
        return NULL;
    }

    for (int i = 0; i < count; i++) {
        void *obj = get_manager_element(objects, i);
        if (!obj) continue;

        // Read object name (FixedString at offset)
        const char *obj_name = read_fixed_string((char*)obj + OBJECT_OFFSET_NAME);
        if (obj_name && strcmp(obj_name, name) == 0) {
            return obj;
        }
    }

    return NULL;
}

const char* stats_get_type(StatsObjectPtr obj) {
    if (!obj) return NULL;

    // Read ModifierListIndex
    uint32_t modifier_list_idx = 0;
    if (!safe_read_u32((char*)obj + OBJECT_OFFSET_MODIFIERLIST_IDX, &modifier_list_idx)) {
        return NULL;
    }

    // Look up ModifierList by index
    void *modifier_lists = get_modifier_lists_manager();
    if (!modifier_lists) return NULL;

    void *modifier_list = get_manager_element(modifier_lists, modifier_list_idx);
    if (!modifier_list) return NULL;

    // ModifierList has Name field - find its offset
    // struct ModifierList { CNamedElementManager<Modifier> Attributes; FixedString Name; }
    // So Name is after the nested CNamedElementManager
    #define MODIFIERLIST_OFFSET_NAME 0x60  // After Attributes manager

    return read_fixed_string((char*)modifier_list + MODIFIERLIST_OFFSET_NAME);
}

const char* stats_get_name(StatsObjectPtr obj) {
    if (!obj) return NULL;
    return read_fixed_string((char*)obj + OBJECT_OFFSET_NAME);
}

int stats_get_level(StatsObjectPtr obj) {
    if (!obj) return -1;

    uint32_t level = 0;
    if (!safe_read_u32((char*)obj + OBJECT_OFFSET_LEVEL, &level)) {
        return -1;
    }

    return (int)level;
}

const char* stats_get_using(StatsObjectPtr obj) {
    if (!obj) return NULL;

    int32_t using_idx = 0;
    if (!safe_read_i32((char*)obj + OBJECT_OFFSET_USING, &using_idx)) {
        return NULL;
    }

    if (using_idx < 0) return NULL;  // No parent

    // Look up parent stat by index
    void *objects = get_objects_manager();
    if (!objects) return NULL;

    void *parent = get_manager_element(objects, using_idx);
    if (!parent) return NULL;

    return stats_get_name(parent);
}

// ============================================================================
// Property Access (Read) - Stub implementations
// TODO: Implement actual property lookup via IndexedProperties
// ============================================================================

const char* stats_get_string(StatsObjectPtr obj, const char *prop) {
    if (!obj || !prop) return NULL;

    // TODO: Implement property lookup
    // 1. Get ModifierList for this object's type
    // 2. Look up property info (index, type) from ModifierList
    // 3. Read IndexedProperties[index]
    // 4. Dereference from appropriate pool (FixedStrings, etc.)

    log_stats("stats_get_string not yet implemented");
    return NULL;
}

bool stats_get_int(StatsObjectPtr obj, const char *prop, int64_t *out_value) {
    if (!obj || !prop || !out_value) return false;

    // TODO: Implement property lookup
    log_stats("stats_get_int not yet implemented");
    return false;
}

bool stats_get_float(StatsObjectPtr obj, const char *prop, float *out_value) {
    if (!obj || !prop || !out_value) return false;

    // TODO: Implement property lookup
    log_stats("stats_get_float not yet implemented");
    return false;
}

// ============================================================================
// Property Access (Write) - Stub implementations
// ============================================================================

bool stats_set_string(StatsObjectPtr obj, const char *prop, const char *value) {
    if (!obj || !prop || !value) return false;

    log_stats("stats_set_string not yet implemented");
    return false;
}

bool stats_set_int(StatsObjectPtr obj, const char *prop, int64_t value) {
    if (!obj || !prop) return false;

    (void)value;  // Unused for now
    log_stats("stats_set_int not yet implemented");
    return false;
}

bool stats_set_float(StatsObjectPtr obj, const char *prop, float value) {
    if (!obj || !prop) return false;

    (void)value;  // Unused for now
    log_stats("stats_set_float not yet implemented");
    return false;
}

// ============================================================================
// Sync - Stub implementation
// ============================================================================

bool stats_sync(const char *name) {
    if (!name) return false;

    log_stats("stats_sync not yet implemented");
    return false;
}

// ============================================================================
// Enumeration
// ============================================================================

int stats_get_count(const char *type) {
    if (!stats_manager_ready()) return -1;

    void *objects = get_objects_manager();
    if (!objects) return -1;

    int total = get_manager_count(objects);
    if (total < 0) return -1;

    // If no type filter, return total
    if (!type) return total;

    // Count objects matching the type
    int count = 0;
    for (int i = 0; i < total; i++) {
        void *obj = get_manager_element(objects, i);
        if (!obj) continue;

        const char *obj_type = stats_get_type(obj);
        if (obj_type && strcmp(obj_type, type) == 0) {
            count++;
        }
    }

    return count;
}

const char* stats_get_name_at(const char *type, int index) {
    if (!stats_manager_ready() || index < 0) return NULL;

    void *objects = get_objects_manager();
    if (!objects) return NULL;

    int total = get_manager_count(objects);
    if (total < 0) return NULL;

    // If no type filter, direct access
    if (!type) {
        if (index >= total) return NULL;
        void *obj = get_manager_element(objects, index);
        return obj ? stats_get_name(obj) : NULL;
    }

    // Find nth object matching the type
    int count = 0;
    for (int i = 0; i < total; i++) {
        void *obj = get_manager_element(objects, i);
        if (!obj) continue;

        const char *obj_type = stats_get_type(obj);
        if (obj_type && strcmp(obj_type, type) == 0) {
            if (count == index) {
                return stats_get_name(obj);
            }
            count++;
        }
    }

    return NULL;
}

// ============================================================================
// Stat Creation - Stub implementation
// ============================================================================

StatsObjectPtr stats_create(const char *name, const char *type, const char *template_name) {
    if (!name || !type) return NULL;

    (void)template_name;  // Unused for now
    log_stats("stats_create not yet implemented");
    return NULL;
}

// ============================================================================
// Debugging
// ============================================================================

void stats_dump(StatsObjectPtr obj) {
    if (!obj) {
        log_stats("Cannot dump NULL stat object");
        return;
    }

    const char *name = stats_get_name(obj);
    const char *type = stats_get_type(obj);
    int level = stats_get_level(obj);
    const char *using_stat = stats_get_using(obj);

    log_stats("=== Stat Object Dump ===");
    log_stats("  Address: %p", obj);
    log_stats("  Name: %s", name ? name : "(null)");
    log_stats("  Type: %s", type ? type : "(null)");
    log_stats("  Level: %d", level);
    log_stats("  Using: %s", using_stat ? using_stat : "(none)");
}

void stats_dump_types(void) {
    if (!stats_manager_ready()) {
        log_stats("Stats system not ready");
        return;
    }

    void *modifier_lists = get_modifier_lists_manager();
    if (!modifier_lists) {
        log_stats("Failed to get ModifierLists manager");
        return;
    }

    int count = get_manager_count(modifier_lists);
    log_stats("=== Stat Types (ModifierLists) ===");
    log_stats("Total: %d", count);

    for (int i = 0; i < count && i < 50; i++) {  // Limit output
        void *ml = get_manager_element(modifier_lists, i);
        if (!ml) continue;

        const char *name = read_fixed_string((char*)ml + MODIFIERLIST_OFFSET_NAME);
        log_stats("  [%d] %s", i, name ? name : "(unnamed)");
    }
}
