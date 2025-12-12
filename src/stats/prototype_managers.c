/**
 * prototype_managers.c - Prototype Manager Accessors for BG3SE-macOS
 *
 * Implements singleton accessors and sync functions for prototype managers.
 * Uses discovered Ghidra offsets to locate manager instances at runtime.
 */

#include "prototype_managers.h"
#include "stats_manager.h"
#include "logging.h"
#include "../strings/fixed_string.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <mach/mach.h>

// ============================================================================
// Ghidra-Discovered Offsets (Dec 2025)
// ============================================================================

// Base address assumption for offset calculation
#define GHIDRA_BASE_ADDRESS 0x100000000ULL

// Singleton pointer locations (double-pointer pattern: *g_pManager gives Manager*)
// These are global addresses where the manager pointer is stored

// PassivePrototypeManager* at 0x108aeccd8 (discovered via ADRP+LDR in GetPassivePrototype)
#define OFFSET_PASSIVE_PROTOTYPE_MANAGER_PTR 0x108aeccd8ULL

// BoostPrototypeManager::m_ptr at 0x108991528 (symbol table, not exported)
#define OFFSET_BOOST_PROTOTYPE_MANAGER_PTR 0x108991528ULL

// InterruptPrototypeManager pointer - need to find via GetPrototype function
// GetPrototype at 0x101b9686c - analyze to find singleton
// From EvaluateInterrupt ADRP patterns: 0x108aecce0, 0x108aecd70
#define OFFSET_INTERRUPT_PROTOTYPE_MANAGER_PTR 0x108aecce0ULL

// SpellPrototypeManager::m_ptr at 0x1089bac80 (discovered via GetSpellPrototype decompilation)
// GetSpellPrototype at 0x10346e740: adrp x8,0x1089ba000; ldr x20,[x8, #0xc80] = 0x1089bac80
#define OFFSET_SPELL_PROTOTYPE_MANAGER_PTR 0x1089bac80ULL

// StatusPrototypeManager::m_ptr at 0x1089bdb30 (discovered via Ghidra symbol search)
// Symbol: __ZN3eoc22StatusPrototypeManager5m_ptrE at 0x1089bdb30
#define OFFSET_STATUS_PROTOTYPE_MANAGER_PTR 0x1089bdb30ULL

// Additional globals from EvaluateInterrupt (may be related)
#define OFFSET_MEMORY_MANAGER 0x108aefa98ULL  // Memory manager (appears in multiple functions)

// ============================================================================
// Prototype Init Function Offsets (Dec 12, 2025)
// ============================================================================

// SpellPrototype::Init at 0x101f72754 (populates prototype from stats)
// Signature: void SpellPrototype::Init(SpellPrototype* this, uint32_t spell_name_fs)
#define OFFSET_SPELL_PROTOTYPE_INIT 0x101f72754ULL

// RefMap offsets in SpellPrototypeManager (from GetSpellPrototype decompilation)
// Manager structure uses open-addressed hash table with separate arrays:
#define REFMAP_OFFSET_BUCKETS    0x08  // Hash → index bucket array
#define REFMAP_OFFSET_CAPACITY   0x10  // Capacity field
#define REFMAP_OFFSET_COUNT      0x14  // Count field (might be at +0x10 as uint32)
#define REFMAP_OFFSET_NEXT       0x18  // Next chain array (collision handling)
#define REFMAP_OFFSET_KEYS       0x28  // FixedString keys array
#define REFMAP_OFFSET_VALUES     0x38  // Prototype* values array

// SpellPrototype struct is estimated ~300+ bytes
#define SPELL_PROTOTYPE_SIZE     0x200  // 512 bytes (conservative estimate)

// ============================================================================
// Memory Safety Helpers
// ============================================================================

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

// ============================================================================
// Function Pointer Types
// ============================================================================

// SpellPrototype::Init(SpellPrototype* this, FixedString const& spell_name)
// Populates prototype fields from the corresponding stats object
// NOTE: FixedString const& means we pass a POINTER to the FixedString value
typedef void (*SpellPrototypeInit_fn)(void* prototype, const uint32_t* spell_name_fs_ptr);

// ============================================================================
// Global State
// ============================================================================

static void *g_MainBinaryBase = NULL;
static bool g_Initialized = false;

// Cached manager pointers (resolved lazily)
static void **g_pPassivePrototypeManagerPtr = NULL;
static void **g_pBoostPrototypeManagerPtr = NULL;
static void **g_pInterruptPrototypeManagerPtr = NULL;
static void **g_pSpellPrototypeManagerPtr = NULL;
static void **g_pStatusPrototypeManagerPtr = NULL;

// Cached function pointers (resolved during init)
static SpellPrototypeInit_fn g_SpellPrototypeInit = NULL;

// ============================================================================
// Helper: Calculate runtime address from Ghidra offset
// ============================================================================

static void* ghidra_to_runtime(uint64_t ghidra_addr) {
    if (!g_MainBinaryBase) return NULL;
    return (void*)((uintptr_t)g_MainBinaryBase + (ghidra_addr - GHIDRA_BASE_ADDRESS));
}

// ============================================================================
// Initialization
// ============================================================================

bool prototype_managers_init(void *main_binary_base) {
    if (g_Initialized) {
        LOG_STATS_DEBUG("[PrototypeManagers] Already initialized");
        return true;
    }

    g_MainBinaryBase = main_binary_base;

    LOG_STATS_DEBUG("[PrototypeManagers] === Initialization ===");
    LOG_STATS_DEBUG("[PrototypeManagers] Binary base: %p", main_binary_base);

    // Resolve singleton pointer addresses from Ghidra offsets

    // PassivePrototypeManager
    g_pPassivePrototypeManagerPtr = (void**)ghidra_to_runtime(OFFSET_PASSIVE_PROTOTYPE_MANAGER_PTR);
    LOG_STATS_DEBUG("[PrototypeManagers] PassivePrototypeManager ptr addr: %p (Ghidra: 0x%llx)",
                    (void*)g_pPassivePrototypeManagerPtr,
                    (unsigned long long)OFFSET_PASSIVE_PROTOTYPE_MANAGER_PTR);

    // BoostPrototypeManager
    g_pBoostPrototypeManagerPtr = (void**)ghidra_to_runtime(OFFSET_BOOST_PROTOTYPE_MANAGER_PTR);
    LOG_STATS_DEBUG("[PrototypeManagers] BoostPrototypeManager ptr addr: %p (Ghidra: 0x%llx)",
                    (void*)g_pBoostPrototypeManagerPtr,
                    (unsigned long long)OFFSET_BOOST_PROTOTYPE_MANAGER_PTR);

    // InterruptPrototypeManager
    g_pInterruptPrototypeManagerPtr = (void**)ghidra_to_runtime(OFFSET_INTERRUPT_PROTOTYPE_MANAGER_PTR);
    LOG_STATS_DEBUG("[PrototypeManagers] InterruptPrototypeManager ptr addr: %p (Ghidra: 0x%llx)",
                    (void*)g_pInterruptPrototypeManagerPtr,
                    (unsigned long long)OFFSET_INTERRUPT_PROTOTYPE_MANAGER_PTR);

    // SpellPrototypeManager - discovered via GetSpellPrototype decompilation
    g_pSpellPrototypeManagerPtr = (void**)ghidra_to_runtime(OFFSET_SPELL_PROTOTYPE_MANAGER_PTR);
    LOG_STATS_DEBUG("[PrototypeManagers] SpellPrototypeManager ptr addr: %p (Ghidra: 0x%llx)",
                    (void*)g_pSpellPrototypeManagerPtr,
                    (unsigned long long)OFFSET_SPELL_PROTOTYPE_MANAGER_PTR);

    // StatusPrototypeManager - discovered via Ghidra symbol search
    g_pStatusPrototypeManagerPtr = (void**)ghidra_to_runtime(OFFSET_STATUS_PROTOTYPE_MANAGER_PTR);
    LOG_STATS_DEBUG("[PrototypeManagers] StatusPrototypeManager ptr addr: %p (Ghidra: 0x%llx)",
                    (void*)g_pStatusPrototypeManagerPtr,
                    (unsigned long long)OFFSET_STATUS_PROTOTYPE_MANAGER_PTR);

    // Resolve Init function pointers
    g_SpellPrototypeInit = (SpellPrototypeInit_fn)ghidra_to_runtime(OFFSET_SPELL_PROTOTYPE_INIT);
    LOG_STATS_DEBUG("[PrototypeManagers] SpellPrototype::Init at: %p (Ghidra: 0x%llx)",
                    (void*)g_SpellPrototypeInit,
                    (unsigned long long)OFFSET_SPELL_PROTOTYPE_INIT);

    g_Initialized = true;
    LOG_STATS_DEBUG("[PrototypeManagers] Initialization complete");

    return true;
}

bool prototype_managers_ready(void) {
    return g_Initialized && g_MainBinaryBase != NULL;
}

// ============================================================================
// Singleton Accessors
// ============================================================================

void* get_passive_prototype_manager(void) {
    if (!g_pPassivePrototypeManagerPtr) return NULL;

    void *manager = NULL;
    if (!safe_read_ptr(g_pPassivePrototypeManagerPtr, &manager)) {
        return NULL;
    }

    return manager;
}

void* get_boost_prototype_manager(void) {
    if (!g_pBoostPrototypeManagerPtr) return NULL;

    void *manager = NULL;
    if (!safe_read_ptr(g_pBoostPrototypeManagerPtr, &manager)) {
        return NULL;
    }

    return manager;
}

void* get_interrupt_prototype_manager(void) {
    if (!g_pInterruptPrototypeManagerPtr) return NULL;

    void *manager = NULL;
    if (!safe_read_ptr(g_pInterruptPrototypeManagerPtr, &manager)) {
        return NULL;
    }

    return manager;
}

void* get_spell_prototype_manager(void) {
    if (!g_pSpellPrototypeManagerPtr) return NULL;

    void *manager = NULL;
    if (!safe_read_ptr(g_pSpellPrototypeManagerPtr, &manager)) {
        return NULL;
    }

    return manager;
}

void* get_status_prototype_manager(void) {
    if (!g_pStatusPrototypeManagerPtr) return NULL;

    void *manager = NULL;
    if (!safe_read_ptr(g_pStatusPrototypeManagerPtr, &manager)) {
        return NULL;
    }

    return manager;
}

// ============================================================================
// Prototype Sync Functions
// ============================================================================

// ============================================================================
// RefMap Lookup Helper (from GetSpellPrototype decompilation)
// ============================================================================

// Lookup a prototype in the manager's RefMap by FixedString key
// Returns pointer to the prototype, or NULL if not found
//
// RefMap structure (open-addressed hash table):
//   +0x08: bucket_array (int32_t*) - hash → first entry index
//   +0x10: capacity (int32_t) - number of buckets
//   +0x18: next_chain (int32_t*) - collision chain (negative = end, encodes bucket)
//   +0x28: keys_array (uint32_t* - FixedString indices)
//   +0x38: values_array (void** - Prototype pointers)
//
// NOTE: The hash function is complex (not simple key % capacity).
// For now, we use linear search through entries which is fast enough
// for ~5000 spell prototypes.
static void* refmap_lookup(void* manager, uint32_t fs_key) {
    if (!manager || fs_key == 0 || fs_key == 0xFFFFFFFF) return NULL;

    // Read RefMap structure
    int32_t capacity = 0;
    void* keys_array = NULL;
    void* values_array = NULL;

    if (!safe_read_u32((char*)manager + REFMAP_OFFSET_CAPACITY, (uint32_t*)&capacity)) {
        return NULL;
    }
    if (capacity == 0) return NULL;

    if (!safe_read_ptr((char*)manager + REFMAP_OFFSET_KEYS, &keys_array)) {
        return NULL;
    }
    if (!safe_read_ptr((char*)manager + REFMAP_OFFSET_VALUES, &values_array)) {
        return NULL;
    }

    // Linear search through entries (hash function is non-trivial, so we scan)
    // Cap at 10000 entries to prevent infinite loops
    int32_t max_entries = (capacity < 10000) ? capacity : 10000;

    for (int32_t i = 0; i < max_entries; i++) {
        uint32_t stored_key = 0;
        if (!safe_read_u32((char*)keys_array + (uint64_t)i * 4, &stored_key)) {
            continue;
        }

        if (stored_key == fs_key) {
            // Found it! Read the value (prototype pointer)
            void* prototype = NULL;
            if (safe_read_ptr((char*)values_array + (uint64_t)i * 8, &prototype)) {
                return prototype;
            }
            return NULL;
        }
    }

    return NULL;
}

// ============================================================================
// Prototype Sync Functions
// ============================================================================

// Offset of Name (FixedString) in stats::Object
#define STATS_OBJECT_OFFSET_NAME 0x20

bool sync_spell_prototype(StatsObjectPtr obj, const char *name) {
    if (!obj || !name) return false;

    void *manager = get_spell_prototype_manager();
    if (!manager) {
        LOG_STATS_DEBUG("[PrototypeManagers] sync_spell_prototype: Manager not accessible for '%s'", name);
        return false;
    }

    LOG_STATS_DEBUG("[PrototypeManagers] sync_spell_prototype: Manager at %p for '%s'", manager, name);

    // Get FixedString key from the stats object itself
    uint32_t fs_key = 0;
    if (!safe_read_u32((char*)obj + STATS_OBJECT_OFFSET_NAME, &fs_key)) {
        LOG_STATS_DEBUG("[PrototypeManagers]   Failed to read FixedString from stats object");
        return false;
    }

    // Check for invalid FixedString (shadow stats may have fs_key = 0)
    if (fs_key == 0 || fs_key == 0xFFFFFFFF) {
        LOG_STATS_DEBUG("[PrototypeManagers]   Stats object has invalid FixedString (0x%x) - likely a shadow stat", fs_key);
        LOG_STATS_DEBUG("[PrototypeManagers]   Shadow stat sync requires string interning (not yet implemented)");
        return true;  // Return true to not block other sync operations
    }

    LOG_STATS_DEBUG("[PrototypeManagers]   FixedString key: 0x%x", fs_key);

    // Look up existing prototype in manager's RefMap
    void* prototype = refmap_lookup(manager, fs_key);

    if (prototype) {
        LOG_STATS_DEBUG("[PrototypeManagers]   Found existing prototype at %p", prototype);

        // Call SpellPrototype::Init to refresh from stats
        // NOTE: Init takes FixedString const& so we pass pointer to the FS value
        if (g_SpellPrototypeInit) {
            LOG_STATS_DEBUG("[PrototypeManagers]   Calling SpellPrototype::Init(%p, &0x%x)", prototype, fs_key);
            g_SpellPrototypeInit(prototype, &fs_key);
            LOG_STATS_DEBUG("[PrototypeManagers]   Init complete for '%s'", name);
            return true;
        } else {
            LOG_STATS_DEBUG("[PrototypeManagers]   Init function not available");
            return false;
        }
    } else {
        // Prototype not found - this is a newly created stat
        LOG_STATS_DEBUG("[PrototypeManagers]   No existing prototype found for '%s'", name);
        LOG_STATS_DEBUG("[PrototypeManagers]   New spell prototypes require RefMap insertion (not yet implemented)");

        // For now, return true but log that full insertion isn't done
        // This allows sync to "succeed" for stats that inherit from existing ones
        // The game may still work if the base prototype exists
        return true;
    }
}

bool sync_status_prototype(StatsObjectPtr obj, const char *name) {
    if (!obj || !name) return false;

    void *manager = get_status_prototype_manager();
    if (!manager) {
        LOG_STATS_DEBUG("[PrototypeManagers] sync_status_prototype: Manager not accessible for '%s'", name);
        return false;
    }

    LOG_STATS_DEBUG("[PrototypeManagers] sync_status_prototype: Manager found at %p for '%s'", manager, name);

    // StatusPrototypeManager uses RefMap<FixedString, StatusPrototype> for lookup
    // Singleton found via Ghidra at 0x1089bdb30

    // TODO: Implementation requires:
    // 1. Find or create StatusPrototype in manager's HashMap
    // 2. Call StatusPrototype::Init(statsObject) or manually populate fields
    // 3. StatusPrototype struct layout needs discovery

    LOG_STATS_DEBUG("[PrototypeManagers]   TODO: Insert prototype into manager's RefMap");

    return true;
}

bool sync_passive_prototype(StatsObjectPtr obj, const char *name) {
    if (!obj || !name) return false;

    void *manager = get_passive_prototype_manager();
    if (!manager) {
        LOG_STATS_DEBUG("[PrototypeManagers] sync_passive_prototype: Manager not accessible for '%s'", name);
        return false;
    }

    LOG_STATS_DEBUG("[PrototypeManagers] sync_passive_prototype: Manager found at %p for '%s'", manager, name);

    // PassivePrototypeManager uses DEPRECATED_RefMapImpl for lookup
    // From GetPassivePrototype decompilation:
    //   uVar4 = ls::DEPRECATED_RefMapImpl<...eoc::PassivePrototype...>::operator[](...)

    // TODO: Implementation requires:
    // 1. Understand RefMap layout (likely: HashMap + Array)
    // 2. Find the Insert or operator[] function
    // 3. Either call PassivePrototype::Init or insert manually

    LOG_STATS_DEBUG("[PrototypeManagers]   Passive manager uses RefMap<FixedString, PassivePrototype>");
    LOG_STATS_DEBUG("[PrototypeManagers]   TODO: Insert prototype into manager's RefMap");

    return true;
}

bool sync_interrupt_prototype(StatsObjectPtr obj, const char *name) {
    if (!obj || !name) return false;

    void *manager = get_interrupt_prototype_manager();
    if (!manager) {
        LOG_STATS_DEBUG("[PrototypeManagers] sync_interrupt_prototype: Manager not accessible for '%s'", name);
        return false;
    }

    LOG_STATS_DEBUG("[PrototypeManagers] sync_interrupt_prototype: Manager found at %p for '%s'", manager, name);

    // From destructor analysis, InterruptPrototype is ~0x160+ bytes
    // Structure includes multiple arrays at offsets 0xC0, 0xD0, 0xF0, 0x110, 0x120

    LOG_STATS_DEBUG("[PrototypeManagers]   InterruptPrototype struct is ~0x160+ bytes");
    LOG_STATS_DEBUG("[PrototypeManagers]   TODO: Allocate and populate prototype, insert into manager");

    return true;
}

// ============================================================================
// Unified Sync Interface
// ============================================================================

bool sync_stat_prototype(StatsObjectPtr obj, const char *name, const char *type) {
    if (!obj || !name || !type) return false;

    if (!prototype_managers_ready()) {
        LOG_STATS_DEBUG("[PrototypeManagers] sync_stat_prototype: Not initialized");
        return false;
    }

    // Dispatch based on stat type
    if (strcmp(type, "SpellData") == 0) {
        return sync_spell_prototype(obj, name);
    }
    if (strcmp(type, "StatusData") == 0) {
        return sync_status_prototype(obj, name);
    }
    if (strcmp(type, "PassiveData") == 0) {
        return sync_passive_prototype(obj, name);
    }
    if (strcmp(type, "InterruptData") == 0) {
        return sync_interrupt_prototype(obj, name);
    }

    // Types that don't need prototype sync
    // Weapon, Armor, Character, Object, EquipmentSet, CriticalHitTypeData
    // These are used directly from RPGStats without a separate prototype manager
    LOG_STATS_DEBUG("[PrototypeManagers] sync_stat_prototype: Type '%s' doesn't need prototype sync", type);
    return true;
}

// ============================================================================
// Debug Functions
// ============================================================================

void prototype_managers_dump_status(void) {
    LOG_STATS_DEBUG("=== Prototype Managers Status ===");
    LOG_STATS_DEBUG("Initialized: %s", g_Initialized ? "yes" : "no");
    LOG_STATS_DEBUG("Binary base: %p", g_MainBinaryBase);

    LOG_STATS_DEBUG("");
    LOG_STATS_DEBUG("Manager Singletons:");

    // Passive
    void *passive_mgr = get_passive_prototype_manager();
    LOG_STATS_DEBUG("  PassivePrototypeManager:");
    LOG_STATS_DEBUG("    Ptr addr: %p", (void*)g_pPassivePrototypeManagerPtr);
    LOG_STATS_DEBUG("    Instance: %p", passive_mgr);

    // Boost
    void *boost_mgr = get_boost_prototype_manager();
    LOG_STATS_DEBUG("  BoostPrototypeManager:");
    LOG_STATS_DEBUG("    Ptr addr: %p", (void*)g_pBoostPrototypeManagerPtr);
    LOG_STATS_DEBUG("    Instance: %p", boost_mgr);

    // Interrupt
    void *interrupt_mgr = get_interrupt_prototype_manager();
    LOG_STATS_DEBUG("  InterruptPrototypeManager:");
    LOG_STATS_DEBUG("    Ptr addr: %p", (void*)g_pInterruptPrototypeManagerPtr);
    LOG_STATS_DEBUG("    Instance: %p", interrupt_mgr);

    // Spell
    void *spell_mgr = get_spell_prototype_manager();
    LOG_STATS_DEBUG("  SpellPrototypeManager:");
    LOG_STATS_DEBUG("    Ptr addr: %p", (void*)g_pSpellPrototypeManagerPtr);
    LOG_STATS_DEBUG("    Instance: %p", spell_mgr);

    // Status
    void *status_mgr = get_status_prototype_manager();
    LOG_STATS_DEBUG("  StatusPrototypeManager:");
    LOG_STATS_DEBUG("    Ptr addr: %p", (void*)g_pStatusPrototypeManagerPtr);
    LOG_STATS_DEBUG("    Instance: %p", status_mgr);

    LOG_STATS_DEBUG("");
    LOG_STATS_DEBUG("Sync Requirements:");
    LOG_STATS_DEBUG("  SpellData -> SpellPrototypeManager (singleton found at 0x1089bac80)");
    LOG_STATS_DEBUG("  StatusData -> StatusPrototypeManager (singleton found at 0x1089bdb30)");
    LOG_STATS_DEBUG("  PassiveData -> PassivePrototypeManager (singleton found at 0x108aeccd8)");
    LOG_STATS_DEBUG("  InterruptData -> InterruptPrototypeManager (singleton found at 0x108aecce0)");
    LOG_STATS_DEBUG("  BoostData -> BoostPrototypeManager (singleton found at 0x108991528)");
    LOG_STATS_DEBUG("  Weapon/Armor/etc -> No prototype manager (direct RPGStats use)");
}

void prototype_managers_probe(const char *manager_name) {
    if (!manager_name) return;

    LOG_STATS_DEBUG("=== Probing %s ===", manager_name);

    void *manager = NULL;

    if (strcmp(manager_name, "Passive") == 0) {
        manager = get_passive_prototype_manager();
    } else if (strcmp(manager_name, "Boost") == 0) {
        manager = get_boost_prototype_manager();
    } else if (strcmp(manager_name, "Interrupt") == 0) {
        manager = get_interrupt_prototype_manager();
    } else if (strcmp(manager_name, "Spell") == 0) {
        manager = get_spell_prototype_manager();
    } else if (strcmp(manager_name, "Status") == 0) {
        manager = get_status_prototype_manager();
    } else {
        LOG_STATS_DEBUG("Unknown manager: %s", manager_name);
        return;
    }

    if (!manager) {
        LOG_STATS_DEBUG("Manager not accessible");
        return;
    }

    LOG_STATS_DEBUG("Manager at: %p", manager);

    // Probe first 128 bytes of manager structure
    LOG_STATS_DEBUG("First 128 bytes:");
    for (int off = 0; off < 128; off += 8) {
        void *val = NULL;
        if (safe_read_ptr((char*)manager + off, &val)) {
            LOG_STATS_DEBUG("  +0x%02x: %p", off, val);
        }
    }

    // Try to find RefMap/HashMap patterns
    // Typical pattern: VMT, then Array<T*> (buf, cap, size), then HashMap
    LOG_STATS_DEBUG("");
    LOG_STATS_DEBUG("Looking for RefMap pattern (Array + HashMap):");

    // At offset 0x00: likely VMT
    void *vmt = NULL;
    safe_read_ptr(manager, &vmt);
    LOG_STATS_DEBUG("  VMT: %p", vmt);

    // At offset 0x08-0x18: likely Array (buf, cap, size)
    void *buf = NULL;
    uint32_t cap = 0, size = 0;
    safe_read_ptr((char*)manager + 0x08, &buf);
    safe_read_u32((char*)manager + 0x10, &cap);
    safe_read_u32((char*)manager + 0x14, &size);
    LOG_STATS_DEBUG("  Array: buf=%p cap=%u size=%u", buf, cap, size);

    if (buf && size > 0 && size < 10000) {
        LOG_STATS_DEBUG("  First 3 elements:");
        for (uint32_t i = 0; i < 3 && i < size; i++) {
            void *elem = NULL;
            if (safe_read_ptr((char*)buf + i * sizeof(void*), &elem)) {
                LOG_STATS_DEBUG("    [%u] = %p", i, elem);
            }
        }
    }
}
