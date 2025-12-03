/**
 * fixed_string.c - FixedString Resolution Implementation
 *
 * Resolves FixedString indices to actual string values by accessing
 * the GlobalStringTable at runtime.
 *
 * Discovery Strategy:
 * 1. Try dlsym for mangled C++ symbol
 * 2. Use known offset from binary analysis (if available)
 * 3. Pattern scan for ADRP+LDR sequences (fallback)
 */

#include "fixed_string.h"
#include "../core/logging.h"
#include <mach/mach.h>
#include <mach-o/dyld.h>
#include <dlfcn.h>
#include <string.h>
#include <stdlib.h>

// ============================================================================
// Module State
// ============================================================================

static void **g_pGlobalStringTable = NULL;  // Pointer to GlobalStringTable*
static void *g_MainBinaryBase = NULL;
static bool g_Initialized = false;

// Runtime-discovered offsets (may differ from Windows x64)
static uint32_t g_OffsetBuckets = SUBTABLE_OFFSET_BUCKETS;
static uint32_t g_OffsetNumBuckets = SUBTABLE_OFFSET_NUM_BUCKETS;
static uint32_t g_OffsetEntrySize = SUBTABLE_OFFSET_ENTRY_SIZE;
static uint32_t g_OffsetEntriesPerBucket = SUBTABLE_OFFSET_ENTRIES_PER_BKT;
static uint32_t g_SubTableSize = SUBTABLE_SIZE;

// Statistics
static uint32_t g_ResolvedCount = 0;
static uint32_t g_FailedCount = 0;

// ============================================================================
// Safe Memory Access (pattern from stats_manager.c)
// ============================================================================

static bool safe_read_ptr(void *addr, void **out) {
    if (!addr || !out) return false;

    mach_port_t task = mach_task_self();
    mach_msg_type_number_t bytes_read = 0;
    vm_offset_t buffer = 0;

    kern_return_t kr = vm_read(task, (vm_address_t)addr, sizeof(void *),
                               &buffer, &bytes_read);
    if (kr != KERN_SUCCESS || bytes_read != sizeof(void *)) {
        return false;
    }

    *out = *(void **)buffer;
    vm_deallocate(task, buffer, bytes_read);
    return true;
}

static bool safe_read_u32(void *addr, uint32_t *out) {
    if (!addr || !out) return false;

    mach_port_t task = mach_task_self();
    mach_msg_type_number_t bytes_read = 0;
    vm_offset_t buffer = 0;

    kern_return_t kr = vm_read(task, (vm_address_t)addr, sizeof(uint32_t),
                               &buffer, &bytes_read);
    if (kr != KERN_SUCCESS || bytes_read != sizeof(uint32_t)) {
        return false;
    }

    *out = *(uint32_t *)buffer;
    vm_deallocate(task, buffer, bytes_read);
    return true;
}

static bool safe_read_u64(void *addr, uint64_t *out) {
    if (!addr || !out) return false;

    mach_port_t task = mach_task_self();
    mach_msg_type_number_t bytes_read = 0;
    vm_offset_t buffer = 0;

    kern_return_t kr = vm_read(task, (vm_address_t)addr, sizeof(uint64_t),
                               &buffer, &bytes_read);
    if (kr != KERN_SUCCESS || bytes_read != sizeof(uint64_t)) {
        return false;
    }

    *out = *(uint64_t *)buffer;
    vm_deallocate(task, buffer, bytes_read);
    return true;
}

static bool safe_read_bytes(void *addr, void *out, size_t len) {
    if (!addr || !out || len == 0) return false;

    mach_port_t task = mach_task_self();
    mach_msg_type_number_t bytes_read = 0;
    vm_offset_t buffer = 0;

    kern_return_t kr = vm_read(task, (vm_address_t)addr, (vm_size_t)len,
                               &buffer, &bytes_read);
    if (kr != KERN_SUCCESS || bytes_read != len) {
        return false;
    }

    memcpy(out, (void *)buffer, len);
    vm_deallocate(task, buffer, bytes_read);
    return true;
}

// ============================================================================
// Ghidra Offset (for fallback when dlsym fails)
// ============================================================================

// Ghidra analysis shows gGlobalStringTable is typically a static pointer
// TODO: Find actual offset via Ghidra search for "GlobalStringTable" string xrefs
// Placeholder - needs to be discovered for macOS ARM64 binary
#define GHIDRA_BASE_ADDRESS           0x100000000ULL
#define OFFSET_GLOBAL_STRING_TABLE    0x0ULL  // Set to 0 = not yet discovered

// ============================================================================
// Symbol Discovery
// ============================================================================

static void *try_dlsym_discovery(void) {
    void *handle = dlopen(NULL, RTLD_NOW);
    if (!handle) {
        log_message("[FixedString] dlopen(NULL) failed");
        return NULL;
    }

    // Try various mangled names for gGlobalStringTable
    const char *symbol_names[] = {
        "_ZN2ls19gGlobalStringTableE",      // ls::gGlobalStringTable
        "__ZN2ls19gGlobalStringTableE",     // macOS leading underscore
        "_ZN2ls18GlobalStringTableE",       // Alternate
        "__ZN2ls18GlobalStringTableE",
        "ls__gGlobalStringTable",           // C-style mangling
        "_ls__gGlobalStringTable",
        NULL
    };

    for (int i = 0; symbol_names[i]; i++) {
        void *sym = dlsym(handle, symbol_names[i]);
        if (sym) {
            log_message("[FixedString] Found via dlsym('%s'): %p",
                       symbol_names[i], sym);
            return sym;
        }
    }

    log_message("[FixedString] dlsym discovery failed - symbol not exported");
    return NULL;
}

// ============================================================================
// Runtime Offset Probing
// ============================================================================

/**
 * Probe a potential SubTable at the given base address.
 * Returns true if it looks like a valid SubTable.
 */
static bool probe_subtable(void *subtable_base, int *out_num_buckets,
                           uint64_t *out_entry_size, void **out_buckets) {
    if (!subtable_base) return false;

    // Try reading fields at Windows x64 offsets
    uint32_t num_buckets = 0;
    uint32_t entries_per_bucket = 0;
    uint64_t entry_size = 0;
    void *buckets = NULL;

    if (!safe_read_u32((char *)subtable_base + g_OffsetNumBuckets, &num_buckets)) {
        return false;
    }

    if (!safe_read_u64((char *)subtable_base + g_OffsetEntrySize, &entry_size)) {
        return false;
    }

    if (!safe_read_u32((char *)subtable_base + g_OffsetEntriesPerBucket, &entries_per_bucket)) {
        return false;
    }

    if (!safe_read_ptr((char *)subtable_base + g_OffsetBuckets, &buckets)) {
        return false;
    }

    // Sanity checks for valid SubTable
    if (num_buckets == 0 || num_buckets > 0x100000) return false;
    if (entry_size == 0 || entry_size > 0x1000) return false;
    if (entries_per_bucket == 0 || entries_per_bucket > 0x10000) return false;
    if (!buckets || (uintptr_t)buckets < 0x100000000ULL) return false;

    // Try to read first bucket
    void *first_bucket = NULL;
    if (!safe_read_ptr(buckets, &first_bucket) || !first_bucket) {
        return false;
    }

    if (out_num_buckets) *out_num_buckets = (int)num_buckets;
    if (out_entry_size) *out_entry_size = entry_size;
    if (out_buckets) *out_buckets = buckets;

    return true;
}

/**
 * Try different offset configurations to find working SubTable layout.
 */
bool fixed_string_probe_offsets(void) {
    if (!g_pGlobalStringTable || !*g_pGlobalStringTable) {
        log_message("[FixedString] Cannot probe - GlobalStringTable not found");
        return false;
    }

    void *gst = NULL;
    if (!safe_read_ptr(g_pGlobalStringTable, &gst) || !gst) {
        log_message("[FixedString] Cannot read GlobalStringTable pointer");
        return false;
    }

    log_message("[FixedString] GlobalStringTable at %p", gst);

    // Try Windows x64 offsets first
    void *subtable0 = gst;  // First SubTable at offset 0

    int num_buckets = 0;
    uint64_t entry_size = 0;
    void *buckets = NULL;

    if (probe_subtable(subtable0, &num_buckets, &entry_size, &buckets)) {
        log_message("[FixedString] SubTable[0] valid with Windows offsets:");
        log_message("[FixedString]   NumBuckets=%d EntrySize=%llu Buckets=%p",
                   num_buckets, entry_size, buckets);
        return true;
    }

    // Try alternate offset configurations for ARM64
    // ARM64 may have different alignment/padding
    struct {
        uint32_t buckets;
        uint32_t num_buckets;
        uint32_t entry_size;
        uint32_t entries_per_bucket;
        const char *name;
    } offset_configs[] = {
        // Windows x64 baseline
        { 0x1140, 0x10C0, 0x1088, 0x1090, "Windows x64" },
        // Possible ARM64 variants (more compact)
        { 0x0B40, 0x0AC0, 0x0A88, 0x0A90, "ARM64 compact" },
        { 0x02B8, 0x0268, 0x0248, 0x0250, "ARM64 minimal" },
        // Aligned variants
        { 0x1180, 0x1100, 0x10C0, 0x10C8, "Aligned variant 1" },
        { 0x1200, 0x1180, 0x1140, 0x1148, "Aligned variant 2" },
        { 0, 0, 0, 0, NULL }
    };

    for (int i = 0; offset_configs[i].name; i++) {
        g_OffsetBuckets = offset_configs[i].buckets;
        g_OffsetNumBuckets = offset_configs[i].num_buckets;
        g_OffsetEntrySize = offset_configs[i].entry_size;
        g_OffsetEntriesPerBucket = offset_configs[i].entries_per_bucket;

        if (probe_subtable(subtable0, &num_buckets, &entry_size, &buckets)) {
            log_message("[FixedString] Found working offsets: %s",
                       offset_configs[i].name);
            log_message("[FixedString]   Buckets=0x%x NumBuckets=0x%x "
                       "EntrySize=0x%x EntriesPerBucket=0x%x",
                       g_OffsetBuckets, g_OffsetNumBuckets,
                       g_OffsetEntrySize, g_OffsetEntriesPerBucket);
            return true;
        }
    }

    log_message("[FixedString] Offset probing failed - no valid configuration found");
    return false;
}

// ============================================================================
// Initialization
// ============================================================================

void fixed_string_init(void *main_binary_base) {
    if (g_Initialized) {
        log_message("[FixedString] Already initialized");
        return;
    }

    g_MainBinaryBase = main_binary_base;
    log_message("[FixedString] Initializing with binary base %p", main_binary_base);

    // Try dlsym first
    g_pGlobalStringTable = try_dlsym_discovery();

    if (g_pGlobalStringTable) {
        void *gst = NULL;
        if (safe_read_ptr(g_pGlobalStringTable, &gst) && gst) {
            log_message("[FixedString] GlobalStringTable = %p", gst);

            // Probe for correct offsets
            if (fixed_string_probe_offsets()) {
                g_Initialized = true;
                log_message("[FixedString] Initialization complete");
                return;
            }
        }
    }

    // Fallback: Use Ghidra offset if available
    if (OFFSET_GLOBAL_STRING_TABLE != 0 && g_MainBinaryBase) {
        uintptr_t runtime_addr = (uintptr_t)g_MainBinaryBase +
                                  (OFFSET_GLOBAL_STRING_TABLE - GHIDRA_BASE_ADDRESS);
        g_pGlobalStringTable = (void **)runtime_addr;
        log_message("[FixedString] Using Ghidra offset: %p (base %p + 0x%llx)",
                   (void *)g_pGlobalStringTable, g_MainBinaryBase,
                   (unsigned long long)(OFFSET_GLOBAL_STRING_TABLE - GHIDRA_BASE_ADDRESS));

        void *gst = NULL;
        if (safe_read_ptr(g_pGlobalStringTable, &gst) && gst) {
            log_message("[FixedString] GlobalStringTable = %p", gst);

            if (fixed_string_probe_offsets()) {
                g_Initialized = true;
                log_message("[FixedString] Initialization complete via Ghidra offset");
                return;
            }
        }
    }

    // If all discovery methods failed
    log_message("[FixedString] WARNING: GlobalStringTable not found");
    log_message("[FixedString] FixedString resolution will not work until "
               "offset is discovered via Ghidra");
    log_message("[FixedString] To find offset: search Ghidra for 'gGlobalStringTable' "
               "or 'GlobalStringTable' string xrefs");

    g_Initialized = true;  // Mark as initialized even if not working
}

// ============================================================================
// Resolution
// ============================================================================

const char *fixed_string_resolve(uint32_t index) {
    if (index == FS_NULL_INDEX) {
        return NULL;
    }

    if (!g_pGlobalStringTable) {
        g_FailedCount++;
        return NULL;
    }

    void *gst = NULL;
    if (!safe_read_ptr(g_pGlobalStringTable, &gst) || !gst) {
        g_FailedCount++;
        return NULL;
    }

    // Decode index
    uint32_t subTableIdx = index & FS_SUBTABLE_MASK;
    uint32_t bucketIdx = (index >> FS_BUCKET_SHIFT) & FS_BUCKET_MASK;
    uint32_t entryIdx = index >> FS_ENTRY_SHIFT;

    // Bounds check
    if (subTableIdx >= GST_NUM_SUBTABLES) {
        g_FailedCount++;
        return NULL;
    }

    // Calculate SubTable address
    void *subTable = (char *)gst + (subTableIdx * g_SubTableSize);

    // Read SubTable fields
    uint32_t numBuckets = 0;
    uint32_t entriesPerBucket = 0;
    uint64_t entrySize = 0;
    void *buckets = NULL;

    if (!safe_read_u32((char *)subTable + g_OffsetNumBuckets, &numBuckets) ||
        !safe_read_u32((char *)subTable + g_OffsetEntriesPerBucket, &entriesPerBucket) ||
        !safe_read_u64((char *)subTable + g_OffsetEntrySize, &entrySize) ||
        !safe_read_ptr((char *)subTable + g_OffsetBuckets, &buckets)) {
        g_FailedCount++;
        return NULL;
    }

    // Bounds check
    if (bucketIdx >= numBuckets || entryIdx >= entriesPerBucket) {
        g_FailedCount++;
        return NULL;
    }

    if (!buckets) {
        g_FailedCount++;
        return NULL;
    }

    // Get bucket pointer
    void *bucket = NULL;
    if (!safe_read_ptr((char *)buckets + bucketIdx * sizeof(void *), &bucket) || !bucket) {
        g_FailedCount++;
        return NULL;
    }

    // Calculate entry address
    void *entry = (char *)bucket + (entryIdx * entrySize);

    // Read string length from header to validate
    uint32_t strLength = 0;
    if (!safe_read_u32((char *)entry + 0x08, &strLength)) {
        g_FailedCount++;
        return NULL;
    }

    // Sanity check length
    if (strLength == 0 || strLength > 4096) {
        g_FailedCount++;
        return NULL;
    }

    // String is at entry + 0x18 (after header)
    // Return pointer to string data (caller must treat as read-only)
    g_ResolvedCount++;
    return (const char *)((char *)entry + STRING_ENTRY_HEADER_SIZE);
}

// ============================================================================
// Utility Functions
// ============================================================================

bool fixed_string_is_valid(uint32_t index) {
    return index != FS_NULL_INDEX;
}

bool fixed_string_is_ready(void) {
    return g_Initialized && g_pGlobalStringTable && *g_pGlobalStringTable;
}

void fixed_string_get_stats(uint32_t *out_resolved, uint32_t *out_failed) {
    if (out_resolved) *out_resolved = g_ResolvedCount;
    if (out_failed) *out_failed = g_FailedCount;
}

// ============================================================================
// Debug Functions
// ============================================================================

void fixed_string_dump_subtable_info(int subtable_idx) {
    if (subtable_idx < 0 || subtable_idx >= GST_NUM_SUBTABLES) {
        log_message("[FixedString] Invalid SubTable index: %d", subtable_idx);
        return;
    }

    if (!g_pGlobalStringTable || !*g_pGlobalStringTable) {
        log_message("[FixedString] GlobalStringTable not available");
        return;
    }

    void *gst = NULL;
    if (!safe_read_ptr(g_pGlobalStringTable, &gst) || !gst) {
        log_message("[FixedString] Cannot read GlobalStringTable");
        return;
    }

    void *subTable = (char *)gst + (subtable_idx * g_SubTableSize);

    uint32_t numBuckets = 0;
    uint32_t entriesPerBucket = 0;
    uint64_t entrySize = 0;
    void *buckets = NULL;

    safe_read_u32((char *)subTable + g_OffsetNumBuckets, &numBuckets);
    safe_read_u32((char *)subTable + g_OffsetEntriesPerBucket, &entriesPerBucket);
    safe_read_u64((char *)subTable + g_OffsetEntrySize, &entrySize);
    safe_read_ptr((char *)subTable + g_OffsetBuckets, &buckets);

    log_message("[FixedString] SubTable[%d] at %p:", subtable_idx, subTable);
    log_message("[FixedString]   NumBuckets: %u", numBuckets);
    log_message("[FixedString]   EntriesPerBucket: %u", entriesPerBucket);
    log_message("[FixedString]   EntrySize: %llu", entrySize);
    log_message("[FixedString]   Buckets: %p", buckets);

    // Try to read first string
    if (buckets && numBuckets > 0 && entrySize > 0) {
        void *firstBucket = NULL;
        if (safe_read_ptr(buckets, &firstBucket) && firstBucket) {
            // First entry in first bucket
            void *entry = firstBucket;
            char strBuf[64] = {0};

            if (safe_read_bytes((char *)entry + STRING_ENTRY_HEADER_SIZE,
                               strBuf, sizeof(strBuf) - 1)) {
                log_message("[FixedString]   First string: \"%s\"", strBuf);
            }
        }
    }
}
