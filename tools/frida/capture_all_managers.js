/**
 * Frida script to capture ALL StaticData manager pointers during character creation.
 *
 * Run with: frida -p <PID> -l capture_all_managers.js
 *
 * Navigate through character creation (race, class, background, origin, deity selection)
 * to trigger captures for all manager types.
 */

// Manager structure offsets (same for all managers)
const MANAGER_COUNT_OFFSET = 0x7C;
const MANAGER_ARRAY_OFFSET = 0x80;

// Expected entry sizes (from staticdata_manager.c)
const ENTRY_SIZES = {
    "Feat": 0x128,      // 296 bytes
    "Race": 0x200,      // 512 bytes estimate
    "Background": 0x80, // 128 bytes estimate
    "Origin": 0x180,    // 384 bytes estimate
    "God": 0x60,        // 96 bytes estimate
    "Class": 0x100      // 256 bytes estimate
};

// Output file paths
const OUTPUT_FILES = {
    "Feat": "/tmp/bg3se_featmanager.txt",
    "Race": "/tmp/bg3se_racemanager.txt",
    "Background": "/tmp/bg3se_backgroundmanager.txt",
    "Origin": "/tmp/bg3se_originmanager.txt",
    "God": "/tmp/bg3se_godmanager.txt",
    "Class": "/tmp/bg3se_classmanager.txt"
};

// Track captured managers
var capturedManagers = {};

// Find main binary base
var mainModule = null;
Process.enumerateModules().forEach(function(mod) {
    if (mod.name.indexOf("Baldur") !== -1 && mod.name.indexOf(".dylib") === -1) {
        mainModule = mod;
    }
});

if (!mainModule) {
    var largest = null;
    Process.enumerateModules().forEach(function(mod) {
        if (!largest || mod.size > largest.size) {
            largest = mod;
        }
    });
    mainModule = largest;
}

console.log("[*] Main module: " + mainModule.name + " @ " + mainModule.base);

/**
 * Validate a potential manager pointer by checking structure
 */
function validateManager(ptr, expectedType) {
    try {
        var count = ptr.add(MANAGER_COUNT_OFFSET).readU32();
        var array = ptr.add(MANAGER_ARRAY_OFFSET).readPointer();

        // Validate: reasonable count, non-null array
        if (count > 0 && count < 5000 && !array.isNull()) {
            // Try to read first entry to verify array is valid
            var firstEntry = array.readPointer();
            if (!firstEntry.isNull() || count === 0) {
                return { count: count, array: array };
            }
        }
    } catch (e) {
        // Memory read error - invalid pointer
    }
    return null;
}

/**
 * Write manager info to capture file
 */
function writeCapture(type, ptr, info) {
    var outputPath = OUTPUT_FILES[type];
    if (!outputPath) return;

    try {
        var file = new File(outputPath, "w");
        file.write(ptr.toString() + "\n");
        file.write(info.count.toString() + "\n");
        file.write(info.array.toString() + "\n");
        file.close();
        console.log("[+] Wrote " + type + " to " + outputPath);
    } catch (e) {
        console.log("[!] Failed to write " + type + ": " + e);
    }
}

/**
 * Try to capture a manager from function arguments
 */
function tryCapture(funcName, args, type) {
    if (capturedManagers[type]) return; // Already captured

    // Try different argument positions
    for (var i = 0; i < 4; i++) {
        var ptr = args[i];
        if (ptr && !ptr.isNull()) {
            var info = validateManager(ptr, type);
            if (info) {
                console.log("\n[+] " + funcName + " - Found " + type + "Manager at arg[" + i + "]: " + ptr);
                console.log("    count = " + info.count);
                console.log("    array = " + info.array);

                capturedManagers[type] = ptr;
                writeCapture(type, ptr, info);
                return true;
            }
        }
    }
    return false;
}

// ============================================================================
// Known function hooks (from Ghidra analysis)
// ============================================================================

// FeatManager::GetFeats at offset 0x01b752b4
var getFeatsAddr = mainModule.base.add(0x01b752b4);
try {
    Interceptor.attach(getFeatsAddr, {
        onEnter: function(args) {
            tryCapture("GetFeats", args, "Feat");
        }
    });
    console.log("[*] Hooked GetFeats @ " + getFeatsAddr);
} catch (e) {
    console.log("[!] Failed to hook GetFeats: " + e);
}

// GetAllFeats at offset 0x0120b3e8
var getAllFeatsAddr = mainModule.base.add(0x0120b3e8);
try {
    Interceptor.attach(getAllFeatsAddr, {
        onEnter: function(args) {
            tryCapture("GetAllFeats", args, "Feat");
        }
    });
    console.log("[*] Hooked GetAllFeats @ " + getAllFeatsAddr);
} catch (e) {
    console.log("[!] Failed to hook GetAllFeats: " + e);
}

// ============================================================================
// TypeContext-based discovery (backup approach)
// ============================================================================

// ImmutableDataHeadmaster::m_State pointer location
// From STATICDATA.md: PTR_m_State_1083c4a68
var mStatePtr = mainModule.base.add(0x083c4a68);

/**
 * Traverse TypeContext linked list to find managers
 */
function traverseTypeContext() {
    console.log("\n[*] Traversing TypeContext...");

    try {
        var ptrToMState = mStatePtr.readPointer();
        if (ptrToMState.isNull()) {
            console.log("[!] m_State is null - game not fully loaded?");
            return;
        }

        // Head of TypeInfo linked list at m_State + 8
        var typeInfo = ptrToMState.add(8).readPointer();
        var count = 0;
        var maxIter = 200;

        while (!typeInfo.isNull() && count < maxIter) {
            try {
                var mgrPtr = typeInfo.readPointer();           // +0x00: manager ptr
                var namePtr = typeInfo.add(8).readPointer();   // +0x08: type name
                var nextPtr = typeInfo.add(0x18).readPointer(); // +0x18: next

                // Try to read type name as C string
                var typeName = "";
                try {
                    typeName = namePtr.readCString();
                } catch (e) {
                    // May be FixedString, skip
                }

                // Check for known manager types
                var managerType = null;
                if (typeName.indexOf("RaceManager") !== -1) managerType = "Race";
                else if (typeName.indexOf("OriginManager") !== -1) managerType = "Origin";
                else if (typeName.indexOf("GodManager") !== -1) managerType = "God";
                else if (typeName.indexOf("BackgroundManager") !== -1) managerType = "Background";
                else if (typeName.indexOf("ClassDescription") !== -1) managerType = "Class";

                if (managerType && !capturedManagers[managerType]) {
                    var info = validateManager(mgrPtr, managerType);
                    if (info) {
                        console.log("[+] TypeContext found " + managerType + "Manager: " + mgrPtr);
                        console.log("    count = " + info.count + ", array = " + info.array);
                        capturedManagers[managerType] = mgrPtr;
                        writeCapture(managerType, mgrPtr, info);
                    }
                }

                typeInfo = nextPtr;
                count++;
            } catch (e) {
                break;
            }
        }

        console.log("[*] Traversed " + count + " TypeInfo entries");
    } catch (e) {
        console.log("[!] TypeContext traversal error: " + e);
    }
}

// Try TypeContext traversal after a delay (game needs to load)
setTimeout(function() {
    traverseTypeContext();
}, 2000);

// ============================================================================
// Status and manual triggers
// ============================================================================

function printStatus() {
    console.log("\n=== Capture Status ===");
    for (var type in OUTPUT_FILES) {
        var status = capturedManagers[type] ? "CAPTURED @ " + capturedManagers[type] : "Not captured";
        console.log("  " + type + ": " + status);
    }
    console.log("=====================\n");
}

// Export functions for manual use
global.status = printStatus;
global.rescan = traverseTypeContext;

console.log("\n[*] Multi-manager capture script loaded");
console.log("[*] Navigate through character creation to trigger captures");
console.log("[*] Commands: status() - show capture status, rescan() - retry TypeContext");
console.log("[*] Press Ctrl+C to detach\n");

// Print initial status after delay
setTimeout(printStatus, 3000);
