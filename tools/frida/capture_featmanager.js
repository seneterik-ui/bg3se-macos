/**
 * capture_featmanager.js - Frida script to capture FeatManager pointer
 *
 * Usage:
 *   frida -n "Baldur's Gate 3" -l tools/frida/capture_featmanager.js
 *
 * Then navigate to Withers respec in game to trigger GetFeats call.
 *
 * Key insight: Interceptor.attach with onEnter ONLY captures arguments
 * WITHOUT replacing the function - game continues to work normally.
 */

'use strict';

// Module name with smart apostrophe as it appears in the binary
const BINARY_NAME = "Baldur's Gate 3";

// Offsets from Ghidra analysis (STATICDATA.md)
const OFFSETS = {
    // FeatManager::GetFeats function
    // Signature: void GetFeats(void* out_array, FeatManager* this)
    // ARM64: x0 = out_array, x1 = FeatManager*
    GetFeats: 0x01b752b4,

    // Alternative: GetAllFeats wrapper
    // Signature: void GetAllFeats(void* environment)
    // FeatManager accessed via environment + 0x130
    GetAllFeats: 0x0120b3e8,

    // FeatManager structure offsets (from GetFeats decompilation)
    FEATMANAGER_COUNT: 0x7C,   // int32_t count
    FEATMANAGER_ARRAY: 0x80,   // Feat* array pointer

    // Feat structure size
    FEAT_SIZE: 0x128  // 296 bytes per feat
};

// State
let capturedFeatManager = null;
let captureCount = 0;

function hexdump_preview(ptr, size) {
    try {
        const bytes = ptr.readByteArray(size);
        if (!bytes) return "null";
        const arr = new Uint8Array(bytes);
        let hex = "";
        for (let i = 0; i < Math.min(arr.length, 32); i++) {
            hex += arr[i].toString(16).padStart(2, '0') + " ";
        }
        return hex.trim() + (arr.length > 32 ? " ..." : "");
    } catch (e) {
        return "error: " + e.message;
    }
}

function readGuid(ptr) {
    try {
        const bytes = ptr.readByteArray(16);
        if (!bytes) return "null";
        const arr = new Uint8Array(bytes);

        // Format as standard GUID: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
        let guid = "";
        for (let i = 0; i < 4; i++) guid += arr[i].toString(16).padStart(2, '0');
        guid += "-";
        for (let i = 4; i < 6; i++) guid += arr[i].toString(16).padStart(2, '0');
        guid += "-";
        for (let i = 6; i < 8; i++) guid += arr[i].toString(16).padStart(2, '0');
        guid += "-";
        for (let i = 8; i < 10; i++) guid += arr[i].toString(16).padStart(2, '0');
        guid += "-";
        for (let i = 10; i < 16; i++) guid += arr[i].toString(16).padStart(2, '0');

        return guid;
    } catch (e) {
        return "error: " + e.message;
    }
}

function analyzeFeatManager(featManager) {
    console.log("\n[FeatManager Analysis]");
    console.log("  Address: " + featManager);

    try {
        // Read count at +0x7C
        const count = featManager.add(OFFSETS.FEATMANAGER_COUNT).readS32();
        console.log("  Count (+0x7C): " + count);

        // Read array pointer at +0x80
        const arrayPtr = featManager.add(OFFSETS.FEATMANAGER_ARRAY).readPointer();
        console.log("  Array (+0x80): " + arrayPtr);

        if (count > 0 && count < 1000 && !arrayPtr.isNull()) {
            console.log("\n[First 3 Feats]");
            for (let i = 0; i < Math.min(3, count); i++) {
                const featPtr = arrayPtr.add(i * OFFSETS.FEAT_SIZE);
                const guid = readGuid(featPtr);
                console.log("  [" + i + "] " + featPtr + " GUID: " + guid);

                // Preview first 32 bytes
                console.log("      Hex: " + hexdump_preview(featPtr, 32));
            }

            // Success indicator
            console.log("\n[SUCCESS] FeatManager captured with " + count + " feats");
            console.log("[INFO] Array pointer: " + arrayPtr);

            // Send to host
            send({
                type: "featmanager_captured",
                address: featManager.toString(),
                count: count,
                array: arrayPtr.toString(),
                sample_guids: []
            });

            return true;
        } else {
            console.log("[WARNING] Invalid count or null array");
            return false;
        }
    } catch (e) {
        console.log("[ERROR] " + e.message);
        return false;
    }
}

function main() {
    const base = Module.getBaseAddress(BINARY_NAME);
    if (!base) {
        console.log("[ERROR] Could not find module: " + BINARY_NAME);
        return;
    }

    console.log("[*] Base address: " + base);
    console.log("[*] Installing FeatManager hooks...\n");

    // Hook GetFeats - receives FeatManager* as second argument (x1)
    const getFeatsAddr = base.add(OFFSETS.GetFeats);
    console.log("[*] Hooking GetFeats at " + getFeatsAddr);

    Interceptor.attach(getFeatsAddr, {
        onEnter: function(args) {
            captureCount++;
            const outArray = args[0];
            const featManager = args[1];

            console.log("\n========================================");
            console.log("[GetFeats] Call #" + captureCount);
            console.log("  out_array (x0): " + outArray);
            console.log("  feat_manager (x1): " + featManager);

            if (!featManager.isNull() && !capturedFeatManager) {
                capturedFeatManager = featManager;
                analyzeFeatManager(featManager);
            } else if (capturedFeatManager) {
                // Check if same pointer
                if (featManager.equals(capturedFeatManager)) {
                    console.log("  [Already captured - same pointer]");
                } else {
                    console.log("  [WARNING] Different FeatManager pointer!");
                    console.log("  Previous: " + capturedFeatManager);
                    console.log("  Current:  " + featManager);
                }
            }
        }
        // NO onLeave - let original function execute normally
    });

    // Also hook GetAllFeats as backup
    const getAllFeatsAddr = base.add(OFFSETS.GetAllFeats);
    console.log("[*] Hooking GetAllFeats at " + getAllFeatsAddr);

    Interceptor.attach(getAllFeatsAddr, {
        onEnter: function(args) {
            const environment = args[0];
            console.log("\n[GetAllFeats] Called with environment: " + environment);

            // Try to extract FeatManager from environment + 0x130
            if (!environment.isNull()) {
                try {
                    const featManager = environment.add(0x130).readPointer();
                    console.log("  FeatManager (env+0x130): " + featManager);

                    if (!featManager.isNull() && !capturedFeatManager) {
                        capturedFeatManager = featManager;
                        analyzeFeatManager(featManager);
                    }
                } catch (e) {
                    console.log("  [Could not read env+0x130: " + e.message + "]");
                }
            }
        }
    });

    console.log("\n========================================");
    console.log("[*] Hooks installed successfully!");
    console.log("[*] Navigate to Withers respec to trigger GetFeats");
    console.log("[*] The game should work normally - hooks only observe");
    console.log("========================================\n");
}

main();
