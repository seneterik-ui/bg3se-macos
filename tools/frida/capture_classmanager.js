/**
 * Frida script to capture ClassDescriptionManager pointer during character creation.
 *
 * Run with: frida -p <PID> -l capture_classmanager.js
 *
 * Trigger: Navigate to class selection in character creation.
 *
 * NOTE: ClassDescription has a 16-byte ParentGuid before the Name field,
 * so Name is at offset +0x28 instead of +0x18.
 */

const MANAGER_COUNT_OFFSET = 0x7C;
const MANAGER_ARRAY_OFFSET = 0x80;
const CLASS_SIZE = 0x100;  // 256 bytes per class (estimate)
const OUTPUT_FILE = "/tmp/bg3se_classmanager.txt";

var mainModule = null;
Process.enumerateModules().forEach(function(mod) {
    if (mod.name.indexOf("Baldur") !== -1 && mod.name.indexOf(".dylib") === -1) {
        mainModule = mod;
    }
});
if (!mainModule) {
    Process.enumerateModules().forEach(function(mod) {
        if (!mainModule || mod.size > mainModule.size) mainModule = mod;
    });
}
console.log("[*] Main module: " + mainModule.name + " @ " + mainModule.base);

var capturedManager = null;

function validateAndCapture(funcName, ptr, argIndex) {
    if (capturedManager) return;
    if (!ptr || ptr.isNull()) return;

    try {
        var count = ptr.add(MANAGER_COUNT_OFFSET).readU32();
        var array = ptr.add(MANAGER_ARRAY_OFFSET).readPointer();

        // Classes: expect 12-50 entries (12 base classes + subclasses)
        if (count >= 10 && count < 200 && !array.isNull()) {
            console.log("\n[+] " + funcName + " - Found ClassManager candidate at arg[" + argIndex + "]: " + ptr);
            console.log("    count@+0x7C = " + count);
            console.log("    array@+0x80 = " + array);

            // Verify first entry has valid GUID at +0x08
            var firstEntry = array;
            var guidBytes = firstEntry.add(0x08).readByteArray(16);
            console.log("    First entry GUID: " + hexdump(guidBytes, {header:false,ansi:false}).split('\n')[0]);

            capturedManager = ptr;

            var file = new File(OUTPUT_FILE, "w");
            file.write(ptr.toString() + "\n");
            file.write(count.toString() + "\n");
            file.write(array.toString() + "\n");
            file.close();

            console.log("[+] Wrote ClassManager to " + OUTPUT_FILE);
            console.log("[+] In BG3SE: Ext.StaticData.LoadFridaCapture('Class')");
        }
    } catch (e) {
        // Invalid pointer
    }
}

// TypeContext traversal for ClassDescriptionManager
var mStatePtr = mainModule.base.add(0x083c4a68);

function findViaTypeContext() {
    if (capturedManager) return;
    console.log("\n[*] Scanning TypeContext for ClassDescriptionManager...");

    try {
        var ptrToMState = mStatePtr.readPointer();
        if (ptrToMState.isNull()) return;

        var typeInfo = ptrToMState.add(8).readPointer();
        var count = 0;

        while (!typeInfo.isNull() && count < 200) {
            try {
                var mgrPtr = typeInfo.readPointer();
                var namePtr = typeInfo.add(8).readPointer();
                var nextPtr = typeInfo.add(0x18).readPointer();

                var typeName = "";
                try { typeName = namePtr.readCString(); } catch (e) {}

                // ClassDescriptions or ClassDescriptionManager
                if (typeName.indexOf("ClassDescription") !== -1) {
                    console.log("[+] Found ClassDescriptionManager in TypeContext: " + mgrPtr);
                    validateAndCapture("TypeContext", mgrPtr, 0);
                    return;
                }

                typeInfo = nextPtr;
                count++;
            } catch (e) { break; }
        }

        console.log("[!] ClassDescriptionManager not found in TypeContext");
        console.log("[*] May need to navigate to class selection to trigger loading");
    } catch (e) {
        console.log("[!] TypeContext error: " + e);
    }
}

// Try TypeContext after game loads
setTimeout(findViaTypeContext, 2000);

console.log("\n[*] ClassManager capture script loaded");
console.log("[*] Navigate to class selection in character creation");
console.log("[*] Press Ctrl+C to detach\n");
