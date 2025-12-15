// Capture real FeatManager from Environment object
// FeatManager is at Environment+0x130 (discovered via Ghidra disassembly)

var moduleBase = null;
Process.enumerateModules().forEach(function(m) {
    if (m.name.indexOf("Baldur") !== -1) {
        moduleBase = m.base;
        console.log("[+] Found module: " + m.name + " at " + moduleBase);
    }
});

if (!moduleBase) {
    console.log("[!] Could not find Baldur's Gate 3 module");
} else {
    // ApplyAndValidateLevelUp at 0x1011f344c
    // Takes Environment* as first parameter (x0)
    // FeatManager is at Environment+0x130
    var applyLevelUpAddr = moduleBase.add(0x1011f344c - 0x100000000);
    console.log("[+] ApplyAndValidateLevelUp at: " + applyLevelUpAddr);

    try {
        Interceptor.attach(applyLevelUpAddr, {
            onEnter: function(args) {
                var env = args[0];  // x0 = Environment*
                console.log("\n[LEVEL UP] ApplyAndValidateLevelUp called!");
                console.log("  Environment*: " + env);

                if (env && !env.isNull()) {
                    // FeatManager is at Environment+0x130
                    var featMgrPtr = env.add(0x130).readPointer();
                    console.log("  FeatManager* (env+0x130): " + featMgrPtr);

                    if (featMgrPtr && !featMgrPtr.isNull()) {
                        // Read count at +0x7C, array at +0x80
                        var count7c = featMgrPtr.add(0x7C).readU32();
                        var array80 = featMgrPtr.add(0x80).readPointer();
                        console.log("  FeatManager->count (+0x7C): " + count7c);
                        console.log("  FeatManager->array (+0x80): " + array80);

                        // Also check +0x00 for comparison
                        var count0 = featMgrPtr.add(0x00).readU32();
                        console.log("  FeatManager->+0x00: " + count0);

                        if (count7c > 0 && count7c < 1000 && array80 && !array80.isNull()) {
                            console.log("\n  *** FOUND REAL FEATMANAGER! ***");
                            console.log("  Address: " + featMgrPtr);
                            console.log("  Count: " + count7c);
                            console.log("  Array: " + array80);

                            // Try to read first feat
                            var firstFeat = array80.readPointer();
                            console.log("  First Feat*: " + firstFeat);
                        }
                    }
                }
            }
        });
        console.log("[+] Hooked ApplyAndValidateLevelUp");
    } catch (e) {
        console.log("[!] Failed to hook ApplyAndValidateLevelUp: " + e);
    }

    // Also hook GetAllFeats at 0x10120b3e8
    var getAllFeatsAddr = moduleBase.add(0x10120b3e8 - 0x100000000);
    console.log("[+] GetAllFeats at: " + getAllFeatsAddr);

    try {
        Interceptor.attach(getAllFeatsAddr, {
            onEnter: function(args) {
                var env = args[0];  // x0 = Environment* (const ref)
                console.log("\n[GET ALL FEATS] GetAllFeats called!");
                console.log("  Environment*: " + env);

                // Note: GetAllFeats takes Environment const& which might be different
                // Check if this is actually an Environment or something else
            }
        });
        console.log("[+] Hooked GetAllFeats");
    } catch (e) {
        console.log("[!] Failed to hook GetAllFeats: " + e);
    }

    // GetFeats at 0x101b752b4 - this gets FeatManager* in x1
    var getFeatsAddr = moduleBase.add(0x101b752b4 - 0x100000000);
    console.log("[+] GetFeats at: " + getFeatsAddr);

    try {
        Interceptor.attach(getFeatsAddr, {
            onEnter: function(args) {
                var outputBuffer = args[0];  // x0 = output array buffer
                var featMgr = args[1];       // x1 = FeatManager* (the real one!)

                console.log("\n[GET FEATS] GetFeats called!");
                console.log("  Output buffer: " + outputBuffer);
                console.log("  FeatManager*: " + featMgr);

                if (featMgr && !featMgr.isNull()) {
                    var count = featMgr.add(0x7C).readU32();
                    var array = featMgr.add(0x80).readPointer();
                    console.log("  Count (+0x7C): " + count);
                    console.log("  Array (+0x80): " + array);

                    if (count > 0 && count < 1000) {
                        console.log("\n  *** CAPTURED REAL FEATMANAGER! ***");
                        console.log("  Save this address for static capture: " + featMgr);

                        // Dump first few entries
                        if (array && !array.isNull()) {
                            for (var i = 0; i < Math.min(count, 3); i++) {
                                var featPtr = array.add(i * 0x128);  // 0x128 bytes per feat
                                console.log("  Feat[" + i + "]: " + featPtr);

                                // Try reading GUID at +8 and +16
                                try {
                                    var guid1 = featPtr.add(8).readByteArray(16);
                                    console.log("    GUID1: " + hexdump(guid1, {length: 16}));
                                } catch (e) {}
                            }
                        }
                    }
                }
            }
        });
        console.log("[+] Hooked GetFeats");
    } catch (e) {
        console.log("[!] Failed to hook GetFeats: " + e);
    }
}

console.log("\n[+] Hooks installed. Now trigger feat selection in-game (level up or respec)");

function hexdump(arr, opts) {
    var bytes = new Uint8Array(arr);
    var hex = "";
    for (var i = 0; i < bytes.length; i++) {
        hex += ("0" + bytes[i].toString(16)).slice(-2) + " ";
    }
    return hex.trim();
}
