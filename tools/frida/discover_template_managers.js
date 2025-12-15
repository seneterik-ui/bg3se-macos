/**
 * Frida script to discover template manager access patterns.
 * Run with: frida -U -n "Baldur's Gate 3" -l discover_template_managers.js
 *
 * Hooks known template-related functions to capture GlobalTemplateBank,
 * CacheTemplateManager, and LocalTemplateManager pointers.
 */

// Known offsets from MULTI_ISSUE.md and Ghidra analysis
const OFFSETS = {
    // ActionData::Visit functions that take GameObjectTemplate* param
    IActionDataVisit: 0x1011233b0,        // eoc::IActionData::Visit
    PlaySoundActionVisit: 0x10112395c,    // eoc::PlaySoundActionData::Visit
    DisarmTrapActionVisit: 0x101123da8,   // eoc::DisarmTrapActionData::Visit
    BookActionVisit: 0x101124260,         // eoc::BookActionData::Visit

    // TypeContext registrations (template managers register here)
    RegisterCampChestTM: 0x100c676f4,     // RegisterType<CampChestTemplateManager>
    RegisterAvatarContainerTM: 0x100c67bd4, // RegisterType<AvatarContainerTemplateManager>

    // TeleportCharacter (uses GameObjectTemplate)
    TeleportCharacter: 0x10d6718,
};

// String addresses for reference
const STRINGS = {
    RootTemplate: 0x107b6af72,
    Templates: 0x107b45f61,
};

// Find main binary
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

// Utility: Dump memory around a pointer
function dumpAround(ptr, name, size) {
    size = size || 0x80;
    try {
        console.log("\n[+] " + name + " @ " + ptr);
        console.log(hexdump(ptr, { offset: 0, length: size, header: true, ansi: true }));
    } catch(e) {
        console.log("    [!] Cannot read memory at " + ptr);
    }
}

// Utility: Try to read FixedString index and resolve
function tryReadFixedString(ptr, offset) {
    try {
        var fs = ptr.add(offset).readU32();
        return "fs_idx=0x" + fs.toString(16);
    } catch(e) {
        return "error";
    }
}

// Utility: Check if pointer looks valid
function isValidPtr(p) {
    try {
        if (p.isNull()) return false;
        var val = p.readU64();
        return true;
    } catch(e) {
        return false;
    }
}

// Track captured managers
var capturedManagers = {
    GlobalTemplateBank: null,
    CacheTemplateManager: null,
    LocalTemplateManager: null,
    templates: []
};

// Hook IActionData::Visit - takes (ObjectVisitor*, GameObjectTemplate*)
// Third param (x2) is GameObjectTemplate*
function hookActionDataVisit(name, offset) {
    var addr = mainModule.base.add(offset);
    console.log("[*] Hooking " + name + " @ " + addr);

    try {
        Interceptor.attach(addr, {
            onEnter: function(args) {
                // args[0] = this (IActionData*)
                // args[1] = ObjectVisitor*
                // args[2] = GameObjectTemplate const*
                var tmpl = args[2];

                if (tmpl && !tmpl.isNull() && isValidPtr(tmpl)) {
                    console.log("\n[+] " + name + " called with template @ " + tmpl);

                    // Try to read template fields (based on GameObjectTemplate struct)
                    try {
                        var vmt = tmpl.readPointer();
                        var tags = tmpl.add(0x08).readPointer();
                        var id_fs = tmpl.add(0x10).readU32();
                        var templateName_fs = tmpl.add(0x14).readU32();
                        var parentId_fs = tmpl.add(0x18).readU32();
                        var handle = tmpl.add(0x1C).readU32();

                        console.log("    VMT: " + vmt);
                        console.log("    Id (fs): 0x" + id_fs.toString(16));
                        console.log("    TemplateName (fs): 0x" + templateName_fs.toString(16));
                        console.log("    ParentId (fs): 0x" + parentId_fs.toString(16));
                        console.log("    Handle: 0x" + handle.toString(16));

                        // Store unique templates
                        var tmplAddr = tmpl.toString();
                        if (capturedManagers.templates.indexOf(tmplAddr) === -1) {
                            capturedManagers.templates.push(tmplAddr);
                            console.log("    [*] New template captured (#" + capturedManagers.templates.length + ")");

                            // Save to file
                            saveCapture();
                        }
                    } catch(e) {
                        console.log("    [!] Error reading template: " + e);
                    }
                }
            }
        });
    } catch(e) {
        console.log("[!] Failed to hook " + name + ": " + e);
    }
}

// Hook RegisterType functions to capture when template managers initialize
function hookRegisterType(name, offset) {
    var addr = mainModule.base.add(offset);
    console.log("[*] Hooking " + name + " @ " + addr);

    try {
        Interceptor.attach(addr, {
            onEnter: function(args) {
                console.log("\n[+] " + name + " called!");
                console.log("    x0 (TypeContext*): " + args[0]);
                console.log("    x1 (int* output): " + args[1]);

                // Dump context
                if (args[0] && !args[0].isNull()) {
                    dumpAround(args[0], "TypeContext", 0x40);
                }
            },
            onLeave: function(retval) {
                console.log("    returned: " + retval);
            }
        });
    } catch(e) {
        console.log("[!] Failed to hook " + name + ": " + e);
    }
}

// Save captured data to file
function saveCapture() {
    var outputPath = "/tmp/bg3se_templates.txt";
    var content = "";
    content += "# Captured templates\n";
    content += "count=" + capturedManagers.templates.length + "\n";
    for (var i = 0; i < capturedManagers.templates.length; i++) {
        content += "template[" + i + "]=" + capturedManagers.templates[i] + "\n";
    }

    var file = new File(outputPath, "w");
    file.write(content);
    file.close();
    console.log("[*] Saved capture to " + outputPath);
}

// Scan memory for "RootTemplate" string references
function scanForTemplateStrings() {
    console.log("\n[*] Scanning for template-related strings...");

    var patterns = [
        { name: "RootTemplate", pattern: "526f6f7454656d706c617465" }, // "RootTemplate" hex
        { name: "Templates/", pattern: "54656d706c617465732f" },       // "Templates/" hex
    ];

    patterns.forEach(function(p) {
        console.log("[*] Searching for: " + p.name);
        var results = Memory.scanSync(mainModule.base, mainModule.size, p.pattern);
        console.log("    Found " + results.length + " matches");
        results.slice(0, 3).forEach(function(r) {
            console.log("      @ " + r.address);
        });
    });
}

// Install hooks
console.log("\n[*] Installing hooks...\n");

// Hook ActionData::Visit functions
hookActionDataVisit("IActionData::Visit", OFFSETS.IActionDataVisit);
hookActionDataVisit("PlaySoundActionData::Visit", OFFSETS.PlaySoundActionVisit);
hookActionDataVisit("DisarmTrapActionData::Visit", OFFSETS.DisarmTrapActionVisit);
hookActionDataVisit("BookActionData::Visit", OFFSETS.BookActionVisit);

// Hook TypeContext registration (fires during init)
// Note: These may have already fired by the time we attach
// hookRegisterType("RegisterType<CampChestTemplateManager>", OFFSETS.RegisterCampChestTM);
// hookRegisterType("RegisterType<AvatarContainerTemplateManager>", OFFSETS.RegisterAvatarContainerTM);

console.log("\n[*] Hooks installed.");
console.log("[*] To trigger template capture:");
console.log("    - Open inventory (accesses item templates)");
console.log("    - Open character sheet (accesses character templates)");
console.log("    - Use an item (triggers ActionData::Visit)");
console.log("    - Enter a new area (loads templates)");
console.log("\n[*] Press Ctrl+C to detach.\n");

// Optional: Scan for strings
// scanForTemplateStrings();
