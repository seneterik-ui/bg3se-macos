-- EntityTest: Test GetComponent functionality
Ext.Print("[EntityTest] BootstrapServer.lua loaded!")

-- Test GUIDs - player characters (guaranteed to have ecl::Character)
local playerGuids = {
    "c7c13742-bacd-460a-8f65-f864fe41f255", -- Astarion
    "58a69333-40bf-8358-1d17-fff240d7fb12", -- Laezel
}

-- HashMap entities (found earlier, but may not be characters)
local hashMapGuids = {
    "a5eaeafe-220d-bc4d-4cc3-b94574d334c7",
    "6e250e36-614a-a8dc-4104-45dabb8405f2",
}

-- Combined for testing
local testGuids = {}
for _, g in ipairs(playerGuids) do table.insert(testGuids, g) end
for _, g in ipairs(hashMapGuids) do table.insert(testGuids, g) end

-- Components to test (matching component_templates.h)
local testComponents = {
    "ecl::Character",
    "ecl::Item",
    "eoc::combat::ParticipantComponent",
    "ls::anubis::TreeComponent",
}

local function testGetComponent()
    Ext.Print("[EntityTest] === GetComponent Test ===")

    for _, guid in ipairs(testGuids) do
        Ext.Print("[EntityTest] Testing GUID: " .. guid)

        local entity = Ext.Entity.Get(guid)
        if entity then
            Ext.Print("[EntityTest]   Entity found: " .. tostring(entity))

            -- Test each component type
            for _, compName in ipairs(testComponents) do
                local comp = entity:GetComponent(compName)
                if comp then
                    Ext.Print("[EntityTest]   " .. compName .. ": FOUND at " .. tostring(comp))
                else
                    Ext.Print("[EntityTest]   " .. compName .. ": nil")
                end
            end
        else
            Ext.Print("[EntityTest]   Entity NOT FOUND")
        end
        Ext.Print("")
    end
end

-- Test just HashMap entities (exist at SessionLoaded time)
local function testHashMapEntities()
    Ext.Print("[EntityTest] === HashMap Entity Test ===")
    for _, guid in ipairs(hashMapGuids) do
        Ext.Print("[EntityTest] Testing HashMap GUID: " .. guid)
        local entity = Ext.Entity.Get(guid)
        if entity then
            Ext.Print("[EntityTest]   Entity found: " .. tostring(entity))

            -- Test TryGet by dumping storage data
            local handle = entity:GetHandle()
            Ext.Print("[EntityTest]   Handle: " .. string.format("0x%x", handle))
            local success, msg = Ext.Entity.DumpStorage(handle)
            Ext.Print("[EntityTest]   DumpStorage: " .. tostring(success) .. " - " .. tostring(msg))

            -- Test GetComponent calls
            for _, compName in ipairs(testComponents) do
                local comp = entity:GetComponent(compName)
                if comp then
                    Ext.Print("[EntityTest]   " .. compName .. ": FOUND at " .. tostring(comp))
                else
                    Ext.Print("[EntityTest]   " .. compName .. ": nil")
                end
            end
        else
            Ext.Print("[EntityTest]   Entity NOT FOUND")
        end
    end
end

-- Run test on SessionLoaded (server should be initialized)
Ext.Events.SessionLoaded:Subscribe(function()
    Ext.Print("[EntityTest] SessionLoaded - discovering EntityWorld...")

    local discovered = Ext.Entity.Discover()
    Ext.Print("[EntityTest] Discover result: " .. tostring(discovered))

    if discovered then
        -- Test HashMap entities immediately (they exist now)
        testHashMapEntities()
    else
        Ext.Print("[EntityTest] EntityWorld not found - cannot test")
    end
end)

-- Test players when an Osiris event fires (after they're loaded)
local playerTestDone = false
Ext.Osiris.RegisterListener("PROC_CharacterEnteredCombat", 1, "after", function(char)
    if not playerTestDone then
        playerTestDone = true
        Ext.Print("[EntityTest] Combat started - testing player entities")
        testGetComponent()
    end
end)

Ext.Print("[EntityTest] Module initialized. HashMap entities tested on load, players tested on combat.")
