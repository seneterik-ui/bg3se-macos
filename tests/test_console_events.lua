-- Test script for DoConsoleCommand and LuaConsoleInput events
-- Run via: copy/paste into bg3se-console or source via Ext.Require

local passed = 0
local failed = 0

local function test(name, condition)
    if condition then
        Ext.Print("[PASS] " .. name)
        passed = passed + 1
    else
        Ext.Print("[FAIL] " .. name)
        failed = failed + 1
    end
end

local function section(name)
    Ext.Print("")
    Ext.Print("=== " .. name .. " ===")
end

-- ============================================================================
-- Test 1: Event Objects Exist
-- ============================================================================
section("Event Registration")

test("DoConsoleCommand event exists", Ext.Events.DoConsoleCommand ~= nil)
test("LuaConsoleInput event exists", Ext.Events.LuaConsoleInput ~= nil)
test("DoConsoleCommand has Subscribe", type(Ext.Events.DoConsoleCommand.Subscribe) == "function")
test("DoConsoleCommand has Unsubscribe", type(Ext.Events.DoConsoleCommand.Unsubscribe) == "function")
test("LuaConsoleInput has Subscribe", type(Ext.Events.LuaConsoleInput.Subscribe) == "function")
test("LuaConsoleInput has Unsubscribe", type(Ext.Events.LuaConsoleInput.Unsubscribe) == "function")

-- ============================================================================
-- Test 2: Subscribe Returns Handler ID
-- ============================================================================
section("Subscription")

local cmdHandlerId = nil
local cmdEventReceived = false
local cmdEventData = nil

cmdHandlerId = Ext.Events.DoConsoleCommand:Subscribe(function(e)
    cmdEventReceived = true
    cmdEventData = e
end)

test("DoConsoleCommand Subscribe returns handler ID", type(cmdHandlerId) == "number" and cmdHandlerId > 0)

local luaHandlerId = nil
local luaEventReceived = false
local luaEventData = nil

luaHandlerId = Ext.Events.LuaConsoleInput:Subscribe(function(e)
    luaEventReceived = true
    luaEventData = e
end)

test("LuaConsoleInput Subscribe returns handler ID", type(luaHandlerId) == "number" and luaHandlerId > 0)

-- ============================================================================
-- Test 3: Unsubscribe Works
-- ============================================================================
section("Unsubscription")

-- Unsubscribe and resubscribe to test the mechanism
local tempId = Ext.Events.DoConsoleCommand:Subscribe(function(e) end)
local unsubResult = Ext.Events.DoConsoleCommand:Unsubscribe(tempId)
test("Unsubscribe returns true for valid handler", unsubResult == true)

local unsubInvalid = Ext.Events.DoConsoleCommand:Unsubscribe(999999)
test("Unsubscribe returns false for invalid handler", unsubInvalid == false)

-- ============================================================================
-- Test 4: Priority Option
-- ============================================================================
section("Priority Ordering")

local callOrder = {}

local lowPriorityId = Ext.Events.DoConsoleCommand:Subscribe(function(e)
    table.insert(callOrder, "low")
end, {Priority = 200})

local highPriorityId = Ext.Events.DoConsoleCommand:Subscribe(function(e)
    table.insert(callOrder, "high")
end, {Priority = 50})

local medPriorityId = Ext.Events.DoConsoleCommand:Subscribe(function(e)
    table.insert(callOrder, "med")
end, {Priority = 100})

test("Priority handlers registered", lowPriorityId ~= nil and highPriorityId ~= nil and medPriorityId ~= nil)

-- Clean up priority handlers
Ext.Events.DoConsoleCommand:Unsubscribe(lowPriorityId)
Ext.Events.DoConsoleCommand:Unsubscribe(highPriorityId)
Ext.Events.DoConsoleCommand:Unsubscribe(medPriorityId)

-- ============================================================================
-- Test 5: Once Option
-- ============================================================================
section("Once Flag")

local onceCallCount = 0
local onceHandlerId = Ext.Events.DoConsoleCommand:Subscribe(function(e)
    onceCallCount = onceCallCount + 1
end, {Once = true})

test("Once handler registered", onceHandlerId ~= nil)

-- ============================================================================
-- Test 6: All 10 Events Exist
-- ============================================================================
section("All Events Present")

local eventNames = {
    "SessionLoading",
    "SessionLoaded",
    "ResetCompleted",
    "Tick",
    "StatsLoaded",
    "ModuleLoadStarted",
    "GameStateChanged",
    "KeyInput",
    "DoConsoleCommand",
    "LuaConsoleInput"
}

local allExist = true
for _, name in ipairs(eventNames) do
    if Ext.Events[name] == nil then
        Ext.Print("[FAIL] Missing event: " .. name)
        allExist = false
        failed = failed + 1
    end
end

if allExist then
    test("All 10 events exist", true)
end

-- ============================================================================
-- Clean up test handlers
-- ============================================================================
section("Cleanup")

Ext.Events.DoConsoleCommand:Unsubscribe(cmdHandlerId)
Ext.Events.LuaConsoleInput:Unsubscribe(luaHandlerId)
Ext.Print("Test handlers cleaned up")

-- ============================================================================
-- Summary
-- ============================================================================
section("Summary")
Ext.Print("Passed: " .. passed)
Ext.Print("Failed: " .. failed)

if failed == 0 then
    Ext.Print("")
    Ext.Print("All tests passed!")
else
    Ext.Print("")
    Ext.Print("Some tests failed. Check output above.")
end

-- ============================================================================
-- Interactive Test Instructions
-- ============================================================================
Ext.Print("")
Ext.Print("=== Interactive Tests ===")
Ext.Print("To test event firing, run these manually:")
Ext.Print("")
Ext.Print("1. Test DoConsoleCommand:")
Ext.Print("   Ext.Events.DoConsoleCommand:Subscribe(function(e)")
Ext.Print("       Ext.Print('Command: ' .. e.Command)")
Ext.Print("   end)")
Ext.Print("   Then type: !help")
Ext.Print("")
Ext.Print("2. Test Prevent pattern:")
Ext.Print("   Ext.Events.DoConsoleCommand:Subscribe(function(e)")
Ext.Print("       if e.Command:match('^!block') then")
Ext.Print("           Ext.Print('Blocked!')")
Ext.Print("           e.Prevent = true")
Ext.Print("       end")
Ext.Print("   end)")
Ext.Print("   Then type: !block test (should be blocked)")
Ext.Print("   Then type: !help (should work)")
