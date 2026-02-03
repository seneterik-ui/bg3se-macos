-- BG3SE-macOS NetworkManager
-- Manages network channels and routes messages
-- Issue #6: NetChannel API
--
-- Ported from Windows BG3SE with minimal modifications

--- @class NetworkManager
local NetworkManager = {
    --- @type table<string, table<string, NetChannel>>
    Channels = {},
    Initialized = false
}

function NetworkManager:CreateNetModule(ext)
    local net = {}
    setmetatable(net, {
        __index = ext.Net,
    })
    net.CreateChannel = function (module, channel, messageHandler, requestHandler)
        local ch = self:AddChannel(module, channel)
        ch.MessageHandler = messageHandler
        ch.RequestHandler = requestHandler
        return ch
    end
    return net
end

--- @param module string
--- @param channel string
function NetworkManager:AddChannel(module, channel)
    if Ext.Mod and Ext.Mod.IsModLoaded and not Ext.Mod.IsModLoaded(module) then
        error("Creating network channel for nonexistent mod " .. module)
    end

    local ch = NetChannel:New(module, channel)
    self:RegisterChannel(ch)
    return ch
end

--- @param channel NetChannel
function NetworkManager:RegisterChannel(channel)
    if self.Channels[channel.Module] == nil then
        self.Channels[channel.Module] = {}
    end

    if self.Channels[channel.Module][channel.Channel] ~= nil then
        error("Channel '" .. channel.Channel .. "' for module " .. channel.Module .. " already registered")
    end

    self.Channels[channel.Module][channel.Channel] = channel
end


function NetworkManager:RegisterEvents()
    if self.Initialized then return end
    self.Initialized = true

    if Ext.Events and Ext.Events.NetModMessage then
        Ext.Events.NetModMessage:Subscribe(function (e)
            self:MessageReceived(e)
        end)
    end
end


--- @param e LuaNetMessageEvent
function NetworkManager:MessageReceived(e)
    if not e.Module or e.Module == "" then
        Ext.Print("[NetworkManager] Message received without module")
        return
    end

    if not self.Channels[e.Module] or not self.Channels[e.Module][e.Channel] then
        Ext.Print("[NetworkManager] Message received for unregistered channel: " .. e.Module .. "/" .. e.Channel)
        return
    end

    local channel = self.Channels[e.Module][e.Channel]
    channel:OnMessage(e)
end

return NetworkManager
