-- BG3SE-macOS NetChannel
-- Network channel for multiplayer mod communication
-- Issue #6: NetChannel API
--
-- Ported from Windows BG3SE with minimal modifications

--- @class NetChannel
--- @field RequestHandler fun(string, number): string
--- @field MessageHandler fun(string, number)
--- @field Module string
--- @field Channel string
local NetChannel = {}

---@param module string
---@param channel string
---@return NetChannel
function NetChannel:Instantiate(module, channel)
    return {
        Module = module,
        Channel = channel
    }
end


function NetChannel:SetHandler(handler)
    self.MessageHandler = handler
end

function NetChannel:SetRequestHandler(handler)
    self.RequestHandler = handler
end

function NetChannel:IsBinary()
    return Ext.Net.Version() >= 2
end

function NetChannel:Stringify(msg)
    -- Use binary JSON if supported
    local binary = self:IsBinary()
    if binary and Ext.Json.Stringify then
        return Ext.Json.Stringify(msg)
    end
    return Ext.Json.Stringify(msg)
end

function NetChannel:DoSendToServer(message, handler)
    local msg = self:Stringify(message)
    Ext.Net.PostMessageToServer(self.Channel, msg, self.Module, handler, nil, self:IsBinary())
end

function NetChannel:SendToServer(message)
    self:DoSendToServer(message, nil)
end

function NetChannel:RequestToServer(message, handler)
    local replyHandler = function (reply, binary)
        handler(Ext.Json.Parse(reply))
    end
    self:DoSendToServer(message, replyHandler)
end

function NetChannel:DoSendToClient(message, user, handler)
    local msg = self:Stringify(message)
    if type(user) == "number" then
        Ext.Net.PostMessageToUser(user, self.Channel, msg, self.Module, handler, nil, self:IsBinary())
    else
        Ext.Net.PostMessageToClient(user, self.Channel, msg, self.Module, handler, nil, self:IsBinary())
    end
end

function NetChannel:SendToClient(message, user)
    self:DoSendToClient(message, user, nil)
end

function NetChannel:RequestToClient(message, user, handler)
    local replyHandler = function (reply, binary)
        handler(Ext.Json.Parse(reply))
    end
    self:DoSendToClient(message, user, replyHandler)
end

function NetChannel:Broadcast(message, excludeCharacter)
    local msg = self:Stringify(message)
    Ext.Net.BroadcastMessage(self.Channel, msg, excludeCharacter, self.Module, nil, nil, self:IsBinary())
end

function NetChannel:OnMessage(e)
    local request = Ext.Json.Parse(e.Payload)
    if e.RequestId and e.RequestId ~= 0 then
        if self.RequestHandler then
            local ok, ret = xpcall(self.RequestHandler, debug.traceback, request, e.UserID)
            if ok then
                local reply = self:Stringify(ret)
                if Ext.IsServer() then
                    Ext.Net.PostMessageToUser(e.UserID, e.Channel, reply, e.Module, nil, e.RequestId, self:IsBinary())
                else
                    Ext.Net.PostMessageToServer(e.Channel, reply, e.Module, nil, e.RequestId, self:IsBinary())
                end
            else
                Ext.Print("[NetChannel] Error during request dispatch for " .. e.Module .. "/" .. e.Channel .. ": " .. tostring(ret))
            end
        else
            Ext.Print("[NetChannel] Request received for " .. e.Module .. "/" .. e.Channel .. " but no request handler registered")
        end
    else
        if self.MessageHandler then
            local ok, err = xpcall(self.MessageHandler, debug.traceback, request, e.UserID)
            if not ok then
                Ext.Print("[NetChannel] Error during message dispatch for " .. e.Module .. "/" .. e.Channel .. ": " .. tostring(err))
            end
        else
            Ext.Print("[NetChannel] Message received for " .. e.Module .. "/" .. e.Channel .. " but no message handler registered")
        end
    end
end


return Class.Create(NetChannel)
