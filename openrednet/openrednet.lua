-- OpenRedNet
-- Secure Websocketting Library
-- Made by: Cali
-- Built on: ccryptolib

local x25519 = require("ccryptolib.x25519")
local random = require("ccryptolib.random")
local aead = require("ccryptolib.aead")
local lib = {
 x25519 = x25519,
 random = random,
 aead = aead,
 sockets = {},
 blacklist = {},
 serializer = {}
}

-- this initializes the randomizer
local postHandle = assert(http.post("https://krist.dev/ws/start", ""))
local data = textutils.unserializeJSON(postHandle.readAll())
postHandle.close()
random.init(data.url)
http.websocket(data.url).close()

lib.privKey = random.random(32)
lib.pubKey = x25519.publicKey(lib.privKey)

function lib.indexOf(arr, val)
 for i, v in ipairs(arr) do
  if v == val then
   return i
  end
 end
 return nil
end

function lib.serializer:genTableString(val, name, skipnewlines, depth)
 skipnewlines = skipnewlines or false
 depth = depth or 0

 local tmp = string.rep(" ", depth)

 if name then tmp = tmp .. name .. " = " end

 if type(val) == "table" then
  tmp = tmp .. "{" .. (not skipnewlines and "\n" or "")

  for k, v in pairs(val) do
   tmp = tmp .. self:genTableString(v, k, skipnewlines, depth + 1) .. "," .. (not skipnewlines and "\n" or "")
  end

  tmp = tmp .. string.rep(" ", depth) .. "}"
 elseif type(val) == "number" then
  tmp = tmp .. tostring(val)
 elseif type(val) == "string" then
  tmp = tmp .. string.format("%q", val)
 elseif type(val) == "boolean" then
  tmp = tmp .. (val and "true" or "false")
 else
  tmp = tmp .. "\"[inserializeable datatype:" .. type(val) .. "]\""
 end

 return tmp
end

function lib.serializer:getTableFromString(val)
 local fn, err = load("return " .. val, "sandbox", "t", {})
 if fn then
  local suc, res = pcall(fn)
  return suc and res or {}
 else
  return {}
 end
end

function lib:isConnected(ip)
 ip = self:getIP(ip)
 return self.sockets[ip] ~= nil
end

function lib:getIP(name)
 local ip = name
 local serv = rednet.lookup("orn_shake", tostring(name))
 if serv then
  ip = serv
 end
 ip = tonumber(ip)
 if ip == nil then ip = -1 end
 return ip
end

function lib:host(hn, func, res)
 local per = peripheral.find("modem", rednet.open)
 self.hostname = tostring(hn or os.getComputerID())
 rednet.host("orn_shake", self.hostname)
 self.get = func or function() end
 self.onmessage = res or function() end
 parallel.waitForAll(func, function()
  self:listen()
 end, function()
  self:listenShake()
 end)
end

function lib:listenShake()
 while true do
  local id, cpubKey = rednet.receive("orn_shake", 5)
  if id then
   if not self.blacklist[id] then
    -- Ignore connection attempts from blacklisted IPs
    rednet.send(id, self.pubKey, "orn_shake")
    self.sockets[id] = self.x25519.exchange(self.privKey, cpubKey)
   end
  end
 end
end

function lib:listen()
 while true do
  local id, msg = rednet.receive("orn")
  if self.sockets[id] then
   if msg == "_%disc" then
    -- Server requested disconnect, clean up socket
    self.sockets[id] = nil
   else
    local decrypted = self.aead.decrypt(self.sockets[id], msg.nonce, msg.tag, msg.encryptedMessage, msg.unencryptedMessage)
    if decrypted == nil then
     -- Failed decryption, possible attack or corruption
     self:disconnect(id)
    else
     if msg.unencryptedMessage == "_%tbs" then decrypted = lib.serializer:getTableFromString(decrypted) end
     self.onmessage(id, decrypted, msg.unencryptedMessage)
    end
   end
  end
 end
end

function lib:send(ip, message, unencryptedMessage)
 ip = self:getIP(ip)
 if self.sockets[ip] then
  unencryptedMessage = unencryptedMessage or ""
  message = tostring(message)
  unencryptedMessage = tostring(unencryptedMessage)
  local nonce = self.random.random(12)
  local encrypted, tag = self.aead.encrypt(self.sockets[ip], nonce, message, unencryptedMessage)
  rednet.send(ip, {encryptedMessage = encrypted, unencryptedMessage = unencryptedMessage, nonce = nonce, tag = tag}, "orn")
 end
end

function lib:sendTable(ip, message)
 self:send(ip, self.serializer:genTableString(message), "_%tbs")
end

function lib:disconnect(ip)
 ip = self:getIP(ip)
 self.sockets[ip] = nil
 rednet.send(ip, "_%disc")
end

function lib:connect(ip)
 --Secure a safe connection through handshakes and key exchange
 ip = self:getIP(ip)
 local id, msg

 -- Attempt Handshake
 rednet.send(ip, self.pubKey, "orn_shake")
 id, msg = rednet.receive("orn_shake", 5)
 if id == ip then
  --accepted handshake
  self.sockets[ip] = self.x25519.exchange(self.privKey, msg)
  return true
 end

 return false
end

return lib
