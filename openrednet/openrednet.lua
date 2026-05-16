local x25519 = require("ccryptolib.x25519")
local random = require("ccryptolib.random")
local aead = require("ccryptolib.aead")
local lib = {
 x25519 = x25519,
 random = random,
 aead = aead,
 sockets = {},
 blacklist = {},
}

-- this initializes the randomizer
local postHandle = assert(http.post("https://krist.dev/ws/start", ""))
local data = textutils.unserializeJSON(postHandle.readAll())
postHandle.close()
random.init(data.url)
http.websocket(data.url).close()

lib.privKey = random.random(32)
lib.pubKey = x25519.publicKey(lib.privKey)

function lib:isConnected(ip)
 return self.sockets[ip] ~= nil
end

function lib:host(hn, func, res)
 local per = peripheral.find("modem", rednet.open)
 self.hostname = hn or os.getComputerID()
 rednet.host("orn_shake", tostring(self.hostname))
 rednet.host("orn", tostring(self.hostname))
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
   if msg == "disconnect" then
    -- Server requested disconnect, clean up socket
    self.sockets[id] = nil
   else
    local decrypted = self.aead.decrypt(self.sockets[id], msg.nonce, msg.tag, msg.encryptedMessage, msg.unencryptedMessage)
    if decrypted == nil then
     -- Failed decryption, possible attack or corruption
     self:disconnect(id)
    else
     self.onmessage(id, decrypted, msg.unencryptedMessage)
    end
   end
  end
 end
end

function lib:send(ip, message, unencryptedMessage)
 if self.sockets[ip] then
  unencryptedMessage = unencryptedMessage or ""
  message = tostring(message)
  unencryptedMessage = tostring(unencryptedMessage)
  local nonce = self.random.random(12)
  local encrypted, tag = self.aead.encrypt(self.sockets[ip], nonce, message, unencryptedMessage)
  rednet.send(ip, {encryptedMessage = encrypted, unencryptedMessage = unencryptedMessage, nonce = nonce, tag = tag}, "orn")
 end
end

function lib:disconnect(ip)
 self.sockets[ip] = nil
 rednet:send(ip, "disconnect")
end

function lib:connect(ip)
 --Secure a safe connection through handshakes and key exchange
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
