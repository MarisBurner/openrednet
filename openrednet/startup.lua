local openrednet = require("openrednet")

term.clear()
term.setCursorPos(1,1)

openrednet:host(nil,function()
 term.clear()
 term.setCursorPos(1,1)
 print("Hosting on "..openrednet.hostname)
 
end,function(id, msg)
 print("Received message from "..id..": "..tostring(msg))
end)