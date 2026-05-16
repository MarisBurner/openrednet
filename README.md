# openrednet
A secure, intuitive websocketting system CC: Tweaked

When you load the folder into a computer, you can run "./openrednet/setup.lua"

Load in the library using ```local openrednet = require("openrednet")```

You can start hosting using ```openrednet:host(ip, mainFn, recievedMessageFn)```

Establish a connection to a client using ```openrednet:connect(ip)```

If a safe connection is established, you can send a message using ```openrednet:send(ip, encryptedData, unencryptedData)```

You can also disconnect from clients using ```openrednet:disconnect(ip)```

Remember, if there are any IP's you do not want to connect to you, list them in the blacklist table.
```openrednet.blacklist[ip] = true```
