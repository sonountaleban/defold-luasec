loopgcClient = {}

loopgcClient.name = "loop-gc.client"

loopgcClient.test = function()
	local socket = require("builtins.scripts.socket")
	local ssl = require("luasec.ssl")
	local config = require("tests.config")
		
	local params = {
	   mode = "client",
	   protocol = "tlsv1_2",
	   key = sys.load_resource(config.certs .. "clientAkey.pem"),
	   certificate = sys.load_resource(config.certs .. "clientA.pem"),
	   cafile = sys.load_resource(config.certs .. "rootA.pem"),
	   verify = {"peer", "fail_if_no_peer_cert"},
	   options = "all",
	}
	
	local counter = 1
	while counter < 11 do
	   local peer = socket.tcp()
	   assert( peer:connect(config.serverIP, config.serverPort, 8888) )
	
	   -- [[ SSL wrapper
	   peer = assert( ssl.wrap(peer, params) )
	   assert( peer:dohandshake() )
	   --]]
	
	   print(counter .. " " .. peer:receive("*l"))
	  
	   counter = counter + 1
	end

	return true
end

return loopgcClient