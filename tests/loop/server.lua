loopServer = {}

loopServer.name = "loop.server"

loopServer.test = function()
	local socket = require("builtins.scripts.socket")
	local ssl = require("luasec.ssl")
	local config = require("tests.config")
		
	local params = {
	   mode = "server",
	   protocol = "any",
	   key = sys.load_resource(config.certs .. "serverAkey.pem"),
	   certificate = sys.load_resource(config.certs .. "serverA.pem"),
	   cafile = sys.load_resource(config.certs .. "rootA.pem"),
	   verify = {"peer", "fail_if_no_peer_cert"},
	   options = "all",
	}
	
	-- [[ SSL context 
	local ctx = assert( ssl.newcontext(params) )
	--]]
	
	local server = socket.tcp()
	server:setoption('reuseaddr', true)
	assert( server:bind("*", config.serverPort) )
	server:listen()
	
	local counter = 1
	while counter < 11 do
	   local peer = server:accept()
	 
	   -- [[ SSL wrapper
	   peer = assert( ssl.wrap(peer, ctx) )
	   assert( peer:dohandshake() )
	   --]]
	
	   peer:send("loop test " .. counter .. "\n")
	   peer:close()
	   
	   counter = counter + 1
	end
	
	return true
end

return loopServer
