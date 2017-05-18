verificationFailstringServer = {}

verificationFailstringServer.name = "verification.fail-string.server"

verificationFailstringServer.test = function()
	local socket = require("builtins.scripts.socket")
	local ssl = require("luasec.ssl")
	local config = require("tests.config")
		
	local params = {
	   mode = "server",
	   protocol = "tlsv1",
	   key = sys.load_resource(config.certs .. "serverAkey.pem"),
	   certificate = sys.load_resource(config.certs .. "serverA.pem"),
	   cafile = sys.load_resource(config.certs .. "rootA.pem"),
	   verify = "none",
	   options = "all",
	}
	
	-- [[ SSL context
	local ctx = assert(ssl.newcontext(params))
	--]]
	
	local server = socket.tcp()
	server:setoption('reuseaddr', true)
	assert( server:bind("*", config.serverPort) )
	server:listen()
	
	local peer = server:accept()
	
	-- [[ SSL wrapper
	peer = assert( ssl.wrap(peer, ctx) )
	assert( peer:dohandshake() )
	--]]
	
	local err, msg = peer:getpeerverification()
	print(err, msg)
	
	peer:send("oneshot test\n")
	peer:close()

	return true
end

return verificationFailstringServer