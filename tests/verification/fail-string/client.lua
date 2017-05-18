verificationFailstringClient = {}

verificationFailstringClient.name = "verification.fail-string.client"

verificationFailstringClient.test = function()
	local socket = require("builtins.scripts.socket")
	local ssl = require("luasec.ssl")
	local config = require("tests.config")
		
	local params = {
	   mode = "client",
	   protocol = "tlsv1",
	   key = sys.load_resource(config.certs .. "clientBkey.pem"),
	   certificate = sys.load_resource(config.certs .. "clientB.pem"),
	   cafile = sys.load_resource(config.certs .. "rootB.pem"),
	   verify = "none",
	   options = "all",
	}
	
	local peer = socket.tcp()
	peer:connect(config.serverIP, config.serverPort, 8888)
	
	-- [[ SSL wrapper
	peer = assert( ssl.wrap(peer, params) )
	assert(peer:dohandshake())
	--]]
	
	local err, msg = peer:getpeerverification()
	print(err, msg)
	
	print(peer:receive("*l"))
	peer:close()

	return true
end

return verificationFailstringClient