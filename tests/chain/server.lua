chainServer = {}

chainServer.name = "chain.server"

chainServer.test = function()
	local socket = require("builtins.scripts.socket")
	local ssl = require("luasec.ssl")
	local util = require("tests.chain.util") 
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
	
	local ctx = assert(ssl.newcontext(params))
	
	local server = socket.tcp()
	server:setoption('reuseaddr', true)
	assert( server:bind("*", config.serverPort) )
	server:listen()
	
	local conn = server:accept()
	
	conn = assert( ssl.wrap(conn, ctx) )
	assert( conn:dohandshake() )
	
	util.show( conn:getpeercertificate() )
	
	print("----------------------------------------------------------------------")
	
	for k, cert in ipairs( conn:getpeerchain() ) do
	  util.show(cert)
	end
	
	util.show( ssl.loadcertificate(params.certificate) )
	
	print("----------------------------------------------------------------------")
	local cert = conn:getpeercertificate()
	print( cert )
	print( cert:digest() )
	print( cert:digest("sha1") )
	print( cert:digest("sha256") )
	print( cert:digest("sha512") )
	
	conn:close()
	server:close()
	
	return true
end

return chainServer