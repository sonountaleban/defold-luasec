dhparamServer = {}

dhparamServer.name = "dhparam.server"

dhparamServer.test = function()
	local socket = require("builtins.scripts.socket")
	local ssl = require("luasec.ssl")
	local config = require("tests.config")

	local function dhparam_cb(export, keylength)
	  print("---")
	  print("DH Callback")
	  print("Export", export)
	  print("Key length", keylength)
	  print("---")
	  local filename
	  if keylength == 512 then
	    filename = config.certs .. "dh-512.pem"
	  elseif keylength == 1024 then
	    filename = config.certs .. "dh-1024.pem"
	  else
	    -- No key
	    return nil
	  end
	  return sys.load_resource(filename)
	end
	
	local params = {
	   mode = "server",
	   protocol = "any",
	   key = sys.load_resource(config.certs .. "serverAkey.pem"),
	   certificate = sys.load_resource(config.certs .. "serverA.pem"),
	   cafile = sys.load_resource(config.certs .. "rootA.pem"),
	   verify = {"peer", "fail_if_no_peer_cert"},
	   options = "all",
	   dhparam = dhparam_cb,
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
	
	peer:send("oneshot test\n")
	peer:close()

	return true
end

return dhparamServer