loadkey = {}

loadkey.name = "loadkey"

loadkey.test = function()
	local ssl = require("luasec.ssl")
	local config = require("tests.config")
	
	local pass = "foobar"
	local cfg = {
	  protocol = "tlsv1",
	  mode = "client",
	  key = sys.load_resource(config.certs .. "key.pem"),
	  password = pass,
	}
	
	-- Shell
	print(string.format("*** Hint: password is '%s' ***", pass))
	ctx, err = ssl.newcontext(cfg)
	assert(ctx, err)
	print("Shell: ok")
	
	-- Text password
	cfg.password = pass
	ctx, err = ssl.newcontext(cfg)
	assert(ctx, err)
	print("Text: ok")
	
	-- Callback
	cfg.password = function() return pass end
	ctx, err = ssl.newcontext(cfg)
	assert(ctx, err)
	print("Callback: ok")

	return true
end

return loadkey