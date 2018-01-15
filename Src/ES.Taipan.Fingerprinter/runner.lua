local http = require ("socket.http")

uri = ''
function getRequest(u)  
  return http.request(u)
end

function log(txt)
	print("[LOG] " .. txt)
end

if (#arg < 2) then
	print("Please specify the path to the script to execute and the url to use for testing purpose. Eg. php/wordpress/wordpress.lua http://www.example.com")
else
  print("Start Runner")
	script_file = arg[1]
	uri = arg[2]

	if script_file:sub(script_file:len() - 3) == ".lua" then
		script_file = script_file:sub (0, script_file:len() - 4)
	end
	script_file = script_file:gsub ("/", "."):gsub ("\\", ".")
	print ("Require: " .. script_file)
	result = require(script_file)
	if (result) then
		print ("Execution succeed!")
		print ("App: " .. appName)
		print ("Version: " .. appVersion)
	else
		print ("Execution failed :(")
	end

end