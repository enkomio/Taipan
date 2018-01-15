-- main
final_uri = ""
if uri:sub (uri:len ()) ~= "/" then
	final_uri = "/"
end

function checkPage (page, regex)
	fullpath = uri .. final_uri .. page
	html = getRequest (fullpath)

	result = false
	if html ~= "" then
		version = html:match (regex)
		if version ~= "" and version ~= nil then
			log ("Found PhpMyAdmin version: " .. version)
			appVersion = version
			result = true
		end
	end

	return result
end

pages = {	
	{ "", 'PMA_VERSION:"([0-9.]+)"' },
	{ "doc/html/index.html", 'phpMyAdmin ([0-9.]+)' },
	{ "Documentation.html", "<h1>phpMyAdmin ([0-9.]+)" },
	{ "Documentation.html", "<title>phpMyAdmin ([0-9.]+)" },
	{ "README", "Version ([0-9.]+)" }	
}

for key, value in pairs (pages) do
	if (checkPage (value[1], value[2])) then
		return true
	end
end

return false