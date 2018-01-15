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
			log ("Found Drupal version: " .. version)
			appVersion = version
			result = true
		end
	end

	return result
end

pages = {
	{ "CHANGELOG.txt", "Drupal ([0-9.]+)," },
	{ "includes/bootstrap.inc", "define\\('VERSION', '([0-9.]+)'\\);" }
}

for key, value in pairs (pages) do
	if (checkPage (value[1], value[2])) then
		return true
	end
end

return false