-- main
final_uri = ""
if uri:sub (uri:len ()) ~= "/" then
	final_uri = "/"
end

function checkPage (page, regex)
	fullpath = uri .. final_uri .. page
	html = getRequest (fullpath)

	result = false
	if html ~= "" and not html:match("NOTE: Current Release Notes are maintained at") then
		version = html:match (regex)
		if version ~= "" and version ~= nil then
			log ("Found Magento version: " .. version)
			appVersion = version
			result = true
		end
	end

	return result
end

pages = {
	{ "composer.json", '"version": "([0-9.]+)",' },
	{ "composer.lock", '2-base": "([0-9.]+)"' },
	{ "RELEASE_NOTES.txt", "==== ([0-9.]+) ====" },
	{ "CHANGELOG.md", "^([0-9.]+).=============" }
}

for key, value in pairs (pages) do
	if (checkPage (value[1], value[2])) then
		return true
	end
end

return false