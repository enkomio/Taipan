-- main
final_uri = ""
if uri:sub (uri:len ()) ~= "/" then
	final_uri = "/"
end

function checkPage (page, regex)
	fullpath = uri .. final_uri .. page
	html = getRequest (fullpath)

	result = false
	if html ~= nil then
		version = html:match (regex)
		if version ~= "" and version ~= nil then
			log ("Found vBulletin version: " .. version)
			appVersion = version
			result = true
		end
	end

	return result
end

pages = {
	{ "", '<meta name="generator" content="vBulletin ([0-9.]+)"/>' }
}

for key, value in pairs (pages) do
	if (checkPage (value[1], value[2])) then
		return true
	end
end

return false