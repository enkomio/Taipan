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
		local raw_version = html:match (regex)
		if raw_version ~= "" and raw_version ~= nil then	
			local words = {}
			for w in string.gmatch(raw_version, '.') do
				table.insert(words, w)
			end			
			appVersion = words[1] .. '.' .. words[2] .. '.' .. words[3] .. words[4]
			log ("Found MyBB version: " .. appVersion)
			result = true
		end
	end

	return result
end

pages = {
	{ "install/resources/mybb_theme.xml", '<theme name="MyBB Master Style" version="([0-9]+)">' }
}

for key, value in pairs (pages) do
	if (checkPage (value[1], value[2])) then
		return true
	end
end

return false