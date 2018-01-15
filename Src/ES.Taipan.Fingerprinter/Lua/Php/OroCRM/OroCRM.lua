-- main
final_uri = ""
if uri:sub (uri:len ()) ~= "/" then
	final_uri = "/"
end

function checkPage (page, regex)
	fullpath = uri .. final_uri .. page
	html = getRequest (fullpath)
  
	result = false
	-- the second check is to avoid False Positives
	if html ~= "" and (html:match("Enhanced data change log with ability to save changes for collections")) ~= "" then
		version = html:match (regex)
		if version ~= "" and version ~= nil then
			log ("Found OroCRM version: " .. version)
			appVersion = version
			result = true
		end
	end

	return result
end

pages = {
	{ "CHANGELOG.md", "^CHANGELOG for ([0-9.]+)" }
}

for key, value in pairs (pages) do
	if (checkPage (value[1], value[2])) then
		return true
	end
end

return false