-- main
final_uri = ""
if uri:sub (uri:len ()) ~= "/" then
	final_uri = "/"
end

-- request the xml file
final_uri = uri .. final_uri .. "administrator/manifests/files/joomla.xml"
html = getRequest (final_uri)

result = false
if html ~= "" then
	version = html:match ("<version>([0-9.]+)</version>")
	if version ~= "" and version ~= "" then		
		appVersion = version
		result = true
	end
end

return result