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
			log ("Found Wordpress version: " .. version)
			appVersion = version
			result = true
		end
	end

	return result
end

pages = {
	{ "readme.html", "<br />[^0-9.]+ ([0-9.]+)" },
	{ "", '<meta name="generator" content="WordPress ([0-9.]+)" />' },
	{ "", "wp.emoji.release.min.js.m=[0-9]+h&ver=([0-9.]+)" },
	{ "", "wp.emoji.release.min.js.ver=([0-9.]+)" },
	{ "", "wp.emoji.js.ver=([0-9.]+)" },
	{ "", "wp.emoji.js.m=[0-9]+h&ver=([0-9.]+)" },
	{ "", "wp.embed.min.js.ver=([0-9.]+)" },
	{ "", "wp.embed.min.js.m=[0-9]+h&ver=([0-9.]+)" },
	{ "", "wp.embed.js.ver=([0-9.]+)" },
	{ "", "wp.embed.js.m=[0-9]+h&ver=([0-9.]+)" },
	{ "", '^WP:([0-9.]+)' },
	{ "feed/", "<generator>http://wordpress.org/.v=([0-9.]+)</generator>" },
	{ "feed/rdf/", '<admin:generatorAgent rdf:resource="http://wordpress.org/.v=([0-9.]+)" />' },
	{ "feed/atom/", '<generator uri="http://wordpress.org/" version="([0-9.]+)">WordPress</generator>' },
	{ "sitemap.xml", 'generator="wordpress/([0-9.]+)"' },
	{ "wp-links-opml.php", 'generator="WordPress/([0-9.]+)"' }
}

for key, value in pairs (pages) do
	if (checkPage (value[1], value[2])) then
		return true
	end
end

return false