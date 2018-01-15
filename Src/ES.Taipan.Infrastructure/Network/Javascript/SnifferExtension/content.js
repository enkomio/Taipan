chrome.runtime.sendMessage({}, function (response) {
    var s = document.createElement("script");
    s.text = "var networkRequests = JSON.parse('" + JSON.stringify(response) + "');";
    document.body.appendChild(s);
});
