var requests = [];
var responses = [];

chrome.webRequest.onBeforeSendHeaders.addListener(
        function (details) {
            requests.push(details);
            return {};
        },
        { urls: ["<all_urls>"] },
        ["blocking", "requestHeaders"]
);

chrome.webRequest.onCompleted.addListener(
        function (details) {
            responses.push(details);
            return {};
        },
        { urls: ["<all_urls>"] },
        ["responseHeaders"]
);

chrome.runtime.onMessage.addListener(
  function (request, sender, sendResponse) {
      var out = { reqs: requests, resps: responses };
      sendResponse(out);
  });
