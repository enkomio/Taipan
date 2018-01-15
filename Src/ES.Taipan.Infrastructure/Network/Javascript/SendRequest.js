// read arguments
var context = arguments[0];

var url = context["url"];
var sourcePage = context["source"];
var elementId = context["elementId"];
var data = context["data"];

result = {
    error: "",
    html: ""
};

// Step 1 - clean-up all not Taipan forms or hyperlinks elements
var forms = document.getElementsByTagName("form");
for (var i = 0; i < forms.length; i++) {
    if (!forms[i].getAttribute("taipan_id")) {
        forms[i].remove();
    }
}

var anchors = document.getElementsByTagName("a");
for (var i = 0; i < anchors.length; i++) {
    if (!anchors[i].getAttribute("taipan_id")) {
        anchors[i].remove();
    }
}


// Step 2 - Rebase all scripts, since I haven't loaded them from the remote server
var scripts = document.querySelectorAll('script');	
var scriptRebase = false;
for(var i=0; i<scripts.length; i++) {
    var scriptSrc = scripts[i].getAttribute("src");
    if (scriptSrc && !scriptSrc.startsWith("http:") && !scriptSrc.startsWith("https:")) {
        scriptRebase = true;
        var uriScript = new URL(scriptSrc, sourcePage);

        var newScript = document.createElement('script');
        newScript.type= 'text/javascript';
        newScript.src= uriScript.href;

        window.document.body.appendChild(newScript);
    }    
}

// Step 3 - modify the HTML code
var element = document.querySelectorAll('[taipan_id="' + elementId + '"]')[0];		
if (!element) {
    // element not found
    result.error = "Element '" + elementId + "' not found";
    return;
}
		
var tagName = element.tagName.toLowerCase();
				
if (tagName == 'a') {			
    element.href = url;					
}
else if (tagName == 'form') {			
    element.action = url;	

    // parse input data
    var chunks = data.split('&');
    var parameters = {};
    for(var i=0; i<chunks.length; i++) {
        var nv = chunks[i].split('=');	
        if (nv.length == 1) {   
            parameters[nv[0]] = '';
        }
        else {
            parameters[nv[0]] = nv[1];
        }
    }

    // modify values
    var inputs = element.getElementsByTagName("input");
    for(var i=0; i<inputs.length; i++) {
        var name = inputs[i].getAttribute("name");	
        if (parameters[name]) {					
            inputs[i].setAttribute("value", parameters[name]);
        }				
    }
}		
else {
    // try to send request to an element that is not a form or hyperlink
    result.error = "Tagtype '" + tagName + "' not supported";
    return;
}
		
// Step 4 - submit the request by submitting the element
function submitRequest() {
    if (tagName == 'a') {	
        element.click();
    }
    else {
        var submitButton = element.querySelectorAll('[type="submit"]')[0];
        if (!submitButton) {
            element.submit();
        }
        else {
            submitButton.click();
        }
    }
}

if (scriptRebase) {    
    setTimeout(function() {
        submitRequest();
    }, 2000);
        
    result.html = window.document.childNodes[0].outerHTML;
}
else {
    submitRequest();
    result.html = window.document.childNodes[0].outerHTML;  
}