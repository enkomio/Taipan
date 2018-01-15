// scan page content
var items = [];
var taipan_attribute = 1;

function getEvents(elem) {
    var result = [];
    var events = ['onchange', 'onclick', 'onmouseover', 'onmouseout', 'onkeydown', 'onload', 'ondblclick', 'onsubmit'];
    for (var i = 0; i < events.length; i++) {
        var eventName = events[i];
        var eventObj = elem.getAttribute(eventName);
        if (eventObj) {
            result.push(eventName);
        }
    }
    return result.join(',');
}

var anchors = document.getElementsByTagName("a");
for (var i = 0; i < anchors.length; i++) {
    anchors[i].setAttribute("taipan_id", taipan_attribute);
    items.push({
        Id: taipan_attribute++,
        Url: anchors[i].href,
        Html: anchors[i].outerHTML,
        Events: getEvents(anchors[i])
    });
}

var links = document.getElementsByTagName("link");
for (var i = 0; i < links.length; i++) {
    links[i].setAttribute("taipan_id", taipan_attribute);
    items.push({
        Id: taipan_attribute++,
        Url: links[i].href,
        Html: links[i].outerHTML,
        Events: ""
    });
}

var forms = document.getElementsByTagName("form");
for (var i = 0; i < forms.length; i++) {
    forms[i].setAttribute("taipan_id", taipan_attribute);
	
    if (!forms[i].getAttribute('onsubmit') && forms[i].onsubmit) {
        var callback = 'var c = ' + forms[i].onsubmit.toString() + ';';
        var data = btoa(callback);
        forms[i].setAttribute('onsubmit', "eval(atob('" + data + "')); c.call(this); return true;");
    }
	                
    items.push({
        Id: taipan_attribute++,
        Url: forms[i].getAttribute("action"),
        Html: forms[i].outerHTML,
        Events: getEvents(forms[i])
    });        
}

var frames = window.frames;
for (var i = 0; i < frames.length; i++) {
    try {
        frames[i].setAttribute("taipan_id", taipan_attribute);
        items.push({
            Id: taipan_attribute++,
            Url: frames[i].location.href,
            Html: frames[i].document.body.outerHTML,
            Events: ""
        });
    }
    catch (err) { }
}

var iframes = document.getElementsByTagName("iframe");
for (var i = 0; i < iframes.length; i++) {
    iframes[i].setAttribute("taipan_id", taipan_attribute);
    items.push({
        Id: taipan_attribute++,
        Url: iframes[i].src,
        Html: iframes[i].outerHTML,
        Events: ""
    });
}


var html = window.document.childNodes[0].outerHTML;

// compose result
var result = {
    Html: html,
    Result: items
};

return result;