namespace ES.Taipan.Crawler

open System
open System.Collections.Generic
open ES.Taipan.Infrastructure.Network

type WebLink(webRequest: WebRequest, htmlCode: String, sessionId: Guid) =     
    new(webRequest: WebRequest, mutation: Boolean, sessionId: Guid) = new WebLink(webRequest, String.Empty, sessionId)
    new(webRequest: WebRequest, sessionId: Guid) = new WebLink(webRequest, String.Empty, sessionId)

    member val Id = Guid.NewGuid() with get, set
    member val SessionId = sessionId with get, set
    member val Request = webRequest with get, set
    member val ParsedHtmlCode = htmlCode with get, set
    member val OriginalWebLink : WebLink option = None with get, set
    member val Referer : WebLink option = None with get, set

    override this.ToString() =
        this.Request.ToString()
       
