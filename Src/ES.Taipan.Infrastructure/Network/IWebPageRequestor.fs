namespace ES.Taipan.Infrastructure.Network

type IWebPageRequestor = 
    interface
        abstract RequestWebPage : WebRequest -> WebResponse
        abstract RequestInitialWebPage : WebRequest -> WebResponse
        abstract HttpRequestor : IHttpRequestor with get
        abstract SetPageNotFoundIdentifier : IPageNotFoundIdentifier -> unit
    end