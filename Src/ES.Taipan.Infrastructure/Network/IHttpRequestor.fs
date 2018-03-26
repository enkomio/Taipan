namespace ES.Taipan.Infrastructure.Network

open System

type IHttpRequestor = 
    interface
        abstract Settings : HttpRequestorSettings with get
        abstract CertificationValidate : IEvent<CertificationValidateEventArgs> with get
        abstract DownloadData: HttpRequest -> Byte array
        abstract SendRequest: HttpRequest -> HttpResponse option
        abstract SessionState : SessionStateManager option with get, set        
    end
