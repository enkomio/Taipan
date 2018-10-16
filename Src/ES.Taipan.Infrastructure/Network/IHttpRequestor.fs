namespace ES.Taipan.Infrastructure.Network

open System

type IHttpRequestor = 
    interface
        abstract Id: Guid with get
        abstract Settings: HttpRequestorSettings with get        
        abstract CertificationValidate: IEvent<CertificationValidateEventArgs> with get
        abstract RequestNotificationCallback: (IHttpRequestor * HttpRequest * Boolean -> unit) with get, set
        abstract DownloadData: HttpRequest -> Byte array
        abstract SendRequest: HttpRequest -> HttpResponse option
        abstract SessionState: SessionStateManager option with get, set        
    end
