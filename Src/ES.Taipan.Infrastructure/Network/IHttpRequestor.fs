namespace ES.Taipan.Infrastructure.Network

open System
open ES.Taipan.Infrastructure.Service

type IHttpRequestor = 
    interface
        abstract Id: Guid with get
        abstract Settings: HttpRequestorSettings with get        
        abstract Metrics: ServiceMetrics with get, set
        abstract CertificationValidate: IEvent<CertificationValidateEventArgs> with get        
        abstract DownloadData: HttpRequest -> Byte array
        abstract SendRequest: HttpRequest -> HttpResponse option
        abstract SessionState: SessionStateManager option with get, set        
    end
