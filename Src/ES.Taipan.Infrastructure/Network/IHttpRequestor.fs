namespace ES.Taipan.Infrastructure.Network

open System
open System.Threading.Tasks

type IHttpRequestor = 
    interface
        abstract Settings : HttpRequestorSettings with get
        abstract CertificationValidate : IEvent<CertificationValidateEventArgs> with get
        abstract SetAuthentication : AuthenticationType -> unit
        abstract DownloadData: HttpRequest -> Byte array
        abstract SendRequest: HttpRequest -> HttpResponse option
        abstract SendRequestAsync: HttpRequest -> Async<HttpResponse option>
        abstract SessionState : SessionStateManager option with get, set        
    end
