namespace ES.Taipan.Inspector

open System
open ES.Taipan.Infrastructure.Network

type TestRequestType =
    | CrawledPage
    | WebApplicationIdentified
    | HiddenResource

type TestRequest(webRequest: WebRequest, webResponse: WebResponse, requestType: TestRequestType, data: _) = 
    member val RequestType = requestType with get
    member val WebRequest = webRequest with get    
    member val WebResponse = webResponse with get
    
    override this.ToString() =
        String.Format("[{0}] {1}", this.RequestType, this.WebRequest)

    member this.GetData<'T>() =
        data :> Object :?> 'T