namespace ES.Taipan.Discoverer

open System
open ES.Taipan.Infrastructure.Network

type ResourceDiscovered(resource: Resource, baseUri: Uri, request: HttpRequest, response: HttpResponse) =    
    member val BaseUri = baseUri with get
    member val Resource = resource with get
    member val Request = request with get
    member val Response = response with get

    override this.ToString() =
        this.Request.ToString()


