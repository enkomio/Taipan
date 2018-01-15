namespace ES.Taipan.Discoverer

open System
open ES.Taipan.Infrastructure.Network

type DiscoverRequest(httpRequest: HttpRequest) =    
    member val Request = httpRequest with get

    override this.ToString() =
        this.Request.ToString()


