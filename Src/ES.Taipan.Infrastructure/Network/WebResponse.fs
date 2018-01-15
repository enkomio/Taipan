namespace ES.Taipan.Infrastructure.Network

open System

type WebResponse(httpResponse: HttpResponse) = 
    
    member val Id = Guid.NewGuid() with get, set
    member val HttpResponse = httpResponse with get, set
    member val PageExists = false with get, set

    override this.ToString() =
        match this.PageExists with
        | true -> this.HttpResponse.ToString()
        | false -> "Page not exists"