namespace ES.Taipan.Infrastructure.Network

open System

type HttpMethods =
    | Get
    | Post
    | Head
    | Custom of String

    override this.ToString() =
        match this with
        | Get -> "GET"
        | Post -> "POST"
        | Head -> "HEAD"
        | Custom m -> m

    static member ToHttpMethod(httpMethod: String) =
        match httpMethod.ToUpper() with
        | "GET" -> Get
        | "POST" -> Post
        | "HEAD" -> Head
        | m -> Custom m