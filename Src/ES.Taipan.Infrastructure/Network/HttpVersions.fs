namespace ES.Taipan.Infrastructure.Network

open System

type HttpVersions =
    | Http10
    | Http11
    | Custom of String

    override this.ToString() =
        match this with
        | Http10 -> "HTTP/1.0"
        | Http11 -> "HTTP/1.1"
        | Custom v -> v
