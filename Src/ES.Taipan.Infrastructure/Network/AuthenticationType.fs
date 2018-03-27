namespace ES.Taipan.Infrastructure.Network

open System
open System.Net

type AuthenticationType =
    | NoAuthentication
    | HttpBasic
    | HttpDigest
    | WebForm
    | Bearer 

    override this.ToString() =
        match this with
        | NoAuthentication -> "None"
        | Bearer -> "Bearer"
        | HttpBasic -> "Basic"
        | HttpDigest -> "Digest"
        | WebForm -> "WebForm"

    static member Parse(authInfo: String) =
        match authInfo.ToLower() with
        | "none" -> NoAuthentication
        | "bearer" -> Bearer
        | "basic" -> HttpBasic
        | "digest" -> HttpDigest
        | "webform" -> WebForm
        | _ -> failwith "Unrecognized value"