namespace ES.Taipan.Infrastructure.Network

open System
open System.Text.RegularExpressions
open System.Collections.Generic
open System.Net

type WebFormAuthenticationDescriptor() =
    let _requests = new Queue<HttpRequest>()

    member val LoginMatchingPattern = String.Empty with get, set
    member val LogoutMatchingPattern = String.Empty with get, set

    member this.AddRequest(req: HttpRequest) =
        _requests.Enqueue(req)

    member this.TryAuthenticate(sendRequest: HttpRequest -> HttpResponse option) =
        if _requests |> Seq.isEmpty then false
        else
            _requests
            |> Seq.map sendRequest
            |> Seq.last
            |> fun httpResponse -> httpResponse.IsSome && Regex.IsMatch(httpResponse.Value.Html, this.LoginMatchingPattern)

    member this.IsLoggedOut(httpResponse: HttpResponse) =
        Regex.IsMatch(httpResponse.Html, this.LogoutMatchingPattern)