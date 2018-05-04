namespace ES.Taipan.Infrastructure.Network

open System
open System.Text
open System.Net
open System.Collections.Generic

type SourcePage = {
    ElementId: String
    DocumentHtml: String
    Info: String
}

type HttpRequest(uri: Uri) =
    new(uri: String) = new HttpRequest(new Uri(uri))

    member val Id = Guid.NewGuid() with get, set
    member val Uri = uri with get, set
    member val Method = HttpMethods.Get with get, set
    member val HttpVersion = HttpVersions.Http11 with get, set
    member val Cookies = new List<Cookie>() with get, set
    member val Headers = new List<HttpHeader>() with get, set
    member val Data = String.Empty with get, set
    member val AllowAutoRedirect : Boolean option = None with get, set
    member val Source: SourcePage option = None with get, set

    static member DeepClone(httpRequestTemplate: HttpRequest) =
        let cookies = httpRequestTemplate.Cookies |> Seq.toList
        let headers = httpRequestTemplate.Headers |> Seq.toList

        let httpRequest = new HttpRequest(httpRequestTemplate.Uri)
        httpRequest.Method <- httpRequestTemplate.Method
        httpRequest.HttpVersion <- httpRequestTemplate.HttpVersion
        httpRequest.Data <- httpRequestTemplate.Data
        httpRequest.AllowAutoRedirect <- httpRequestTemplate.AllowAutoRedirect

        cookies
        |> List.iter(fun cookie -> 
            let newCookie = new Cookie(cookie.Name, cookie.Value, cookie.Path, cookie.Domain)
            newCookie.Comment <- cookie.Comment
            newCookie.CommentUri <- cookie.CommentUri
            newCookie.Discard <- cookie.Discard
            newCookie.Expired <- cookie.Expired
            newCookie.Expires <- cookie.Expires
            newCookie.HttpOnly <- cookie.HttpOnly
            newCookie.Port <- cookie.Port
            newCookie.Secure <- cookie.Secure
            newCookie.Version <- cookie.Version
            httpRequest.Cookies.Add(newCookie)
        )

        headers
        |> List.iter(fun httpHeader ->
            httpRequest.Headers.Add(new HttpHeader(Name = httpHeader.Name, Value = httpHeader.Value))
        )

        match httpRequestTemplate.Source with
        | Some source -> 
            httpRequest.Source <- Some {
                DocumentHtml = source.DocumentHtml
                ElementId = source.ElementId
                Info = source.Info
            }            
        | None -> ()

        httpRequest

    override this.ToString() =
        match this.Method with
        | HttpMethods.Get -> String.Format("{0} {1}", this.Method, this.Uri.PathAndQuery)
        | _ -> 
            let data =
                let limit = 40
                if this.Data.Length > limit then this.Data.[..limit-3] + "..."
                else this.Data
            String.Format("{0} {1} [Data: {2}]", this.Method, this.Uri.PathAndQuery, data)

    member this.ToPlainText() =
        let content = new StringBuilder()

        let statusLine = String.Format("{0} {1} {2}", this.Method.ToString().ToUpper(), this.Uri, this.HttpVersion)
        content.AppendLine(statusLine) |> ignore

        for httpHeader in this.Headers do
            let line = String.Format("{0}: {1}", httpHeader.Name.Trim(), httpHeader.Value.Trim())
            content.AppendLine(line) |> ignore

        // add host
        let line = String.Format("Host: {0}", this.Uri.Host)
        content.AppendLine(line) |> ignore

        for cookie in this.Cookies do
            let line = String.Format("Cookie: {0}={1}", cookie.Name.Trim(), cookie.Value.Trim())
            content.AppendLine(line) |> ignore

        if not <| String.IsNullOrEmpty(this.Data) then
            content.AppendLine().AppendLine(this.Data) |> ignore

        content.ToString().Trim()