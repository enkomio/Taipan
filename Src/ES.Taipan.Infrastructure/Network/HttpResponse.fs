namespace ES.Taipan.Infrastructure.Network

open System
open System.IO
open System.Net
open System.Text
open System.Collections.Generic

type HttpResponse() =
    let mutable _content: Byte[] = [||]
    let mutable _html = String.Empty

    let buildHtml() =        
        _html <- 
            if _content <> null then
                Encoding.UTF8.GetString(_content)
            else
                String.Empty

    let buildContent() =        
        _content <- 
            if _html <> null then
                Encoding.UTF8.GetBytes(_html)
            else
                [||]

    member val Id = Guid.NewGuid() with get, set
    member val HttpVersion = HttpVersions.Http11 with get, set
    member val StatusCode = HttpStatusCode.NotFound with get, set
    member val ReasonPhrase = String.Empty with get, set
    member val Headers = new List<HttpHeader>() with get, set
    member val Cookies = new List<Cookie>() with get, set
    member val ResponseUri : Uri option = None with get, set
    
    member this.Content
        with get() = _content
        and set(v) = 
            _content <- v
            buildHtml()

    member this.Html
        with get() = _html
        and set(v) = 
            _html <- v
            buildContent()

    override this.ToString() =
        String.Format("{0} Len={1} Html={2}", this.StatusCode, this.Html.Length, this.Html)

    static member val Empty = new HttpResponse() with get
    static member val Error = new HttpResponse() with get

    member this.ToPlainText() =
        let content = new StringBuilder()

        let statusLine = String.Format("{0} {1} {2}", this.HttpVersion.ToString().ToUpper(), int this.StatusCode, this.ReasonPhrase)
        content.AppendLine(statusLine) |> ignore

        // The cookies are included in the response headers
        for httpHeader in this.Headers do
            let line = String.Format("{0}: {1}", httpHeader.Name.Trim(), httpHeader.Value.Trim())
            content.AppendLine(line) |> ignore
        
        if not <| String.IsNullOrEmpty(this.Html) then
            content.AppendLine().Append(this.Html) |> ignore

        content.ToString().Trim()