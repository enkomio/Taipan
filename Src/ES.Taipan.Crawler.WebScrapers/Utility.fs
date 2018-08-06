namespace ES.Taipan.Crawler.WebScrapers

open System
open ES.Taipan.Infrastructure.Network
open ES.Taipan.Infrastructure.Text

[<AutoOpen>]
module internal Utility =
    let isPrintableString(content: String) =
        let (<|>) f g x = f x || g x
        content.ToCharArray()
        |> Seq.forall((Char.IsControl >> not) <|> ((=) '\n') <|> ((=) '\r') <|> ((=) '\t'))

    let isContentType(webResponse: WebResponse, contentTypes: String list) =
        let contentTypeHeader =
            webResponse.HttpResponse.Headers
            |> Seq.tryFind (fun header -> header.Name.Equals("Content-Type", StringComparison.OrdinalIgnoreCase))

        match contentTypeHeader with
        | Some responseContentType ->
            contentTypes
            |> List.exists(fun contentType ->
                responseContentType.Value.ToLower().Contains(contentType)
            )
        | None -> false

    let isValidContent(webResponse: WebResponse) =        
        isContentType(webResponse, ["text/html"]) || isPrintableString(webResponse.HttpResponse.Html)

