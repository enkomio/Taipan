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

    let isValidContentType(webResponse: WebResponse) =
        let contentTypeHeader =
            webResponse.HttpResponse.Headers
            |> Seq.tryFind (fun header -> header.Name.Equals("Content-Type", StringComparison.OrdinalIgnoreCase))

        if contentTypeHeader.IsSome then
            contentTypeHeader.Value.Value.ToLower().Contains("text/html") || 
            isPrintableString(webResponse.HttpResponse.Html)
        else
            false

