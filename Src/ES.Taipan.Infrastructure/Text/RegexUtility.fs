namespace ES.Taipan.Infrastructure.Text

open System
open System.Net
open System.Linq
open System.Text
open System.Text.RegularExpressions
open ES.Taipan.Infrastructure.Validation
open AngleSharp.Parser.Html

[<AutoOpen>]
module RegexUtility =

    let (=~) (text: String) (regex: String) =
        Regex.IsMatch(text, regex, RegexOptions.Singleline ||| RegexOptions.Multiline ||| RegexOptions.IgnoreCase)

    let getAllHtmlTags(html: String, tagName: String) =
        let parser = new HtmlParser()
        parser.Parse(html).All
        |> Seq.filter(fun e -> e.LocalName.Equals(tagName, StringComparison.OrdinalIgnoreCase))
        |> Seq.map(fun e -> e.OuterHtml)
        
    let getHtmlInputValue(html: String, attributeName: String) =
        let parser = new HtmlParser()
        parser.Parse(html).All
        |> Seq.filter(fun e -> e.LocalName.Equals("input", StringComparison.OrdinalIgnoreCase))
        |> Seq.filter(fun e -> e.HasAttribute(attributeName))
        |> Seq.map(fun e -> e.GetAttribute(attributeName))
        |> Seq.tryHead
        |> fun v -> defaultArg v String.Empty
    
    let getHtmlAttributeValueFromChunk(htmlTag: String, attributeName: String) =
        notNull htmlTag "htmlTag"
        notEmpty attributeName "attributeName"

        let mutable regexString = String.Format( "({0})=(['\"])", attributeName )
        let regex = new Regex( regexString, RegexOptions.Singleline ||| RegexOptions.Multiline ||| RegexOptions.IgnoreCase )
        let regexMatch = regex.Match(htmlTag)
                        
        if regexMatch.Success then
            // identify the attribute enclosing character, if it is ' or " and calculate the new regex string
            // in order to obtain the real attribute value
            let gc = regexMatch.Groups
            let delimiter = gc.[2].Value
            regexString <- String.Format( "({0})={1}(.*?){1}", attributeName, delimiter )
        else
            // no delimiter present, the attribute value and with the tag or with a space
            regexString <- String.Format( "({0})=(.*?)([\\s>]|/>|$)", attributeName )
        
        // redo the match in order to retrieve the attribute value with the correct value delimiter
        let regex = new Regex( regexString, RegexOptions.Singleline ||| RegexOptions.Multiline ||| RegexOptions.IgnoreCase )
        let regexMatch = regex.Match(htmlTag)

        if regexMatch.Success then
            let attributeValue = regexMatch.Groups.[2].Value
            Some <| WebUtility.HtmlDecode(attributeValue)
        else
            None

    let private removeContentFromText (regexString: String, text: String) =
        let mutable cleanText = text
        let removedText = new StringBuilder()
        let regex = new Regex(regexString, RegexOptions.IgnoreCase ||| RegexOptions.Singleline)
        let mutable matchVal = regex.Match(text)

        if matchVal.Success then
            while (matchVal.Success) do
                let textToRemove = matchVal.Groups.[1].Value
                removedText.Append(textToRemove) |> ignore
                cleanText <- cleanText.Replace(textToRemove, String.Empty)
                matchVal <- matchVal.NextMatch()

        (cleanText, removedText.ToString())

    let removeScriptContent(html: String) =
        notNull html "html"
        removeContentFromText(@"(<script.*?</script>)", html)

    let removeHtmlComments(html: String) =
        notNull html "html"
        removeContentFromText(@"(<!--.*?-->)", html)

