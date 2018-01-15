namespace ES.Taipan.Infrastructure.Text

open System
open System.Text
open System.Text.RegularExpressions
open ES.Taipan.Infrastructure.Validation

module WebUtility =

    let notHyperlinkSchemas = ["#"; "file:"; "ftp:"; "data:"; "javascript:"; "mailto:"; "about:"]

    let private relativeOrAbsolute(uriStr: String) =        
        if uriStr.Trim().StartsWith("/") then new Uri(uriStr, UriKind.Relative)
        else new Uri(uriStr, UriKind.RelativeOrAbsolute)

    let private isWellFormedUriString(uriString: String, uriKind: UriKind) =
        if Uri.IsWellFormedUriString(uriString, uriKind) then
            true
        else
            let escapedUriString = Uri.EscapeUriString(uriString)
            Uri.IsWellFormedUriString(escapedUriString, uriKind)

    let composeDataFromParameters(dataParameters: (String * String) list) = 
        let composedData = new StringBuilder()
        let orderedParametersList = 
            dataParameters
            // sort by tuple because they are sorted in lexicographical order
            |> List.sortBy (fun t -> t)
            
        for (paramName, paramValue) in orderedParametersList do
            if not <| String.IsNullOrWhiteSpace(paramName) then
                composedData.AppendFormat("&{0}={1}", paramName, paramValue) |> ignore

        if composedData.Length > 0 then composedData.ToString().Substring(1)
        else composedData.ToString()

    let getParametersFromData(data: String)=
        notNull data "data"

        [
            for chunk in data.Split([|'&'|]) do
                if not <| String.IsNullOrWhiteSpace(chunk) then
                    let indexOfEqual = chunk.IndexOf('=')
                    if indexOfEqual >= 0 then
                        let paramName = chunk.Substring(0, indexOfEqual)
                        let paramValue = chunk.Substring(indexOfEqual + 1)
                        yield (paramName, paramValue)
                    else
                        yield (chunk, String.Empty)
        ]

    let getPageExtension(uri: Uri) =
        notNull uri "uri"

        let absoluteUri = uri.AbsolutePath
        let lastIndexOfDot = absoluteUri.LastIndexOf('.')
        if lastIndexOfDot >= 0 then
            Some <| absoluteUri.Substring(lastIndexOfDot)
        else
            None
            
    let hasSameParametersAndData(firstHttpRequestData: String, secondHttpRequestData: String) =
        notNull firstHttpRequestData "firstHttpRequestData"
        notNull secondHttpRequestData "secondHttpRequestData"

        let firstReqParameters = 
            getParametersFromData(firstHttpRequestData)
            |> List.sortBy (fun (name,value) -> name)

        let secondReqParameters = 
            getParametersFromData(secondHttpRequestData)
            |> List.sortBy (fun (name,value) -> name)
            
        if firstReqParameters.Length <> secondReqParameters.Length then
            false
        else
            firstReqParameters
            |> List.zip secondReqParameters
            |> List.forall (fun ((name1,value1),(name2,value2)) -> 
                name1.Equals(name2, StringComparison.Ordinal) && value1.Equals(value2, StringComparison.Ordinal))

    let areUriEquals(firstUri: Uri, secondUri: Uri) =
        notNull firstUri "areUriEquals"
        notNull secondUri "secondUri"

        let (cleanFirstUri, cleanSecondUri) =
            [firstUri; secondUri]
            |> List.map (fun uri ->
                let uriBuilder = new UriBuilder(uri)
                uriBuilder.Fragment <- String.Empty
                uriBuilder.Query <- String.Empty
                uriBuilder.Uri
            )
            |> fun uriList -> (uriList.[0], uriList.[1])            

        if not <| cleanFirstUri.Equals(cleanSecondUri) then
            false
        elif firstUri.Scheme <> secondUri.Scheme then
            false
        elif firstUri.Port <> secondUri.Port then
            false
        else      
            // verify the query parameters
            let dataStringFirstUri = 
                if String.IsNullOrWhiteSpace(firstUri.Query) then String.Empty
                else firstUri.Query.Substring(1).Trim() // delete the initial question mark character

            let dataStringSecondUri = 
                if String.IsNullOrWhiteSpace(secondUri.Query) then String.Empty
                else secondUri.Query.Substring(1).Trim() // delete the initial question mark character

            hasSameParametersAndData(dataStringFirstUri, dataStringSecondUri)
            
    let canonicalizeUri(uri: Uri) =        
        notNull uri "uri"

        if uri.IsAbsoluteUri then
            let uriBuilder = new UriBuilder(uri)
            let canonicalizedPath = Uri.UnescapeDataString(uriBuilder.Path)
            uriBuilder.Path <- Regex.Replace(canonicalizedPath, "/+", "/")
            uriBuilder.Uri
        else
            let uriString = uri.ToString()

            let clean(uriString: String) =
                let strippedUriString = uriString.Trim().Replace('+', ' ')
                let unescapedDataString = Uri.UnescapeDataString(strippedUriString)
                let tmp = Regex.Replace(unescapedDataString, "/+", "/")
                Regex.Replace(tmp, "/\\./", "/")

            let indexOfQuery = uriString.IndexOf('?') 
            if indexOfQuery >= 0 then
                // clean only the path string
                let pathUri = uriString.Substring(0, indexOfQuery)
                let queryString = uriString.Substring(indexOfQuery)
                relativeOrAbsolute(clean(pathUri) + queryString)
            else
                // no query string
                let canonicalizedPath = Uri.UnescapeDataString(uriString)
                relativeOrAbsolute(clean(canonicalizedPath))

    let isWrongUriString(uriString: String) =
        notNull uriString "uriString"
        notHyperlinkSchemas
        |> Seq.exists uriString.StartsWith
    
    let getAbsoluteUriValue(baseUri: Uri, partialUri: Uri) =
        notNull baseUri "baseUri"
        notNull partialUri "partialUri"

        let canonicalizedUri = canonicalizeUri(partialUri)

        if partialUri.IsAbsoluteUri then
            canonicalizedUri
        else
            let combinedUri = new Uri(baseUri, canonicalizedUri)
            canonicalizeUri(combinedUri)
        
    let getAbsoluteUriStringValueSameHost(baseUriString: String, partialUriStringRaw: String) =  
        notEmpty baseUriString "baseUriString"
        notNull partialUriStringRaw "partialUriStringRaw"
        
        let partialUriString = 
            if partialUriStringRaw.StartsWith("//") then (new Uri(baseUriString)).Scheme + ":" + partialUriStringRaw
            else partialUriStringRaw

        if isWrongUriString(partialUriString) then
            None  
        elif String.IsNullOrWhiteSpace(partialUriString) then
            Some <| System.Net.WebUtility.HtmlDecode(baseUriString)
        else
            try
                let baseUri = new Uri(baseUriString)
                let partialUri = relativeOrAbsolute(partialUriString.Trim())
                let fixedUri = getAbsoluteUriValue(baseUri, partialUri)
                if baseUri.Host.Equals(fixedUri.Host, StringComparison.OrdinalIgnoreCase) then
                    Some <| System.Net.WebUtility.HtmlDecode(fixedUri.AbsoluteUri)
                else 
                    None
            with
            | :? UriFormatException -> None
