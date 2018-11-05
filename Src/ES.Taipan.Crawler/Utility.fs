namespace ES.Taipan.Crawler

open System
open System.Text
open System.Text.RegularExpressions
open ES.Taipan.Infrastructure.Network

[<AutoOpen>]
module Utility =        
    let private replaceValueInFormEncodedData(data: String, request: HttpRequest, defaultValues: DefaultParameter seq) =
        data.Split([|"&"|], StringSplitOptions.RemoveEmptyEntries)
            |> Array.map(fun paramChunk ->
                let nameValue = paramChunk.Split('=')
                if nameValue.Length > 1 then (nameValue.[0], nameValue.[1])
                else (paramChunk, String.Empty)
            ) 
            |> Array.map(fun (name, value) ->
                match 
                    defaultValues 
                    |> Seq.tryFind(fun defParam -> 
                        defParam.Name.Equals(name, StringComparison.Ordinal) && 
                        defParam.Path.Equals(request.Uri.AbsolutePath, StringComparison.Ordinal)
                    ) with
                | Some defParam -> String.Format("{0}={1}", name, defParam.Value)
                | _ -> String.Format("{0}={1}", name, value)
            )
            |> fun effectiveParams -> String.Join("&", effectiveParams)

    let private tryGetDefaultValue(parameterName: String, request: HttpRequest, defaultValues: DefaultParameter seq) =
        defaultValues 
        |> Seq.tryFind(fun defParam -> 
            defParam.Name.Equals(parameterName, StringComparison.Ordinal) && 
            defParam.Path.Equals(request.Uri.AbsolutePath, StringComparison.Ordinal)
        ) 

    let private replaceValueInMultipartEncodedData(data: String, request: HttpRequest, defaultValues: DefaultParameter seq) =
        let headerBoundary = WebUtility.getBoundary(request)
        let boundary = "--" + headerBoundary
        let resultData = new StringBuilder()
        let newLine = "\r\n"
        let doubleNewLine = newLine + newLine

        data.Split([|boundary|], StringSplitOptions.RemoveEmptyEntries)
        |> Array.map(fun item -> item.Trim())
        |> Array.filter((<>) "--")
        |> Array.iter(fun item ->
            let items = item.Split([|doubleNewLine|], StringSplitOptions.RemoveEmptyEntries)
            let (header, value) = 
                if items.Length > 1
                then (items.[0].Trim(), items.[1].Trim())
                else (item.Trim(), String.Empty)
            let matchesName = Regex.Match(header, "name=\"(.*?)\"", RegexOptions.IgnoreCase)
            let matchesFilename = Regex.Match(header, "filename=\"", RegexOptions.IgnoreCase)

            let mutable finalValue = value
            let mutable parameterName = String.Empty
            if matchesName.Success then
                parameterName <- matchesName.Groups.[1].Value
                match tryGetDefaultValue(parameterName, request, defaultValues) with
                | Some defaultParameter -> finalValue <- defaultParameter.Value
                | None -> ()

            // create header
            let header =
                if matchesFilename.Success
                then String.Format("Content-Disposition: form-data; name=\"{0}\" filename=\"\"{1}Content-Type: text/plain", parameterName, newLine)
                else String.Format("Content-Disposition: form-data; name=\"{0}\"", parameterName)

            // create the parameter
            resultData
                .Append(boundary)
                .Append(newLine)
                .AppendFormat(header)
                .Append(doubleNewLine)
                .Append(finalValue)
                .Append(newLine)
                |> ignore
        )
        
        resultData.Append(boundary).Append("--").Append(newLine) |> ignore
        resultData.ToString()

    let private replaceParameterValueWithDefaultValue(data: String, request: HttpRequest, defaultValues: DefaultParameter seq) =
        if WebUtility.isMultiPartFormData(request) 
        then replaceValueInMultipartEncodedData(data, request, defaultValues)
        else replaceValueInFormEncodedData(data, request, defaultValues)
    
    let replaceParameterValue(request: HttpRequest, defaultValues: DefaultParameter seq) =
        let query = request.Uri.Query
        if query.Length > 1 then
            let newQuery = replaceParameterValueWithDefaultValue(query.Substring(1), request, defaultValues)
            let uriBuilder = new UriBuilder(request.Uri)
            uriBuilder.Query <- newQuery
            request.Uri <- uriBuilder.Uri
        
        if request.Data.Length > 0 then
            let newData = replaceParameterValueWithDefaultValue(request.Data, request, defaultValues)
            request.Data <- newData