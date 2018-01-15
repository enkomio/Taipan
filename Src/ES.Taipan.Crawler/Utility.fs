namespace ES.Taipan.Crawler

open System
open ES.Taipan.Infrastructure.Network

[<AutoOpen>]
module Utility =

    let private replaceParameterValueWithDefaultValue(data: String, request: HttpRequest, defaultValues: DefaultParameter seq) =
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