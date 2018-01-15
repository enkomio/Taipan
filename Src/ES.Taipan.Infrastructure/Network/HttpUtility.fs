namespace ES.Taipan.Infrastructure.Network

open System
open System.Collections.Generic
open System.Net

module HttpUtility =

    /// Return the absolute path directory. Some examples:
    /// http://www.example.com/a/b/c/index.php    -> /a/b/c 
    /// http://www.example.com/a/b/c/index        -> /a/b/c
    /// http://www.example.com/a/b/c/             -> /a/b/c
    let getAbsolutePathDirectory(uri: Uri) =
        let uriWebsite = uri.AbsolutePath
        if not <| uriWebsite.EndsWith("/") then
            let lastIndexOfSlash = uriWebsite.LastIndexOf('/')
            uriWebsite.Substring(0, lastIndexOfSlash)
         elif uriWebsite.Length > 0 then
            uriWebsite.Substring(0, uriWebsite.Length - 1)
        else 
            uriWebsite

    /// Return the web page name. Some examples:
    /// http://www.example.com/a/b/c/index.php    -> index.php
    /// http://www.example.com/a/b/c/index        -> index
    /// http://www.example.com/a/b/c/             -> <String.Empty>
    let getPage(uri: Uri) =
        let absolutePath = uri.AbsolutePath
        if absolutePath.EndsWith("/") then
            String.Empty
        else
            let lastIndexOfSlash = absolutePath.LastIndexOf("/")
            absolutePath.Substring(lastIndexOfSlash + 1)

    let getHeader(hdrName: String, headers: HttpHeader seq) =
        headers |> Seq.find(fun hdr -> hdr.Name.Equals(hdrName, StringComparison.Ordinal))

    let tryGetHeader(hdrName: String, headers: HttpHeader seq) =
        headers |> Seq.tryFind(fun hdr -> hdr.Name.Equals(hdrName, StringComparison.Ordinal))

    let setHeader(headerName: String, headerValue: String, headers: List<HttpHeader>) =
        match tryGetHeader(headerName,  headers) with
        | Some header -> header.Value <- headerValue
        | None -> headers.Add(new HttpHeader(Name = headerName, Value = headerValue))

    let isRedirect(statusCode: HttpStatusCode) =
        match statusCode with
        | HttpStatusCode.Found
        | HttpStatusCode.Moved
        | HttpStatusCode.MovedPermanently
        | HttpStatusCode.MultipleChoices
        | HttpStatusCode.NotModified
        | HttpStatusCode.Redirect
        | HttpStatusCode.RedirectKeepVerb
        | HttpStatusCode.RedirectMethod
        | HttpStatusCode.SeeOther
        | HttpStatusCode.TemporaryRedirect
        | HttpStatusCode.Unused
        | HttpStatusCode.UseProxy -> true
        | _ -> false
