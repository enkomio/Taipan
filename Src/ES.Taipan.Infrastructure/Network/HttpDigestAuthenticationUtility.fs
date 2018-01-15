namespace ES.Taipan.Infrastructure.Network

open System
open System.Text.RegularExpressions
open System.IO
open System.Text
open System.Net
open System.Security.Cryptography

type private AuthenticationInfo =
    {
        Opaque              : String
        Qop                 : String
        Realm               : String
        Nonce               : String
    }

module internal HttpDigestAuthenticationUtility =
    
    let private getRegexValue regex str =
        let regex = new Regex(regex, RegexOptions.IgnoreCase)
        let regexMatch = regex.Match(str)
        if regexMatch.Success then
            Some <| regexMatch.Groups.[1].Value
        else
            None

    let private format (formatString: String) (values: Object array) =
        String.Format(formatString, values)

    let private getMd5 (txt: String) =
        let bytes = Encoding.ASCII.GetBytes(txt)
        let hash = MD5.Create().ComputeHash(bytes)
        let sb = new StringBuilder()
        for byte in hash do
            sb.Append(byte) |> ignore
            
        sb.ToString()

    let private retrieveAuthenticationInfo(httpResponse: HttpResponse) =
        httpResponse.Headers
        |> Seq.tryFind (fun header -> header.Name.Equals("WWW-Authenticate", StringComparison.OrdinalIgnoreCase))
        |> fun authHeader ->
            if authHeader.IsSome then
                let realm = getRegexValue "realm=\"(.*?)\"" authHeader.Value.Value
                let nonce = getRegexValue "nonce=\"(.*?)\"" authHeader.Value.Value
                let opaque = getRegexValue "opaque=\"(.*?)\"" authHeader.Value.Value
                let qop = getRegexValue "qop=\"(.*?)\"" authHeader.Value.Value
                
                if realm.IsSome && nonce.IsSome then
                    
                    let mutable authInfo = 
                        { 
                            Opaque = String.Empty
                            Qop = String.Empty
                            Realm = realm.Value
                            Nonce = nonce.Value
                        }

                    if opaque.IsSome then
                        authInfo <- {authInfo with Opaque = opaque.Value}

                    if qop.IsSome then
                        authInfo <- {authInfo with Qop = qop.Value}

                    Some authInfo
                else
                    None
            else
                None

    let getHttpDigestAuthenticationString(httpRequest: HttpRequest, httpResponse: HttpResponse, username: String, password: String) =
        let authInfo = retrieveAuthenticationInfo(httpResponse)
        
        if authInfo.IsSome then
            let realm = authInfo.Value.Realm
            let nonce = authInfo.Value.Nonce
            let opaque = if not <| String.IsNullOrWhiteSpace(authInfo.Value.Opaque) then format ", opaque=\"{0}\"" [|authInfo.Value.Opaque|] else String.Empty
            let qop = if not <| String.IsNullOrWhiteSpace(authInfo.Value.Qop) then format ", qop={0}" [|authInfo.Value.Qop|] else String.Empty
            
            // create the various piece of digest information
            let ha1 = format "{0}:{1}:{2}" [|username; realm; password|]
            let mutable ha2 = String.Empty
            let mutable nc = String.Empty
            let mutable cnonce = String.Empty
            let mutable r = String.Empty

            // build the various authentication peace according to the kind of authentication requested
            if String.IsNullOrWhiteSpace(qop) || authInfo.Value.Qop.Equals("auth", StringComparison.OrdinalIgnoreCase) then
                ha2 <- getMd5 <| format "{0}:{1}" [|httpRequest.Method.ToString(); httpRequest.Uri.AbsoluteUri|]
            
            elif authInfo.Value.Qop.Equals("auth-int", StringComparison.OrdinalIgnoreCase) then
                failwith "HTTP DIGEST Auth-Int type to be implemented"
            
            if authInfo.Value.Qop.Equals("auth", StringComparison.OrdinalIgnoreCase) || authInfo.Value.Qop.Equals("auth-int", StringComparison.OrdinalIgnoreCase) then
                let ncValue = "00000001"
                let cnonceValue = (new Random()).Next(123400, 9999999).ToString()
                nc <- format ", nc={0}" [|ncValue|]
                cnonce <- format ", cnonce=\"{0}\"" [|cnonceValue|]
                
                r <- getMd5 <| format "{0}:{1}:{2}:{3}:{4}:{5}" [|ha1; nonce; ncValue; cnonceValue; authInfo.Value.Qop; ha2|]
            
            elif String.IsNullOrWhiteSpace(authInfo.Value.Qop) then
                r <- getMd5 <| format "{0}:{1}:{2}" [|ha1; nonce; ha2|]

            // return the http header
            format "Digest username=\"{0}\", realm=\"{1}\", nonce=\"{2}\", uri=\"{3}\", response=\"{4}\"{5}{6}{7}{8}"
                [|
                    username
                    realm
                    nonce
                    httpRequest.Uri.PathAndQuery
                    r
                    opaque
                    qop
                    nc
                    cnonce
                |] 

        else
            String.Empty
