namespace ES.Taipan.Infrastructure.Network

open System
open System.Text.RegularExpressions
open ES.Taipan.Infrastructure.Text

type internal DigestAuthenticationInfo = {
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

    let retrieveAuthenticationInfo(httpResponse: HttpResponse) =
        httpResponse.Headers
        |> Seq.tryFind (fun header -> header.Name.Equals("WWW-Authenticate", StringComparison.OrdinalIgnoreCase))
        |> fun authHeader ->
            if authHeader.IsSome then
                let indexOfSpace = authHeader.Value.Value.IndexOf(' ')
                let encType = authHeader.Value.Value.Substring(0, indexOfSpace).Trim()
                if encType.Equals("Digest", StringComparison.OrdinalIgnoreCase) then
                    let realm = getRegexValue "realm=\"(.*?)\"" authHeader.Value.Value
                    let nonce = getRegexValue "nonce=\"(.*?)\"" authHeader.Value.Value
                    let opaque = getRegexValue "opaque=\"(.*?)\"" authHeader.Value.Value
                    let qop = getRegexValue "qop=\"(.*?)\"" authHeader.Value.Value
                
                    if realm.IsSome && nonce.IsSome then
                        { 
                            Opaque = if opaque.IsSome then opaque.Value else String.Empty
                            Qop = if qop.IsSome then qop.Value else String.Empty
                            Realm = realm.Value
                            Nonce = nonce.Value
                        } |> Some
                    else
                        None
                else
                    None
            else
                None

    let getHttpDigestAuthenticationString(httpRequest: HttpRequest, authInfo: DigestAuthenticationInfo, username: String, password: String) =
        let ncValue = "00000001"
        let cnonceValue = (new Random()).Next(123400, 9999999).ToString()

        let ha1 = toCleanTextMd5(String.Format("{0}:{1}:{2}", username, authInfo.Realm, password))
        let ha2 = toCleanTextMd5(String.Format("{0}:{1}", httpRequest.Method.ToString().ToUpper(), httpRequest.Uri.AbsolutePath))
        let response = toCleanTextMd5(String.Format("{0}:{1}:{2}:{3}:{4}:{5}", ha1, authInfo.Nonce, ncValue, cnonceValue, "auth", ha2))
        format "Digest username=\"{0}\", realm=\"{1}\", nonce=\"{2}\", uri=\"{3}\", qop=auth, nc={4}, cnonce=\"{5}\", response=\"{6}\", opaque=\"{7}\""
            [|
                username
                authInfo.Realm
                authInfo.Nonce
                httpRequest.Uri.AbsolutePath
                ncValue
                cnonceValue
                response
                authInfo.Opaque
            |]