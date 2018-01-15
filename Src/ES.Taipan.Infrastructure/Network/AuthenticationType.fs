namespace ES.Taipan.Infrastructure.Network

open System
open System.Net
open System.Linq
open System.Collections.Generic
open System.Xml.Linq

type AuthenticationType =
    | NoAuthentication
    | HttpBasic of NetworkCredential
    | HttpDigest of NetworkCredential
    | WebForm of WebFormAuthenticationDescriptor
    | CookiesBased of Cookie list

    override this.ToString() =
        match this with
        | NoAuthentication -> "None"
        | HttpBasic _ -> "Basic"
        | HttpDigest _ -> "Digest"
        | WebForm _ -> "WebForm"
        | CookiesBased _ -> "Cookies"

    // TODO: eliminare questo codice
    (*
    member this.ToXElement() =
        let x str = XName.Get str

        // create the authentication section
        let authenticationElement = new XElement(x"Authentication")
        authenticationElement.Add(new XElement(x"Type", this.ToString()))

        match this with
        | NoAuthentication -> ()

        | HttpBasic nc ->
            let credentials = new XElement(x"Credentials", [|new XElement(x"Username", nc.UserName); new XElement(x"Password", nc.Password)|])
            authenticationElement.Add(credentials)

        | HttpDigest nc ->
            let credentials = new XElement(x"Credentials", [|new XElement(x"Username", nc.UserName); new XElement(x"Password", nc.Password)|])
            authenticationElement.Add(credentials)

        | WebForm (loginMacro, logoutMacro) -> 
            let macros = new XElement(x"Macros", [|new XElement(x"Login", loginMacro); new XElement(x"Logout", logoutMacro)|])
            authenticationElement.Add(macros)

        | CookiesBased cookies ->
            let cookiesElement = new XElement(x"Cookies")                        
            cookies
            |> List.iter (fun cookie ->
                cookiesElement.Add(x"Cookie", [|new XElement(x"Name", cookie.Name); new XElement(x"Value", cookie.Value);|])
            )
            authenticationElement.Add(cookiesElement)

        authenticationElement

    static member GetAuthentication(root: XElement) =
        let x str = XName.Get str

        let authenticationElementType = root.Element(x"Authentication").Element(x"Type").Value
        match authenticationElementType.ToUpperInvariant() with
        | "NONE" -> AuthenticationType.NoAuthentication

        | "BASIC" -> 
            let credentials = root.Element(x"Authentication").Element(x"Credentials")
            AuthenticationType.HttpBasic(new NetworkCredential(credentials.Element(x"Username").Value, credentials.Element(x"Password").Value))

        | "DIGEST" -> 
            let credentials = root.Element(x"Authentication").Element(x"Credentials")
            AuthenticationType.HttpDigest(new NetworkCredential(credentials.Element(x"Username").Value, credentials.Element(x"Password").Value))

        | "WEBFORM" ->
            let macros = root.Element(x"Authentication").Element(x"Macros")
            AuthenticationType.WebForm(macros.Element(x"Login").Value, macros.Element(x"Logout").Value)

        | "COOKIES" ->            
            let cookiesElements = root.Element(x"Authentication").Element(x"Cookies").Elements(x"Cookie")

            let cookies =
                cookiesElements
                |> Seq.map (fun cookieElement -> 
                    let name = cookieElement.Element(x"Name").Value
                    let value = cookieElement.Element(x"Value").Value
                    new Cookie(name, value)
                )
                |> List.ofSeq

            AuthenticationType.CookiesBased(cookies)
        | _ -> 
            failwith ("The type of authentication '" + authenticationElementType + "' must still be implemented")


    *)