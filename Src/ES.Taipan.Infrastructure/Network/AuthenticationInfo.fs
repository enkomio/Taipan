namespace ES.Taipan.Infrastructure.Network

open System
open System.Collections.Generic
open System.Xml.Linq

type AuthenticationInfo() =
    static let x str = XName.Get str
    member val Enabled = false with get, set
    member val Type = AuthenticationType.NoAuthentication with get, set
    member val Username = String.Empty with get, set
    member val Password = String.Empty with get, set
    member val Token = String.Empty with get, set
    member val LoginPattern = new List<String>() with get
    member val LogoutPattern = new List<String>() with get
    member val DynamicAuthParameterPatterns = new List<String>() with get

    member this.ToXElement() =
        let authInfo = new XElement(x"AuthenticationInfo")

        authInfo.Add(new XElement(x"Type", this.Type.ToString()))
        authInfo.Add(new XElement(x"Username", this.Username))
        authInfo.Add(new XElement(x"Password", this.Password))
        authInfo.Add(new XElement(x"Token", this.Token))
        authInfo.Add(new XElement(x"Enabled", this.Enabled))

        let loginPattern = new XElement(x"LoginPattern")
        authInfo.Add(loginPattern)
        this.LoginPattern
        |> Seq.iter(fun pattern -> loginPattern.Add(new XElement(x"Pattern", pattern)))

        let logoutPattern = new XElement(x"LogoutPattern")
        authInfo.Add(logoutPattern)
        this.LogoutPattern
        |> Seq.iter(fun pattern -> logoutPattern.Add(new XElement(x"Pattern", pattern)))

        let dynamicAuthParameterPatterns = new XElement(x"DynamicAuthParameterPatterns")
        authInfo.Add(dynamicAuthParameterPatterns)
        this.DynamicAuthParameterPatterns
        |> Seq.iter(fun pattern -> dynamicAuthParameterPatterns.Add(new XElement(x"Pattern", pattern)))
        
        authInfo

    member this.AcquireSettingsFromXElement(root: XElement) =
        this.Type <- AuthenticationType.Parse(root.Element(x"Type").Value)
        this.Username <- root.Element(x"Username").Value
        this.Password <- root.Element(x"Password").Value
        this.Token <- root.Element(x"Token").Value
        this.Enabled <- Boolean.Parse(root.Element(x"Enabled").Value)

        root.Element(x"LoginPattern").Elements(x"Pattern")
        |> Seq.iter(fun xPattern -> this.LoginPattern.Add(xPattern.Value))

        root.Element(x"LogoutPattern").Elements(x"Pattern")
        |> Seq.iter(fun xPattern -> this.LogoutPattern.Add(xPattern.Value))

        root.Element(x"DynamicAuthParameterPatterns").Elements(x"Pattern")
        |> Seq.iter(fun xPattern -> this.DynamicAuthParameterPatterns.Add(xPattern.Value))