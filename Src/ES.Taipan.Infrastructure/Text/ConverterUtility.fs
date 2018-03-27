namespace ES.Taipan.Infrastructure.Text

open System
open System.Linq
open System.Text
open System.Text.RegularExpressions
open ES.Taipan.Infrastructure.Validation
open System.Security.Cryptography

[<AutoOpen>]
module ConverterUtility =

    let toAsciiBase64(text: String) =        
        notNull text "text"
        let stringBytes = Encoding.ASCII.GetBytes(text)
        Convert.ToBase64String(stringBytes)

    let private toMd5(text: String) =
        let bytes = Encoding.UTF8.GetBytes(text)
        let md5 = MD5.Create();
        let hashBytes = md5.ComputeHash(bytes)
        BitConverter.ToString(hashBytes).Replace("-", String.Empty)

    let toCleanTextMd5(text: String) =        
        text.ToCharArray()
        |> Array.filter(Char.IsControl >> not)
        |> fun chars -> toMd5(new String(chars)).ToLower()