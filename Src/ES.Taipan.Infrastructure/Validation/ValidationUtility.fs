namespace ES.Taipan.Infrastructure.Validation

open System
open System.Threading

[<AutoOpen>]
module ValidationUtility =
    
    let notNull o (name: String) =
        if o = null then raise <| new ArgumentNullException(name)

    let notEmpty (s: String) (name: String) =
        if String.IsNullOrWhiteSpace(s) then raise <| new ArgumentNullException(name)