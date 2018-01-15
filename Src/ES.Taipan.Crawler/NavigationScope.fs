namespace ES.Taipan.Crawler

open System
open System.Collections.Generic
open ES.Taipan.Infrastructure.Network

type NavigationScope =     
    | WholeDomain
    | EnteredPathAndBelow
    | EnteredPath

    static member Parse(stringValue: String) =
        match stringValue.ToUpper() with
        | "WHOLEDOMAIN" -> WholeDomain
        | "ENTEREDPATHANDBELOW" -> EnteredPathAndBelow
        | "ENTEREDPATH" -> EnteredPath
        | _ -> failwith "Parse"

    override this.ToString() =
        match this with
        | WholeDomain -> "WholeDomain"
        | EnteredPathAndBelow -> "EnteredPathAndBelow"
        | EnteredPath -> "EnteredPath"