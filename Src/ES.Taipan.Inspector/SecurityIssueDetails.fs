namespace ES.Taipan.Inspector

open System
open System.Collections.Generic

type SecurityIssueDetails() =
    member val Properties = new Dictionary<String, String>() with get