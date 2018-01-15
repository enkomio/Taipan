namespace ES.Taipan.Inspector

open System
open System.Collections.Generic
open ES.Taipan.Infrastructure.Network

type NewSecurityIssueFoundMessage(issue: SecurityIssue) =     
    member val Issue = issue with get

type InspectorSettingsMessage() =
    member val Settings: VulnerabilityScannerSettings option = None with get, set