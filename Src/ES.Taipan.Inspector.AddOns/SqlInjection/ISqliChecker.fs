namespace ES.Taipan.Inspector.AddOns.SqlInjection

open System
open System.Collections.Generic
open ES.Taipan.Inspector
open ES.Taipan.Infrastructure.Network

type AttackDetails = {
    ParameterName: String
    Requests: WebRequest seq
    Responses: WebResponse seq
    Details: Dictionary<String, String>
}

type CheckResult = {
    Success: Boolean
    Details: AttackDetails option
} with
    static member NotVulnerable = {
        Success = false
        Details = None
    }

type ISqliChecker =
    interface
        abstract Test: ProbeParameter * ProbeRequest -> CheckResult
        abstract VulnName : String with get
        abstract VulnId : Guid with get
    end

