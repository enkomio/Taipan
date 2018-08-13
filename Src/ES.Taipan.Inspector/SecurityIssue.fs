namespace ES.Taipan.Inspector

open System
open System.Collections.Generic
open ES.Taipan.Infrastructure.Network

type EntryPoint =
    | QueryString
    | UriSegment
    | DataString
    | Cookie
    | Header
    | Other of String
    
    override this.ToString() =
        match this with
        | QueryString -> "QUERY"
        | UriSegment -> "URI"
        | DataString -> "DATA"
        | Cookie -> "COOKIE"
        | Header -> "HEADER"
        | Other s -> s

type SecurityIssue(addOnId: Guid) =
    member val Id = Guid.NewGuid() with get, set
    member val Name = String.Empty with get, set
    member val AddOnId = addOnId with get, set
    member val Details = new SecurityIssueDetails() with get, set  
    member val Uri : Uri = null with get, set
    member val EntryPoint = EntryPoint.Other String.Empty with get, set
    member val Transactions = new Dictionary<WebRequest, WebResponse>() with get, set
    member val Note = String.Empty with get, set
    
    override this.ToString() =
        if not <| String.IsNullOrWhiteSpace(this.Note) then
            String.Format("{0} on {1}. {2}", this.Name, this.Uri, this.Note)
        else
            String.Format("{0} on {1}", this.Name, this.Uri)

    override this.GetHashCode() =
        this.Uri.GetHashCode()

    override this.Equals(o: Object) =
        match o with
        | null -> false
        | :? SecurityIssue as secIssue -> 
            secIssue.AddOnId = this.AddOnId &&
            secIssue.EntryPoint = this.EntryPoint &&
            secIssue.Uri.Equals(this.Uri)
        | _ -> false