namespace ES.Taipan.Discoverer

open System

type Resource(path: String) =    
    member val Path = path with get, set
    member val Group = String.Empty with get, set

    override this.Equals(o: Object) =
        match o with
        | :? Resource as r -> r.Path.Equals(this.Path, StringComparison.Ordinal) 
        | _ -> false

    override this.ToString() =
        String.Format("Path={0} Group={1}", this.Path, this.Group)

