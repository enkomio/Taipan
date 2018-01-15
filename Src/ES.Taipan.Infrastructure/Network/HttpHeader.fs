namespace ES.Taipan.Infrastructure.Network

open System

type HttpHeader() =
    
    member val Id = Guid.NewGuid() with get, set
    member val Name = String.Empty with get, set
    member val Value = String.Empty with get, set

    override this.ToString() =
        String.Format("{0}: {1}", this.Name, this.Value)