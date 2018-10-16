namespace ES.Taipan.Inspector

open ES.Taipan.Infrastructure.Network

type NewWebPageRequestorMessage() =
    member val WebPageRequestor: IWebPageRequestor option = None with get, set