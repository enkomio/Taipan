namespace ES.Taipan.Infrastructure.Network

open System

type IPageNotFoundIdentifier =
    interface
        abstract PageExists : HttpRequest * HttpResponse option -> Boolean
    end

