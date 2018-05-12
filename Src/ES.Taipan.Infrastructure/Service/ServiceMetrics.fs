namespace ES.Taipan.Infrastructure.Service

open System
open System.Collections.Concurrent
open ES.Taipan.Infrastructure.Messaging

type Metric = {
    Name : String
    Value : String
    TimeStamp : DateTime
}

type RequestMetricsMessage() =
    inherit ResultMessage()

type ServiceMetrics(serviceName: String) =
    let _metrics = new ConcurrentDictionary<String, Metric>()
    
    member val ServiceName = serviceName with get

    member this.AddMetric(name: String, value: String) =
        _metrics.[name] <- {Name = name; Value = value; TimeStamp = DateTime.UtcNow}

    member this.GetAll() =
        _metrics.Values |> Seq.toList