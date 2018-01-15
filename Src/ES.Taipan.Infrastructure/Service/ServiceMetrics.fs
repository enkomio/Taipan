namespace ES.Taipan.Infrastructure.Service

open System
open System.Collections.Concurrent

type Metric = {
    Name : String
    Value : String
    TimeStamp : DateTime
}

type ServiceMetrics(serviceName: String) =
    let _metrics = new ConcurrentDictionary<String, Metric>()

    member val ServiceName = serviceName with get

    member this.AddMetric(name: String, value: String) =
        _metrics.[name] <- {Name = name; Value = value; TimeStamp = DateTime.Now}

    member this.GetAll() =
        _metrics.Values |> Seq.toList