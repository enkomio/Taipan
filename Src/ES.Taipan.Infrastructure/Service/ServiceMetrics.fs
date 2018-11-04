namespace ES.Taipan.Infrastructure.Service

open System
open System.Collections.Concurrent
open ES.Taipan.Infrastructure.Messaging

type Metric = {
    Group: String
    Name : String
    Value : String
    TimeStamp : DateTime
}

type RequestMetricsMessage() =
    inherit ResultMessage()

type ServiceMetrics(serviceName: String) =
    let _metrics = new ConcurrentDictionary<String, Metric>()
    let _subMetrics = new ConcurrentDictionary<String, ServiceMetrics>()
    
    member val Id = Guid.NewGuid() with get
    member val ServiceName = serviceName with get
    member val Temp = new ConcurrentDictionary<String, Object>() with get

    member this.GetSubMetrics(name: String) =
        lock _subMetrics (fun _ ->
            if not <| _subMetrics.ContainsKey(name) then
                _subMetrics.[name] <- new ServiceMetrics(name)
            _subMetrics.[name]
        )

    member this.GetAllSubMetrics() =
        _subMetrics |> Seq.readonly

    member this.AddMetric(group: String, name: String, value: String) =
        _metrics.[name] <- {Group = group; Name = name; Value = value; TimeStamp = DateTime.UtcNow}

    member this.AddMetric(name: String, value: String) =
        this.AddMetric(name, name, value)

    member this.GetAll() =
        _metrics.Values |> Seq.toList