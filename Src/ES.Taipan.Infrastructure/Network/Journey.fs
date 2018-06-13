namespace ES.Taipan.Infrastructure.Network

open System
open System.Text
open System.IO
open System.Collections.Generic
open System.Xml.Linq
open System.Linq

type JourneyTransactionParameterType =
    | Query
    | Data
        with
            override this.ToString() =
                match this with
                | Query -> "Query"
                | Data -> "Data"

            static member Parse(txt: String) =
                match txt.ToLower() with
                | "query" -> Query
                | "data" -> Data
                | _ -> failwith "Not a valid JourneyTransactionParameterType"

type JourneyTransactionParameter = {
    Name: String
    Value: String
    Type: JourneyTransactionParameterType
    IsStatic: Boolean
}

type JourneyTransactionRequest() =
    member val Method = String.Empty with get, set
    member val Uri = String.Empty with get, set
    member val Headers = List.empty<String * String> with get, set
    member val Data = String.Empty with get, set

type JourneyTransactionResponse() =
    member val ResponseCode = -1 with get, set
    member val Headers = List.empty<String * String> with get, set
    member val Content = String.Empty with get, set

type JourneyTransaction() =
    member val Index = 0 with get, set    
    member val TemplateRequest = new JourneyTransactionRequest() with get, set
    member val TemplateResponse = new JourneyTransactionResponse() with get, set    
    member val TransactionResponse: HttpResponse option = None with get, set
    member val Parameters = new List<JourneyTransactionParameter>() with get

    member this.AddParameter(name: String, value: String, pType: String, isStatic: Boolean) = 
        {
            Name = name
            Value = value
            Type = JourneyTransactionParameterType.Parse(pType)
            IsStatic = isStatic
        } |> this.Parameters.Add
        
    member this.BuildBaseHttpRequest() =
        let httpRequest = new HttpRequest(this.TemplateRequest.Uri, Method = HttpMethods.ToHttpMethod(this.TemplateRequest.Method))

        // add headers
        this.TemplateRequest.Headers
        |> List.iter(fun (name, value) -> httpRequest.Headers.Add(new HttpHeader(Name = name, Value = value)))
        
        httpRequest
        
    override this.ToString() =
        String.Format("{0} #Params: {1}", this.TemplateRequest.Uri, this.Parameters.Count)

type JourneyPath() =
    member val Transactions = new List<JourneyTransaction>() with get

    member this.Item
      with get index = this.Transactions |> Seq.find(fun transaction -> transaction.Index = index)

    member this.CreateTransaction() =
        let transaction = new JourneyTransaction()
        this.Transactions.Add(transaction)
        transaction

type Journey() =
    static let x str = XName.Get str
    member val Paths = new List<JourneyPath>() with get

    member this.CreatePath() =
        let path = new JourneyPath()
        this.Paths.Add(path)
        path

    member this.ToXElement() =
        let journey = new XElement(x"Journey")
        this.Paths
        |> Seq.iter (fun path -> 
            let pathElem = new XElement(x"Path")
            journey.Add(pathElem)

            path.Transactions
            |> Seq.iter(fun transaction ->
                // parameters
                let parametersElem = new XElement(x"Parameters")
                transaction.Parameters
                |> Seq.iter(fun journeyParam ->
                    let parameterElem = 
                        new XElement(x"Parameter",
                            new XElement(x"Name", journeyParam.Name),
                            new XElement(x"Value", journeyParam.Value),
                            new XElement(x"Type", journeyParam.Type.ToString()),
                            new XElement(x"IsStatic", journeyParam.IsStatic)
                        )
                    parametersElem.Add(parameterElem)
                )

                // request
                let reqHeader = new XElement(x"Headers")
                transaction.TemplateRequest.Headers
                |> Seq.iter(fun (n, v) ->
                    let xHeader = new XElement(x"Header", new XElement(x"Name", n), new XElement(x"Value", v))
                    reqHeader.Add(xHeader)
                )
                let req = 
                    new XElement(x"TemplateRequest",
                        new XElement(x"Method", transaction.TemplateRequest.Method),
                        new XElement(x"Data", transaction.TemplateRequest.Data),
                        new XElement(x"Uri", transaction.TemplateRequest.Uri),
                        reqHeader
                    )

                // response
                let respHeader = new XElement(x"Headers")                
                transaction.TemplateResponse.Headers
                |> Seq.iter(fun (n, v) ->
                    let xHeader = new XElement(x"Header", new XElement(x"Name", n), new XElement(x"Value", v))
                    respHeader.Add(xHeader)
                )                
                let resp = 
                    new XElement(x"TemplateResponse",
                        new XElement(x"ResponseCode", transaction.TemplateResponse.ResponseCode),
                        new XElement(x"Base64Content", Convert.ToBase64String(Encoding.UTF8.GetBytes(transaction.TemplateResponse.Content))),
                        respHeader
                    )

                let transactionElem = 
                    new XElement(x"Transaction",
                        new XElement(x"Index", transaction.Index),
                        req,
                        resp,
                        parametersElem
                    )
                pathElem.Add(transactionElem)                
            )
        )
        
        journey

    member this.AcquireSettingsFromXElement(root: XElement) =
        root.Elements(x"Path")
        |> Seq.iter(fun xPath ->
            let path = new JourneyPath()
            this.Paths.Add(path)

            xPath.Elements(x"Transaction")
            |> Seq.iter(fun xTransaction ->
                let transaction = new JourneyTransaction()
                transaction.Index <- Int32.Parse(xTransaction.Element(x"Index").Value)                  
                
                // request
                let req = xTransaction.Element(x"TemplateRequest")
                transaction.TemplateRequest.Data <- req.Element(x"Data").Value
                transaction.TemplateRequest.Method <- req.Element(x"Method").Value
                transaction.TemplateRequest.Uri <- req.Element(x"Uri").Value
                
                transaction.TemplateRequest.Headers <-
                    req.Element(x"Headers").Elements(x"Header")
                    |> Seq.map(fun xHdr -> (xHdr.Element(x"Name").Value, xHdr.Element(x"Value").Value))
                    |> Seq.toList                          
                          
                // response
                let resp = xTransaction.Element(x"TemplateResponse")   
                transaction.TemplateResponse.Content <- Encoding.UTF8.GetString(Convert.FromBase64String(resp.Element(x"Base64Content").Value))
                transaction.TemplateResponse.ResponseCode <- Int32.Parse(resp.Element(x"ResponseCode").Value)
                
                transaction.TemplateResponse.Headers <-
                    resp.Element(x"Headers").Elements(x"Element")
                    |> Seq.map(fun xHdr -> (xHdr.Element(x"Name").Value, xHdr.Element(x"Value").Value))
                    |> Seq.toList
                
                path.Transactions.Add(transaction)

                xTransaction.Element(x"Parameters").Elements(x"Parameter")
                |> Seq.iter(fun xParam ->
                    let parameter = {
                        Name = xParam.Element(x"Name").Value
                        Value = xParam.Element(x"Value").Value
                        Type = JourneyTransactionParameterType.Parse(xParam.Element(x"Type").Value)
                        IsStatic = Boolean.Parse(xParam.Element(x"IsStatic").Value)
                    }
                    transaction.Parameters.Add(parameter)
                )
            )
        )

