namespace ES.Taipan.Fingerprinter

open System
open System.Linq
open System.Collections.Generic
open ES.Taipan.Infrastructure.Network
open ES.Taipan.Infrastructure.Service

type FingerprintingStrategy(webPageRequestor: IWebPageRequestor, serviceStateController: ServiceStateController) =
    member val SuccessRate = 0.8 with get, set

    member this.Calculate(directory: String, signatures: IEnumerable<BaseSignature>) =
        let matchedSignatures = new List<SignatureVerificationResult>()

        for signature in signatures do
            if not <| serviceStateController.IsStopped then
                serviceStateController.WaitIfPauseRequested()

                let signatureVerificationResponse = signature.Verify(directory, webPageRequestor)
                if signatureVerificationResponse.Found then
                    matchedSignatures.Add(signatureVerificationResponse)
        
        let rate = 
            match signatures.Count() with
            | x when x > 0 -> (float)matchedSignatures.Count / (float)(signatures.Count())
            | _ -> 1.0

        new FingerprintResult(Rate = rate, MatchedSignatures = matchedSignatures)