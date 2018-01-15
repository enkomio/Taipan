namespace ES.Taipan.Fingerprinter

open System
open System.Collections.Generic
open ES.Taipan.Infrastructure.Network

type FingerprintResult() =    
    member val Rate = 0.0 with get, set
    member val MatchedSignatures = new List<SignatureVerificationResult>() with get, set
    
    member this.IsHighThan(minimumValue: float) =
        this.Rate >= minimumValue && this.Rate > 0.

    override this.ToString() =
        String.Format("Rate={0}% Num matched sign={1}", (this.Rate * 100.0), this.MatchedSignatures.Count)