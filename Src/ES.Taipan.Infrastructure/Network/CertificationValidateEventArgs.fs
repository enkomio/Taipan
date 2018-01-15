namespace ES.Taipan.Infrastructure.Network

open System
open System.Security.Cryptography.X509Certificates
open System.Net
open System.Net.Security

type CertificationValidateEventArgs(certificate: X509Certificate, chain: X509Chain, policy:SslPolicyErrors) = 
    inherit EventArgs()
    
    member val Certificate = certificate with get
    member val Chain = chain with get
    member val Policy = policy with get
