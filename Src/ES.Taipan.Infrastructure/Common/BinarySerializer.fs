namespace ES.Taipan.Infrastructure.Common

open System
open System.IO
open System.Runtime.Serialization.Formatters.Binary
open ES.Taipan.Infrastructure.Validation

/// Provide functionality for object serialization and deserialization by using a BinaryFormatter
type BinarySerializer() =
    
    static member Serialize(objectToSerialize: Object) =
        notNull objectToSerialize "objectToSerialize"

        let binaryFormatter = new BinaryFormatter()
        use memoryStream = new MemoryStream()
        binaryFormatter.Serialize(memoryStream, objectToSerialize)  
        memoryStream.Position <- 0L
        
        let base64SerializedString = Convert.ToBase64String(memoryStream.GetBuffer())  
        base64SerializedString

    static member DeSerialize(objectToDeSerialize: String) =
        notNull objectToDeSerialize "objectToDeSerialize"

        let buffer = Convert.FromBase64String(objectToDeSerialize)
        use memoryStream = new MemoryStream()
        memoryStream.Write(buffer, 0, buffer.Length)
        memoryStream.Position <- 0L

        let binaryFormatter = new BinaryFormatter()        
        binaryFormatter.Deserialize(memoryStream)