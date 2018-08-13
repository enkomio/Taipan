namespace ES.Taipan.Inspector.AddOns.VCSInformationDisclosure

open System
open System.IO
open System.Net
open System.Collections.Generic
open System.Text.RegularExpressions
open System.Text
open Ionic.Zlib
open ES.Taipan.Infrastructure.Network
open ES.Taipan.Infrastructure.Text
open ES.Fslog

type internal GitObject =
    | Blob of String
    | Description of String
    | Index of (String * Int32) list
    | Config of String
    | Commit of String
    | Tree of (String * String) list
    | Tag of String
    
    override this.ToString() =
        let pretty(hdr: String, txt: String) = String.Format("{0}: {1}", hdr,txt.[0..(if txt.Length > 62 then 60 else txt.Length-1)])
        match this with
        | Description v -> pretty("Description", v)
        | Config v -> pretty("Config", v)
        | Index l -> pretty("Index", String.Join(Environment.NewLine, l |> List.map(fun (k,v) -> k + " " + v.ToString())).Trim())
        | Blob v -> pretty("Blob", v)
        | Commit s -> pretty("Commit", s)
        | Tree tl -> pretty("Tree", String.Join(Environment.NewLine, tl |> List.map(fun (k,v) -> k + " " + v)).Trim())
        | Tag t -> pretty("Tag", t)

type internal GitDownloader(httpRequestor: IHttpRequestor) =
    let _analyzedPath = new HashSet<String>()
    let _leak = new Dictionary<String, GitObject>()
    let _gitResources = [
        "HEAD"
        "objects/info/packs"
        "COMMIT_EDITMSG"
        "packed-refs"
        "refs/heads/master"
        "refs/remotes/origin/HEAD"
        "refs/stash"
        "logs/HEAD"
        "logs/refs/heads/master"
        "logs/refs/remotes/origin/HEAD"
        "info/refs"
        "info/exclude"    
    ]
        
    let getRegexFirstValue(text: String, pattern: String) =
        let matches = Regex.Match(text, pattern, RegexOptions.Singleline)
        match matches.Success with
        | true ->
            Some <| matches.Groups.[1].Value.Trim()
        | _ -> None
        
    let download(root: String, path: String) =
        try            
            match WebUtility.getAbsoluteUriStringValueSameHost(root, path) with
            | Some url -> httpRequestor.DownloadData(new HttpRequest(url))
            | _ -> Array.empty<Byte>
        with _ -> Array.empty<Byte>

    let decompressContent(content: Byte array) =
        try        
            let mo = Encoding.UTF8.GetString(content)
            use memoryStreamDecompressed = new MemoryStream()
            use memoryStreamCompressed = new MemoryStream(content)

            let zlib = new ZlibStream(memoryStreamCompressed, CompressionMode.Decompress)
            zlib.CopyTo(memoryStreamDecompressed)
            memoryStreamDecompressed.GetBuffer()        
        with _ -> Array.empty<Byte>

    let analyzeGitElementContent(content: String) = [    
        for rawLine in content.Split([|'\n'|]) do
            let line = rawLine.Trim().ToLower()
            if not(String.IsNullOrWhiteSpace(line)) then
                match getRegexFirstValue(line, "ref: (.+)") with
                | Some reference -> 
                    yield reference.Trim()
                | None ->
                    match getRegexFirstValue(line, "pack.([a-fA-F0-9]{40})") with
                    | Some hash -> 
                        let hashUrlPath = String.Format("objects/packs/{0}.pack", hash)
                        yield hashUrlPath.Trim()

                        let hashUrlPath = String.Format("objects/packs/{0}.idx", hash)
                        yield hashUrlPath.Trim()
                    | _ ->
                        match getRegexFirstValue(line, "([a-fA-F0-9]{40})") with
                        | Some hash -> 
                            let hashUrlPath = String.Format("objects/{0}/{1}", hash.[0..1], hash.[2..])                    
                            yield hashUrlPath.Trim()
                        | _ -> ()
                    
    ]

    let (|BlobType|CommitType|TreeType|TagType|) (content: String) =
        let prefix = content.Substring(0, 10).ToLower()
        if prefix.StartsWith("tree") then TreeType
        elif prefix.StartsWith("commit") then CommitType
        elif prefix.StartsWith("tag") then TagType          
        else BlobType
        
    let parseTreeObject(content: String, buffer: Byte array) = 
        Tree [ 
            let items = new List<String * String>()
            let mutable skip = true
            let name = new StringBuilder()
            let hash = new StringBuilder()
            let mutable mode = 0

            for b in buffer do
                if not skip then
                    match mode with
                    | 0 -> 
                        if b = 0uy then
                            mode <- 1
                        else
                            // parsgin name     
                            name.Append(Convert.ToChar(b)) |> ignore
                    | _ -> 
                        // parsing hash
                        let byteStr = Convert.ToInt32(b).ToString("X").PadLeft(2, '0')
                        hash.Append(byteStr) |> ignore
                        if hash.Length = 40 then
                            mode <- 0

                            if not(String.IsNullOrEmpty(name.ToString())) then
                                // clena name
                                let name = name.ToString().Split(' ').[1]
                                yield (name, hash.ToString().ToLower())

                            name.Clear() |> ignore
                            hash.Clear() |> ignore

                if b = 0uy then
                    skip <- false
        ]

    let parseBlobObject(buffer: Byte array) =
        let content = new StringBuilder()
        let mutable skip = true
        // according to https://git-scm.com/book/en/v2/Git-Internals-Git-Objects the 
        // effective content of the object is after the NULL character
        for b in buffer do
            if not skip && b <> 0uy then
                content.Append(Convert.ToChar(b)) |> ignore

            if b = 0uy then
                skip <- false

        Blob(content.ToString())

    let parseCommitType(buffer: Byte array) =
        let strContent = Encoding.UTF8.GetString(buffer)
        let commitContent = strContent.Split(Convert.ToChar(0)).[1]
        Commit commitContent

    let extractDecompressedContent(buffer: Byte array) =
        let stringContent = Encoding.Default.GetString(buffer)
        match stringContent with
        | CommitType -> parseCommitType(buffer)
        | TreeType -> parseTreeObject(stringContent, buffer)
        | TagType -> Tag stringContent
        | BlobType -> parseBlobObject(buffer)
   
    let extractObject(content: Byte array) =
        let buffer = decompressContent(content)        
        extractDecompressedContent(buffer)

    let analyzeGitObject(gitObject: GitObject) = [
        match gitObject with
        | Commit cc -> 
            for e in analyzeGitElementContent(cc) do
                yield e
        | Tree tl -> 
            for (id, msg) in tl do
                for e in analyzeGitElementContent(msg) do
                    yield e
        | Tag v ->
            for e in analyzeGitElementContent(v) do
                yield e
        | _ -> ()
    ]

    let rec analyzeGitElement(rootUrl: String, path: String) = [
        if _analyzedPath.Add(path)  then
            let data = download(rootUrl, path)
            let newElements = new HashSet<String>()

            if data.Length > 0 then
                // extract object and elements
                match getRegexFirstValue(path, "([a-fA-F0-9]{2}/[a-fA-F0-9]{38})") with
                | Some rawId -> 
                    let cleanId = rawId.Replace("/", String.Empty)
                    let gitObject = extractObject(data)    
                    yield (cleanId, gitObject)

                    // extract id from specific object
                    analyzeGitObject(gitObject)
                    |> List.iter(fun e -> newElements.Add(e) |> ignore)
                    
                | None ->
                    analyzeGitElementContent(Encoding.UTF8.GetString(data))
                    |> List.iter(fun e -> newElements.Add(e) |> ignore)
            
                // analyze all extracted elements
                for referenceUrl in newElements do        
                    yield! analyzeGitElement(rootUrl, referenceUrl)
    ]

    let readString(binReader: BinaryReader, length: Int32) =
        Encoding.UTF8.GetString(binReader.ReadBytes(length))

    let readByteTerminatedString(binReader: BinaryReader, endingByte: Byte) =
        let buffer = new List<Byte>()
        let mutable b = binReader.ReadByte()
        while b <> endingByte do
            buffer.Add(b)
            b <- binReader.ReadByte()
        Encoding.UTF8.GetString(buffer |> Seq.toArray)

    let readNullTerminatedString(binReader: BinaryReader) =
        readByteTerminatedString(binReader, 0uy)

    let readInt32(binReader: BinaryReader) =
        BitConverter.ToInt32(binReader.ReadBytes(4) |> Array.rev, 0)

    let readInt16(binReader: BinaryReader) =
        BitConverter.ToInt16(binReader.ReadBytes(2) |> Array.rev, 0)

    let parseIndex(rawContent: Byte array) =
        use memStream = new MemoryStream(rawContent)
        use binReader = new BinaryReader(memStream, Encoding.UTF8)
        
        // for more info see: http://stackoverflow.com/questions/4084921/what-does-the-git-index-contain-exactly
        // more info: https://github.com/git/git/blob/master/Documentation/technical/index-format.txt
        // useful source code: https://github.com/git/git/blob/111ef79afe185f8731920569450f6a65320f5d5f/builtin/unpack-objects.c#L478
        let signature = readString(binReader, 4)
        let version = readInt32(binReader)
        let numOfEntries = readInt32(binReader)

        let mutable previousPath: String option = None
        let items = new List<String * Int32 * Int32>()
        if signature.Equals("DIRC", StringComparison.Ordinal) && (version = 2 || version = 3 || version = 4) then
            let mutable offset = 12
            for i=0 to numOfEntries-1 do
                let entryStartOffset = memStream.Position
                let ctimeSeconds = readInt32(binReader)
                let ctimeNanoSeconds = readInt32(binReader)
                let mtimeSeconds = readInt32(binReader)
                let mtimeNanoSeconds = readInt32(binReader)
                let dev = readInt32(binReader)
                let ino = readInt32(binReader)
                let mode = readInt32(binReader)        
                let uid = readInt32(binReader)
                let gid = readInt32(binReader)
                let fileSize = readInt32(binReader)
                let sha1 = binReader.ReadBytes(160/8)
                let flags = readInt16(binReader)
                let extendedFlagsEnabled = ((uint32 flags <<< 1) &&& uint32 0x80000000) > uint32 0
                let nameSize = int32(uint32 flags &&& uint32 0x00000fff)

                if version >= 3 && extendedFlagsEnabled then
                    // See: https://github.com/git/git/blob/master/Documentation/technical/index-format.txt#L96
                    readInt16(binReader) |> ignore

                if version >= 4 then
                    // TODO
                    // See: https://github.com/git/git/blob/master/Documentation/technical/index-format.txt#L116
                    ()
                else                    
                    previousPath <- Some <| readString(binReader, int32 nameSize)

                    // consume 1 byte due to NULL terminated string
                    binReader.ReadByte() |> ignore

                    let entryLen = int32(memStream.Position - entryStartOffset)

                    let mutable padding = 0
                    if entryLen % 8 <> 0 then 
                        padding <- 8 - (entryLen % 8)
                        binReader.ReadBytes(padding) |> ignore

                    items.Add(previousPath.Value, fileSize, int32 memStream.Position)
        items |> Seq.toList

    let parseExtensions(buffer: Byte array) =
        use memStream = new MemoryStream(buffer)
        use binReader = new BinaryReader(memStream)
        let entries = new List<String * String>()
        let mutable finish = false

        while not finish do
            try
                let signature = readString(binReader, 4)       
                if signature.Equals("TREE", StringComparison.OrdinalIgnoreCase) then
                    let size = readInt32(binReader)
                    let offset = size + int32 memStream.Position
                    while int32 memStream.Position < offset do
                        let pathComponent = readNullTerminatedString(binReader)
                        let entryCount = Int32.Parse(readByteTerminatedString(binReader, 32uy))                    
                        let numSubTree = Int32.Parse(readByteTerminatedString(binReader, 10uy))
                        if entryCount >= 0 then
                            let objectName = String.Join(String.Empty, binReader.ReadBytes(20) |> Seq.map(fun b -> Convert.ToInt32(b).ToString("X").PadLeft(2, '0')))
                            entries.Add(pathComponent, objectName)
                elif signature.Equals("REUC", StringComparison.OrdinalIgnoreCase) then                    
                    let size = readInt32(binReader)
                    let offset = size + int32 memStream.Position
                    while int32 memStream.Position < offset do
                        let pathName = readNullTerminatedString(binReader)
                        let o1 = Int32.Parse(readNullTerminatedString(binReader))
                        let o2 = Int32.Parse(readNullTerminatedString(binReader))
                        let o3 = Int32.Parse(readNullTerminatedString(binReader))

                        [o1; o2; o3]
                        |> List.filter(fun o -> o <> 0)
                        |> List.iter(fun o ->
                            let objectName = String.Join(String.Empty, binReader.ReadBytes(20) |> Seq.map(fun b -> Convert.ToInt32(b).ToString("X").PadLeft(2, '0')))
                            entries.Add(pathName, objectName)
                        )
                elif signature.Equals("link", StringComparison.OrdinalIgnoreCase) then
                    // skip
                    let size = readInt32(binReader)
                    binReader.ReadBytes(size) |> ignore
                elif signature.Equals("UNTR", StringComparison.OrdinalIgnoreCase) then
                    // skip
                    let size = readInt32(binReader)                    
                    binReader.ReadBytes(size) |> ignore

                    (*let count = Int32.Parse(readNullTerminatedString(binReader))
                    for i=0 to count-1 do
                        let str = readNullTerminatedString(binReader)
                        ()
                    *)
                        
                else
                    finish <- true
            with _ -> 
                finish <- true

        entries

    member this.AnalyzeUrl(baseUrl: String) = [     
        let configData = download(baseUrl, "config")
        if configData.Length > 0 then
            yield ("config", Config(Encoding.UTF8.GetString(configData)))

        let descriptionData = download(baseUrl, "description")
        if descriptionData.Length > 0 then
            yield ("description", Description(Encoding.UTF8.GetString(descriptionData)))

        let indexData = download(baseUrl, "index")
        if indexData.Length > 0 then
            let indexCleanContent = parseIndex(indexData)            
            let (_, _, finalOffset) = indexCleanContent |> List.last
            yield ("index", Index(indexCleanContent |> List.map(fun (p, s, _) -> (p,s))))

            // parse the remaining data            
            let len = indexData.Length - finalOffset
            if len > 0 then
                let remainingDataBuffer = Array.zeroCreate<Byte> len
                Array.Copy(indexData, finalOffset, remainingDataBuffer, 0, len)
                
                let entries =  parseExtensions(remainingDataBuffer)
                for (name, objectId) in entries do
                    let hashUrlPath = String.Format("{0}/{1}", objectId.[0..1], objectId.[2..]) 
                    let rootUrl = new Uri(new Uri(baseUrl), "objects/")
                    yield! analyzeGitElement(rootUrl.AbsoluteUri, hashUrlPath)
       
        for res in _gitResources do
            yield! analyzeGitElement(baseUrl, res)
    ]