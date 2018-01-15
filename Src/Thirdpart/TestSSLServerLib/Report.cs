using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace TestSSLServerLib
{

    /*
     * This class accumulates the information about the tested server,
     * and produces the report.
     */

    public class Report
    {

        /*
         * Connection name (server name).
         */
        public string ConnName
        {
            get
            {
                return connName;
            }
            set
            {
                connName = value;
            }
        }

        /*
         * Connection port.
         */
        public int ConnPort
        {
            get
            {
                return connPort;
            }
            set
            {
                connPort = value;
            }
        }

        /*
         * Server name sent in the SNI extension. This may be null if
         * no SNI extension was sent.
         */
        public string SNI
        {
            get
            {
                return sni;
            }
            set
            {
                sni = value;
            }
        }

        /*
         * List of supported SSLv2 cipher suites, in the order returned
         * by the server (which is purely advisory, since selection is
         * done by the client). It is null if SSLv2 is not supported.
         */
        public int[] SSLv2CipherSuites
        {
            get
            {
                return ssl2Suites;
            }
            set
            {
                ssl2Suites = value;
            }
        }

        /*
         * Certificate sent by the server if SSLv2 is supported (null
         * otherwise). It is reported as a chain of length 1.
         */
        public X509Chain SSLv2Chain
        {
            get
            {
                return ssl2Chain;
            }
        }

        /*
         * List of supported cipher suites, indexed by protocol version.
         * This map contains information for version SSL 3.0 and more.
         */
        public IDictionary<int, SupportedCipherSuites> CipherSuites
        {
            get
            {
                return suites;
            }
        }

        /*
         * Support for SSLv3+ with a SSLv2 ClientHello format.
         */
        public bool SupportsV2Hello
        {
            get
            {
                return helloV2;
            }
            set
            {
                helloV2 = value;
            }
        }

        /*
         * Set to true if we had to shorten our ClientHello messages
         * (this indicates a server with a fixed, small buffer for
         * incoming ClientHello).
         */
        public bool NeedsShortHello
        {
            get
            {
                return shortHello;
            }
            set
            {
                shortHello = value;
            }
        }

        /*
         * Set to true if we had to suppress extensions from our
         * ClientHello (flawed server that does not support extensions).
         */
        public bool NoExtensions
        {
            get
            {
                return noExts;
            }
            set
            {
                noExts = value;
            }
        }

        /*
         * Set to true if the server, at some point, agreed to use
         * Deflate compression.
         */
        public bool DeflateCompress
        {
            get
            {
                return compress;
            }
            set
            {
                compress = value;
            }
        }

        /*
         * Set to true if the server appears to support secure
         * renegotiation (at least, it understands and returns an empty
         * extension; this does not demonstrate that the server would
         * accept an actual renegotiation, but if it does, then chances
         * are that it will tag it with the proper extension value).
         */
        public bool SupportsSecureRenegotiation
        {
            get
            {
                return doesRenego;
            }
            set
            {
                doesRenego = value;
            }
        }

        /*
         * Set to true if the server appears to support the Encrypt-then-MAC
         * extension (RFC 7366). This is only about the extension, _not_
         * cipher suites that are "natively" in Encrypt-then-MAC mode (e.g.
         * AES/GCM and ChaCha20+Poly1305 cipher suites).
         */
        public bool SupportsEncryptThenMAC
        {
            get
            {
                return doesEtM;
            }
            set
            {
                doesEtM = value;
            }
        }

        /*
         * Set the server time offset (serverTime - clientTime), in
         * milliseconds.
         *
         * Int64.MinValue means that the server sends 0 (the standard
         * method to indicate that the clock is not available).
         *
         * Int64.MaxValue means that the server sends random bytes
         * in the time field (non-standard, but widespread because
         * OpenSSL does that by default since September 2013).
         */
        public long ServerTimeOffset
        {
            get
            {
                return serverTimeOffset;
            }
            set
            {
                serverTimeOffset = value;
            }
        }

        /*
         * Minimal size (in bits) of DH parameters sent by server. If
         * server never used DHE or SRP, then this is 0.
         */
        public int MinDHSize
        {
            get
            {
                return minDHSize;
            }
            set
            {
                minDHSize = value;
            }
        }

        /*
         * Minimal size (in bits) of ECDH parameters sent by server. If
         * server never used ECDHE, then this is 0. This value is for
         * handshakes where the client DID NOT send a "supported curve"
         * extension.
         */
        public int MinECSize
        {
            get
            {
                return minECSize;
            }
            set
            {
                minECSize = value;
            }
        }

        /*
         * Minimal size (in bits) of ECDH parameters sent by server. If
         * server never used ECDHE, then this is 0. This value is for
         * handshakes where the client sent a "supported curve" extension.
         */
        public int MinECSizeExt
        {
            get
            {
                return minECSizeExt;
            }
            set
            {
                minECSizeExt = value;
            }
        }

        /*
         * Named curves used by the server for ECDH parameters.
         */
        public SSLCurve[] NamedCurves
        {
            get
            {
                return namedCurves;
            }
            set
            {
                namedCurves = value;
            }
        }

        /*
         * List of EC suites that the server supports when the client
         * does not send a Supported Elliptic Curves extension. The
         * list is not in any specific order.
         */
        public int[] SpontaneousEC
        {
            get
            {
                return spontaneousEC;
            }
            set
            {
                spontaneousEC = value;
            }
        }

        /*
         * Named curves spontaneously used by the server for ECDH
         * parameters. These are the curves that the server elected to
         * use in the absence of a "supported elliptic curves" extension
         * from the client.
         */
        public SSLCurve[] SpontaneousNamedCurves
        {
            get
            {
                return spontaneousNamedCurves;
            }
            set
            {
                spontaneousNamedCurves = value;
            }
        }

        /*
         * If non-zero, then this is the size of the "explicit prime"
         * curve selected by the server.
         */
        public int CurveExplicitPrime
        {
            get
            {
                return curveExplicitPrime;
            }
            set
            {
                curveExplicitPrime = value;
            }
        }

        /*
         * If non-zero, then this is the size of the "explicit char2"
         * curve selected by the server.
         */
        public int CurveExplicitChar2
        {
            get
            {
                return curveExplicitChar2;
            }
            set
            {
                curveExplicitChar2 = value;
            }
        }

        /*
         * Set to true if the server was detected to reuse DH parameters
         * (for DHE or DH_anon).
         */
        public bool KXReuseDH
        {
            get
            {
                return kxReuseDH;
            }
            set
            {
                kxReuseDH = value;
            }
        }

        /*
         * Set to true if the server was detected to reuse ECDH parameters
         * (for ECDHE or ECDH_anon).
         */
        public bool KXReuseECDH
        {
            get
            {
                return kxReuseECDH;
            }
            set
            {
                kxReuseECDH = value;
            }
        }

        /*
         * Set to true if one ServerKeyExchange message (at least) could
         * not be fully decoded.
         */
        public bool UnknownSKE
        {
            get
            {
                return unknownSKE;
            }
            set
            {
                unknownSKE = value;
            }
        }

        /*
         * Get all certificate chains gathered so far.
         */
        public X509Chain[] AllChains
        {
            get
            {
                return M.ToValueArray(chains);
            }
        }

        /*
         * The warnings aggregated after analysis. The map is indexed
         * by warning identifier; map values are explicit messsages.
         */
        public IDictionary<string, string> Warnings
        {
            get
            {
                return warnings;
            }
        }

        /*
         * If true, then the report will include the whole certificates
         * sent by the server (PEM format).
         */
        public bool ShowCertPEM
        {
            get
            {
                return withPEM;
            }
            set
            {
                withPEM = value;
            }
        }

        string connName;
        int connPort;
        string sni;
        int[] ssl2Suites;
        X509Chain ssl2Chain;
        bool helloV2;
        bool shortHello;
        bool noExts;
        IDictionary<int, SupportedCipherSuites> suites;
        IDictionary<string, X509Chain> chains;
        bool compress;
        long serverTimeOffset;
        bool doesRenego;
        bool doesEtM;
        int minDHSize;
        int minECSize;
        int minECSizeExt;
        SSLCurve[] namedCurves;
        int[] spontaneousEC;
        SSLCurve[] spontaneousNamedCurves;
        int curveExplicitPrime;
        int curveExplicitChar2;
        bool kxReuseDH;
        bool kxReuseECDH;
        bool unknownSKE;

        IDictionary<string, string> warnings;
        bool withPEM;

        /*
         * Create an empty report instance.
         */
        internal Report()
        {
            suites = new SortedDictionary<int, SupportedCipherSuites>();
            chains = new SortedDictionary<string, X509Chain>(
                StringComparer.Ordinal);
            serverTimeOffset = Int64.MinValue;
        }

        /*
         * Set the cipher suites supported for a specific protocol version
         * (SSLv3+).
         */
        internal void SetCipherSuites(int version, SupportedCipherSuites scs)
        {
            suites[version] = scs;
        }

        /*
         * Record a certificate sent by a SSLv2 server. The certificate
         * is alone.
         */
        internal void SetSSLv2Certificate(byte[] ssl2Cert)
        {
            if (ssl2Cert == null)
            {
                ssl2Chain = null;
            }
            else
            {
                ssl2Chain = X509Chain.Make(
                    new byte[][] { ssl2Cert }, true);
            }
        }

        /*
         * Record a new certificate chain sent by the server. Duplicates
         * are merged.
         */
        internal void AddServerChain(byte[][] chain)
        {
            X509Chain xc = X509Chain.Make(chain, true);
            chains[xc.Hash] = xc;
        }

        /*
         * Test whether a given named curve is part of the "spontaneous"
         * named curves.
         */
        bool IsSpontaneous(SSLCurve sc)
        {
            if (spontaneousNamedCurves == null)
            {
                return false;
            }
            for (int i = 0; i < spontaneousNamedCurves.Length; i++)
            {
                if (sc.Id == spontaneousNamedCurves[i].Id)
                {
                    return true;
                }
            }
            return false;
        }

        /*
         * Analyse data and compute the list of relevant warnings.
         */
        internal void Analyse()
        {
            warnings = new SortedDictionary<string, string>(
                StringComparer.Ordinal);
            if (ssl2Suites != null)
            {
                if (ssl2Suites.Length > 0)
                {
                    warnings["PV002"] = "Server supports SSL 2.0.";
                }
                else
                {
                    warnings["PV005"] = "Server claims to support"
                        + " SSL 2.0, but with no cipher suite";
                }
            }
            if (suites.ContainsKey(M.SSLv30))
            {
                warnings["PV003"] = "Server supports SSL 3.0.";
            }
            if (unknownSKE)
            {
                warnings["SK001"] = "Some Server Key Exchange messages"
                    + " could not be processed.";
            }
            if (minDHSize > 0 && minDHSize < 2048)
            {
                warnings["SK002"] = "Server uses DH parameters smaller"
                    + " than 2048 bits.";
            }
            if (minECSize > 0 && minECSize < 192)
            {
                warnings["SK003"] = "Server chooses ECDH parameters"
                    + " smaller than 192 bits.";
            }
            if (minECSizeExt > 0 && minECSizeExt < 192)
            {
                warnings["SK004"] = "Server supports ECDH parameters"
                    + " smaller than 192 bits (if requested).";
            }
            if (NeedsShortHello)
            {
                warnings["PV001"] = "Server needs short ClientHello.";
            }
            if (NoExtensions)
            {
                warnings["PV004"] =
                    "Server does not tolerate extensions.";
            }
            if (DeflateCompress)
            {
                warnings["CP001"] = "Server supports compression.";
            }

            bool hasCS0 = false;
            bool hasCS1 = false;
            bool hasCS2 = false;
            bool hasCSX = false;
            bool hasRC4 = false;
            bool hasNoFS = false;
            foreach (int pv in suites.Keys)
            {
                SupportedCipherSuites scs = suites[pv];
                foreach (int s in scs.Suites)
                {
                    CipherSuite cs;
                    if (CipherSuite.ALL.TryGetValue(s, out cs))
                    {
                        switch (cs.Strength)
                        {
                            case 0: hasCS0 = true; break;
                            case 1: hasCS1 = true; break;
                            case 2: hasCS2 = true; break;
                        }
                        if (cs.IsRC4)
                        {
                            hasRC4 = true;
                        }
                        if (!cs.HasForwardSecrecy)
                        {
                            hasNoFS = true;
                        }
                    }
                    else
                    {
                        hasCSX = true;
                    }
                }
            }
            if (hasCS0)
            {
                warnings["CS001"] =
                    "Server supports unencrypted cipher suites.";
            }
            if (hasCS1)
            {
                warnings["CS002"] = "Server supports very weak"
                    + " cipher suites (40 bits).";
            }
            if (hasCS2)
            {
                warnings["CS003"] = "Server supports weak"
                    + " cipher suites (56 bits).";
            }
            if (hasCSX)
            {
                warnings["CS004"] = "Server supports unrecognized"
                    + " cipher suites (unknown strength).";
            }
            if (hasRC4)
            {
                warnings["CS005"] = "Server supports RC4.";
            }
            if (hasNoFS)
            {
                warnings["CS006"] = "Server supports cipher suites"
                    + " with no forward secrecy.";
            }
            if (!doesRenego)
            {
                warnings["RN001"] = "Server does not support"
                    + " secure renegotiation.";
            }
            bool hasBadSignHash = false;
            foreach (X509Chain xchain in chains.Values)
            {
                string[] shs = xchain.SignHashes;
                if (shs == null)
                {
                    continue;
                }
                foreach (string sh in shs)
                {
                    switch (sh)
                    {
                        case "MD2":
                        case "MD5":
                        case "SHA-1":
                        case "UNKNOWN":
                            hasBadSignHash = true;
                            break;
                    }
                }
            }
            if (hasBadSignHash)
            {
                warnings["XC001"] = "Server certificate was signed with"
                    + " a weak/deprecated/unknown hash function.";
            }
        }

        /*
         * Print the report on the provided writer (text version for
         * humans).
         */
        public ReportDataDto Print(TextWriter w)
        {
            var reportData = new ReportDataDto();
            
            if (sni == null)
            {
                w.WriteLine("No SNI sent");
            }
            else
            {
                w.WriteLine("SNI: {0}", sni);
            }
            if (ssl2Suites != null && ssl2Suites.Length > 0)
            {
                w.WriteLine("  {0}", M.VersionString(M.SSLv20));
                foreach (int s in ssl2Suites)
                {
                    w.WriteLine("     {0}", CipherSuite.ToNameV2(s));
                }
            }
            SupportedCipherSuites last = null;
            foreach (int v in suites.Keys)
            {
                w.Write("  {0}:", M.VersionString(v));
                SupportedCipherSuites scs = suites[v];                
                last = scs;
                w.WriteLine();
                w.Write("     server selection: ");
                if (scs.PrefClient)
                {
                    w.WriteLine("uses client preferences");
                }
                else if (scs.PrefServer)
                {
                    w.WriteLine("enforce server preferences");
                }
                else
                {
                    w.WriteLine("complex");
                }
                foreach (int s in scs.Suites)
                {
                    CipherSuite cs;
                    string strength;
                    string fsf;
                    string anon;
                    string kt;
                    if (CipherSuite.ALL.TryGetValue(s, out cs))
                    {
                        strength = cs.Strength.ToString();
                        fsf = cs.HasForwardSecrecy ? "f" : "-";
                        anon = cs.IsAnonymous ? "A" : "-";
                        kt = cs.ServerKeyType;

                        if (cs.Strength < 3)
                        {
                            reportData.WeakCipher = true;
                        }
                    }
                    else
                    {
                        strength = "?";
                        fsf = "?";
                        anon = "?";
                        kt = "?";
                    }
                    w.WriteLine("     {0}{1}{2} (key: {3,4})  {4}",
                        strength, fsf, anon, kt,
                        CipherSuite.ToName(s));
                }
            }
            w.WriteLine(Environment.NewLine);
            if (ssl2Chain != null)
            {
                w.WriteLine("SSLv2 certificate");
                PrintCert(w, ssl2Chain, 0, reportData, this.ConnName);
                w.WriteLine(Environment.NewLine);
            }
            w.WriteLine("SSLv3/TLS: {0} certificate chain(s)", chains.Count);
            foreach (X509Chain xchain in chains.Values)
            {
                int n = xchain.Elements.Length;
                w.WriteLine("Chain: length={0}", n);
                if (xchain.Decodable)
                {
                    w.WriteLine("Names match:        {0}", xchain.NamesMatch ? "yes" : "no");
                    w.WriteLine("Includes root:      {0}", xchain.IncludesRoot ? "yes" : "no");
                    w.Write("Signature hash(es):");
                    foreach (string name in xchain.SignHashes)
                    {
                        w.Write(" {0}", name);
                    }
                    w.WriteLine();
                }
                else if (n == 0)
                {
                    w.WriteLine("CHAIN IS EMPTY");
                }
                else
                {
                    w.WriteLine("CHAIN PROCESSING ERROR");
                }

                w.WriteLine();
                for (int i = 0; i < n; i++)
                {
                    w.WriteLine("Certificate: {0}", i);
                    PrintCert(w, xchain, i, reportData, this.ConnName);
                }
            }

            w.WriteLine(Environment.NewLine);
            w.WriteLine("Server compression support: {0}", DeflateCompress ? "yes" : "no");
            if (serverTimeOffset == Int64.MinValue)
            {
                w.WriteLine("Server does not send its system time.");
            }
            else if (serverTimeOffset == Int64.MaxValue)
            {
                w.WriteLine("Server sends a random system time.");
            }
            else
            {
                DateTime dt = DateTime.UtcNow;
                dt = dt.AddMilliseconds((double)serverTimeOffset);
                w.WriteLine("Server time: {0:yyyy-MM-dd HH:mm:ss} UTC (offset: {1} ms)", dt, serverTimeOffset);
            }
            w.WriteLine("Secure renegotiation support: {0}", doesRenego ? "yes" : "no");
            w.WriteLine("Encrypt-then-MAC support (RFC 7366): {0}", doesEtM ? "yes" : "no");
            w.WriteLine("SSLv2 ClientHello format (for SSLv3+): {0}", helloV2 ? "yes" : "no");
            if (minDHSize > 0)
            {
                w.WriteLine("Minimum DH size: {0}", minDHSize);
                w.WriteLine("DH parameter reuse: {0}", kxReuseDH ? "yes" : " no");
            }
            if (minECSize > 0)
            {
                w.WriteLine("Minimum EC size (no extension):   {0}", minECSize);
            }
            if (minECSizeExt > 0)
            {
                w.WriteLine("Minimum EC size (with extension): {0}", minECSizeExt);
                if (minECSize == 0)
                {
                    w.WriteLine("Server does not use EC without" + " the client extension");
                }
            }
            if (minECSize > 0 || minECSizeExt > 0)
            {
                w.WriteLine("ECDH parameter reuse: {0}", kxReuseECDH ? "yes" : " no");
            }
            if (namedCurves != null && namedCurves.Length > 0)
            {
                w.WriteLine("Supported curves (size and name)" + " ('*' = selected by server):");
                foreach (SSLCurve nc in namedCurves)
                {
                    w.WriteLine("  {0} {1,3}  {2}",
                        IsSpontaneous(nc) ? "*" : " ",
                        nc.Size, nc.Name);
                }
                if (curveExplicitPrime > 0)
                {
                    w.WriteLine("  explicit prime, size = {0}", curveExplicitPrime);
                }
                if (curveExplicitChar2 > 0)
                {
                    w.WriteLine("  explicit char2, size = {0}", curveExplicitChar2);
                }
            }

            w.WriteLine(Environment.NewLine);
            if (warnings == null)
            {
                Analyse();
            }
            if (warnings.Count != 0)
            {
                foreach (string k in warnings.Keys)
                {
                    w.WriteLine("WARN[{0}]: {1}", k, warnings[k]);
                    reportData.Issues.Add(warnings[k]);
                }
            }

            return reportData;
        }

        bool NameMismatch(String name, String domain)
        {
            var result = false;

            var domainItems = domain.Split('.');
            var nameItems = name.Split('.');

            for(var i=0; i<domainItems.Length; i++)
            {
                if (i < domainItems.Length && i < nameItems.Length)
                {
                    var domainItem = domainItems[i];
                    var nameItem = nameItems[i];

                    if (!nameItem.Equals(domainItem, StringComparison.OrdinalIgnoreCase) && !nameItem.Equals("*"))
                    {
                        result = true;
                    }
                }                
            }

            return result;
        }

        void PrintCert(TextWriter w, X509Chain xchain, int num, ReportDataDto reportData, String domain)
        {
            w.WriteLine("\tThumprint:  {0}", xchain.ThumbprintsRev[num]);
            X509Cert xc = xchain.ElementsRev[num];
            if (xc == null)
            {
                w.WriteLine("\tUNDECODABLE: {0}", xchain.DecodingIssuesRev[num]);
            }
            else
            {
                w.WriteLine("\tSerial:     {0}", xc.SerialHex);
                w.WriteLine("\tSubject:    {0}", xc.Subject.ToString());
                w.WriteLine("\tIssuer:     {0}", xc.Issuer.ToString());
                w.WriteLine("\tValid from: {0:yyyy-MM-dd HH:mm:ss} UTC", xc.ValidFrom);
                w.WriteLine("\tValid to:   {0:yyyy-MM-dd HH:mm:ss} UTC", xc.ValidTo);
                w.WriteLine("\tKey type:   {0}", xc.KeyType);
                w.WriteLine("\tKey size:   {0}", xc.KeySize);
                string cname = xc.CurveName;
                if (cname != null)
                {
                    w.WriteLine("\tKey curve:  {0}", cname);
                }
                w.WriteLine("\tSign hash:  {0}", xc.HashAlgorithm);
                if (xc.SelfIssued)
                {
                    w.WriteLine("\t(Self-Issued)");
                }
                if (num == 0)
                {
                    w.Write("\tServer names:");
                    string[] names = xc.ServerNames;
                    if (names.Length == 0)
                    {
                        w.WriteLine(" NONE");
                    }
                    else
                    {
                        foreach (string name in names)
                        {
                            reportData.NameMismatch = NameMismatch(name, domain);
                            w.Write(name);
                        }
                    }
                }
            }
            if (withPEM)
            {
                M.WritePEM(w, "CERTIFICATE", xchain.EncodedRev[num]);
            }
        }
    }
}