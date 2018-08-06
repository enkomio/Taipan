using System;
using System.Collections.Generic;
using System.IO;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Threading;

/*
 * A FullTest instance gathers configuration for the tests, and maintains
 * the state during a run. Instances are NOT thread-safe.
 */

class FullTest {

	/*
	 * Set to true to activate extra messages during data collection.
	 */
	internal bool Verbose {
		get {
			return verbose;
		}
		set {
			verbose = value;
		}
	}

	/*
	 * Debug log stream (can be null for no debug log).
	 */
	internal TextWriter DebugLog {
		get {
			return debugLog;
		}
		set {
			debugLog = value;
		}
	}

	/*
	 * Minimum SSL/TLS version to test. Defaults to 0.
	 */
	internal int MinVersion {
		get {
			return minVersion;
		}
		set {
			minVersion = value;
		}
	}

	/*
	 * Maximum SSL/TLS version to test. Defaults to TLS 1.2.
	 */
	internal int MaxVersion {
		get {
			return maxVersion;
		}
		set {
			maxVersion = value;
		}
	}

	/*
	 * Target server name. This MUST be set.
	 */
	internal string ServerName {
		get {
			return serverName;
		}
		set {
			serverName = value;
		}
	}

	/*
	 * Target server port. Defaults to 443.
	 */
	internal int ServerPort {
		get {
			return serverPort;
		}
		set {
			serverPort = value;
		}
	}

	/*
	 * If null, then the SNI extension will use the server name.
	 * If non-null, then:
	 * -- if it is equal to "-" then no SNI extension will be sent;
	 * -- otherwise, that value will be used as SNI.
	 */
	internal string ExplicitSNI {
		get {
			return explicitSNI;
		}
		set {
			explicitSNI = value;
		}
	}

	/*
	 * Set to true to enumerate all possible cipher suites. By
	 * default, only known cipher suites will be enumerated.
	 */
	internal bool AllSuites {
		get {
			return allSuites;
		}
		set {
			allSuites = value;
		}
	}

	/*
	 * Set to true to force a "supported elliptic curves" extension
	 * at all times. Some servers may refuse to use EC-based cipher
	 * suites if that extension is not present.
	 */
	internal bool AddECExt {
		get {
			return addECExt;
		}
		set {
			addECExt = value;
		}
	}

	/*
	 * If non-null, then a HTTP proxy will be used ("CONNECT").
	 */
	internal string ProxName {
		get {
			return proxName;
		}
		set {
			proxName = value;
		}
	}

	/*
	 * Port to connect to the HTTP proxy; default value is 3128.
	 */
	internal int ProxPort {
		get {
			return proxPort;
		}
		set {
			proxPort = value;
		}
	}

	/*
	 * If true and a HTTP proxy is used, then the connection with
	 * the HTTP proxy will use SSL.
	 */
	internal bool ProxSSL {
		get {
			return proxSSL;
		}
		set {
			proxSSL = value;
		}
	}

	/*
	 * The read timeout on server's responses, in milliseconds.
	 * Default is -1, which means "infinite". The read timeout is
	 * applied only on SSL 3.x connections as long as no ServerHello
	 * or SSL alert was received; it is meant to quickly detect cases
	 * where the server does not talk SSL/TLS at all, but will block
	 * indefinitely upon an incoming client connection.
	 */
	internal int ReadTimeout {
		get {
			return readTimeout;
		}
		set {
			readTimeout = value;
		}
	}

	/*
	 * The extra wait delay before each connection, in milliseconds.
	 * Default is 0. Adding a delay can help with some servers that
	 * don't tolerate well connection attempts in fast succession.
	 */
	internal int ConnectionWait {
		get {
			return connectionWait;
		}
		set {
			connectionWait = value;
		}
	}

	bool verbose;
	TextWriter debugLog;
	int minVersion;
	int maxVersion;
	string serverName;
	int serverPort;
	string explicitSNI;
	bool allSuites;
	bool addECExt;
	string proxName;
	int proxPort;
	bool proxSSL;
	int readTimeout;
	int connectionWait;

	Report rp;
	SSLTestBuilder tb;
	bool withExts;
	bool gotSSLAnswer;
	bool gotReadTimeout;
	bool serverCompress;
	int sslAlert;
	List<int> csl;
	int maxRecordLen;
	bool serverClaimsNoTime;
	List<long> timeOffsets;
	int minDHSize;
	int minECSize;
	int minECSizeExt;
	IDictionary<int, SSLCurve> namedCurves;
	int curveExplicitPrime;
	int curveExplicitChar2;
	bool unknownSKE;
	bool doesRenego;
	bool doesEtM;

	internal FullTest()
	{
		verbose = false;
		minVersion = 0;
		maxVersion = M.TLSv12;
		serverName = null;
		serverPort = 443;
		explicitSNI = null;
		allSuites = false;
		readTimeout = -1;
		connectionWait = 0;
		proxName = null;
		proxPort = 3128;
		proxSSL = false;
		addECExt = false;
	}

	/*
	 * Run the tests and return the report.
	 */
	internal Report Run()
	{
		string sni = explicitSNI;
		if (sni == null) {
			sni = serverName;
		} else if (sni == "-") {
			sni = null;
		}

		/*
		 * Accumulate time offsets between client and server.
		 */
		timeOffsets = new List<long>();

		/*
		 * To keep track of DHE/ECDHE parameters.
		 */
		minDHSize = 0;
		minECSize = 0;
		minECSizeExt = 0;
		namedCurves = new SortedDictionary<int, SSLCurve>();
		curveExplicitPrime = 0;
		curveExplicitChar2 = 0;
		unknownSKE = false;
		doesRenego = false;
		doesEtM = false;

		/*
		 * Overall process:
		 *
		 *  1. First, try SSL 2.0. This is a single connection.
		 *  After this test, everything else uses SSL 3.0+.
		 *
		 *  2. Try to confirm that we are talking to an actual
		 *  SSL/TLS server and obtain its tolerance to variants:
		 *  maximum client version, presence of extensions,
		 *  large ClientHello messages.
		 *
		 *  3. For each supported protocol version, find
		 *  accepted cipher suites, then work out server's
		 *  behaviour for suite selection (client order, server
		 *  order, other).
		 *
		 *  4. Print report for cipher suites.
		 *
		 *  5. Print other information (compression support,
		 *  certificate information, DHE/ECDHE details...).
		 */
		rp = new Report();
		rp.ConnName = serverName;
		rp.ConnPort = serverPort;
		rp.SNI = sni;
		bool hasSSLv2 = false;

		/*
		 * SSL 2.0 attempt.
		 */
		if (minVersion <= M.SSLv20) {
			if (verbose) {
				Console.WriteLine("[trying version=SSLv2]");
			}
			SSL2 v2 = DoConnectV2();
			if (v2 != null) {
				if (verbose) {
					Console.WriteLine("[SSLv2 supported,"
						+ " {0} cipher suite(s)]",
						v2.CipherSuites.Length);
				}
				if (v2.CipherSuites.Length > 0) {
					hasSSLv2 = true;
				}
			}
		}

		/*
		 * Make the list of cipher suites we are interested in.
		 */
		csl = new List<int>();
		if (allSuites) {
			for (int i = 1; i <= 0xFFFF; i ++) {
				if (i == M.TLS_EMPTY_RENEGOTIATION_INFO_SCSV
					|| i == M.TLS_FALLBACK_SCSV)
				{
					continue;
				}
				csl.Add(i);
			}
		} else {
			foreach (int s in CipherSuite.ALL.Keys) {
				if (s != 0) {
					csl.Add(s);
				}
			}
		}

		/*
		 * Create a test builder and populate it with the
		 * configured information.
		 */
		tb = new SSLTestBuilder();
		tb.ServerName = sni;
		tb.MaxVersion = maxVersion;
		withExts = true;
		gotSSLAnswer = false;
		serverCompress = false;
		sslAlert = -1;
		maxRecordLen = 8192;
		if (addECExt) {
			List<int> rx = new List<int>();
			foreach (int x in SSLCurve.ALL.Keys) {
				rx.Add(x);
			}
			tb.SupportedCurves = rx.ToArray();
		}

		/*
		 * Each try entails using a protocol version, a
		 * maximum record length, and optional extensions.
		 * We then try all chunks of cipher suites (in our
		 * list of cipher suites to try) until we get a
		 * successfull handshake.
		 *
		 * On error, we try reducing maximum record length.
		 * If that still fails, we lower the maximum version.
		 * If even SSL 3.0 fails with a small record, then
		 * we try again the whole process without extensions.
		 */
		for (;;) {
			if (maxVersion < M.SSLv30) {
				if (!hasSSLv2) {
					throw new Exception(
						"No SSLv2 support, not"
						+ " testing higher versions");
				}
				break;
			}
			maxRecordLen = 8192;
			if (TryConnect() || gotReadTimeout) {
				break;
			}
			maxRecordLen = 1024;
			if (TryConnect() || gotReadTimeout) {
				break;
			}
			maxRecordLen = 256;
			if (TryConnect() || gotReadTimeout) {
				break;
			}
			int v = tb.MaxVersion;
			if (v > M.SSLv30) {
				tb.MaxVersion = v - 1;
				continue;
			}
			if (withExts) {
				withExts = false;
				tb.DisableExtensions();
				tb.MaxVersion = maxVersion;
				continue;
			}

			/*
			 * No success.
			 */
			if (gotSSLAnswer && sslAlert >= 0) {
				throw new SSLAlertException(sslAlert);
			} else {
				string msg = "Could not initiate a handshake"
					+ " (not SSL/TLS?)";
				if (gotReadTimeout) {
					msg += " [read timeout]";
				}
				throw new Exception(msg);
			}
		}
		if (maxRecordLen < 8192) {
			rp.NeedsShortHello = true;
		}
		if (!withExts) {
			rp.NoExtensions = true;
		}

		maxVersion = tb.MaxVersion;
		int startVersion = minVersion;
		if (startVersion < M.SSLv30) {
			startVersion = M.SSLv30;
		}

		/*
		 * Now extract supported cipher suites for each protocol
		 * version. We also try to get the highest version for
		 * which EC-based cipher suites are supported, and
		 * extract all supported EC-based cipher suites for
		 * that version.
		 *
		 * For each such protocol version, we also try connecting
		 * with a ClientHello in V2 format; we do so while ensuring
		 * that the total hello length is no more than 127 bytes,
		 * for maximum interoperability. Note that the V2 format
		 * has no room for any extension.
		 */
		int maxECVersion = -1;
		int[] suppEC = null;
		for (int v = startVersion; v <= maxVersion; v ++) {
			tb.MaxVersion = v;
			SupportedCipherSuites scs = GetSupportedCipherSuites();
			if (scs == null) {
				continue;
			}
			rp.SetCipherSuites(v, scs);
			int[] ecs = scs.GetKnownECSuites();
			if (ecs.Length > 0) {
				maxECVersion = v;
				suppEC = ecs;
			}
			if (scs.KXReuseDH) {
				rp.KXReuseDH = true;
			}
			if (scs.KXReuseECDH) {
				rp.KXReuseECDH = true;
			}

			/*
			 * Check V2 format for ClientHello.
			 * We set cipher suites to the list of suites
			 * that the server supports. The list may be
			 * truncated (because some servers don't support
			 * V2 ClientHello longer than 127 bytes) so we need
			 * to put non-EC suites first: some servers will not
			 * accept EC suites when there is no "supported
			 * curves" extension, and the V2 ClientHello message
			 * does not have room for extensions.
			 */
			int savedRV = tb.RecordVersion;
			tb.RecordVersion = M.SSLv20;
			tb.CipherSuites = scs.GetKnownSuitesLowEC();
			if (DoConnect() != null) {
				rp.SupportsV2Hello = true;
			}
			tb.RecordVersion = savedRV;
		}

		/*
		 * At that point, if the server used an EC-based cipher
		 * suite, and we did not present a Supported Elliptic
		 * Curves extension, then the server selected the
		 * curve(s) all by itself. If we always presented that
		 * extension, then we want to try talking to the server
		 * without it, to see if it accepts doing EC at all
		 * without the extension, and, if yes, what curve it may
		 * use in that case.
		 */
		int[] spontaneousEC;
		SSLCurve[] spontaneousNamedCurves;
		if (addECExt && withExts && maxECVersion >= 0) {
			if (verbose) {
				Console.WriteLine("[spontaneous EC support,"
					+ " version={0}, {1} suite(s)]",
					M.VersionString(maxECVersion),
					suppEC.Length);
			}
			IDictionary<int, SSLCurve> oldNamedCurves = namedCurves;
			namedCurves = new SortedDictionary<int, SSLCurve>();
			tb.MaxVersion = maxECVersion;
			tb.SupportedCurves = null;
			spontaneousEC = GetSupportedCipherSuites(suppEC, null);
			spontaneousNamedCurves = M.ToValueArray(namedCurves);
			foreach (int s in namedCurves.Keys) {
				oldNamedCurves[s] = namedCurves[s];
			}
			namedCurves = oldNamedCurves;
			if (verbose) {
				Console.WriteLine();
			}
		} else {
			spontaneousEC = suppEC;
			spontaneousNamedCurves = M.ToValueArray(namedCurves);
		}

		/*
		 * We now try to enumerate all supported EC curves.
		 */
		if (withExts && maxECVersion >= 0) {
			tb.MaxVersion = maxECVersion;
			tb.CipherSuites = suppEC;

			if (verbose) {
				Console.WriteLine("[elliptic curve enumeration,"
					+ " version={0}, {1} suite(s)]",
					M.VersionString(maxECVersion),
					suppEC.Length);
			}

			/*
			 * Try named curves.
			 */
			IDictionary<int, int> rec =
				new SortedDictionary<int, int>();
			foreach (int id in SSLCurve.ALL.Keys) {
				AddToSet(rec, id);
			}
			while (rec.Count > 0) {
				tb.SupportedCurves = SetToArray(rec);
				SSLTestResult tr = DoConnect();
				if (tr == null) {
					break;
				}
				SSLCurve sc = tr.Curve;
				if (sc == null) {
					break;
				}
				if (!rec.ContainsKey(sc.Id)) {
					break;
				}
				rec.Remove(sc.Id);
			}

			/*
			 * Try explicit curves, prime and char2.
			 */
			tb.SupportedCurves = new int[] {
				SSLCurve.EXPLICIT_PRIME
			};
			DoConnect();
			tb.SupportedCurves = new int[] {
				SSLCurve.EXPLICIT_CHAR2
			};
			DoConnect();

			if (verbose) {
				Console.WriteLine();
			}
		}

		rp.DeflateCompress = serverCompress;
		rp.ServerTimeOffset = GetServerTimeOffset();
		rp.SupportsSecureRenegotiation = doesRenego;
		rp.SupportsEncryptThenMAC = doesEtM;
		rp.MinDHSize = minDHSize;
		rp.MinECSize = minECSize;
		rp.MinECSizeExt = minECSizeExt;
		rp.NamedCurves = M.ToValueArray(namedCurves);
		rp.SpontaneousEC = spontaneousEC;
		rp.SpontaneousNamedCurves = spontaneousNamedCurves;
		rp.CurveExplicitPrime = curveExplicitPrime;
		rp.CurveExplicitChar2 = curveExplicitChar2;
		rp.UnknownSKE = unknownSKE;
		return rp;
	}

	Stream OpenConnection()
	{
		if (connectionWait > 0) {
			Thread.Sleep(connectionWait);
		}

		if (proxName == null) {
			TcpClient tc = new TcpClient(serverName, serverPort);
			return tc.GetStream();
		}

		Stream ns = null;
		try {
			TcpClient tc = new TcpClient(proxName, proxPort);
			ns = tc.GetStream();
			if (proxSSL) {
				SslStream ss = new SslStream(ns, true);
				ss.AuthenticateAsClient(proxName);
				ns = ss;
			}
			HTTPProx hp = new HTTPProx();
			Stream ns2 = hp.DoProxy(ns, serverName, serverPort);
			ns = null;
			return ns2;
		} finally {
			if (ns != null) {
				try {
					ns.Close();
				} catch {
					// ignored
				}
			}
		}
	}

	/*
	 * Returned value:
	 *   1  handshake succeeded (at least, a ServerHello was obtained)
	 *   0  failure
	 *  -1  failure with read timeout (the server does not talk
	 *      SSL 3.x at all, so we can stop right away)
	 */
	bool TryConnect()
	{
		int num = tb.ComputeMaxCipherSuites(maxRecordLen);
		if (num < 1) {
			num = 1;
		}
		if (verbose) {
			Console.WriteLine("[trying version={0}, extensions={1},"
				+ " maxLen={2} ({3} suites per hello)]",
				M.VersionString(tb.MaxVersion),
				withExts,
				maxRecordLen, num);
		}
		for (int i = 0; i < csl.Count; i += num) {
			int k = Math.Min(num, csl.Count - i);
			int[] cs = new int[k];
			for (int j = 0; j < k; j ++) {
				cs[j] = csl[i + j];
			}
			tb.CipherSuites = cs;
			if (DoConnect() != null) {
				if (verbose) {
					Console.WriteLine();
					Console.WriteLine("[hello received]");
				}
				return true;
			}
			if (gotReadTimeout) {
				/*
				 * If we get a read timeout, then this means
				 * that the server is not talking SSL 3.x at
				 * all; we can thus stop right here.
				 */
				return false;
			}
		}
		return false;
	}

	/*
	 * Try a connection with the current test settings. Connection
	 * errors get through as exceptions. Other errors result in a
	 * null returned value. If the handshake failed after the
	 * ServerHello, then a non-null object is returned.
	 */
	SSLTestResult DoConnect()
	{
		Stream ns = null;
		try {
			ns = OpenConnection();
			if (verbose) {
				Console.Write(".");
			}
			if (!gotSSLAnswer && readTimeout > 0) {
				RTStream rns = new RTStream(ns);
				rns.RTimeout = readTimeout;
				ns = rns;
			}
			if (debugLog != null) {
				debugLog.WriteLine("===========================================================================");
				ns = new DebugStream(ns, debugLog);
			}
			try {
				bool hasECExt = tb.SupportedCurves != null
					&& tb.SupportedCurves.Length > 0;
				SSLRecord rec = new SSLRecord(ns);
				SSLTestResult tr = tb.RunTest(rec);
				gotSSLAnswer = true;
				if (tr != null) {
					if (tr.DeflateCompress) {
						serverCompress = true;
					}
					AddServerChain(tr.CertificateChain);
					AddServerTime(tr.TimeMillis);
					AddServerDHSize(tr.DHSize);
					AddServerECSize(tr.ECSize, hasECExt);
					AddServerNamedCurve(tr.Curve);
					if (tr.CurveExplicitPrime) {
						curveExplicitPrime = tr.ECSize;
					} else if (tr.CurveExplicitChar2) {
						curveExplicitChar2 = tr.ECSize;
					}
					if (tr.UnknownSKE) {
						unknownSKE = true;
					}
					if (tr.RenegotiationInfo != null) {
						doesRenego = true;
					}
					if (tr.DoesEtM) {
						doesEtM = true;
					}
				}
				return tr;
			} catch (SSLAlertException ae) {
				gotSSLAnswer = true;
				sslAlert = ae.Alert;
				return null;
			} catch (ReadTimeoutException) {
				gotReadTimeout = true;
				return null;
			} catch (Exception) {
				return null;
			}
		} finally {
			try {
				if (ns != null) {
					ns.Close();
				}
			} catch (Exception) {
				// ignored
			}
		}
	}

	/*
	 * Try a SSLv2 connection. An error while opening the TCP
	 * connection is reported as an exception. For all other errors,
	 * null is returned.
	 */
	SSL2 DoConnectV2()
	{
		Stream ns = null;
		try {
			ns = OpenConnection();
			if (readTimeout > 0) {
				RTStream rns = new RTStream(ns);
				rns.RTimeout = readTimeout;
				ns = rns;
			}
			if (debugLog != null) {
				debugLog.WriteLine("===========================================================================");
				ns = new DebugStream(ns, debugLog);
			}
			SSL2 v2 = SSL2.TestServer(ns);
			if (v2 != null) {
				rp.SSLv2CipherSuites = v2.CipherSuites;
				rp.SetSSLv2Certificate(v2.Certificate);
			}
			return v2;
		} finally {
			try {
				if (ns != null) {
					ns.Close();
				}
			} catch (Exception) {
				// ignored
			}
		}
	}

	/*
	 * Get all supported cipher suites with the current configuration.
	 * If there is none, then null is returned (which means that the
	 * protocol version is not supported).
	 */
	SupportedCipherSuites GetSupportedCipherSuites()
	{
		int num = tb.ComputeMaxCipherSuites(maxRecordLen);
		if (num < 1) {
			num = 1;
		}
		if (verbose) {
			Console.WriteLine("[suites: version={0}"
				+ " ({1} suites per hello)]",
				M.VersionString(tb.MaxVersion), num);
		}

		/*
		 * We accumulate hashes of server key exchange parameters
		 * in this map, for DHE/DH_anon and ECDHE/ECDH_anon. This
		 * is used to detect duplicates, i.e. parameter reuse. The
		 * dictionary maps the hash value to an integer whose
		 * upper 16 bits are the cipher suite last associated with
		 * these parameters, and the lower 16 bits are the number
		 * of times these parameters occurred.
		 */
		IDictionary<string, uint> kxHashes =
			new SortedDictionary<string, uint>(
				StringComparer.Ordinal);

		/*
		 * 1. Gather all cipher suites supported by the server.
		 */
		IDictionary<int, int> suppd = new SortedDictionary<int, int>();
		for (int i = 0; i < csl.Count; i += num) {
			int k = Math.Min(num, csl.Count - i);
			int[] tt = new int[k];
			for (int j = 0; j < k; j ++) {
				tt[j] = csl[i + j];
			}
			foreach (int s in
				GetSupportedCipherSuites(tt, kxHashes))
			{
				AddToSet(suppd, s);
			}
		}
		int[] supp = SetToArray(suppd);
		if (supp.Length == 0) {
			if (verbose) {
				Console.WriteLine();
			}
			return null;
		}
		SupportedCipherSuites scs = new SupportedCipherSuites(supp);

		/*
		 * 2. Work out server preferences. We can do that only
		 * if we can send all supported suites in a single
		 * ClientHello.
		 *
		 * Algorithm: we first try suites in numerical order. Then
		 * we try suites in the reverse order of what the server
		 * selected. If the second list is equal to the first one,
		 * then the server enforces its own preferences. If the
		 * second list is the reverse of the first one, then the
		 * server follows client preferences. In all other cases,
		 * the server selection algorithm is deemed "complex".
		 */
		if (supp.Length <= num) {
			int[] supp1 = GetSupportedCipherSuites(
				supp, kxHashes);
			int[] suppRev = new int[supp1.Length];
			for (int i = 0; i < supp1.Length; i ++) {
				suppRev[i] = supp[supp1.Length - 1 - i];
			}
			int[] supp2 = GetSupportedCipherSuites(
				suppRev, kxHashes);

			if (M.Equals(supp2, suppRev)) {
				scs.PrefClient = true;
			} else if (M.Equals(supp1, supp2)) {
				scs.PrefServer = true;
				scs.Suites = supp1;
			}
		}

		/*
		 * See if there was some parameter reuse.
		 */
		foreach (uint v in kxHashes.Values) {
			if ((v & 0xFFFF) == 1) {
				continue;
			}
			int w = (int)(v >> 16);
			CipherSuite cs;
			if (!CipherSuite.ALL.TryGetValue(w, out cs)) {
				continue;
			}
			if (cs.IsDHE) {
				scs.KXReuseDH = true;
			} else if (cs.IsECDHE) {
				scs.KXReuseECDH = true;
			}
		}

		if (verbose) {
			Console.WriteLine();
		}
		return scs;
	}

	/*
	 * Get all cipher suites supported by the server among the
	 * provided array. The suites are returned in the order
	 * selected by the server.
	 *
	 * If none is supported then this method returns an empty array.
	 *
	 * If the server (wrongly) selects a cipher suite that we did
	 * not send, then that extra cipher suite will be returned in
	 * the array, and will appear last.
	 *
	 * This method does not enforce any record length limit. The
	 * caller is responsible for trimming the list when deemed
	 * necessary.
	 *
	 * If the server selects a version that is not equal to the
	 * maximum version supported by the client, then the cipher
	 * suite is deemed NOT supported.
	 */
	int[] GetSupportedCipherSuites(int[] suites,
		IDictionary<string, uint> kxHashes)
	{
		IDictionary<int, int> d = new SortedDictionary<int, int>();
		foreach (int s in suites) {
			AddToSet(d, s);
		}
		List<int> r = new List<int>();
		for (;;) {
			List<int> t = new List<int>();
			foreach (int s in suites) {
				if (d.ContainsKey(s)) {
					t.Add(s);
				}
			}
			tb.CipherSuites = t.ToArray();
			SSLTestResult tr = DoConnect();
			if (tr == null) {
				break;
			}
			if (tr.Version != tb.MaxVersion) {
				break;
			}
			int u = tr.SelectedCipherSuite;
			if (!tr.FailedAfterHello) {
				r.Add(u);
			}
			if (!tr.CipherSuiteInClientList) {
				break;
			}
			string kxh = tr.KXHash;
			if (kxh != null && kxHashes != null) {
				if (kxHashes.ContainsKey(kxh)) {
					uint v = kxHashes[kxh];
					kxHashes[kxh] =
						(uint)((v & 0xFFFF) + 1)
						+ ((uint)u << 16);
				} else {
					kxHashes[kxh] =
						(uint)1 + ((uint)u << 16);
				}
			}
			d.Remove(u);
			if (d.Count == 0) {
				break;
			}
		}
		return r.ToArray();
	}

	void AddServerChain(byte[][] chain)
	{
		if (chain == null || chain.Length == 0) {
			return;
		}
		if (rp == null) {
			return;
		}
		rp.AddServerChain(chain);
	}

	void AddServerTime(long serverTime)
	{
		if (serverTime == 0) {
			serverClaimsNoTime = true;
		} else {
			timeOffsets.Add(serverTime - M.CurrentTimeMillis());
		}
	}

	/*
	 * Estimate time offset between us (client) and the server.
	 * Returned value is "serverTime - clientTime", in milliseconds.
	 * If the gathered samples vary too wildly, then Int64.MaxValue
	 * is returned, meaning that the relevant bytes are probably
	 * random. If the server set the time field to 0 at some point
	 * (which means "time not available"), then this method returns
	 * Int64.MinValue.
	 *
	 * Notion of "too wildly" is: average deviation from average
	 * time offset is greater than 8000 seconds. Since the time is
	 * expressed in seconds over a 32-bit field, a randomized field
	 * will imply that even with only two connections, probability
	 * of missing randomization is less than 1/500000. On the other
	 * hand, with an allowed 8000-second offset, this should still
	 * catch load balancing setups when one machine is off by up
	 * to 2 hours (say, a DST switch that has gone bad).
	 */
	long GetServerTimeOffset()
	{
		if (serverClaimsNoTime) {
			return Int64.MinValue;
		}
		int n = timeOffsets.Count;
		if (n == 0) {
			return Int64.MaxValue;
		}
		long avg = 0;
		foreach (long t in timeOffsets) {
			avg += t;
		}
		avg = (avg + (n / 2)) / (long)n;
		long dev = 0;
		foreach (long t in timeOffsets) {
			dev += Math.Abs(t - avg);
		}
		dev = (dev + (n / 2)) / (long)n;
		if (Math.Abs(dev) > 8000000) {
			return Int64.MaxValue;
		}
		return avg;
	}

	void AddServerDHSize(int size)
	{
		if (size != 0 && (minDHSize == 0 || size < minDHSize)) {
			minDHSize = size;
		}
	}

	void AddServerECSize(int size, bool hasECExt)
	{
		if (size == 0) {
			return;
		}
		if (hasECExt) {
			if (minECSizeExt == 0 || size < minECSizeExt) {
				minECSizeExt = size;
			}
		} else {
			if (minECSize == 0 || size < minECSize) {
				minECSize = size;
			}
		}
	}

	void AddServerNamedCurve(SSLCurve sc)
	{
		if (sc != null) {
			namedCurves[sc.Id] = sc;
		}
	}

	/*
	 * Add a value to a set. This returns true if the value was
	 * indeed added, false otherwise.
	 */
	static bool AddToSet<T>(IDictionary<T, int> s, T val)
	{
		if (!s.ContainsKey(val)) {
			s.Add(val, 0);
			return true;
		} else {
			return false;
		}
	}

	static T[] SetToArray<T>(IDictionary<T, int> s)
	{
		List<T> r = new List<T>();
		foreach (T val in s.Keys) {
			r.Add(val);
		}
		return r.ToArray();
	}
}
