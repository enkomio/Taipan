using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

/*
 * A builder for a test connection to a server.
 */

class SSLTestBuilder {

	/*
	 * Maximum supported protocol version advertised by the client.
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
	 * Version to use on outgoing records.
	 */
	internal int RecordVersion {
		get {
			return recordVersion;
		}
		set {
			recordVersion = value;
		}
	}

	/*
	 * Session ID to use in ClientHello. "null" is equivalent to
	 * an empty session ID.
	 */
	internal byte[] SessionID {
		get {
			return sessionID;
		}
		set {
			if (value != null && value.Length > 32) {
				throw new ArgumentException(
					"Invalid session ID length");
			}
			sessionID = value;
		}
	}

	/*
	 * Cipher suites to send in the ClientHello.
	 */
	internal int[] CipherSuites {
		get {
			return cipherSuites;
		}
		set {
			if (value != null && value.Length > 32767) {
				throw new ArgumentException(
					"Invalid list of cipher suites");
			}
			cipherSuites = value;
		}
	}

	/*
	 * If true, add the special fallback cipher suite.
	 */
	internal bool FallbackSCSV {
		get {
			return fallbackSCSV;
		}
		set {
			fallbackSCSV = value;
		}
	}

	/*
	 * If true, add the special "secure renegotiation" cipher suite.
	 */
	internal bool RenegotiationSCSV {
		get {
			return renegotiationSCSV;
		}
		set {
			renegotiationSCSV = value;
		}
	}

	/*
	 * If true, add the "secure renegotiation" extension.
	 */
	internal bool RenegotiationExtension {
		get {
			return renegotiationExtension;
		}
		set {
			renegotiationExtension = value;
		}
	}

	/*
	 * If true, add the "encrypt-then-MAC" extension.
	 */
	internal bool EncryptThenMACExtension {
		get {
			return encryptThenMACExtension;
		}
		set {
			encryptThenMACExtension = value;
		}
	}

	/*
	 * If not null and not empty, add the "supported elliptic curves"
	 * extension with the provided named curves.
	 */
	internal int[] SupportedCurves {
		get {
			return supportedCurves;
		}
		set {
			supportedCurves = value;
		}
	}

	/*
	 * If true, advertise support for Deflate compression.
	 */
	internal bool DeflateCompress {
		get {
			return deflateCompress;
		}
		set {
			deflateCompress = value;
		}
	}

	/*
	 * Set server name to send as SNI extension (null to not send SNI).
	 */
	internal string ServerName {
		get {
			return serverName;
		}
		set {
			if (value == null) {
				serverName = null;
				return;
			}
			if (value.Length > 0xFFFF) {
				throw new ArgumentException(
					"Invalid server name (too long)");
			}
			foreach (char c in value) {
				if (c <= 0x20 || c >= 0x7F) {
					throw new ArgumentException("Invalid"
						+ " server name (not ASCII)");
				}
			}
			serverName = value;
		}
	}

	int maxVersion;
	int recordVersion;
	byte[] sessionID;
	int[] cipherSuites;
	bool fallbackSCSV;
	bool renegotiationSCSV;
	bool renegotiationExtension;
	bool encryptThenMACExtension;
	int[] supportedCurves;
	bool deflateCompress;
	string serverName;

	/*
	 * Create a new instance with default values.
	 */
	internal SSLTestBuilder()
	{
		Reset();
	}

	/*
	 * Set default values:
	 * -- maximum version is TLS 1.2
	 * -- outgoing record version is SSL 3.0
	 * -- no fallback SCSV
	 * -- no secure renegotiation SCSV
	 * -- no session ID
	 * -- deflate compression is supported
	 * -- secure renegotiation extension is sent
	 * -- no defined server name (for SNI)
	 */
	internal void Reset()
	{
		maxVersion = M.TLSv12;
		recordVersion = M.SSLv30;
		cipherSuites = null;
		fallbackSCSV = false;
		deflateCompress = true;
		sessionID = null;
		renegotiationSCSV = false;
		renegotiationExtension = true;
		encryptThenMACExtension = true;
		supportedCurves = null;
	}

	/*
	 * This method computes the maximum number of cipher suites
	 * that can be configured, for the specified maximum record
	 * length. This is used to support old servers that have
	 * low tolerance to perfectly legal but relatively large
	 * ClientHello messages.
	 *
	 * If this method returns -1, then the provided maximum record
	 * length will necessarily be exceeded, with the current
	 * ClientHello configuration.
	 */
	internal int ComputeMaxCipherSuites(int maxRecordLen)
	{
		int a = 1;
		int len = MakeClientHello(new int[a]).Length;
		if ((len + 5) > maxRecordLen) {
			return -1;
		}

		/*
		 * Bare minimum overhead in a ClientHello:
		 *  5 bytes for the record header
		 *  4 bytes for the handshake message header
		 *  37 bytes for version, random, session ID and compression
		 *  2 bytes for length of list of cipher suites
		 */
		int b = 1 + ((maxRecordLen - 48) >> 1);
		if (b > 32767) {
			b = 32767;
		}
		while ((b - a) > 1) {
			int c = (a + b) >> 1;
			len = MakeClientHello(new int[c]).Length;
			if ((len + 5) <= maxRecordLen) {
				a = c;
			} else {
				b = c;
			}
		}
		return a;
	}

	/*
	 * Deactivate all extensions (including SNI). This is meant to
	 * support flawed servers that are allergic to extensions.
	 */
	internal void DisableExtensions()
	{
		ServerName = null;
		RenegotiationExtension = false;
		SupportedCurves = null;
	}

	/*
	 * Begin a new handshake, and return the server data. If the
	 * server refused to complete the handshake with an explicit
	 * alert, then an SSLAlertException is thrown; for all other
	 * error conditions, an other kind of exception is thrown.
	 */
	internal SSLTestResult RunTest(SSLRecord rec)
	{
		/*
		 * Send ClientHello.
		 */
		rec.SetOutType(M.HANDSHAKE);
		rec.SetOutVersion(recordVersion);
		if (recordVersion < M.SSLv30) {
			byte[] chv2 = SSL2.MakeHelloV2Format(
				maxVersion, 127, cipherSuites);
			rec.RawWrite(chv2);
		} else {
			byte[] ch = MakeClientHello(cipherSuites);
			rec.Write(ch);
		}
		rec.Flush();

		/*
		 * Read handshake messages from server, up to the
		 * ServerHelloDone.
		 */
		SSLTestResult tr = new SSLTestResult();
		tr.Parse(rec);
		tr.CipherSuiteInClientList = false;
		foreach (int s in cipherSuites) {
			if (s == tr.SelectedCipherSuite) {
				tr.CipherSuiteInClientList = true;
			}
		}
		return tr;
	}

	/*
	 * Build a ClientHello using the provided cipher suites.
	 * Returned array contains the complete message with its
	 * 4-byte header (but not the record header).
	 */
	byte[] MakeClientHello(int[] ccs)
	{
		/*
		 * Assemble ClientHello.
		 */
		HList chs = new HList(0xFFFFFF);

		/*
		 * Maximum protocol version.
		 */
		M.Write2(chs, maxVersion);

		/*
		 * Client random. The first four bytes encode the
		 * current time.
		 */
		byte[] clientRandom = new byte[32];
		M.Enc32be((int)(M.CurrentTimeMillis() / 1000), clientRandom, 0);
		M.Rand(clientRandom, 4, clientRandom.Length - 4);
		chs.Write(clientRandom, 0, clientRandom.Length);

		/*
		 * Session ID, for session resumption.
		 */
		if (sessionID == null) {
			M.Write1(chs, 0);
		} else {
			M.Write1(chs, sessionID.Length);
			chs.Write(sessionID, 0, sessionID.Length);
		}

		/*
		 * Cipher suites.
		 */
		List<int> lcs = new List<int>();
		if (ccs != null) {
			foreach (int s in ccs) {
				lcs.Add(s);
			}
			if (renegotiationSCSV) {
				lcs.Add(M.TLS_EMPTY_RENEGOTIATION_INFO_SCSV);
			}
			if (fallbackSCSV) {
				lcs.Add(M.TLS_FALLBACK_SCSV);
			}
		}
		M.Write2(chs, lcs.Count << 1);
		foreach (int s in lcs) {
			M.Write2(chs, s);
		}

		/*
		 * Compression support: the NULL compression must
		 * always be specified; optionally, Deflate compression
		 * can be supported.
		 */
		if (deflateCompress) {
			M.Write1(chs, 2);
			M.Write1(chs, 1);
			M.Write1(chs, 0);
		} else {
			M.Write1(chs, 1);
			M.Write1(chs, 0);
		}

		/*
		 * Extensions.
		 */
		HList exs = new HList(0xFFFF);

		/*
		 * With TLS 1.2, the "signature algorithms" extension is
		 * _always_ included, even if all other extensions are
		 * disabled.
		 */
		if (maxVersion >= M.TLSv12) {
			M.Write2(exs, M.EXT_SIGNATURE_ALGORITHMS);
			M.Write2(exs, 38);
			M.Write2(exs, 36);
			for (int s = 3; s >= 1; s --) {
				for (int h = 6; h >= 1; h --) {
					M.Write1(exs, h);
					M.Write1(exs, s);
				}
			}
		}

		if (serverName != null) {
			M.Write2(exs, M.EXT_SERVER_NAME);
			HList sndata = new HList(0xFFFF);
			HList snles = new HList(0xFFFF);
			snles.WriteByte(0);
			HList snes = new HList(0xFFFF);
			snes.Write(Encoding.UTF8.GetBytes(serverName));
			snles.Write(snes.ToArray());
			sndata.Write(snles.ToArray());
			exs.Write(sndata.ToArray());
		}
		if (renegotiationExtension) {
			M.Write2(exs, M.EXT_RENEGOTIATION_INFO);
			M.Write2(exs, 1);
			M.Write1(exs, 0);
		}
		if (encryptThenMACExtension) {
			M.Write2(exs, M.EXT_ENCRYPT_THEN_MAC);
			M.Write2(exs, 0);
		}
		if (supportedCurves != null && supportedCurves.Length > 0) {
			M.Write2(exs, M.EXT_SUPPORTED_CURVES);
			HList ecdata = new HList(0xFFFF);
			HList ecl = new HList(0xFFFF);
			foreach (int ec in supportedCurves) {
				M.Write2(ecl, ec);
			}
			ecdata.Write(ecl.ToArray());
			exs.Write(ecdata.ToArray());

			/*
			 * Also send supported point format extension; it
			 * seems to be required by some servers.
			 */
			M.Write2(exs, M.EXT_SUPPORTED_EC_POINTS);
			HList epdata = new HList(0xFFFF);
			HList epl = new HList(0xFF);
			M.Write1(epl, 0x00);
			M.Write1(epl, 0x01);
			M.Write1(epl, 0x02);
			epdata.Write(epl.ToArray());
			exs.Write(epdata.ToArray());
		}

		if (exs.Length != 0) {
			chs.Write(exs.ToArray());
		}

		byte[] msg = chs.ToArray();
		MemoryStream ms = new MemoryStream();
		ms.WriteByte(M.CLIENT_HELLO);
		ms.Write(msg, 0, msg.Length);
		return ms.ToArray();
	}
}
