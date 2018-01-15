using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

/*
 * Each CipherSuite instance encodes a cipher suite and its parameters.
 *
 * Static methods are used to locate the relevant CipherSuite instance.
 */

class CipherSuite {

	/*
	 * Get the suite identifier (16 bits).
	 */
	internal int Suite {
		get {
			return suite;
		}
	}

	/*
	 * Get the suite name.
	 */
	internal string Name {
		get {
			return name;
		}
	}

	/*
	 * Get the suite "encryption strength":
	 *   0 = no encryption
	 *   1 = weak (40 bits)
	 *   2 = medium (56 bits)
	 *   3 = strong (96 bits or more)
	 *
	 * "Medium" will deter low-level amateurs, because they won't
	 * get through it with a couple of PC (it can be done within a
	 * week or so, with a FPGA-based machine that costs a few
	 * thousands of dollars -- not a lot, but enough to make it not
	 * worth the effort is the target is something as trivial as a
	 * credit card number).
	 *
	 * "Strong" is beyond current technology, even with lots of billions
	 * of dollars thrown at the problem. Though I put the cut-off at
	 * 96 bits, there is no cipher suite between 57 and 111 bits.
	 */
	internal int Strength {
		get {
			return strength;
		}
	}

	/*
	 * Set to true if the suite uses a block cipher in CBC mode.
	 */
	internal bool IsCBC {
		get {
			return isCBC;
		}
	}

	/*
	 * Set to true if the suite uses RC4.
	 */
	internal bool IsRC4 {
		get {
			return isRC4;
		}
	}

	/*
	 * This returned true if the suite provides forward secrecy (unless
	 * the server does something stupid like using very weak ephemeral
	 * parameters, or storing ephemeral keys).
	 */
	internal bool HasForwardSecrecy {
		get {
			return isDHE || isECDHE || isSRP;
		}
	}

	/*
	 * This returned true if the suite does not ensure server
	 * authentication.
	 */
	internal bool IsAnonymous {
		get {
			return !(isSRP || isPSK) && serverKeyType == "none";
		}
	}

	/*
	 * Set to true if the suite uses ephemeral Diffie-Hellman (classic).
	 */
	internal bool IsDHE {
		get {
			return isDHE;
		}
	}

	/*
	 * Set to true if the suite uses ephemeral Diffie-Hellman (on
	 * elliptic curves).
	 */
	internal bool IsECDHE {
		get {
			return isECDHE;
		}
	}

	/*
	 * Set to true if the suite may use an ephemeral RSA key pair
	 * (this is a weak RSA key pair for "export" cipher suites; its
	 * length will be no more than 512 bits).
	 */
	internal bool IsRSAExport {
		get {
			return isRSAExport;
		}
	}

	/*
	 * Set to true if the suite uses SRP (hence a form of DH key
	 * exchange, but a different ServerKeyExchange message).
	 */
	internal bool IsSRP {
		get {
			return isSRP;
		}
	}

	/*
	 * Set to true if the suite uses a pre-shared key. This modifies
	 * the ServerKeyExchange format, if any (coupled with IsDHE
	 * or IsECDHE).
	 */
	internal bool IsPSK {
		get {
			return isPSK;
		}
	}

	/*
	 * Expected server key type. Defined types are:
	 *   RSA
	 *   DSA
	 *   DH
	 *   EC     (for ECDH or ECDSA)
	 *   none   (anonymous cipher suites)
	 */
	internal string ServerKeyType {
		get {
			return serverKeyType;
		}
	}

	int suite;
	string name;
	int strength;
	bool isCBC;
	bool isRC4;
	bool isDHE;
	bool isECDHE;
	bool isRSAExport;
	bool isSRP;
	bool isPSK;
	string serverKeyType;

	CipherSuite(string descriptor)
	{
		string[] ww = descriptor.Split((char[])null,
			StringSplitOptions.RemoveEmptyEntries);
		if (ww.Length != 6) {
			throw new ArgumentException(
				"Bad cipher suite descriptor");
		}
		suite = ParseHex(ww[0]);
		switch (ww[1]) {
		case "0":
		case "1":
		case "2":
		case "3":
			strength = ww[1][0] - '0';
			break;
		default:
			throw new ArgumentException(
				"Bad encryption strength: " + ww[1]);
		}
		switch (ww[2].ToLowerInvariant()) {
		case "c":
			isCBC = true;
			break;
		case "r":
			isRC4 = true;
			break;
		case "-":
			break;
		default:
			throw new ArgumentException(
				"Bad encryption flags: " + ww[2]);
		}
		switch (ww[3].ToLowerInvariant()) {
		case "d":
			isDHE = true;
			break;
		case "e":
			isECDHE = true;
			break;
		case "s":
			isSRP = true;
			break;
		case "x":
			isRSAExport = true;
			break;
		case "-":
			break;
		default:
			throw new ArgumentException(
				"Bad key exchange flags: " + ww[3]);
		}
		switch (ww[4].ToLowerInvariant()) {
		case "r":
			serverKeyType = "RSA";
			break;
		case "d":
			serverKeyType = "DSA";
			break;
		case "h":
			serverKeyType = "DH";
			break;
		case "e":
			serverKeyType = "EC";
			break;
		case "p":
			isPSK = true;
			serverKeyType = "none";
			break;
		case "q":
			isPSK = true;
			serverKeyType = "RSA";
			break;
		case "n":
			serverKeyType = "none";
			break;
		default:
			throw new ArgumentException(
				"Bad server key type: " + ww[4]);
		}
		name = ww[5];
	}

	static int ParseHex(string s)
	{
		int acc = 0;
		foreach (char c in s) {
			int d;
			if (c >= '0' && c <= '9') {
				d = c - '0';
			} else if (c >= 'A' && c <= 'F') {
				d = c - ('A' - 10);
			} else if (c >= 'a' && c <= 'f') {
				d = c - ('a' - 10);
			} else {
				throw new ArgumentException("Not hex digit");
			}
			if (acc > 0x7FFFFFF) {
				throw new ArgumentException("Hex overflow");
			}
			acc = (acc << 4) + d;
		}
		return acc;
	}

	/*
	 * A map of all cipher suites, indexed by identifier.
	 */
	internal static readonly IDictionary<int, CipherSuite> ALL =
		new SortedDictionary<int, CipherSuite>();

	/*
	 * Some constants for cipher strength.
	 */
	internal const int CLEAR  = 0; // no encryption
	internal const int WEAK   = 1; // weak encryption: 40-bit key
	internal const int MEDIUM = 2; // medium encryption: 56-bit key
	internal const int STRONG = 3; // strong encryption

	/*
	 * Convert strength to a human-readable string.
	 */
	internal static string ToStrength(int strength)
	{
		switch (strength) {
		case CLEAR:  return "no encryption";
		case WEAK:   return "weak encryption (40-bit)";
		case MEDIUM: return "medium encryption (56-bit)";
		case STRONG: return "strong encryption (96-bit or more)";
		default:
			throw new Exception("strange strength: " + strength);
		}
	}

	/*
	 * Get cipher suite name. If the identifier is unknown, then a
	 * synthetic name is returned.
	 */
	internal static string ToName(int suite)
	{
		if (ALL.ContainsKey(suite)) {
			return ALL[suite].name;
		} else {
			return string.Format("UNKNOWN_SUITE:0x{0:X4}", suite);
		}
	}

	/*
	 * Some constants for SSLv2 cipher suites.
	 */
	internal const int SSL_CK_RC4_128_WITH_MD5               = 0x010080;
	internal const int SSL_CK_RC4_128_EXPORT40_WITH_MD5      = 0x020080;
	internal const int SSL_CK_RC2_128_CBC_WITH_MD5           = 0x030080;
	internal const int SSL_CK_RC2_128_CBC_EXPORT40_WITH_MD5  = 0x040080;
	internal const int SSL_CK_IDEA_128_CBC_WITH_MD5          = 0x050080;
	internal const int SSL_CK_DES_64_CBC_WITH_MD5            = 0x060040;
	internal const int SSL_CK_DES_192_EDE3_CBC_WITH_MD5      = 0x0700C0;

	/*
	 * The SSL 2.0 suites, in numerical order.
	 */
	internal static int[] SSL2_SUITES = {
		SSL_CK_RC4_128_WITH_MD5,
		SSL_CK_RC4_128_EXPORT40_WITH_MD5,
		SSL_CK_RC2_128_CBC_WITH_MD5,
		SSL_CK_RC2_128_CBC_EXPORT40_WITH_MD5,
		SSL_CK_IDEA_128_CBC_WITH_MD5,
		SSL_CK_DES_64_CBC_WITH_MD5,
		SSL_CK_DES_192_EDE3_CBC_WITH_MD5
	};

	/*
	 * Get the name for a SSLv2 cipher suite. If the identifier is
	 * unknown, then a synthetic name is returned.
	 */
	internal static string ToNameV2(int suite)
	{
		switch (suite) {
		case SSL_CK_RC4_128_WITH_MD5:
			return "RC4_128_WITH_MD5";
		case SSL_CK_RC4_128_EXPORT40_WITH_MD5:
			return "RC4_128_EXPORT40_WITH_MD5";
		case SSL_CK_RC2_128_CBC_WITH_MD5:
			return "RC2_128_CBC_WITH_MD5";
		case SSL_CK_RC2_128_CBC_EXPORT40_WITH_MD5:
			return "RC2_128_CBC_EXPORT40_WITH_MD5";
		case SSL_CK_IDEA_128_CBC_WITH_MD5:
			return "IDEA_128_CBC_WITH_MD5";
		case SSL_CK_DES_64_CBC_WITH_MD5:
			return "DES_64_CBC_WITH_MD5";
		case SSL_CK_DES_192_EDE3_CBC_WITH_MD5:
			return "DES_192_EDE3_CBC_WITH_MD5";
		default:
			return string.Format("UNKNOWN_SUITE:0x{0:X6}", suite);
		}
	}

	static CipherSuite()
	{
		StringReader r = new StringReader(STD_SUITES);
		for (;;) {
			string line = r.ReadLine();
			if (line == null) {
				break;
			}
			line = line.Trim();
			if (line.Length == 0 || line.StartsWith("#")) {
				continue;
			}
			CipherSuite cs = new CipherSuite(line);
			if (ALL.ContainsKey(cs.Suite)) {
				throw new ArgumentException(string.Format(
					"Duplicate suite: 0x{0:X4}", cs.Suite));
			}
			ALL[cs.Suite] = cs;
			string name = cs.Name;

			/*
			 * Consistency test: the strength and CBC status can
			 * normally be inferred from the name itself.
			 */
			bool inferredCBC = name.Contains("_CBC_");
			bool inferredRC4 = name.Contains("RC4");
			int inferredStrength;
			if (name.Contains("_NULL_")) {
				inferredStrength = CLEAR;
			} else if (name.Contains("DES40")
				|| name.Contains("_40_"))
			{
				inferredStrength = WEAK;
			} else if (name.Contains("_DES_")) {
				inferredStrength = MEDIUM;
			} else {
				inferredStrength = STRONG;
			}
			bool isDHE = false;
			bool isECDHE = false;
			bool isRSAExport = false;
			bool isSRP = false;
			bool isPSK = false;
			string serverKeyType = "none";
			if (name.StartsWith("RSA_PSK")) {
				isPSK = true;
				serverKeyType = "RSA";
			} else if (name.StartsWith("RSA_EXPORT")) {
				isRSAExport = true;
				serverKeyType = "RSA";
			} else if (name.StartsWith("RSA_")) {
				serverKeyType = "RSA";
			} else if (name.StartsWith("DHE_PSK")) {
				isDHE = true;
				isPSK = true;
			} else if (name.StartsWith("DHE_DSS")) {
				isDHE = true;
				serverKeyType = "DSA";
			} else if (name.StartsWith("DHE_RSA")) {
				isDHE = true;
				serverKeyType = "RSA";
			} else if (name.StartsWith("DH_anon")) {
				isDHE = true;
			} else if (name.StartsWith("DH_")) {
				serverKeyType = "DH";
			} else if (name.StartsWith("ECDHE_PSK")) {
				isECDHE = true;
				isPSK = true;
			} else if (name.StartsWith("ECDHE_ECDSA")) {
				isECDHE = true;
				serverKeyType = "EC";
			} else if (name.StartsWith("ECDHE_RSA")) {
				isECDHE = true;
				serverKeyType = "RSA";
			} else if (name.StartsWith("ECDH_anon")) {
				isECDHE = true;
			} else if (name.StartsWith("ECDH_")) {
				serverKeyType = "EC";
			} else if (name.StartsWith("PSK_DHE")) {
				isDHE = true;
				isPSK = true;
			} else if (name.StartsWith("PSK_")) {
				isPSK = true;
			} else if (name.StartsWith("KRB5_")) {
				isPSK = true;
			} else if (name.StartsWith("SRP_")) {
				isSRP = true;
			} else {
				throw new ArgumentException(
					"Weird name: " + cs.Name);
			}
			if (inferredStrength != cs.Strength
				|| inferredCBC != cs.IsCBC
				|| inferredRC4 != cs.IsRC4
				|| isDHE != cs.IsDHE
				|| isECDHE != cs.IsECDHE
				|| isRSAExport != cs.IsRSAExport
				|| isSRP != cs.IsSRP
				|| isPSK != cs.IsPSK
				|| serverKeyType != cs.ServerKeyType)
			{
				Console.WriteLine("BAD: {0}", cs.Name);
				Console.WriteLine("strength: {0} / {1}", inferredStrength, cs.Strength);
				Console.WriteLine("RC4: {0} / {1}", inferredRC4, cs.IsRC4);
				Console.WriteLine("DHE: {0} / {1}", isDHE, cs.IsDHE);
				Console.WriteLine("ECDHE: {0} / {1}", isECDHE, cs.IsECDHE);
				Console.WriteLine("SRP: {0} / {1}", isSRP, cs.IsSRP);
				Console.WriteLine("PSK: {0} / {1}", isPSK, cs.IsPSK);
				Console.WriteLine("keytype: {0} / {1}", serverKeyType, cs.ServerKeyType);
				throw new ArgumentException(
					"Wrong classification: " + cs.Name);
			}
		}
	}

	const string STD_SUITES =
/*
  +------------- cipher suite identifier (hex)
  |  +---------- encryption strength (0=none, 1=weak, 2=medium, 3=strong)
  |  | +-------- encryption flags (c=block cipher in CBC mode, r=RC4)
  |  | | +------ key exchange flags (d=DHE, e=ECDHE, s=SRP, x=RSA/export)
  |  | | | +---- server key type (r=RSA, d=DSA, h=DH, e=EC, p=PSK,
  |  | | | |     q=RSA+PSK, n=none)
  |  | | | | +-- suite name
  |  | | | | |
  V  V V V V V
 */
@"
0001 0 - - r RSA_WITH_NULL_MD5
0002 0 - - r RSA_WITH_NULL_SHA
0003 1 r x r RSA_EXPORT_WITH_RC4_40_MD5
0004 3 r - r RSA_WITH_RC4_128_MD5
0005 3 r - r RSA_WITH_RC4_128_SHA
0006 1 c x r RSA_EXPORT_WITH_RC2_CBC_40_MD5
0007 3 c - r RSA_WITH_IDEA_CBC_SHA
0008 1 c x r RSA_EXPORT_WITH_DES40_CBC_SHA
0009 2 c - r RSA_WITH_DES_CBC_SHA
000A 3 c - r RSA_WITH_3DES_EDE_CBC_SHA
000B 1 c - h DH_DSS_EXPORT_WITH_DES40_CBC_SHA
000C 2 c - h DH_DSS_WITH_DES_CBC_SHA
000D 3 c - h DH_DSS_WITH_3DES_EDE_CBC_SHA
000E 1 c - h DH_RSA_EXPORT_WITH_DES40_CBC_SHA
000F 2 c - h DH_RSA_WITH_DES_CBC_SHA
0010 3 c - h DH_RSA_WITH_3DES_EDE_CBC_SHA
0011 1 c d d DHE_DSS_EXPORT_WITH_DES40_CBC_SHA
0012 2 c d d DHE_DSS_WITH_DES_CBC_SHA
0013 3 c d d DHE_DSS_WITH_3DES_EDE_CBC_SHA
0014 1 c d r DHE_RSA_EXPORT_WITH_DES40_CBC_SHA
0015 2 c d r DHE_RSA_WITH_DES_CBC_SHA
0016 3 c d r DHE_RSA_WITH_3DES_EDE_CBC_SHA
0017 1 r d n DH_anon_EXPORT_WITH_RC4_40_MD5
0018 3 r d n DH_anon_WITH_RC4_128_MD5
0019 1 c d n DH_anon_EXPORT_WITH_DES40_CBC_SHA
001A 2 c d n DH_anon_WITH_DES_CBC_SHA
001B 3 c d n DH_anon_WITH_3DES_EDE_CBC_SHA
001E 2 c - p KRB5_WITH_DES_CBC_SHA
001F 3 c - p KRB5_WITH_3DES_EDE_CBC_SHA
0020 3 r - p KRB5_WITH_RC4_128_SHA
0021 3 c - p KRB5_WITH_IDEA_CBC_SHA
0022 2 c - p KRB5_WITH_DES_CBC_MD5
0023 3 c - p KRB5_WITH_3DES_EDE_CBC_MD5
0024 3 r - p KRB5_WITH_RC4_128_MD5
0025 3 c - p KRB5_WITH_IDEA_CBC_MD5
0026 1 c - p KRB5_EXPORT_WITH_DES_CBC_40_SHA
0027 1 c - p KRB5_EXPORT_WITH_RC2_CBC_40_SHA
0028 1 r - p KRB5_EXPORT_WITH_RC4_40_SHA
0029 1 c - p KRB5_EXPORT_WITH_DES_CBC_40_MD5
002A 1 c - p KRB5_EXPORT_WITH_RC2_CBC_40_MD5
002B 1 r - p KRB5_EXPORT_WITH_RC4_40_MD5
002C 0 - - p PSK_WITH_NULL_SHA
002D 0 - d p DHE_PSK_WITH_NULL_SHA
002E 0 - - q RSA_PSK_WITH_NULL_SHA
002F 3 c - r RSA_WITH_AES_128_CBC_SHA
0030 3 c - h DH_DSS_WITH_AES_128_CBC_SHA
0031 3 c - h DH_RSA_WITH_AES_128_CBC_SHA
0032 3 c d d DHE_DSS_WITH_AES_128_CBC_SHA
0033 3 c d r DHE_RSA_WITH_AES_128_CBC_SHA
0034 3 c d n DH_anon_WITH_AES_128_CBC_SHA
0035 3 c - r RSA_WITH_AES_256_CBC_SHA
0036 3 c - h DH_DSS_WITH_AES_256_CBC_SHA
0037 3 c - h DH_RSA_WITH_AES_256_CBC_SHA
0038 3 c d d DHE_DSS_WITH_AES_256_CBC_SHA
0039 3 c d r DHE_RSA_WITH_AES_256_CBC_SHA
003A 3 c d n DH_anon_WITH_AES_256_CBC_SHA
003B 0 - - r RSA_WITH_NULL_SHA256
003C 3 c - r RSA_WITH_AES_128_CBC_SHA256
003D 3 c - r RSA_WITH_AES_256_CBC_SHA256
003E 3 c - h DH_DSS_WITH_AES_128_CBC_SHA256
003F 3 c - h DH_RSA_WITH_AES_128_CBC_SHA256
0040 3 c d d DHE_DSS_WITH_AES_128_CBC_SHA256
0041 3 c - r RSA_WITH_CAMELLIA_128_CBC_SHA
0042 3 c - h DH_DSS_WITH_CAMELLIA_128_CBC_SHA
0043 3 c - h DH_RSA_WITH_CAMELLIA_128_CBC_SHA
0044 3 c d d DHE_DSS_WITH_CAMELLIA_128_CBC_SHA
0045 3 c d r DHE_RSA_WITH_CAMELLIA_128_CBC_SHA
0046 3 c d n DH_anon_WITH_CAMELLIA_128_CBC_SHA
0067 3 c d r DHE_RSA_WITH_AES_128_CBC_SHA256
0068 3 c - h DH_DSS_WITH_AES_256_CBC_SHA256
0069 3 c - h DH_RSA_WITH_AES_256_CBC_SHA256
006A 3 c d d DHE_DSS_WITH_AES_256_CBC_SHA256
006B 3 c d r DHE_RSA_WITH_AES_256_CBC_SHA256
006C 3 c d n DH_anon_WITH_AES_128_CBC_SHA256
006D 3 c d n DH_anon_WITH_AES_256_CBC_SHA256
0084 3 c - r RSA_WITH_CAMELLIA_256_CBC_SHA
0085 3 c - h DH_DSS_WITH_CAMELLIA_256_CBC_SHA
0086 3 c - h DH_RSA_WITH_CAMELLIA_256_CBC_SHA
0087 3 c d d DHE_DSS_WITH_CAMELLIA_256_CBC_SHA
0088 3 c d r DHE_RSA_WITH_CAMELLIA_256_CBC_SHA
0089 3 c d n DH_anon_WITH_CAMELLIA_256_CBC_SHA
008A 3 r - p PSK_WITH_RC4_128_SHA
008B 3 c - p PSK_WITH_3DES_EDE_CBC_SHA
008C 3 c - p PSK_WITH_AES_128_CBC_SHA
008D 3 c - p PSK_WITH_AES_256_CBC_SHA
008E 3 r d p DHE_PSK_WITH_RC4_128_SHA
008F 3 c d p DHE_PSK_WITH_3DES_EDE_CBC_SHA
0090 3 c d p DHE_PSK_WITH_AES_128_CBC_SHA
0091 3 c d p DHE_PSK_WITH_AES_256_CBC_SHA
0092 3 r - q RSA_PSK_WITH_RC4_128_SHA
0093 3 c - q RSA_PSK_WITH_3DES_EDE_CBC_SHA
0094 3 c - q RSA_PSK_WITH_AES_128_CBC_SHA
0095 3 c - q RSA_PSK_WITH_AES_256_CBC_SHA
0096 3 c - r RSA_WITH_SEED_CBC_SHA
0097 3 c - h DH_DSS_WITH_SEED_CBC_SHA
0098 3 c - h DH_RSA_WITH_SEED_CBC_SHA
0099 3 c d d DHE_DSS_WITH_SEED_CBC_SHA
009A 3 c d r DHE_RSA_WITH_SEED_CBC_SHA
009B 3 c d n DH_anon_WITH_SEED_CBC_SHA
009C 3 - - r RSA_WITH_AES_128_GCM_SHA256
009D 3 - - r RSA_WITH_AES_256_GCM_SHA384
009E 3 - d r DHE_RSA_WITH_AES_128_GCM_SHA256
009F 3 - d r DHE_RSA_WITH_AES_256_GCM_SHA384
00A0 3 - - h DH_RSA_WITH_AES_128_GCM_SHA256
00A1 3 - - h DH_RSA_WITH_AES_256_GCM_SHA384
00A2 3 - d d DHE_DSS_WITH_AES_128_GCM_SHA256
00A3 3 - d d DHE_DSS_WITH_AES_256_GCM_SHA384
00A4 3 - - h DH_DSS_WITH_AES_128_GCM_SHA256
00A5 3 - - h DH_DSS_WITH_AES_256_GCM_SHA384
00A6 3 - d n DH_anon_WITH_AES_128_GCM_SHA256
00A7 3 - d n DH_anon_WITH_AES_256_GCM_SHA384
00A8 3 - - p PSK_WITH_AES_128_GCM_SHA256
00A9 3 - - p PSK_WITH_AES_256_GCM_SHA384
00AA 3 - d p DHE_PSK_WITH_AES_128_GCM_SHA256
00AB 3 - d p DHE_PSK_WITH_AES_256_GCM_SHA384
00AC 3 - - q RSA_PSK_WITH_AES_128_GCM_SHA256
00AD 3 - - q RSA_PSK_WITH_AES_256_GCM_SHA384
00AE 3 c - p PSK_WITH_AES_128_CBC_SHA256
00AF 3 c - p PSK_WITH_AES_256_CBC_SHA384
00B0 0 - - p PSK_WITH_NULL_SHA256
00B1 0 - - p PSK_WITH_NULL_SHA384
00B2 3 c d p DHE_PSK_WITH_AES_128_CBC_SHA256
00B3 3 c d p DHE_PSK_WITH_AES_256_CBC_SHA384
00B4 0 - d p DHE_PSK_WITH_NULL_SHA256
00B5 0 - d p DHE_PSK_WITH_NULL_SHA384
00B6 3 c - q RSA_PSK_WITH_AES_128_CBC_SHA256
00B7 3 c - q RSA_PSK_WITH_AES_256_CBC_SHA384
00B8 0 - - q RSA_PSK_WITH_NULL_SHA256
00B9 0 - - q RSA_PSK_WITH_NULL_SHA384
00BA 3 c - r RSA_WITH_CAMELLIA_128_CBC_SHA256
00BB 3 c - h DH_DSS_WITH_CAMELLIA_128_CBC_SHA256
00BC 3 c - h DH_RSA_WITH_CAMELLIA_128_CBC_SHA256
00BD 3 c d d DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256
00BE 3 c d r DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256
00BF 3 c d n DH_anon_WITH_CAMELLIA_128_CBC_SHA256
00C0 3 c - r RSA_WITH_CAMELLIA_256_CBC_SHA256
00C1 3 c - h DH_DSS_WITH_CAMELLIA_256_CBC_SHA256
00C2 3 c - h DH_RSA_WITH_CAMELLIA_256_CBC_SHA256
00C3 3 c d d DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256
00C4 3 c d r DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256
00C5 3 c d n DH_anon_WITH_CAMELLIA_256_CBC_SHA256
C001 0 - - e ECDH_ECDSA_WITH_NULL_SHA
C002 3 r - e ECDH_ECDSA_WITH_RC4_128_SHA
C003 3 c - e ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA
C004 3 c - e ECDH_ECDSA_WITH_AES_128_CBC_SHA
C005 3 c - e ECDH_ECDSA_WITH_AES_256_CBC_SHA
C006 0 - e e ECDHE_ECDSA_WITH_NULL_SHA
C007 3 r e e ECDHE_ECDSA_WITH_RC4_128_SHA
C008 3 c e e ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA
C009 3 c e e ECDHE_ECDSA_WITH_AES_128_CBC_SHA
C00A 3 c e e ECDHE_ECDSA_WITH_AES_256_CBC_SHA
C00B 0 - - e ECDH_RSA_WITH_NULL_SHA
C00C 3 r - e ECDH_RSA_WITH_RC4_128_SHA
C00D 3 c - e ECDH_RSA_WITH_3DES_EDE_CBC_SHA
C00E 3 c - e ECDH_RSA_WITH_AES_128_CBC_SHA
C00F 3 c - e ECDH_RSA_WITH_AES_256_CBC_SHA
C010 0 - e r ECDHE_RSA_WITH_NULL_SHA
C011 3 r e r ECDHE_RSA_WITH_RC4_128_SHA
C012 3 c e r ECDHE_RSA_WITH_3DES_EDE_CBC_SHA
C013 3 c e r ECDHE_RSA_WITH_AES_128_CBC_SHA
C014 3 c e r ECDHE_RSA_WITH_AES_256_CBC_SHA
C015 0 - e n ECDH_anon_WITH_NULL_SHA
C016 3 r e n ECDH_anon_WITH_RC4_128_SHA
C017 3 c e n ECDH_anon_WITH_3DES_EDE_CBC_SHA
C018 3 c e n ECDH_anon_WITH_AES_128_CBC_SHA
C019 3 c e n ECDH_anon_WITH_AES_256_CBC_SHA
C01A 3 c s n SRP_SHA_WITH_3DES_EDE_CBC_SHA
C01B 3 c s n SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA
C01C 3 c s n SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA
C01D 3 c s n SRP_SHA_WITH_AES_128_CBC_SHA
C01E 3 c s n SRP_SHA_RSA_WITH_AES_128_CBC_SHA
C01F 3 c s n SRP_SHA_DSS_WITH_AES_128_CBC_SHA
C020 3 c s n SRP_SHA_WITH_AES_256_CBC_SHA
C021 3 c s n SRP_SHA_RSA_WITH_AES_256_CBC_SHA
C022 3 c s n SRP_SHA_DSS_WITH_AES_256_CBC_SHA
C023 3 c e e ECDHE_ECDSA_WITH_AES_128_CBC_SHA256
C024 3 c e e ECDHE_ECDSA_WITH_AES_256_CBC_SHA384
C025 3 c - e ECDH_ECDSA_WITH_AES_128_CBC_SHA256
C026 3 c - e ECDH_ECDSA_WITH_AES_256_CBC_SHA384
C027 3 c e r ECDHE_RSA_WITH_AES_128_CBC_SHA256
C028 3 c e r ECDHE_RSA_WITH_AES_256_CBC_SHA384
C029 3 c - e ECDH_RSA_WITH_AES_128_CBC_SHA256
C02A 3 c - e ECDH_RSA_WITH_AES_256_CBC_SHA384
C02B 3 - e e ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
C02C 3 - e e ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
C02D 3 - - e ECDH_ECDSA_WITH_AES_128_GCM_SHA256
C02E 3 - - e ECDH_ECDSA_WITH_AES_256_GCM_SHA384
C02F 3 - e r ECDHE_RSA_WITH_AES_128_GCM_SHA256
C030 3 - e r ECDHE_RSA_WITH_AES_256_GCM_SHA384
C031 3 - - e ECDH_RSA_WITH_AES_128_GCM_SHA256
C032 3 - - e ECDH_RSA_WITH_AES_256_GCM_SHA384
C033 3 r e p ECDHE_PSK_WITH_RC4_128_SHA
C034 3 c e p ECDHE_PSK_WITH_3DES_EDE_CBC_SHA
C035 3 c e p ECDHE_PSK_WITH_AES_128_CBC_SHA
C036 3 c e p ECDHE_PSK_WITH_AES_256_CBC_SHA
C037 3 c e p ECDHE_PSK_WITH_AES_128_CBC_SHA256
C038 3 c e p ECDHE_PSK_WITH_AES_256_CBC_SHA384
C039 0 - e p ECDHE_PSK_WITH_NULL_SHA
C03A 0 - e p ECDHE_PSK_WITH_NULL_SHA256
C03B 0 - e p ECDHE_PSK_WITH_NULL_SHA384
C03C 3 c - r RSA_WITH_ARIA_128_CBC_SHA256
C03D 3 c - r RSA_WITH_ARIA_256_CBC_SHA384
C03E 3 c - h DH_DSS_WITH_ARIA_128_CBC_SHA256
C03F 3 c - h DH_DSS_WITH_ARIA_256_CBC_SHA384
C040 3 c - h DH_RSA_WITH_ARIA_128_CBC_SHA256
C041 3 c - h DH_RSA_WITH_ARIA_256_CBC_SHA384
C042 3 c d d DHE_DSS_WITH_ARIA_128_CBC_SHA256
C043 3 c d d DHE_DSS_WITH_ARIA_256_CBC_SHA384
C044 3 c d r DHE_RSA_WITH_ARIA_128_CBC_SHA256
C045 3 c d r DHE_RSA_WITH_ARIA_256_CBC_SHA384
C046 3 c d n DH_anon_WITH_ARIA_128_CBC_SHA256
C047 3 c d n DH_anon_WITH_ARIA_256_CBC_SHA384
C048 3 c e e ECDHE_ECDSA_WITH_ARIA_128_CBC_SHA256
C049 3 c e e ECDHE_ECDSA_WITH_ARIA_256_CBC_SHA384
C04A 3 c - e ECDH_ECDSA_WITH_ARIA_128_CBC_SHA256
C04B 3 c - e ECDH_ECDSA_WITH_ARIA_256_CBC_SHA384
C04C 3 c e r ECDHE_RSA_WITH_ARIA_128_CBC_SHA256
C04D 3 c e r ECDHE_RSA_WITH_ARIA_256_CBC_SHA384
C04E 3 c - e ECDH_RSA_WITH_ARIA_128_CBC_SHA256
C04F 3 c - e ECDH_RSA_WITH_ARIA_256_CBC_SHA384
C050 3 - - r RSA_WITH_ARIA_128_GCM_SHA256
C051 3 - - r RSA_WITH_ARIA_256_GCM_SHA384
C052 3 - d r DHE_RSA_WITH_ARIA_128_GCM_SHA256
C053 3 - d r DHE_RSA_WITH_ARIA_256_GCM_SHA384
C054 3 - - h DH_RSA_WITH_ARIA_128_GCM_SHA256
C055 3 - - h DH_RSA_WITH_ARIA_256_GCM_SHA384
C056 3 - d d DHE_DSS_WITH_ARIA_128_GCM_SHA256
C057 3 - d d DHE_DSS_WITH_ARIA_256_GCM_SHA384
C058 3 - - h DH_DSS_WITH_ARIA_128_GCM_SHA256
C059 3 - - h DH_DSS_WITH_ARIA_256_GCM_SHA384
C05A 3 - d n DH_anon_WITH_ARIA_128_GCM_SHA256
C05B 3 - d n DH_anon_WITH_ARIA_256_GCM_SHA384
C05C 3 - e e ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256
C05D 3 - e e ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384
C05E 3 - - e ECDH_ECDSA_WITH_ARIA_128_GCM_SHA256
C05F 3 - - e ECDH_ECDSA_WITH_ARIA_256_GCM_SHA384
C060 3 - e r ECDHE_RSA_WITH_ARIA_128_GCM_SHA256
C061 3 - e r ECDHE_RSA_WITH_ARIA_256_GCM_SHA384
C062 3 - - e ECDH_RSA_WITH_ARIA_128_GCM_SHA256
C063 3 - - e ECDH_RSA_WITH_ARIA_256_GCM_SHA384
C064 3 c - p PSK_WITH_ARIA_128_CBC_SHA256
C065 3 c - p PSK_WITH_ARIA_256_CBC_SHA384
C066 3 c d p DHE_PSK_WITH_ARIA_128_CBC_SHA256
C067 3 c d p DHE_PSK_WITH_ARIA_256_CBC_SHA384
C068 3 c - q RSA_PSK_WITH_ARIA_128_CBC_SHA256
C069 3 c - q RSA_PSK_WITH_ARIA_256_CBC_SHA384
C06A 3 - - p PSK_WITH_ARIA_128_GCM_SHA256
C06B 3 - - p PSK_WITH_ARIA_256_GCM_SHA384
C06C 3 - d p DHE_PSK_WITH_ARIA_128_GCM_SHA256
C06D 3 - d p DHE_PSK_WITH_ARIA_256_GCM_SHA384
C06E 3 - - q RSA_PSK_WITH_ARIA_128_GCM_SHA256
C06F 3 - - q RSA_PSK_WITH_ARIA_256_GCM_SHA384
C070 3 c e p ECDHE_PSK_WITH_ARIA_128_CBC_SHA256
C071 3 c e p ECDHE_PSK_WITH_ARIA_256_CBC_SHA384
C072 3 c e e ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256
C073 3 c e e ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384
C074 3 c - e ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256
C075 3 c - e ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384
C076 3 c e r ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256
C077 3 c e r ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384
C078 3 c - e ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256
C079 3 c - e ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384
C07A 3 - - r RSA_WITH_CAMELLIA_128_GCM_SHA256
C07B 3 - - r RSA_WITH_CAMELLIA_256_GCM_SHA384
C07C 3 - d r DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256
C07D 3 - d r DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384
C07E 3 - - h DH_RSA_WITH_CAMELLIA_128_GCM_SHA256
C07F 3 - - h DH_RSA_WITH_CAMELLIA_256_GCM_SHA384
C080 3 - d d DHE_DSS_WITH_CAMELLIA_128_GCM_SHA256
C081 3 - d d DHE_DSS_WITH_CAMELLIA_256_GCM_SHA384
C082 3 - - h DH_DSS_WITH_CAMELLIA_128_GCM_SHA256
C083 3 - - h DH_DSS_WITH_CAMELLIA_256_GCM_SHA384
C084 3 - d n DH_anon_WITH_CAMELLIA_128_GCM_SHA256
C085 3 - d n DH_anon_WITH_CAMELLIA_256_GCM_SHA384
C086 3 - e e ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256
C087 3 - e e ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384
C088 3 - - e ECDH_ECDSA_WITH_CAMELLIA_128_GCM_SHA256
C089 3 - - e ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384
C08A 3 - e r ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256
C08B 3 - e r ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384
C08C 3 - - e ECDH_RSA_WITH_CAMELLIA_128_GCM_SHA256
C08D 3 - - e ECDH_RSA_WITH_CAMELLIA_256_GCM_SHA384
C08E 3 - - p PSK_WITH_CAMELLIA_128_GCM_SHA256
C08F 3 - - p PSK_WITH_CAMELLIA_256_GCM_SHA384
C090 3 - d p DHE_PSK_WITH_CAMELLIA_128_GCM_SHA256
C091 3 - d p DHE_PSK_WITH_CAMELLIA_256_GCM_SHA384
C092 3 - - q RSA_PSK_WITH_CAMELLIA_128_GCM_SHA256
C093 3 - - q RSA_PSK_WITH_CAMELLIA_256_GCM_SHA384
C094 3 c - p PSK_WITH_CAMELLIA_128_CBC_SHA256
C095 3 c - p PSK_WITH_CAMELLIA_256_CBC_SHA384
C096 3 c d p DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256
C097 3 c d p DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384
C098 3 c - q RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256
C099 3 c - q RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384
C09A 3 c e p ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256
C09B 3 c e p ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384
C09C 3 - - r RSA_WITH_AES_128_CCM
C09D 3 - - r RSA_WITH_AES_256_CCM
C09E 3 - d r DHE_RSA_WITH_AES_128_CCM
C09F 3 - d r DHE_RSA_WITH_AES_256_CCM
C0A0 3 - - r RSA_WITH_AES_128_CCM_8
C0A1 3 - - r RSA_WITH_AES_256_CCM_8
C0A2 3 - d r DHE_RSA_WITH_AES_128_CCM_8
C0A3 3 - d r DHE_RSA_WITH_AES_256_CCM_8
C0A4 3 - - p PSK_WITH_AES_128_CCM
C0A5 3 - - p PSK_WITH_AES_256_CCM
C0A6 3 - d p DHE_PSK_WITH_AES_128_CCM
C0A7 3 - d p DHE_PSK_WITH_AES_256_CCM
C0A8 3 - - p PSK_WITH_AES_128_CCM_8
C0A9 3 - - p PSK_WITH_AES_256_CCM_8
C0AA 3 - d p PSK_DHE_WITH_AES_128_CCM_8
C0AB 3 - d p PSK_DHE_WITH_AES_256_CCM_8
C0AC 3 - e e ECDHE_ECDSA_WITH_AES_128_CCM
C0AD 3 - e e ECDHE_ECDSA_WITH_AES_256_CCM
C0AE 3 - e e ECDHE_ECDSA_WITH_AES_128_CCM_8
C0AF 3 - e e ECDHE_ECDSA_WITH_AES_256_CCM_8

# These ones are from draft-mavrogiannopoulos-chacha-tls-01
# Apparently some servers (Google...) deployed them.
# We use the suffix '_OLD' to signify that they are not registered at
# the IANA (and probably will never be).
CC12 3 - - r RSA_WITH_CHACHA20_POLY1305_OLD
CC13 3 - e r ECDHE_RSA_WITH_CHACHA20_POLY1305_OLD
CC14 3 - e e ECDHE_ECDSA_WITH_CHACHA20_POLY1305_OLD
CC15 3 - d r DHE_RSA_WITH_CHACHA20_POLY1305_OLD
CC16 3 - d p DHE_PSK_WITH_CHACHA20_POLY1305_OLD
CC17 3 - - p PSK_WITH_CHACHA20_POLY1305_OLD
CC18 3 - e p ECDHE_PSK_WITH_CHACHA20_POLY1305_OLD
CC19 3 - - q RSA_PSK_WITH_CHACHA20_POLY1305_OLD

# Defined in RFC 7905.
CCA8 3 - e r ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
CCA9 3 - e e ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
CCAA 3 - d r DHE_RSA_WITH_CHACHA20_POLY1305_SHA256
CCAB 3 - - p PSK_WITH_CHACHA20_POLY1305_SHA256
CCAC 3 - e p ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256
CCAD 3 - d p DHE_PSK_WITH_CHACHA20_POLY1305_SHA256
CCAE 3 - - q RSA_PSK_WITH_CHACHA20_POLY1305_SHA256
";

	/*
	 * We do not support FORTEZZA cipher suites, because the
	 * protocol is not published, and nobody uses it anyway.
	 * One of the FORTEZZA cipher suites conflicts with one
	 * of the Kerberos cipher suites (same ID: 0x001E).
	 */
}
