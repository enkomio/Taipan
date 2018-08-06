using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

/*
 * Helper class for named curved (by 16-bit ID, for SSL/TLS).
 */

class SSLCurve {

	internal const int EXPLICIT_PRIME = 0xFF01;
	internal const int EXPLICIT_CHAR2 = 0xFF02;

	internal int Id {
		get {
			return id;
		}
	}

	internal string Name {
		get {
			return name;
		}
	}

	internal int Size {
		get {
			return size;
		}
	}

	int id;
	string name;
	int size;

	SSLCurve(int id, string name, int size)
	{
		this.id = id;
		this.name = name;
		this.size = size;
	}

	internal static IDictionary<int, SSLCurve> ALL;

	static SSLCurve()
	{
		ALL = new SortedDictionary<int, SSLCurve>();

		/* From RFC 4492 */
		Add(1,  "sect163k1 (K-163)", 162);
		Add(2,  "sect163r1", 162);
		Add(3,  "sect163r2 (B-163)", 162);
		Add(4,  "sect193r1", 192);
		Add(5,  "sect193r2", 192);
		Add(6,  "sect233k1 (K-233)", 231);
		Add(7,  "sect233r1 (B-233)", 232);
		Add(8,  "sect239k1", 237);
		Add(9,  "sect283k1 (K-283)", 281);
		Add(10, "sect283r1 (B-283)", 282);
		Add(11, "sect409k1 (K-409)", 407);
		Add(12, "sect409r1 (B-409)", 408);
		Add(13, "sect571k1 (K-571)", 569);
		Add(14, "sect571r1 (B-571)", 570);
		Add(15, "secp160k1", 160);
		Add(16, "secp160r1", 160);
		Add(17, "secp160r2", 160);
		Add(18, "secp192k1", 192);
		Add(19, "secp192r1 (P-192)", 192);
		Add(20, "secp224k1", 224);
		Add(21, "secp224r1 (P-224)", 224);
		Add(22, "secp256k1", 256);
		Add(23, "secp256r1 (P-256)", 256);
		Add(24, "secp384r1 (P-384)", 384);
		Add(25, "secp521r1 (P-521)", 521);

		/* From RFC 7027 */
		Add(26, "brainpoolP256r1", 256);
		Add(27, "brainpoolP384r1", 384);
		Add(28, "brainpoolP512r1", 512);

		/* From draft-ietf-tls-rfc4492bis-07 */
		Add(29, "ecdh_x25519", 252);
		Add(30, "ecdh_x448", 446);
	}

	static void Add(int id, string name, int size)
	{
		ALL[id] = new SSLCurve(id, name, size);
	}
}
