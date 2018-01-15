using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

/*
 * Helper class for named curved (by OID, for PKIX usage).
 */

class PKIXCurve {

	internal string OID {
		get {
			return oid;
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

	string oid;
	string name;
	int size;

	PKIXCurve(string oid, string name, int size)
	{
		this.oid = oid;
		this.name = name;
		this.size = size;
	}

	internal static IDictionary<string, PKIXCurve> ALL;

	static PKIXCurve()
	{
		ALL = new SortedDictionary<string, PKIXCurve>(
			StringComparer.Ordinal);

		/* From ANSI X9.62-2005 */
		Add("1.3.132.0.1",          "ansix9t163k1 (K-163)",  162);
		Add("1.3.132.0.2",          "ansix9t163r1",          162);
		Add("1.3.132.0.15",         "ansix9t163r2 (B-163)",  162);
		Add("1.3.132.0.24",         "ansix9t193r1",          192);
		Add("1.3.132.0.25",         "ansix9t193r2",          192);
		Add("1.3.132.0.26",         "ansix9t233k1 (K-233)",  231);
		Add("1.3.132.0.27",         "ansix9t233r1 (B-233)",  232);
		Add("1.3.132.0.3",          "ansix9t239k1",          237);
		Add("1.3.132.0.16",         "ansix9t283k1 (K-283)",  281);
		Add("1.3.132.0.17",         "ansix9t283r1 (B-283)",  282);
		Add("1.3.132.0.36",         "ansix9t409k1 (K-409)",  407);
		Add("1.3.132.0.37",         "ansix9t409r1 (B-409)",  408);
		Add("1.3.132.0.38",         "ansix9t571k1 (K-571)",  569);
		Add("1.3.132.0.39",         "ansix9t571r1 (B-571)",  570);
		Add("1.3.132.0.9",          "ansix9p160k1",          160);
		Add("1.3.132.0.8",          "ansix9p160r1",          160);
		Add("1.3.132.0.30",         "ansix9p160r2",          160);
		Add("1.3.132.0.31",         "ansix9p192k1",          192);
		Add("1.2.840.10045.3.1.1",  "ansix9p192r1 (P-192)",  192);
		Add("1.3.132.0.32",         "ansix9p224k1",          224);
		Add("1.3.132.0.33",         "ansix9p224r1 (P-224)",  224);
		Add("1.3.132.0.10",         "ansix9p256k1",          256);
		Add("1.2.840.10045.3.1.7",  "ansix9p256r1 (P-256)",  256);
		Add("1.3.132.0.34",         "ansix9p384r1 (P-384)",  384);
		Add("1.3.132.0.35",         "ansix9p521r1 (P-521)",  521);

		/* Brainpool curves */
		Add("1.3.36.3.3.2.8.1.1.1",   "brainpoolP160r1",  160);
		Add("1.3.36.3.3.2.8.1.1.2",   "brainpoolP160t1",  160);
		Add("1.3.36.3.3.2.8.1.1.3",   "brainpoolP192r1",  192);
		Add("1.3.36.3.3.2.8.1.1.4",   "brainpoolP192t1",  192);
		Add("1.3.36.3.3.2.8.1.1.5",   "brainpoolP224r1",  224);
		Add("1.3.36.3.3.2.8.1.1.6",   "brainpoolP224t1",  224);
		Add("1.3.36.3.3.2.8.1.1.7",   "brainpoolP256r1",  255);
		Add("1.3.36.3.3.2.8.1.1.8",   "brainpoolP256t1",  255);
		Add("1.3.36.3.3.2.8.1.1.9",   "brainpoolP320r1",  320);
		Add("1.3.36.3.3.2.8.1.1.10",  "brainpoolP320t1",  320);
		Add("1.3.36.3.3.2.8.1.1.11",  "brainpoolP384r1",  383);
		Add("1.3.36.3.3.2.8.1.1.12",  "brainpoolP384t1",  383);
		Add("1.3.36.3.3.2.8.1.1.13",  "brainpoolP512r1",  511);
		Add("1.3.36.3.3.2.8.1.1.14",  "brainpoolP512t1",  511);
	}

	static void Add(string oid, string name, int size)
	{
		ALL[oid] = new PKIXCurve(oid, name, size);
	}
}
