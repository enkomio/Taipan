using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

using Asn1;
using X500;

/*
 * This class is a generic decoder for X.509 certificates. It is meant
 * to allow for more variants and key types than the X.509 support
 * that comes with the .NET framework.
 *
 * This is not meant for cryptographic purposes, but for analysis.
 */

public class X509Cert {

	/*
	 * Get the hash algorithm associated with the signature algorithm
	 * applied on the certificate. If that value was not recognized,
	 * then this property returns "UNKNOWN".
	 */
	public string HashAlgorithm {
		get {
			return hashAlgorithm;
		}
	}

	/*
	 * Get the certificate serial number. Notation is uppercase
	 * hexadecimal, with an even number of digits (a leading 0 is
	 * added if necessary). Though the number is nominally a
	 * nonnegative INTEGER, some (broken) CA use unsigned encoding,
	 * resulting in a seemingly negative integer; this property
	 * returns the result of unsigned interpretation in that case.
	 *
	 * The returned value should be identical to what is obtained
	 * from X509Certificate2.SerialNumber.
	 */
	public string SerialHex {
		get {
			return serialHex;
		}
	}

	/*
	 * Get the subject DN.
	 */
	public X500Name Subject {
		get {
			return subjectDN;
		}
	}

	/*
	 * Get the issuer DN.
	 */
	public X500Name Issuer {
		get {
			return issuerDN;
		}
	}

	/*
	 * Get start of validity date. Returned value is normalized to
	 * UTC.
	 */
	public DateTime ValidFrom {
		get {
			return validFrom;
		}
	}

	/*
	 * Get end of validity date. Returned value is normalized to
	 * UTC.
	 */
	public DateTime ValidTo {
		get {
			return validTo;
		}
	}

	/*
	 * Get public key type, as a symbolic string. Defined strings
	 * include: RSA, DSA, EC (for RSA, DSA, and elliptic-curve
	 * keys, respectively; "EC" keys are good for ECDSA).
	 * If the key type is unknown, or could not be fully decoded,
	 * then this property returns "UNKNOWN".
	 */
	public string KeyType {
		get {
			return keyType;
		}
	}

	/*
	 * Get public key length, in bits. The "length" of a key depends
	 * on the key type: for RSA, it is the binary length of the
	 * composite modulus; for DSA, the length of the prime modulus;
	 * for EC, the length of the curve subgroup order.
	 *
	 * If the key type or curve was not recognized, then this
	 * method returns 0.
	 */
	public int KeySize {
		get {
			return keySize;
		}
	}

	/*
	 * Get curve OID. If the key is of type EC and uses a named
	 * curve, then this property returns the curve OID. Otherwise,
	 * this returns null.
	 */
	public string CurveOID {
		get {
			return curveOID;
		}
	}

	/*
	 * Get curve name. If the key is of type EC and uses a named
	 * curve, then this property returns a readable name for the
	 * curve, provided that it is recognized; if it is not, then
	 * this property returned the curve OID (decimal-dotted
	 * representation).
	 *
	 * If the key is not of type EC, or does not use a named curve,
	 * then this method returns null.
	 */
	public string CurveName {
		get {
			return GetCurveName(curveOID);
		}
	}

	/*
	 * Get the list of "server names" from the certificate. If there
	 * is a Subject Alt Name extension, then this is the list of
	 * names of type dNSName from that extension. Otherwise, this
	 * is the Common Name (if any) from the subject DN. This may
	 * also be empty.
	 */
	public string[] ServerNames {
		get {
			return serverNames;
		}
	}

	/*
	 * Get the "thumprint". This is the SHA-1 hash of the encoded
	 * certificate, in uppercase hexadecimal (40 characters). This
	 * should be identical to X509Certificate2.Thumbprint.
	 */
	public string Thumbprint {
		get {
			return thumbprint;
		}
	}

	/*
	 * Check whether the certificate appears to be self-issued. A
	 * self-issued certificate is a certificate whose subject and
	 * issuer DN are equal.
	 */
	public bool SelfIssued {
		get {
			return subjectDN.Equals(issuerDN);
		}
	}

	string hashAlgorithm;
	string serialHex;
	X500Name subjectDN;
	X500Name issuerDN;
	DateTime validFrom;
	DateTime validTo;
	string keyType;
	int keySize;
	string curveOID;
	string[] serverNames;
	string thumbprint;
	IDictionary<string, Extension> extensions;

	/*
	 * Create an instance by decoding the provided object.
	 * This constructor assumes ASN.1 DER encoding (not Base64,
	 * not PEM).
	 *
	 * On decoding error, an AsnException is thrown.
	 */
	public X509Cert(byte[] cert)
	{
		/*
		 * Compute thumbprint.
		 */
		thumbprint = M.DoSHA1(cert).ToUpperInvariant();

		/*
		 * Outer layer decoding and extraction of the signature
		 * hash algorithm.
		 */
		AsnElt ac = AsnElt.Decode(cert);
		ac.CheckTag(AsnElt.SEQUENCE);
		ac.CheckNumSub(3);
		hashAlgorithm = GetSignHashName(
			new AlgorithmIdentifier(ac.GetSub(1)));

		/*
		 * TBS exploration. First field is optional; if present,
		 * it contains the certificate version.
		 */
		AsnElt atbs = ac.GetSub(0);
		atbs.CheckNumSubMin(6);
		atbs.CheckNumSubMax(10);
		int off = 0;
		if (atbs.GetSub(0).TagValue == 0) {
			off ++;
		}

		/*
		 * Serial numer: nominally an INTEGER, we extract the
		 * raw bytes, because some CA wrongly use unsigned
		 * encoding.
		 */
		AsnElt aserial = atbs.GetSub(off);
		aserial.CheckTag(AsnElt.INTEGER);
		byte[] sv = aserial.CopyValue();
		int svk = 0;
		while (svk < sv.Length && sv[svk] == 0) {
			svk ++;
		}
		if (svk == sv.Length) {
			serialHex = "00";
		} else {
			StringBuilder sb = new StringBuilder();
			while (svk < sv.Length) {
				sb.AppendFormat("{0:X2}", sv[svk ++]);
			}
			serialHex = sb.ToString();
		}

		/*
		 * Issuer and subject DN.
		 */
		issuerDN = new X500Name(atbs.GetSub(off + 2));
		subjectDN = new X500Name(atbs.GetSub(off + 4));

		/*
		 * Validity dates.
		 */
		AsnElt adates = atbs.GetSub(off + 3);
		adates.CheckTag(AsnElt.SEQUENCE);
		adates.CheckNumSub(2);
		validFrom = adates.GetSub(0).GetTime();
		validTo = adates.GetSub(1).GetTime();

		/*
		 * Public key.
		 */
		AsnElt aspki = atbs.GetSub(off + 5);
		aspki.CheckTag(AsnElt.SEQUENCE);
		aspki.CheckNumSub(2);
		AlgorithmIdentifier kt =
			new AlgorithmIdentifier(aspki.GetSub(0));
		AsnElt aktp = kt.Parameters;
		AsnElt apkv = aspki.GetSub(1);
		apkv.CheckTag(AsnElt.BIT_STRING);
		byte[] kv = apkv.GetBitString();
		curveOID = null;
		keyType = "UNKNOWN";
		keySize = 0;
		switch (kt.OID) {

		/*
		 * RSA public keys should use the 'rsaEncryption' OID,
		 * but some are tagged with the OAEP or the PSS OID,
		 * to somehow specify that the RSA key should be used
		 * only with OAEP or PSS.
		 */
		case "1.2.840.113549.1.1.1":
		case "1.2.840.113549.1.1.7":
		case "1.2.840.113549.1.1.10":
			keyType = "RSA";
			keySize = GetRSAPublicKeySize(kv);
			break;

		/*
		 * All DSA public keys should use that OID.
		 */
		case "1.2.840.10040.4.1":
			keyType = "DSA";
			keySize = GetDSAPublicKeySize(aktp);
			break;

		/*
		 * Elliptic curve keys.
		 * We only support "normal" elliptic curve keys, not
		 * restricted keys.
		 * We only supported named curves (RFC 5480 forbids
		 * explicit curve parameters).
		 */
		case "1.2.840.10045.2.1":
			if (aktp == null) {
				break;
			}
			if (aktp.TagClass != AsnElt.UNIVERSAL
				|| aktp.TagValue != AsnElt.OBJECT_IDENTIFIER)
			{
				break;
			}
			keyType = "EC";
			curveOID = aktp.GetOID();
			keySize = GetCurveSize(curveOID);
			break;

		/* TODO: GOST R 34.10-94 and GOST R 34.10-2001 */

		}

		/*
		 * If there are extensions, process them.
		 * extract the dNSNames.
		 */
		serverNames = null;
		extensions = new SortedDictionary<string, Extension>(
			StringComparer.Ordinal);

		for (int i = off + 6; i < atbs.Sub.Length; i ++) {
			AsnElt aexts = atbs.GetSub(i);
			if (aexts.TagClass != AsnElt.CONTEXT
				|| aexts.TagValue != 3)
			{
				continue;
			}
			aexts.CheckNumSub(1);
			aexts = aexts.GetSub(0);
			aexts.CheckTag(AsnElt.SEQUENCE);
			foreach (AsnElt aext in aexts.Sub) {
				aext.CheckTag(AsnElt.SEQUENCE);
				aext.CheckNumSubMin(2);
				aext.CheckNumSubMax(3);
				AsnElt aoid = aext.GetSub(0);
				aoid.CheckTag(AsnElt.OBJECT_IDENTIFIER);
				string oid = aoid.GetOID();
				AsnElt av;
				bool critical = false;
				if (aext.Sub.Length == 2) {
					av = aext.GetSub(1);
				} else {
					AsnElt acrit = aext.GetSub(1);
					acrit.CheckTag(AsnElt.BOOLEAN);
					critical = acrit.GetBoolean();
					av = aext.GetSub(2);
				}
				av.CheckTag(AsnElt.OCTET_STRING);
				Extension ext = new Extension(
					oid, critical, av.CopyValue());
				if (extensions.ContainsKey(oid)) {
					throw new AsnException(
						"duplicate extension " + oid);
				}
				extensions[oid] = ext;
				ProcessExtension(ext);
			}
		}

		/*
		 * If there was no SAN, or no dNSName in the SAN, then
		 * get the Common Name from the subjectDN.
		 */
		string cn = null;
		foreach (DNPart dnp in subjectDN.Parts) {
			if (dnp.FriendlyType == DNPart.COMMON_NAME) {
				if (cn != null) {
					throw new AsnException(
						"multiple CN in subject DN");
				}
				cn = dnp.Value;
			}
		}
		if (serverNames == null) {
			if (cn == null) {
				serverNames = new string[0];
			} else {
				serverNames = new string[] { cn };
			}
		}
	}

	struct Extension {

		internal string oid;
		internal bool critical;
		internal byte[] extVal;

		internal Extension(string oid, bool critical, byte[] extVal)
		{
			this.oid = oid;
			this.critical = critical;
			this.extVal = extVal;
		}
	}

	void ProcessExtension(Extension ext)
	{
		switch (ext.oid) {

		/*
		 * Subject Alternative Names extension.
		 */
		case "2.5.29.17":
			ProcessAltNames(ext.extVal, false);
			break;

		/*
		 * Issuer Alternative Names extension.
		 */
		case "2.5.29.18":
			ProcessAltNames(ext.extVal, true);
			break;

		}
	}

	void ProcessAltNames(byte[] extVal, bool forIssuer)
	{
		/*
		 * Alternative names processing.
		 *
		 * If the extension contains an X.500 name, and the
		 * corresponding DN in the certificate TBS is empty,
		 * then that X.500 name will be used as subjectDN or
		 * issuerDN. However, if the extension contains several
		 * X.500 names, or if the DN in the TBS is non-empty,
		 * then the X.500 name(s) in the extension will be
		 * ignored.
		 *
		 * For the subject, we also gather dNSNames into
		 * the "serverNames" array.
		 */
		List<string> dnsNames = new List<string>();
		AsnElt ae = AsnElt.Decode(extVal);
		ae.CheckTag(AsnElt.SEQUENCE);
		ae.CheckConstructed();
		bool foundDN = false;
		X500Name dn = null;
		foreach (AsnElt agn in ae.Sub) {
			if (agn.TagClass != AsnElt.CONTEXT) {
				continue;
			}
			switch (agn.TagValue) {
			case 2:
				dnsNames.Add(agn.GetString(AsnElt.IA5String));
				break;
			case 4:
				/*
				 * Since "Name" is a CHOICE, the context
				 * tag applied on it as part of the
				 * GeneralName structure is EXPLICIT. We
				 * have to remove it.
				 */
				agn.CheckNumSub(1);
				AsnElt adn = agn.GetSub(0);
				if (!foundDN) {
					dn = new X500Name(adn, false);
				} else {
					dn = null;
				}
				foundDN = true;
				break;
			}
		}
		if (foundDN && dn != null) {
			if (forIssuer) {
				if (issuerDN.IsEmpty) {
					issuerDN = dn;
				}
			} else {
				if (subjectDN.IsEmpty) {
					subjectDN = dn;
				}
			}
		}
		if (!forIssuer && dnsNames.Count > 0) {
			serverNames = dnsNames.ToArray();
		}
	}

	static int GetRSAPublicKeySize(byte[] kv)
	{
		AsnElt ae = AsnElt.Decode(kv);
		ae.CheckTag(AsnElt.SEQUENCE);
		ae.CheckNumSub(2);
		AsnElt ai = ae.GetSub(0);
		ai.CheckTag(AsnElt.INTEGER);
		ai.CheckPrimitive();
		byte[] v = ai.CopyValue();
		if (v.Length > 0 && v[0] >= 0x80) {
			throw new AsnException(
				"Invalid RSA modulus (negative)");
		}
		int bitLen = M.BitLength(v);
		if (bitLen < 512) {
			throw new AsnException(string.Format(
				"Invalid RSA modulus ({0} bits)", bitLen));
		} else if ((v[v.Length - 1] & 0x01) == 0) {
			throw new AsnException("Invalid RSA modulus (even)");
		}
		return bitLen;
	}

	/*
	 * This method expects the DSA parameters, as an ASN.1 object.
	 */
	static int GetDSAPublicKeySize(AsnElt adp)
	{
		if (adp == null) {
			/*
			 * No parameters -- this means inheritance from
			 * the CA, which we do not analyse because we do
			 * not do chain building.
			 */
			return 0;
		}
		adp.CheckTag(AsnElt.SEQUENCE);
		adp.CheckNumSub(3);
		foreach (AsnElt ai in adp.Sub) {
			ai.CheckTag(AsnElt.INTEGER);
			ai.CheckPrimitive();
		}
		byte[] v = adp.GetSub(0).CopyValue();
		if (v.Length > 0 && v[0] >= 0x80) {
			throw new AsnException(
				"Invalid RSA modulus (negative)");
		}
		int bitLen = M.BitLength(v);
		/*
		 * Acceptable modulus sizes for DSA have varied with
		 * successive versions of FIPS 186:
		 *   512 to 1024, and multiple of 64 (FIPS 186-1)
		 *   1024 only (FIPS 186-2)
		 *   1024, 2048 or 3072 (FIPS 186-3 and 186-4)
		 *
		 * Future versions might allow larger lengths. We
		 * apply the following rules: acceptable sizes are
		 * either multiple of 1024, or multiple of 64 in
		 * the 512..1024 range.
		 */
		bool goodLen;
		if (bitLen < 1024) {
			goodLen = (bitLen >= 512 && ((bitLen & 0x3F) == 0));
		} else {
			goodLen = ((bitLen & 0x3FF) == 0);
		}
		if (!goodLen) {
			throw new AsnException(string.Format(
				"Invalid DSA modulus ({0} bits)", bitLen));
		} else if ((v[v.Length - 1] & 0x01) == 0) {
			throw new AsnException("Invalid DSA modulus (even)");
		}
		return bitLen;
	}

	static string GetSignHashName(AlgorithmIdentifier ai)
	{
		switch (ai.OID) {

		/*
		 * RSA PKCS#1 v1.5.
		 */
		case "1.2.840.113549.1.1.2":
			return "MD2";
		case "1.2.840.113549.1.1.4":
			return "MD5";
		case "1.2.840.113549.1.1.5":
			return "SHA-1";
		case "1.2.840.113549.1.1.14":
			return "SHA-224";
		case "1.2.840.113549.1.1.11":
			return "SHA-256";
		case "1.2.840.113549.1.1.12":
			return "SHA-384";
		case "1.2.840.113549.1.1.13":
			return "SHA-512";

		/*
		 * RSA PSS.
		 * Parameters are:
		 * RSASSA-PSS-params ::= SEQUENCE {
		 *     hashAlgorithm    [0] HashAlgorithm     DEFAULT sha1,
		 *     maskGenAlgorithm [1] MaskGenAlgorithm  DEFAULT mgf1SHA1,
		 *     saltLength       [2] INTEGER           DEFAULT 20,
		 *     trailerField     [3] TrailerField      DEFAULT tfb
		 * }
		 * We are only interested in the first field, which is
		 * an AlgorithmIdentifier structure.
		 */
		case "1.2.840.113549.1.1.10":
			AsnElt apss = ai.Parameters;
			if (apss == null) {
				return "SHA-1";
			}
			apss.CheckNumSubMax(4);
			if (apss.Sub.Length == 0) {
				return "SHA-1";
			}
			AsnElt apss0 = apss.GetSub(0);
			if (apss0.TagClass != AsnElt.CONTEXT
				|| apss0.TagValue != 0)
			{
				return "SHA-1";
			}
			apss0.CheckNumSub(1);
			AlgorithmIdentifier ahi =
				new AlgorithmIdentifier(apss0.GetSub(0));
			return GetHashName(ahi.OID);

		/*
		 * DSA (RFC 3279 and 5758).
		 */
		case "1.2.840.10040.4.1":
			AsnElt adsa = ai.Parameters;
			if (ai == null) {
				throw new AsnException(
					"Missing hash function for DSA");
			}
			AlgorithmIdentifier ahd = new AlgorithmIdentifier(adsa);
			return GetHashName(ahd.OID);
		case "1.2.840.10040.4.3":
			return "SHA-1";
		case "2.16.840.1.101.3.4.3.1":
			return "SHA-224";
		case "2.16.840.1.101.3.4.3.2":
			return "SHA-256";

		/*
		 * ECDSA (ANSI X9.62:2005).
		 */
		case "1.2.840.10045.4.1":
			return "SHA-1";
		case "1.2.840.10045.4.3":
			AsnElt aec = ai.Parameters;
			if (ai == null) {
				throw new AsnException(
					"Missing hash function for ECDSA");
			}
			AlgorithmIdentifier ahe = new AlgorithmIdentifier(aec);
			return GetHashName(ahe.OID);
		case "1.2.840.10045.4.3.1":
			return "SHA-224";
		case "1.2.840.10045.4.3.2":
			return "SHA-256";
		case "1.2.840.10045.4.3.3":
			return "SHA-384";
		case "1.2.840.10045.4.3.4":
			return "SHA-512";

		/* TODO: GOST R 34.10-94 and GOST R 34.10-2001 */

		default:
			return "UNKNOWN";
		}
	}

	static string GetHashName(string oid)
	{
		switch (oid) {
		case "1.3.14.3.2.26":
			return "SHA-1";
		case "1.2.840.113549.2.2":
			return "MD2";
		case "1.2.840.113549.2.4":
			return "MD4";
		case "1.2.840.113549.2.5":
			return "MD5";
		case "2.16.840.1.101.3.4.2.1":
			return "SHA-256";
		case "2.16.840.1.101.3.4.2.2":
			return "SHA-384";
		case "2.16.840.1.101.3.4.2.3":
			return "SHA-512";
		case "2.16.840.1.101.3.4.2.4":
			return "SHA-224";
		case "2.16.840.1.101.3.4.2.5":
			return "SHA-512-224";
		case "2.16.840.1.101.3.4.2.6":
			return "SHA-512-256";

		case "2.16.840.1.101.3.4.2.7":
			return "SHA-3/224";
		case "2.16.840.1.101.3.4.2.8":
			return "SHA-3/256";
		case "2.16.840.1.101.3.4.2.9":
			return "SHA-3/384";
		case "2.16.840.1.101.3.4.2.10":
			return "SHA-3/512";
		case "2.16.840.1.101.3.4.2.11":
			return "SHAKE-128";
		case "2.16.840.1.101.3.4.2.12":
			return "SHAKE-256";

		case "1.2.643.2.2.30.1":
			return "GOST-R-34.11-94";

		default:
			return "UNKNOWN";
		}
	}

	static string GetCurveName(string oid)
	{
		string name;
		int size;
		if (GetCurveData(oid, out name, out size)) {
			return name;
		}
		return oid;
	}

	static int GetCurveSize(string oid)
	{
		string name;
		int size;
		if (GetCurveData(oid, out name, out size)) {
			return size;
		} else {
			return 0;
		}
	}

	static bool GetCurveData(string oid, out string name, out int size)
	{
		PKIXCurve pc;
		if (oid != null && PKIXCurve.ALL.TryGetValue(oid, out pc)) {
			name = pc.Name;
			size = pc.Size;
			return true;
		} else {
			name = null;
			size = 0;
			return false;
		}
	}
}
