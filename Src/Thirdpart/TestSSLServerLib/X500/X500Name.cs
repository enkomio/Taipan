using System;
using System.Collections.Generic;
using System.Text;

using Asn1;

namespace X500 {

/*
 * An X.500 name is a "distinguished name", which is an ordered sequence
 * of RDN (relative distinguished names). Each RDN is an unordered set
 * of name elements. A name element is an arbitrary value with an
 * identifying OID; some (most) name element values are character
 * strings.
 *
 * X.500 names are used primarily to identify certificate owner entities
 * (subject and issuer name in a certificate), and to serve as
 * hierarchical indexing key for values in LDAP.
 *
 * An X.500 name is encoded and decoded using ASN.1. They can also be
 * converted to a string representation. The string representation does
 * not conserve all encoding details, so encoding+parsing will not
 * necessarily restore the exact same binary DN.
 */

public class X500Name {

	/*
	 * Get the individual name elements, in a "flattened" structure
	 * (if a SET in a RDN contains multiple values, then they are
	 * stored consecutively in that array).
	 *
	 * The returned array MUST NOT be modified.
	 */
	public DNPart[] Parts {
		get {
			return Parts_;
		}
	}
	DNPart[] Parts_;

	/*
	 * Get the individual name elements. Each internal array contains
	 * the name elements found in the SET for a specific RDN.
	 */
	public DNPart[][] PartsGen {
		get {
			return PartsGen_;
		}
	}
	DNPart[][] PartsGen_;

	/*
	 * Check whether this DN is empty.
	 */
	public bool IsEmpty {
		get {
			return Parts_.Length == 0;
		}
	}

	int hashCode;

	/*
	 * Constructor for parsing.
	 */
	X500Name(List<List<DNPart>> dn)
	{
		Init(dn);
	}

	void Init(List<List<DNPart>> dn)
	{
		int n = dn.Count;
		List<DNPart> r = new List<DNPart>();
		PartsGen_ = new DNPart[n][];
		for (int i = 0; i < n; i ++) {
			IDictionary<string, DNPart> dd =
				new SortedDictionary<string, DNPart>(
					StringComparer.Ordinal);
			foreach (DNPart dnp in dn[i]) {
				string nt = dnp.OID;
				if (dd.ContainsKey(nt)) {
					throw new AsnException(string.Format(
						"multiple values of type {0}"
						+ " in RDN", nt));
				}
				dd[nt] = dnp;
			}
			PartsGen_[i] = new DNPart[dd.Count];
			int j = 0;
			foreach (DNPart p in dd.Values) {
				PartsGen_[i][j ++] = p;
				r.Add(p);
			}
		}
		Parts_ = r.ToArray();

		uint hc = 0;
		foreach (DNPart dnp in r) {
			hc = ((hc << 7) | (hc >> 25)) + (uint)dnp.GetHashCode();
		}
		hashCode = (int)hc;
	}

	/*
	 * Simplified parsing: this constructor checks that every SET
	 * in the sequence of RDN has size exactly 1, and decodes each
	 * name element as a "generic string".
	 *
	 * On decoding error, an AsnException is thrown.
	 */
	public X500Name(AsnElt aDN) : this(aDN, true)
	{
	}

	/*
	 * Generic parsing. If 'strictStrings' is true, then the following
	 * rules are enforced:
	 * -- Every SET in the sequence of RDN must have size 1.
	 * -- Every name element is decoded as a string (by tag).
	 *
	 * If 'strictStrings' is false, then multiple elements may appear
	 * in each SET, and values needs not be decodable as string (values
	 * with a known OID must still be decodable).
	 *
	 * This constructor checks that within a single RDN, no two
	 * attributes may have the same type.
	 *
	 * On decoding error, an AsnException is thrown.
	 */
	public X500Name(AsnElt aDN, bool strictStrings)
	{
		/*
		 * Note: the SEQUENCE tag MUST be present, since the
		 * ASN.1 definition of Name starts with a CHOICE; thus,
		 * any tag override would have to be explicit, not
		 * implicit.
		 */
		aDN.CheckConstructed();
		aDN.CheckTag(AsnElt.SEQUENCE);
		List<List<DNPart>> r = new List<List<DNPart>>();
		foreach (AsnElt aRDN in aDN.Sub) {
			aRDN.CheckConstructed();
			aRDN.CheckTag(AsnElt.SET);
			aRDN.CheckNumSubMin(1);
			int n = aRDN.Sub.Length;
			if (n != 1 && strictStrings) {
				throw new AsnException(String.Format(
					"several ({0}) values in RDN", n));
			}
			List<DNPart> r2 = new List<DNPart>();
			r.Add(r2);
			for (int i = 0; i < n; i ++) {
				AsnElt aTV = aRDN.Sub[i];
				aTV.CheckConstructed();
				aTV.CheckTag(AsnElt.SEQUENCE);
				aTV.CheckNumSub(2);
				AsnElt aOID = aTV.GetSub(0);
				aOID.CheckTag(AsnElt.OBJECT_IDENTIFIER);
				AsnElt aVal = aTV.GetSub(1);
				string nt = aOID.GetOID();
				DNPart dnp = new DNPart(nt, aVal);
				if (strictStrings && !dnp.IsString) {
					throw new AsnException(
						"RDN is not a string");
				}
				r2.Add(dnp);
			}
		}
		Init(r);
	}

	/*
	 * Encode this DN into a string as specified in RFC 4514.
	 */
	public override string ToString()
	{
		StringBuilder sb = new StringBuilder();
		for (int i = PartsGen_.Length - 1; i >= 0; i --) {
			DNPart[] dd = PartsGen_[i];
			for (int j = 0; j < dd.Length; j ++) {
				if (j > 0) {
					sb.Append("+");
				} else if (sb.Length > 0) {
					sb.Append(",");
				}
				sb.Append(dd[j].ToString());
			}
		}
		return sb.ToString();
	}

	/*
	 * Encode back this DN into an ASN.1 structure.
	 */
	public AsnElt ToAsn1()
	{
		AsnElt[] t1 = new AsnElt[PartsGen_.Length];
		for (int i = 0; i < PartsGen_.Length; i ++) {
			DNPart[] dp = PartsGen_[i];
			AsnElt[] t2 = new AsnElt[dp.Length];
			for (int j = 0; j < dp.Length; j ++) {
				t2[j] = AsnElt.Make(AsnElt.SEQUENCE,
					AsnElt.MakeOID(dp[j].OID),
					dp[j].AsnValue);
			}
			t1[i] = AsnElt.MakeSetOf(t2);
		}
		return AsnElt.Make(AsnElt.SEQUENCE, t1);
	}

	/*
	 * Parse a string into a DN. The input is expected to use
	 * RFC 4514 format. Name elements that are provided as
	 * character strings will be mapped to ASN.1 PrintableString
	 * values (if they are compatible with that string type)
	 * or UTF8String values (otherwise).
	 *
	 * On parse error, an AsnException is thrown.
	 */
	public static X500Name Parse(string str)
	{
		int n = str.Length;
		int p = 0;
		bool acc = false;
		List<List<DNPart>> dn = new List<List<DNPart>>();
		while (p < n) {
			/*
			 * Find the next unescaped '+' or ',' sign.
			 */
			bool lcwb = false;
			int q;
			for (q = p; q < n; q ++) {
				if (lcwb) {
					lcwb = false;
					continue;
				}
				switch (str[q]) {
				case ',':
				case '+':
					goto found;
				case '\\':
					lcwb = true;
					break;
				}
			}
		found:

			/*
			 * Parse DN element.
			 */
			DNPart dnp = DNPart.Parse(str.Substring(p, q - p));
			if (acc) {
				dn[dn.Count - 1].Add(dnp);
			} else {
				List<DNPart> r = new List<DNPart>();
				r.Add(dnp);
				dn.Add(r);
			}

			p = q + 1;
			acc = q < n && str[q] == '+';
		}

		dn.Reverse();
		return new X500Name(dn);
	}

	/*
	 * Compare two DN for equality. "null" is equal to "null" but
	 * to nothing else.
	 */
	public static bool Equals(X500Name dn1, X500Name dn2)
	{
		if (dn1 == null) {
			return dn2 == null;
		} else {
			return dn1.Equals(dn2);
		}
	}

	public override bool Equals(object obj)
	{
		return Equals(obj as X500Name);
	}

	public bool Equals(X500Name dn)
	{
		if (dn == null) {
			return false;
		}
		int n = PartsGen.Length;
		if (dn.PartsGen.Length != n) {
			return false;
		}
		for (int i = 0; i < n; i ++) {
			DNPart[] p1 = PartsGen[i];
			DNPart[] p2 = dn.PartsGen[i];
			int k = p1.Length;
			if (k != p2.Length) {
				return false;
			}
			for (int j = 0; j < k; j ++) {
				if (!p1[j].Equals(p2[j])) {
					return false;
				}
			}
		}
		return true;
	}

	public override int GetHashCode()
	{
		return hashCode;
	}
}

}
