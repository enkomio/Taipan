using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

using Asn1;

namespace X500 {

/*
 * A DNPart instance encodes an X.500 name element: it has a type (an
 * OID) and a value. The value is an ASN.1 object. If the name type is
 * one of a list of standard types, then the value is a character
 * string, and there is a "friendly type" which is a character string
 * (such as "CN" for the "common name", of OID 2.5.4.3).
 */

public class DNPart {

	/*
	 * These are the known "friendly types". The values decode as
	 * strings.
	 */

	public const string COMMON_NAME          = "CN";
	public const string LOCALITY             = "L";
	public const string STATE                = "ST";
	public const string ORGANIZATION         = "O";
	public const string ORGANIZATIONAL_UNIT  = "OU";
	public const string COUNTRY              = "C";
	public const string STREET               = "STREET";
	public const string DOMAIN_COMPONENT     = "DC";
	public const string USER_ID              = "UID";
	public const string EMAIL_ADDRESS        = "EMAILADDRESS";

	/*
	 * Get the type OID (decimal-dotted string representation).
	 */
	public string OID {
		get {
			return OID_;
		}
	}
	string OID_;

	/*
	 * Get the string value for this element. If the element value
	 * could not be decoded as a string, then this method returns
	 * null.
	 *
	 * (Decoding error for name elements of a standard type trigger
	 * exceptions upon instance creation. Thus, a null value is
	 * possible only for a name element that uses an unknown type.)
	 */
	public string Value {
		get {
			return Value_;
		}
	}
	string Value_;

	/*
	 * Tell whether this element is string based. This property
	 * returns true if and only if Value returns a non-null value.
	 */
	public bool IsString {
		get {
			return Value_ != null;
		}
	}

	/*
	 * Get the element value as an ASN.1 structure.
	 */
	public AsnElt AsnValue {
		get {
			return AsnValue_;
		}
	}
	AsnElt AsnValue_;

	/*
	 * Get the "friendly type" for this element. This is the
	 * string mnemonic such as "CN" for "common name". If no
	 * friendly type is known for that element, then the OID
	 * is returned (decimal-dotted representation).
	 */
	public string FriendlyType {
		get {
			return GetFriendlyType(OID);
		}
	}

	/*
	 * "Normalized" string value (converted to uppercase then
	 * lowercase, leading and trailing whitespace trimmed, adjacent
	 * spaces coalesced). This should allow for efficient comparison
	 * while still supporting most corner cases.
	 *
	 * This does not implement full RFC 4518 rules, but it should
	 * be good enough for an analysis tool.
	 */
	string normValue;

	byte[] encodedValue;
	int hashCode;

	internal DNPart(string oid, AsnElt val)
	{
		OID_ = oid;
		AsnValue_ = val;
		encodedValue = val.Encode();
		uint hc = (uint)oid.GetHashCode();
		try {
			string s = val.GetString();
			Value_ = s;
			s = s.ToUpperInvariant().ToLowerInvariant();
			StringBuilder sb = new StringBuilder();
			bool lwws = true;
			foreach (char c in s.Trim()) {
				if (IsControl(c)) {
					continue;
				}
				if (IsWS(c)) {
					if (lwws) {
						continue;
					}
					lwws = true;
					sb.Append(' ');
				} else {
					sb.Append(c);
				}
			}
			int n = sb.Length;
			if (n > 0 && sb[n - 1] == ' ') {
				sb.Length = n - 1;
			}
			normValue = sb.ToString();
			hc += (uint)normValue.GetHashCode();
		} catch {
			if (OID_TO_FT.ContainsKey(oid)) {
				throw;
			}
			Value_ = null;
			foreach (byte b in encodedValue) {
				hc = ((hc << 7) | (hc >> 25)) ^ (uint)b;
			}
		}
		hashCode = (int)hc;
	}

	static bool MustEscape(int x)
	{
		if (x < 0x20 || x >= 0x7F) {
			return true;
		}
		switch (x) {
		case '"':
		case '+':
		case ',':
		case ';':
		case '<':
		case '>':
		case '\\':
			return true;
		default:
			return false;
		}
	}

	/*
	 * Convert this element to a string. This uses RFC 4514 rules.
	 */
	public override string ToString()
	{
		StringBuilder sb = new StringBuilder();
		string ft;
		if (OID_TO_FT.TryGetValue(OID, out ft) && IsString) {
			sb.Append(ft);
			sb.Append("=");
			byte[] buf = Encoding.UTF8.GetBytes(Value);
			for (int i = 0; i < buf.Length; i ++) {
				byte b = buf[i];
				if ((i == 0 && (b == ' ' || b == '#'))
					|| (i == buf.Length - 1 && b == ' ')
					|| MustEscape(b))
				{
					switch ((char)b) {
					case ' ':
					case '"':
					case '#':
					case '+':
					case ',':
					case ';':
					case '<':
					case '=':
					case '>':
					case '\\':
						sb.Append('\\');
						sb.Append((char)b);
						break;
					default:
						sb.AppendFormat("\\{0:X2}", b);
						break;
					}
				} else {
					sb.Append((char)b);
				}
			}
		} else {
			sb.Append(OID);
			sb.Append("=#");
			foreach (byte b in AsnValue.Encode()) {
				sb.AppendFormat("{0:X2}", b);
			}
		}
		return sb.ToString();
	}

	/*
	 * Get the friendly type corresponding to the given OID
	 * (decimal-dotted representation). If no such type is known,
	 * then the OID string is returned.
	 */
	public static string GetFriendlyType(string oid)
	{
		string ft;
		if (OID_TO_FT.TryGetValue(oid, out ft)) {
			return ft;
		}
		return oid;
	}

	static int HexVal(char c)
	{
		if (c >= '0' && c <= '9') {
			return c - '0';
		} else if (c >= 'A' && c <= 'F') {
			return c - ('A' - 10);
		} else if (c >= 'a' && c <= 'f') {
			return c - ('a' - 10);
		} else {
			return -1;
		}
	}

	static int HexValCheck(char c)
	{
		int x = HexVal(c);
		if (x < 0) {
			throw new AsnException(String.Format(
				"Not an hex digit: U+{0:X4}", c));
		}
		return x;
	}

	static int HexVal2(string str, int k)
	{
		if (k >= str.Length) {
			throw new AsnException("Missing hex digits");
		}
		int x = HexVal(str[k]);
		if ((k + 1) >= str.Length) {
			throw new AsnException("Odd number of hex digits");
		}
		return (x << 4) + HexVal(str[k + 1]);
	}

	static int ReadHexEscape(string str, ref int off)
	{
		if (off >= str.Length || str[off] != '\\') {
			return -1;
		}
		if ((off + 1) >= str.Length) {
			throw new AsnException("Truncated escape");
		}
		int x = HexVal(str[off + 1]);
		if (x < 0) {
			return -1;
		}
		if ((off + 2) >= str.Length) {
			throw new AsnException("Truncated escape");
		}
		int y = HexValCheck(str[off + 2]);
		off += 3;
		return (x << 4) + y;
	}

	static int ReadHexUTF(string str, ref int off)
	{
		int x = ReadHexEscape(str, ref off);
		if (x < 0x80 || x >= 0xC0) {
			throw new AsnException(
				"Invalid hex escape: not UTF-8");
		}
		return x;
	}

	static string UnEscapeUTF8(string str)
	{
		StringBuilder sb = new StringBuilder();
		int n = str.Length;
		int k = 0;
		while (k < n) {
			char c = str[k];
			if (c != '\\') {
				sb.Append(c);
				k ++;
				continue;
			}
			int x = ReadHexEscape(str, ref k);
			if (x < 0) {
				sb.Append(str[k + 1]);
				k += 2;
				continue;
			}
			if (x < 0x80) {
				// nothing
			} else if (x < 0xC0) {
				throw new AsnException(
					"Invalid hex escape: not UTF-8");
			} else if (x < 0xE0) {
				x &= 0x1F;
				x = (x << 6) | ReadHexUTF(str, ref k) & 0x3F;
			} else if (x < 0xF0) {
				x &= 0x0F;
				x = (x << 6) | ReadHexUTF(str, ref k) & 0x3F;
				x = (x << 6) | ReadHexUTF(str, ref k) & 0x3F;
			} else if (x < 0xF8) {
				x &= 0x07;
				x = (x << 6) | ReadHexUTF(str, ref k) & 0x3F;
				x = (x << 6) | ReadHexUTF(str, ref k) & 0x3F;
				x = (x << 6) | ReadHexUTF(str, ref k) & 0x3F;
				if (x > 0x10FFFF) {
					throw new AsnException("Invalid"
						+ " hex escape: out of range");
				}
			} else {
				throw new AsnException(
					"Invalid hex escape: not UTF-8");
			}
			if (x < 0x10000) {
				sb.Append((char)x);
			} else {
				x -= 0x10000;
				sb.Append((char)(0xD800 + (x >> 10)));
				sb.Append((char)(0xDC00 + (x & 0x3FF)));
			}
		}
		return sb.ToString();
	}

	internal static DNPart Parse(string str)
	{
		int j = str.IndexOf('=');
		if (j < 0) {
			throw new AsnException("Invalid DN: no '=' sign");
		}
		string a = str.Substring(0, j).Trim();
		string b = str.Substring(j + 1).Trim();
		string oid;
		if (!FT_TO_OID.TryGetValue(a, out oid)) {
			oid = AsnElt.MakeOID(oid).GetOID();
		}
		AsnElt aVal;
		if (b.StartsWith("#")) {
			MemoryStream ms = new MemoryStream();
			int n = b.Length;
			for (int k = 1; k < n; k += 2) {
				int x = HexValCheck(b[k]);
				if (k + 1 >= n) {
					throw new AsnException(
						"Odd number of hex digits");
				}
				x = (x << 4) + HexValCheck(b[k + 1]);
				ms.WriteByte((byte)x);
			}
			try {
				aVal = AsnElt.Decode(ms.ToArray());
			} catch (Exception e) {
				throw new AsnException("Bad DN value: "
					+ e.Message);
			}
		} else {
			b = UnEscapeUTF8(b);
			int type = AsnElt.PrintableString;
			foreach (char c in b) {
				if (!AsnElt.IsPrintable(c)) {
					type = AsnElt.UTF8String;
					break;
				}
			}
			aVal = AsnElt.MakeString(type, b);
		}
		return new DNPart(oid, aVal);
	}

	static Dictionary<string, string> OID_TO_FT;
	static Dictionary<string, string> FT_TO_OID;

	static void AddFT(string oid, string ft)
	{
		OID_TO_FT[oid] = ft;
		FT_TO_OID[ft] = oid;
	}

	static DNPart()
	{
		OID_TO_FT = new Dictionary<string, string>();
		FT_TO_OID = new Dictionary<string, string>(
			StringComparer.OrdinalIgnoreCase);
		AddFT("2.5.4.3", COMMON_NAME);
		AddFT("2.5.4.7", LOCALITY);
		AddFT("2.5.4.8", STATE);
		AddFT("2.5.4.10", ORGANIZATION);
		AddFT("2.5.4.11", ORGANIZATIONAL_UNIT);
		AddFT("2.5.4.6", COUNTRY);
		AddFT("2.5.4.9", STREET);
		AddFT("0.9.2342.19200300.100.1.25", DOMAIN_COMPONENT);
		AddFT("0.9.2342.19200300.100.1.1", USER_ID);
		AddFT("1.2.840.113549.1.9.1", EMAIL_ADDRESS);

		/*
		 * We also accept 'S' as an alias for 'ST' because some
		 * Microsoft software uses it.
		 */
		FT_TO_OID["S"] = FT_TO_OID["ST"];
	}

	/*
	 * Tell whether a given character is a "control character" (to
	 * be ignored for DN comparison purposes). This follows RFC 4518
	 * but only for code points in the first plane.
	 */
	static bool IsControl(char c)
	{
		if (c <= 0x0008
			|| (c >= 0x000E && c <= 0x001F)
			|| (c >= 0x007F && c <= 0x0084)
			|| (c >= 0x0086 && c <= 0x009F)
			|| c == 0x06DD
			|| c == 0x070F
			|| c == 0x180E
			|| (c >= 0x200C && c <= 0x200F)
			|| (c >= 0x202A && c <= 0x202E)
			|| (c >= 0x2060 && c <= 0x2063)
			|| (c >= 0x206A && c <= 0x206F)
			|| c == 0xFEFF
			|| (c >= 0xFFF9 && c <= 0xFFFB))
		{
			return true;
		}
		return false;
	}

	/*
	 * Tell whether a character is whitespace. This follows
	 * rules of RFC 4518.
	 */
	static bool IsWS(char c)
	{
		if (c == 0x0020
			|| c == 0x00A0
			|| c == 0x1680
			|| (c >= 0x2000 && c <= 0x200A)
			|| c == 0x2028
			|| c == 0x2029
			|| c == 0x202F
			|| c == 0x205F
			|| c == 0x3000)
		{
			return true;
		}
		return false;
	}

	public override bool Equals(object obj)
	{
		return Equals(obj as DNPart);
	}

	public bool Equals(DNPart dnp)
	{
		if (dnp == null) {
			return false;
		}
		if (OID != dnp.OID) {
			return false;
		}
		if (IsString) {
			return dnp.IsString
				&& normValue == dnp.normValue;
		} else if (dnp.IsString) {
			return false;
		} else {
			return Eq(encodedValue, dnp.encodedValue);
		}
	}

	public override int GetHashCode()
	{
		return hashCode;
	}

	static bool Eq(byte[] a, byte[] b)
	{
		if (a == b) {
			return true;
		}
		if (a == null || b == null) {
			return false;
		}
		int n = a.Length;
		if (n != b.Length) {
			return false;
		}
		for (int i = 0; i < n; i ++) {
			if (a[i] != b[i]) {
				return false;
			}
		}
		return true;
	}
}

}
