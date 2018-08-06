using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;

/*
 * Clas for various methods and utility constants.
 */

class M {

	internal const int SSLv20 = 0x0200;
	internal const int SSLv30 = 0x0300;
	internal const int TLSv10 = 0x0301;
	internal const int TLSv11 = 0x0302;
	internal const int TLSv12 = 0x0303;

	internal const int CHANGE_CIPHER_SPEC = 20;
	internal const int ALERT              = 21;
	internal const int HANDSHAKE          = 22;
	internal const int APPLICATION        = 23;

	internal const int HELLO_REQUEST        = 0;
	internal const int CLIENT_HELLO         = 1;
	internal const int SERVER_HELLO         = 2;
	internal const int CERTIFICATE          = 11;
	internal const int SERVER_KEY_EXCHANGE  = 12;
	internal const int CERTIFICATE_REQUEST  = 13;
	internal const int SERVER_HELLO_DONE    = 14;
	internal const int CERTIFICATE_VERIFY   = 15;
	internal const int CLIENT_KEY_EXCHANGE  = 16;
	internal const int FINISHED             = 20;

	internal const int TLS_EMPTY_RENEGOTIATION_INFO_SCSV = 0x00FF;
	internal const int TLS_FALLBACK_SCSV = 0x5600;

	/* From RFC 5246 */
	internal const int EXT_SIGNATURE_ALGORITHMS    = 0x000D;

	/* From RFC 6066 */
	internal const int EXT_SERVER_NAME             = 0x0000;
	internal const int EXT_MAX_FRAGMENT_LENGTH     = 0x0001;
	internal const int EXT_CLIENT_CERTIFICATE_URL  = 0x0002;
	internal const int EXT_TRUSTED_CA_KEYS         = 0x0003;
	internal const int EXT_TRUNCATED_HMAC          = 0x0004;
	internal const int EXT_STATUS_REQUEST          = 0x0005;

	/* From RFC 4492 */
	internal const int EXT_SUPPORTED_CURVES        = 0x000A;
	internal const int EXT_SUPPORTED_EC_POINTS     = 0x000B;

	/* From RFC 5746 */
	internal const int EXT_RENEGOTIATION_INFO      = 0xFF01;

	/* From RFC 7366 */
	internal const int EXT_ENCRYPT_THEN_MAC        = 0x0016;

	internal static void Enc16be(int val, byte[] buf, int off)
	{
		buf[off] = (byte)(val >> 8);
		buf[off + 1] = (byte)val;
	}

	internal static void Enc24be(int val, byte[] buf, int off)
	{
		buf[off] = (byte)(val >> 16);
		buf[off + 1] = (byte)(val >> 8);
		buf[off + 2] = (byte)val;
	}

	internal static void Enc32be(int val, byte[] buf, int off)
	{
		buf[off] = (byte)(val >> 24);
		buf[off + 1] = (byte)(val >> 16);
		buf[off + 2] = (byte)(val >> 8);
		buf[off + 3] = (byte)val;
	}

	internal static int Dec16be(byte[] buf, int off)
	{
		return ((int)buf[off] << 8)
			| (int)buf[off + 1];
	}

	internal static int Dec24be(byte[] buf, int off)
	{
		return ((int)buf[off] << 16)
			| ((int)buf[off + 1] << 8)
			| (int)buf[off + 2];
	}

	internal static uint Dec32be(byte[] buf, int off)
	{
		return ((uint)buf[off] << 24)
			| ((uint)buf[off + 1] << 16)
			| ((uint)buf[off + 2] << 8)
			| (uint)buf[off + 3];
	}

	internal static void ReadFully(Stream s, byte[] buf)
	{
		ReadFully(s, buf, 0, buf.Length);
	}

	internal static void ReadFully(Stream s, byte[] buf, int off, int len)
	{
		while (len > 0) {
			int rlen = s.Read(buf, off, len);
			if (rlen <= 0) {
				throw new EndOfStreamException();
			}
			off += rlen;
			len -= rlen;
		}
	}

	static byte[] SKIPBUF = new byte[8192];

	internal static void Skip(Stream s, int len)
	{
		while (len > 0) {
			int rlen = Math.Min(len, SKIPBUF.Length);
			ReadFully(s, SKIPBUF, 0, rlen);
			len -= rlen;
		}
	}

	static readonly DateTime Jan1st1970 =
		new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);

	internal static long CurrentTimeMillis()
	{
		return (long)(DateTime.UtcNow - Jan1st1970).TotalMilliseconds;
	}

	/*
	 * Compute the SHA-1 hash of some bytes, returning the hash
	 * value in hexadecimal (lowercase).
	 */
	internal static string DoSHA1(byte[] buf)
	{
		return DoSHA1(buf, 0, buf.Length);
	}

	internal static string DoSHA1(byte[] buf, int off, int len)
	{
		byte[] hv = new SHA1Managed().ComputeHash(buf, off, len);
		StringBuilder sb = new StringBuilder();
		foreach (byte b in hv) {
			sb.AppendFormat("{0:x2}", b);
		}
		return sb.ToString();
	}

	/*
	 * Hash a whole chain of certificates. This is the SHA-1 hash
	 * of the concatenation of the provided buffers. The hash value
	 * is returned in lowercase hexadecimal.
	 */
	internal static string DoSHA1(byte[][] chain)
	{
		SHA1Managed sh = new SHA1Managed();
		foreach (byte[] ec in chain) {
			sh.TransformBlock(ec, 0, ec.Length, null, 0);
		}
		sh.TransformFinalBlock(new byte[0], 0, 0);
		StringBuilder sb = new StringBuilder();
		foreach (byte b in sh.Hash) {
			sb.AppendFormat("{0:x2}", b);
		}
		return sb.ToString();
	}

	/*
	 * Hash several values together. This makes an unambiguous
	 * concatenation.
	 */
	internal static string DoSHA1Values(params object[] values)
	{
		MemoryStream ms = new MemoryStream();
		foreach (object obj in values) {
			byte[] data;
			if (obj == null) {
				data = new byte[1];
				data[0] = 0x00;
			} else if (obj is int) {
				data = new byte[5];
				data[0] = 0x01;
				Enc32be((int)obj, data, 1);
			} else if (obj is byte[]) {
				byte[] buf = (byte[])obj;
				data = new byte[5 + buf.Length];
				data[0] = 0x01;
				Enc32be(buf.Length, data, 1);
				Array.Copy(buf, 0, data, 5, buf.Length);
			} else {
				throw new ArgumentException(
					"Unsupported object type: "
					+ obj.GetType().FullName);
			}
			ms.Write(data, 0, data.Length);
		}
		return DoSHA1(ms.ToArray());
	}

	internal static int Read1(Stream s)
	{
		int x = s.ReadByte();
		if (x < 0) {
			throw new IOException();
		}
		return x;
	}

	internal static int Read2(Stream s)
	{
		int x = Read1(s);
		return (x << 8) | Read1(s);
	}

	internal static int Read3(Stream s)
	{
		int x = Read1(s);
		x = (x << 8) | Read1(s);
		return (x << 8) | Read1(s);
	}

	internal static void Write1(Stream s, int x)
	{
		s.WriteByte((byte)x);
	}

	internal static void Write2(Stream s, int x)
	{
		s.WriteByte((byte)(x >> 8));
		s.WriteByte((byte)x);
	}

	internal static void Write3(Stream s, int x)
	{
		s.WriteByte((byte)(x >> 16));
		s.WriteByte((byte)(x >> 8));
		s.WriteByte((byte)x);
	}

	internal static void Write4(Stream s, int x)
	{
		s.WriteByte((byte)(x >> 24));
		s.WriteByte((byte)(x >> 16));
		s.WriteByte((byte)(x >> 8));
		s.WriteByte((byte)x);
	}

	internal static void Write4(Stream s, uint x)
	{
		Write4(s, (int)x);
	}

	internal static void WriteExtension(Stream s, int extType, byte[] val)
	{
		if (val.Length > 0xFFFF) {
			throw new ArgumentException("Oversized extension");
		}
		Write2(s, extType);
		Write2(s, val.Length);
		s.Write(val, 0, val.Length);
	}

	static RNGCryptoServiceProvider RNG = new RNGCryptoServiceProvider();
	static byte[] rngBuf = new byte[256];

	internal static void Rand(byte[] buf)
	{
		RNG.GetBytes(buf);
	}

	internal static void Rand(byte[] buf, int off, int len)
	{
		if (len == 0) {
			return;
		}
		if (off == 0 && len == buf.Length) {
			RNG.GetBytes(buf);
			return;
		}
		while (len > 0) {
			RNG.GetBytes(rngBuf);
			int clen = Math.Min(len, rngBuf.Length);
			Array.Copy(rngBuf, 0, buf, off, clen);
			off += clen;
			len -= clen;
		}
	}

	internal static string VersionString(int v)
	{
		if (v == 0x0200) {
			return "SSLv2";
		} else if (v == 0x0300) {
			return "SSLv3";
		} else if ((v >> 8) == 0x03) {
			return "TLSv1." + ((v & 0xFF) - 1);
		} else {
			return string.Format(
				"UNKNOWN_VERSION:0x{0:X4}", v);
		}
	}

	internal static bool Equals(int[] t1, int[] t2)
	{
		if (t1 == t2) {
			return true;
		}
		if (t1 == null || t2 == null) {
			return false;
		}
		int n = t1.Length;
		if (t2.Length != n) {
			return false;
		}
		for (int i = 0; i < n; i ++) {
			if (t1[i] != t2[i]) {
				return false;
			}
		}
		return true;
	}

	internal static void Reverse<T>(T[] tab)
	{
		if (tab == null || tab.Length <= 1) {
			return;
		}
		int n = tab.Length;
		for (int i = 0; i < (n >> 1); i ++) {
			T x = tab[i];
			tab[i] = tab[n - 1 - i];
			tab[n - 1 - i] = x;
		}
	}

	const string B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
		+ "abcdefghijklmnopqrstuvwxyz0123456789+/";

	static string ToBase64(byte[] buf, int off, int len)
	{
		char[] tc = new char[((len + 2) / 3) << 2];
		for (int i = 0, j = 0; i < len; i += 3) {
			if ((i + 3) <= len) {
				int x = Dec24be(buf, off + i);
				tc[j ++] = B64[x >> 18];
				tc[j ++] = B64[(x >> 12) & 0x3F];
				tc[j ++] = B64[(x >> 6) & 0x3F];
				tc[j ++] = B64[x & 0x3F];
			} else if ((i + 2) == len) {
				int x = Dec16be(buf, off + i);
				tc[j ++] = B64[x >> 10];
				tc[j ++] = B64[(x >> 4) & 0x3F];
				tc[j ++] = B64[(x << 2) & 0x3F];
				tc[j ++] = '=';
			} else if ((i + 1) == len) {
				int x = buf[off + i];
				tc[j ++] = B64[(x >> 2) & 0x3F];
				tc[j ++] = B64[(x << 4) & 0x3F];
				tc[j ++] = '=';
				tc[j ++] = '=';
			}
		}
		return new string(tc);
	}

	internal static void WritePEM(TextWriter w, string objType, byte[] buf)
	{
		w.WriteLine("-----BEGIN {0}-----", objType.ToUpperInvariant());
		int n = buf.Length;
		for (int i = 0; i < n; i += 57) {
			int len = Math.Min(57, n - i);
			w.WriteLine(ToBase64(buf, i, len));
		}
		w.WriteLine("-----END {0}-----", objType.ToUpperInvariant());
	}

	internal static string ToPEM(string objType, byte[] buf)
	{
		return ToPEM(objType, buf, "\n");
	}

	internal static string ToPEM(string objType, byte[] buf, string nl)
	{
		StringWriter w = new StringWriter();
		w.NewLine = nl;
		WritePEM(w, objType, buf);
		return w.ToString();
	}

	/*
	 * Compute bit length for an integer (unsigned big-endian).
	 * Bit length is the smallest integer k such that the integer
	 * value is less than 2^k.
	 */
	internal static int BitLength(byte[] v)
	{
		for (int k = 0; k < v.Length; k ++) {
			int b = v[k];
			if (b != 0) {
				int bitLen = (v.Length - k) << 3;
				while (b < 0x80) {
					b <<= 1;
					bitLen --;
				}
				return bitLen;
			}
		}
		return 0;
	}

	/*
	 * Compute "adjusted" bit length for an integer (unsigned
	 * big-endian). The adjusted bit length is the integer k
	 * such that 2^k is closest to the integer value (if the
	 * integer is x = 3*2^m, then the adjusted bit length is
	 * m+2, not m+1).
	 */
	internal static int AdjustedBitLength(byte[] v)
	{
		for (int k = 0; k < v.Length; k ++) {
			int b = v[k];
			if (b == 0) {
				continue;
			}
			int bitLen = (v.Length - k) << 3;
			if (b == 1) {
				if ((k + 1) == v.Length) {
					return 0;
				}
				bitLen -= 7;
				if (v[k + 1] < 0x80) {
					bitLen --;
				}
			} else {
				while (b < 0x80) {
					b <<= 1;
					bitLen --;
				}
				if (b < 0xC0) {
					bitLen --;
				}
			}
			return bitLen;
		}
		return 0;
	}

	internal static V[] ToValueArray<K, V>(IDictionary<K, V> s)
	{
		V[] vv = new V[s.Count];
		int k = 0;
		foreach (V v in s.Values) {
			vv[k ++] = v;
		}
		return vv;
	}
}
