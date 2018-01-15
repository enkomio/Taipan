using System;
using System.IO;
using System.Text;

/*
 * Helper class for connecting through a HTTP proxy. Right now, it
 * does not support any form of authentication.
 *
 * Instances are NOT thread-safe.
 */

class HTTPProx {

	Stream remote;
	int delayed;

	internal HTTPProx()
	{
	}

	/*
	 * Perform the HTTP "CONNECT" with the provided ultimate target.
	 * The returned stream may be the same instance as the one
	 * provided, or a wrapper that will propagate closures.
	 */
	internal Stream DoProxy(Stream remote, string host, int port)
	{
		this.remote = remote;
		string dest = string.Format("{0}:{1}", host, port);
		string msg = string.Format(
			"CONNECT {0} HTTP/1.0\r\nHost: {0}\r\n\r\n",
			dest);
		byte[] emsg = Encoding.UTF8.GetBytes(msg);
		remote.Write(emsg, 0, emsg.Length);
		delayed = -1;
		ParseHTTPResponse();
		return remote;
	}

	/*
	 * Read next character. This method normalizes CR+LF to LF. It
	 * does NOT convert lone CR into LF.
	 */
	char NextChar()
	{
		int x = delayed;
		if (x >= 0) {
			delayed = -1;
			return (char)x;
		}
		x = remote.ReadByte();
		if (x < 0) {
			throw new IOException("Unexpected EOF");
		}
		if (x == '\r') {
			x = remote.ReadByte();
			if (x != '\n') {
				if (x > 0) {
					delayed = x;
				}
				x = '\r';
			}
		}
		return (char)x;
	}

	void ParseString(string s)
	{
		ParseString(s, false);
	}

	void ParseString(string s, bool ignoreLeadingDigits)
	{
		if (ignoreLeadingDigits) {
			if (s.Length == 0) {
				throw new ArgumentException();
			}
			for (;;) {
				char c = NextChar();
				if (c >= '0' && c <= '9') {
					continue;
				}
				if (c != s[0]) {
					throw new IOException(string.Format(
						"Unexpected character U+{0:X4}",
						(int)c));
				}
				break;
			}
			s = s.Substring(1);
		}
		foreach (char c in s) {
			char d = NextChar();
			if (c != d) {
				throw new IOException(string.Format(
					"Unexpected character U+{0:X4}",
					(int)d));
			}
		}
	}

	int ParseDigits(int num)
	{
		int x = 0;
		while (num -- > 0) {
			char c = NextChar();
			if (c < '0' || c > '9') {
				throw new IOException(string.Format(
					"Unexpected character U+{0:X4}",
					(int)c));
			}
			x = (x * 10) + (c - '0');
		}
		return x;
	}

	void ParseHTTPResponse()
	{
		ParseString("HTTP/");
		ParseDigits(1);
		ParseString(".", true);
		ParseDigits(1);
		ParseString(" ", true);
		int code = ParseDigits(3);
		if (code < 200 || code >= 300) {
			throw new IOException(string.Format(
				"Server rejected attempt with code {0}", code));
		}
		bool lcwn = false;
		for (;;) {
			char c = NextChar();
			if (c == '\n') {
				if (lcwn) {
					break;
				}
				lcwn = true;
			} else {
				lcwn = false;
			}
		}
	}
}
