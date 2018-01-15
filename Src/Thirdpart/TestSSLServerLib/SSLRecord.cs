using System;
using System.IO;

/*
 * This stream handles sending and receiving SSL/TLS records (unencrypted).
 *
 * In output mode:
 * -- data is buffered until a full record is obtained
 * -- an explicit Flush() call terminates and sends the current record
 *    (only if there is data to send)
 * -- record type is set explicitly
 *
 * In input mode:
 * -- records MUST have the set expected type, or be alerts
 * -- warning-level alerts are ignored
 * -- fatal-level alerts trigger SSLAlertException
 * -- record type mismatch triggers exceptions
 * -- first received record sets version (from record header); all
 *    subsequent records MUST have the same version
 */

class SSLRecord : Stream {

	const int MAX_RECORD_LEN = 16384;

	Stream sub;
	byte[] outBuf = new byte[MAX_RECORD_LEN + 5];
	int outPtr;
	int outVersion;
	int outType;
	byte[] inBuf = new byte[MAX_RECORD_LEN];
	int inPtr;
	int inEnd;
	int inVersion;
	int inType;
	int inExpectedType;

	bool dumpBytes;

	/*
	 * Create an instance over the provided stream (normally a
	 * network socket).
	 */
	internal SSLRecord(Stream sub)
	{
		this.sub = sub;
		outPtr = 5;
		inPtr = 0;
		inEnd = 0;
		dumpBytes = false;
	}

	internal bool DumpBytes {
		get {
			return dumpBytes;
		}
		set {
			dumpBytes = value;
		}
	}

	public override bool CanRead { get { return true; } }
	public override bool CanSeek { get { return false; } }
	public override bool CanWrite { get { return true; } }
	public override long Length {
		get { throw new NotSupportedException(); }
	}
	public override long Position {
		get { throw new NotSupportedException(); }
		set { throw new NotSupportedException(); }
	}

	public override long Seek(long offset, SeekOrigin origin)
	{
		throw new NotSupportedException();
	}

	public override void SetLength(long value)
	{
		throw new NotSupportedException();
	}

	/*
	 * Set record type. If it differs from the a previously set
	 * record type, then an automatic flush is performed.
	 */
	internal void SetOutType(int type)
	{
		if (outType != 0 && outType != type) {
			Flush();
		}
		outType = type;
	}

	/*
	 * Set the version for the next outgoing record.
	 */
	internal void SetOutVersion(int version)
	{
		outVersion = version;
	}

	/*
	 * Flush accumulated data. Nothing is done if there is no
	 * accumulated data.
	 */
	public override void Flush()
	{
		if (outPtr > 5) {
			outBuf[0] = (byte)outType;
			M.Enc16be(outVersion, outBuf, 1);
			M.Enc16be(outPtr - 5, outBuf, 3);
			if (dumpBytes) {
				Console.WriteLine(">>> record header");
				Dump(outBuf, 0, 5);
				Console.WriteLine(">>> record data");
				Dump(outBuf, 5, outPtr - 5);
			}
			sub.Write(outBuf, 0, outPtr);
			outPtr = 5;
		}
		sub.Flush();
	}

	public override void WriteByte(byte b)
	{
		outBuf[outPtr ++] = b;
		if (outPtr == outBuf.Length) {
			Flush();
		}
	}

	public void Write(byte[] buf)
	{
		Write(buf, 0, buf.Length);
	}

	public override void Write(byte[] buf, int off, int len)
	{
		while (len > 0) {
			int clen = Math.Min(outBuf.Length - outPtr, len);
			Array.Copy(buf, off, outBuf, outPtr, clen);
			outPtr += clen;
			off += clen;
			len -= clen;
			if (outPtr == outBuf.Length) {
				Flush();
			}
		}
	}

	/*
	 * Raw write: write some data on the underlying stream,
	 * bypassing the record layer. This is used to send a ClientHello
	 * in V2 format.
	 */
	internal void RawWrite(byte[] buf)
	{
		RawWrite(buf, 0, buf.Length);
	}

	/*
	 * Raw write: write some data on the underlying stream,
	 * bypassing the record layer. This is used to send a ClientHello
	 * in V2 format.
	 */
	internal void RawWrite(byte[] buf, int off, int len)
	{
		if (dumpBytes) {
			Console.WriteLine(">>> raw write");
			Dump(buf, off, len);
		}
		sub.Write(buf, off, len);
	}

	/*
	 * Set expected type for incoming records.
	 */
	internal void SetExpectedType(int expectedType)
	{
		this.inExpectedType = expectedType;
	}

	/*
	 * Get the version advertised in the last incoming record.
	 */
	internal int GetInVersion()
	{
		return inVersion;
	}

	/*
	 * Obtain next record. Incoming alerts are processed; this method
	 * exists when the next record of the expected type is received
	 * (though it may contain an empty payload).
	 */
	void Refill()
	{
		for (;;) {
			M.ReadFully(sub, inBuf, 0, 5);
			if (dumpBytes) {
				Console.WriteLine("<<< record header");
				Dump(inBuf, 0, 5);
			}
			inType = inBuf[0];
			int v = M.Dec16be(inBuf, 1);
			inEnd = M.Dec16be(inBuf, 3);
			if ((v >> 8) != 0x03) {
				throw new IOException(string.Format(
					"not an SSL 3.x record (0x{0:X4})", v));
			}
			if (inVersion != 0 && inVersion != v) {
				throw new IOException(string.Format(
					"record version change"
					+ " (0x{0:X4} -> 0x{1:X4})",
					inVersion, v));
			}
			inVersion = v;
			if (inEnd > inBuf.Length) {
				throw new IOException(string.Format(
					"oversized input payload (len={0})",
					inEnd));
			}
			if (inType != inExpectedType && inType != M.ALERT) {
				throw new IOException(string.Format(
					"unexpected record type ({0})",
					inType));
			}
			M.ReadFully(sub, inBuf, 0, inEnd);
			if (dumpBytes) {
				Console.WriteLine("<<< record data");
				Dump(inBuf, 0, inEnd);
			}
			inPtr = 0;
			if (inType == M.ALERT) {
				for (int k = 0; k < inEnd; k += 2) {
					int at = inBuf[k];
					if (at != 0x01) {
						throw new SSLAlertException(at);
					}
				}
				/*
				 * We just ignore warnings.
				 */
				continue;
			}
			return;
		}
	}

	public override int ReadByte()
	{
		while (inPtr == inEnd) {
			Refill();
		}
		return inBuf[inPtr ++];
	}

	public override int Read(byte[] buf, int off, int len)
	{
		while (inPtr == inEnd) {
			Refill();
		}
		int clen = Math.Min(inEnd - inPtr, len);
		Array.Copy(inBuf, inPtr, buf, off, clen);
		inPtr += clen;
		return clen;
	}

	static void Dump(byte[] buf, int off, int len)
	{
		for (int i = 0; i < len; i += 16) {
			Console.Write("  {0:x8} ", i);
			for (int j = 0; j < 16 && (i + j) < len; j ++) {
				if (j == 8) {
					Console.Write(" ");
				}
				Console.Write(" {0:x2}", buf[off + i + j]);
			}
			Console.WriteLine();
		}
	}
}
