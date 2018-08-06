using System;
using System.IO;

/*
 * This class wraps around an existing stream, forwarding all bytes
 * back and forth, but also writing a log of all these bytes (hexadecimal)
 * in a text stream.
 */

class DebugStream : Stream {

	/*
	 * The debug log destination. Can be null if not actually logging.
	 */
	internal TextWriter Log {
		get {
			return log;
		}
	}

	Stream sub;
	TextWriter log;
	object logLock;

	/*
	 * Create an instance over the provided stream (normally a
	 * network socket) and debug log (which can be null).
	 */
	internal DebugStream(Stream sub, TextWriter log)
	{
		this.sub = sub;
		this.log = log;
		logLock = new object();
	}

	public override bool CanRead {
		get {
			return sub.CanRead;
		}
	}

	public override bool CanSeek {
		get {
			return sub.CanSeek;
		}
	}

	public override bool CanWrite {
		get {
			return sub.CanWrite;
		}
	}

	public override long Length {
		get {
			return sub.Length;
		}
	}

	public override long Position {
		get {
			return sub.Position;
		}
		set {
			sub.Position = value;
		}
	}

	public override long Seek(long offset, SeekOrigin origin)
	{
		return sub.Seek(offset, origin);
	}

	public override void SetLength(long value)
	{
		sub.SetLength(value);
	}

	public override void Flush()
	{
		sub.Flush();
	}

	public override void WriteByte(byte b)
	{
		sub.WriteByte(b);
		if (log != null) {
			lock (logLock) {
				log.WriteLine(">>> {0:x2}", b);
			}
		}
	}

	public override void Write(byte[] buf, int off, int len)
	{
		sub.Write(buf, off, len);
		if (log != null) {
			lock (logLock) {
				log.Write(">>> ");
				Dump(buf, off, len);
				log.WriteLine();
			}
		}
	}

	public override int ReadByte()
	{
		int x = sub.ReadByte();
		if (log != null) {
			lock (logLock) {
				if (x < 0) {
					log.WriteLine("<<< EOF");
				} else {
					log.WriteLine("<<< {0:x2}", x);
				}
			}
		}
		return x;
	}

	public override int Read(byte[] buf, int off, int len)
	{
		if (len <= 0) {
			return 0;
		}
		int rlen = sub.Read(buf, off, len);
		if (log != null) {
			lock (logLock) {
				if (rlen <= 0) {
					log.WriteLine("<<< EOF");
				} else {
					log.Write("<<< ");
					Dump(buf, off, rlen);
					log.WriteLine();
				}
			}
		}
		return rlen;
	}

	protected override void Dispose(bool disposing)
	{
		if (log != null) {
			lock (logLock) {
				log.Flush();
			}
		}
		try {
			sub.Close();
		} catch {
			// ignored
		}
	}

	void Dump(byte[] buf, int off, int len)
	{
		for (int i = 0; i < len; i ++) {
			if (i != 0) {
				if ((i & 15) == 0) {
					log.WriteLine();
					log.Write("    ");
				} else if ((i & 7) == 0) {
					log.Write("  ");
				} else {
					log.Write(" ");
				}
			}
			log.Write("{0:x2}", buf[off + i]);
		}
	}
}
