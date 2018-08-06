using System;
using System.IO;
using System.Threading;

/*
 * This class implements a read timeout over an arbitrary stream. The
 * actual read operation is performed in another thread.
 *
 * We use this class instead of NetworkStream's inherent timeout support
 * for two reasons:
 *
 *  1. We want to distinguish between a read timeout and other kinds of
 *     error; NetworkStream just throws a basic IOException on timeout
 *     (at least so says the documentation).
 *
 *  2. When we implement more extensive proxy support, the stream we
 *     are working with might be something else than a NetworkStream.
 */

class RTStream : Stream {

	/*
	 * Read timeout is expressed in milliseconds; a negative value
	 * means "no timeout" (read blocks indefinitely).
	 */
	internal int RTimeout {
		get {
			return readTimeout;
		}
		set {
			readTimeout = value;
		}
	}

	Stream sub;
	int readTimeout;
	Thread reader;
	object readerLock;
	byte[] oneByte;
	byte[] readBuf;
	int readOff;
	int readLen;

	/*
	 * Create an instance over the provided stream (normally a
	 * network socket).
	 */
	internal RTStream(Stream sub)
	{
		this.sub = sub;
		oneByte = new byte[1];
		readerLock = new object();
		readBuf = null;
		readTimeout = -1;
		reader = new Thread(ReadWorker);
		reader.IsBackground = true;
		reader.Start();
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
	}

	public override void Write(byte[] buf, int off, int len)
	{
		sub.Write(buf, off, len);
	}

	public override int ReadByte()
	{
		if (Read(oneByte, 0, 1) == 1) {
			return (int)oneByte[0];
		} else {
			return -1;
		}
	}

	public override int Read(byte[] buf, int off, int len)
	{
		if (readTimeout < 0) {
			return sub.Read(buf, off, len);
		}
		if (len < 0) {
			throw new ArgumentException();
		}
		if (len == 0) {
			return 0;
		}
		if (reader == null) {
			return 0;
		}
		lock (readerLock) {
			readBuf = buf;
			readOff = off;
			readLen = len;
			Monitor.PulseAll(readerLock);
			long lim = DateTime.UtcNow.Ticks
				+ (long)readTimeout * (long)10000;
			for (;;) {
				if (readBuf == null) {
					return readLen;
				}
				long now = DateTime.UtcNow.Ticks;
				if (now >= lim) {
					break;
				}
				long wtl = (lim - now) / (long)10000;
				int wt;
				if (wtl <= 0) {
					wt = 1;
				} else if (wtl > (long)Int32.MaxValue) {
					wt = Int32.MaxValue;
				} else {
					wt = (int)wtl;
				}
				Monitor.Wait(readerLock, wt);
			}

			reader.Abort();
			reader = null;
			throw new ReadTimeoutException();
		}
	}

	protected override void Dispose(bool disposing)
	{
		if (reader != null) {
			reader.Abort();
			reader = null;
		}
		try {
			sub.Close();
		} catch {
			// ignored
		}
	}

	void ReadWorker()
	{
		try {
			for (;;) {
				byte[] buf;
				int off, len;
				lock (readerLock) {
					while (readBuf == null) {
						Monitor.Wait(readerLock);
					}
					buf = readBuf;
					off = readOff;
					len = readLen;
				}
				len = sub.Read(buf, off, len);
				lock (readerLock) {
					readBuf = null;
					readLen = len;
					Monitor.PulseAll(readerLock);
				}
			}
		} catch (Exception e) {
			if (e.GetBaseException() is ThreadAbortException) {
				Thread.ResetAbort();
			}
			lock (readerLock) {
				readBuf = null;
				readLen = 0;
				Monitor.PulseAll(readerLock);
			}
			return;
		}
	}
}
