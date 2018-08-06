using System;
using System.IO;

/*
 * A helper class used to write variable-length elements in handshake
 * messages. The instance is created with the maximum length for the
 * data, from which the size of the header is computed. Data is
 * accumulated by writing to it (it is a Stream). When the list is
 * finished, use ToArray() to get the complete list with its header.
 *
 * The 'Length' property qualifies the amount of data _excluding_ the
 * list header.
 */

class HList : Stream {

	MemoryStream data;
	long maxDataLen;
	int llen;

	internal HList(int maxLen)
	{
		if (maxLen <= 0) {
			throw new ArgumentException("Invalid maximum length");
		} else if (maxLen <= 0xFF) {
			llen = 1;
		} else if (maxLen <= 0xFFFF) {
			llen = 2;
		} else if (maxLen <= 0xFFFFFF) {
			llen = 3;
		} else {
			llen = 4;
		}
		maxDataLen = (long)maxLen + (long)llen;
		data = new MemoryStream();
		for (int i = 0; i < llen; i ++) {
			data.WriteByte(0);
		}
	}

	public override bool CanRead { get { return false; } }
	public override bool CanSeek { get { return false; } }
	public override bool CanWrite { get { return true; } }
	public override long Length {
		get {
			return data.Length - (long)llen;
		}
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

	public override void Flush()
	{
	}

	public override void WriteByte(byte b)
	{
		if (data.Length >= maxDataLen) {
			throw new ArgumentException("List size exceeded");
		}
		data.WriteByte(b);
	}

	public void Write(byte[] buf)
	{
		Write(buf, 0, buf.Length);
	}

	public override void Write(byte[] buf, int off, int len)
	{
		if (maxDataLen - data.Length < (long)len) {
			throw new ArgumentException("List size exceeded");
		}
		data.Write(buf, off, len);
	}

	public override int ReadByte()
	{
		throw new NotSupportedException();
	}

	public override int Read(byte[] buf, int off, int len)
	{
		throw new NotSupportedException();
	}

	internal byte[] ToArray()
	{
		byte[] buf = data.ToArray();
		int len = buf.Length - llen;
		for (int j = llen - 1; j >= 0; j --) {
			buf[j] = (byte)len;
			len >>= 8;
		}
		return buf;
	}
}
