using System;
using System.Collections.Generic;
using System.IO;

/*
 * Helper class to parse handshake messages.
 *
 * The constructor reads the 4-byte message header. The Open() and Close()
 * methods are used to open and close sub-structures.
 */

class HMParser {

	/*
	 * Get the message type (from the header).
	 */
	internal int MessageType {
		get {
			return messageType;
		}
	}

	/*
	 * Get the number of bytes that remain to be read from the
	 * currently opened structure.
	 */
	internal int RemainingLength {
		get {
			return remLen;
		}
	}

	/*
	 * Returns true if reading has reached the end of the currently
	 * open structure.
	 */
	internal bool EndOfStruct {
		get {
			return remLen == 0;
		}
	}

	Stream sub;
	int messageType;
	Stack<int> lengths;
	int remLen;

	/*
	 * Create the instance over the provided source stream (normally
	 * a SSLRecord instance). The message header is immediately read.
	 */
	internal HMParser(Stream sub)
	{
		this.sub = sub;
		messageType = M.Read1(sub);
		lengths = new Stack<int>();
		remLen = M.Read3(sub);
	}

	void CheckOpen()
	{
		if (sub == null) {
			throw new IOException("Message is finished");
		}
	}

	void CheckLen(int len)
	{
		CheckOpen();
		if (len > remLen) {
			throw new IOException("Read beyond structure end");
		}
	}

	/*
	 * Read exactly one byte from the message.
	 */
	internal int Read1()
	{
		CheckLen(1);
		int x = M.Read1(sub);
		remLen --;
		return x;
	}

	/*
	 * Read a 16-bit value from the message (big-endian).
	 */
	internal int Read2()
	{
		int x = Read1();
		x = (x << 8) + Read1();
		return x;
	}

	/*
	 * Read a 24-bit value from the message (big-endian).
	 */
	internal int Read3()
	{
		int x = Read1();
		x = (x << 8) + Read1();
		x = (x << 8) + Read1();
		return x;
	}

	/*
	 * Read a 32-bit value from the message (big-endian).
	 */
	internal int Read4()
	{
		int x = Read1();
		x = (x << 8) + Read1();
		x = (x << 8) + Read1();
		x = (x << 8) + Read1();
		return x;
	}

	/*
	 * Read bytes from the message. Exactly as many bytes as
	 * requested will be read.
	 */
	internal void Read(byte[] buf)
	{
		Read(buf, 0, buf.Length);
	}

	/*
	 * Read bytes from the message. Exactly as many bytes as
	 * requested will be read.
	 */
	internal void Read(byte[] buf, int off, int len)
	{
		CheckLen(len);
		M.ReadFully(sub, buf, off, len);
		remLen -= len;
	}

	/*
	 * Read 'len' bytes from the message and return them as a
	 * newly allocated array.
	 */
	internal byte[] ReadBlobFixed(int len)
	{
		byte[] buf = new byte[len];
		Read(buf);
		return buf;
	}

	/*
	 * Read some bytes from the message. The length of the
	 * element to read is supposed to be encoded in a header
	 * of length 'lengthOfLen' (in bytes).
	 */
	internal byte[] ReadBlobVar(int lengthOfLen)
	{
		int len = 0;
		while (lengthOfLen -- > 0) {
			len = (len << 8) + Read1();
		}
		return ReadBlobFixed(len);
	}

	/*
	 * Open a sub-structure. The length of that sub-structure is
	 * obtained by decoding a header of length 'lengthOfLen' bytes.
	 */
	internal void OpenVar(int lengthOfLen)
	{
		int len = 0;
		while (lengthOfLen -- > 0) {
			len = (len << 8) + Read1();
		}
		Open(len);
	}

	/*
	 * Open a sub-structure with the provided length 'len' (in bytes).
	 */
	internal void Open(int len)
	{
		CheckLen(len);
		lengths.Push(remLen - len);
		remLen = len;
	}

	/*
	 * Close the current sub-structure (or message, if no sub-structure
	 * is open). If there were some unread bytes, then an exception is
	 * thrown.
	 */
	internal void Close()
	{
		Close(false);
	}

	/*
	 * Close the current sub-structure (or message, if no
	 * sub-structure is open). If 'skipRemainder' is true, then
	 * remaining bytes in the current sub-structure are read and
	 * discarded; otherwise, if there are remaining bytes, then an
	 * exception is thrown.
	 */
	internal void Close(bool skipRemainder)
	{
		CheckOpen();
		if (remLen > 0) {
			if (!skipRemainder) {
				throw new IOException(
					"Unread data in structure");
			}
			M.Skip(sub, remLen);
		}
		if (lengths.Count == 0) {
			sub = null;
		} else {
			remLen = lengths.Pop();
		}
	}

	/*
	 * Skip remaining bytes on the current structure, but do not
	 * close it.
	 */
	internal void SkipRemainder()
	{
		CheckOpen();
		if (remLen > 0) {
			M.Skip(sub, remLen);
			remLen = 0;
		}
	}
}
