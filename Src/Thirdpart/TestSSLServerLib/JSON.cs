using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

/*
 * A simple class to output a JSON file.
 */

class JSON {

	TextWriter w;
	Stack<bool> state;
	bool firstElement;

	internal JSON(TextWriter w)
	{
		this.w = w;
		state = new Stack<bool>();
		firstElement = true;
	}

	void CheckInObject()
	{
		if (state.Count == 0 || state.Peek()) {
			throw new ArgumentException("Not in an object");
		}
	}

	void CheckInArray()
	{
		if (state.Count == 0 || !state.Peek()) {
			throw new ArgumentException("Not in an array");
		}
	}

	void NewLine()
	{
		if (!firstElement) {
			w.Write(",");
		}
		firstElement = false;
		w.WriteLine();
		for (int n = state.Count; n > 0; n --) {
			w.Write("  ");
		}
	}

	internal void AddPair(string name, bool val)
	{
		CheckInObject();
		NewLine();
		w.Write("{0} : {1}", Encode(name), Encode(val));
	}

	internal void AddPair(string name, long val)
	{
		CheckInObject();
		NewLine();
		w.Write("{0} : {1}", Encode(name), Encode(val));
	}

	internal void AddPair(string name, string val)
	{
		CheckInObject();
		NewLine();
		w.Write("{0} : {1}", Encode(name), Encode(val));
	}

	internal void OpenPairObject(string name)
	{
		CheckInObject();
		NewLine();
		w.Write("{0} : {{", Encode(name));
		state.Push(false);
		firstElement = true;
	}

	internal void OpenPairArray(string name)
	{
		CheckInObject();
		NewLine();
		w.Write("{0} : [", Encode(name));
		state.Push(true);
		firstElement = true;
	}

	internal void AddElement(bool val)
	{
		CheckInArray();
		NewLine();
		w.Write("{0}", Encode(val));
	}

	internal void AddElement(long val)
	{
		CheckInArray();
		NewLine();
		w.Write("{0}", Encode(val));
	}

	internal void AddElement(string val)
	{
		CheckInArray();
		NewLine();
		w.Write("{0}", Encode(val));
	}

	internal void OpenElementObject()
	{
		CheckInArray();
		NewLine();
		w.Write("{");
		state.Push(false);
		firstElement = true;
	}

	internal void OpenElementArray()
	{
		CheckInArray();
		NewLine();
		w.Write("[");
		state.Push(true);
		firstElement = true;
	}

	internal void OpenInit(bool array)
	{
		if (state.Count != 0) {
			throw new ArgumentException("Not in starting state");
		}
		w.Write("{0}", array ? "[" : "{");
		state.Push(array);
		firstElement = true;
	}

	internal void Close()
	{
		if (state.Count == 0) {
			throw new ArgumentException("No open object/array");
		}
		bool ns = state.Pop();
		w.WriteLine();
		for (int i = state.Count; i > 0; i --) {
			w.Write("  ");
		}
		if (ns) {
			w.Write("]");
		} else {
			w.Write("}");
		}
		firstElement = false;

		/*
		 * If closing the top element, add a newline.
		 */
		if (state.Count == 0) {
			w.WriteLine();
		}
	}

	static string Encode(bool val)
	{
		return val ? "true" : "false";
	}

	static string Encode(long val)
	{
		return val.ToString();
	}

	static string Encode(string val)
	{
		if (val == null) {
			return "null";
		}
		StringBuilder sb = new StringBuilder();
		sb.Append("\"");
		foreach (char c in val) {
			switch (c) {
			case '\t':
				sb.Append("\\t");
				break;
			case '\n':
				sb.Append("\\n");
				break;
			case '\r':
				sb.Append("\\r");
				break;
			case '"':
				sb.Append("\\\"");
				break;
			case '\\':
				sb.Append("\\\\");
				break;
			default:
				if (c >= 32 && c <= 126) {
					sb.Append(c);
				} else {
					sb.AppendFormat("\\u{0:X4}", (int)c);
				}
				break;
			}
		}
		sb.Append("\"");
		return sb.ToString();
	}
}
