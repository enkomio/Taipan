using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

class TestSSLServer {

	static void Usage()
	{
		Console.WriteLine(
"Usage: TestSSLServer [ options ] servername [ port ]");
		Console.WriteLine(
"Options:");
		Console.WriteLine(
"  -h                print this help");
		Console.WriteLine(
"  -v                verbose operation");
		Console.WriteLine(
"  -all              exhaustive cipher suite enumeration");
		Console.WriteLine(
"  -min version      set minimum version (SSLv3, TLSv1, TLSv1.1...)");
		Console.WriteLine(
"  -max version      set maximum version (SSLv3, TLSv1, TLSv1.1...)");
		Console.WriteLine(
"  -sni name         override the SNI contents (use '-' as name to disable)");
		Console.WriteLine(
"  -certs            include full certificates in output");
		Console.WriteLine(
"  -t delay          set read timeout (in seconds) for non-SSL detection");
		Console.WriteLine(
"  -w millis         set extra delay (in milliseconds) before each connection");
		Console.WriteLine(
"  -prox name:port   connect through HTTP proxy");
		Console.WriteLine(
"  -proxssl          use SSL/TLS to connect to proxy");
		Console.WriteLine(
"  -ec               add a 'supported curves' extension for all connections");
		Console.WriteLine(
"  -noec             try connecting without a 'supported curves' extension");
		Console.WriteLine(
"  -text fname       write text report in file 'fname' ('-' = stdout)");
		Console.WriteLine(
"  -json fname       write JSON report in file 'fname' ('-' = stdout)");
		Console.WriteLine(
"  -log fname        write debug log in file 'fname' ('-' = stdout)");
		Environment.Exit(1);
	}

	static void Main(string[] args)
	{
		try {
			Process(args);
		} catch (Exception e) {
			Console.WriteLine(e.ToString());
			Environment.Exit(1);
		}
	}

	static void Process(string[] args)
	{
		FullTest ft = new FullTest();
		List<string> r = new List<string>();
		bool withCerts = false;
		string proxString = null;
		string textOut = null;
		string jsonOut = null;
		string logName = null;
		int rtm = 20000;
		int cwait = 0;
		ft.AddECExt = true;
		for (int i = 0; i < args.Length; i ++) {
			string a = args[i];
			switch (a.ToLowerInvariant()) {
			case "-h":
			case "-help":
			case "--help":
				Usage();
				break;
			case "-v":
			case "--verbose":
				ft.Verbose = true;
				break;
			case "-sni":
			case "--sni":
				if (++ i >= args.Length) {
					Usage();
				}
				ft.ExplicitSNI = args[i];
				break;
			case "-all":
			case "--all-suites":
				ft.AllSuites = true;
				break;
			case "-min":
			case "--min-version":
				if (++ i >= args.Length) {
					Usage();
				}
				ft.MinVersion = ParseVersion(args[i]);
				if (ft.MinVersion < M.SSLv20
					|| ft.MinVersion > M.TLSv12)
				{
					Usage();
				}
				break;
			case "-max":
			case "--max-version":
				if (++ i >= args.Length) {
					Usage();
				}
				ft.MaxVersion = ParseVersion(args[i]);
				if (ft.MaxVersion < M.SSLv20
					|| ft.MaxVersion > M.TLSv12)
				{
					Usage();
				}
				break;
			case "-certs":
			case "--with-certificates":
				withCerts = true;
				break;
			case "-t":
			case "--read-timeout":
				if (++ i >= args.Length) {
					Usage();
				}
				if (!Int32.TryParse(args[i], out rtm)) {
					Usage();
				}
				if (rtm <= 0) {
					rtm = -1;
				} else if (rtm > Int32.MaxValue / 1000) {
					rtm = -1;
				} else {
					rtm *= 1000;
				}
				break;
			case "-w":
			case "--wait":
				if (++ i >= args.Length) {
					Usage();
				}
				if (!Int32.TryParse(args[i], out cwait)) {
					Usage();
				}
				if (cwait <= 0) {
					cwait = 0;
				}
				break;
			case "-prox":
			case "--proxy":
				if (++ i >= args.Length) {
					Usage();
				}
				proxString = args[i];
				break;
			case "-proxssl":
			case "--proxy-ssl":
				ft.ProxSSL = true;
				break;
			case "-ec":
			case "--with-ec-ext":
				ft.AddECExt = true;
				break;
			case "-noec":
			case "--without-ec-ext":
				ft.AddECExt = false;
				break;
			case "-text":
			case "--text-output":
				if (++ i >= args.Length) {
					Usage();
				}
				textOut = args[i];
				break;
			case "-json":
			case "--json-output":
				if (++ i >= args.Length) {
					Usage();
				}
				jsonOut = args[i];
				break;
			case "-log":
			case "--log-output":
				if (++ i >= args.Length) {
					Usage();
				}
				logName = args[i];
				break;
			default:
				if (a.Length > 0 && a[0] == '-') {
					Usage();
				}
				r.Add(a);
				break;
			}
		}
		args = r.ToArray();
		if (args.Length == 0 || args.Length > 2) {
			Usage();
		}

		/*
		 * While the parameters should be a _server name_ (and
		 * optional port), some people instinctively provide an
		 * "https://" URL. We will support that case.
		 */
		string sn = args[0];
		if (sn.StartsWith("https://")) {
			sn = sn.Substring(8);
			int j = sn.IndexOf('/');
			if (j >= 0) {
				sn = sn.Substring(0, j);
			}
			j = sn.IndexOf('@');
			if (j >= 0) {
				sn = sn.Substring(j + 1);
			}
		}

		/*
		 * The "server name" might end with ':' followed by a port
		 * number (e.g. if it came for a URL, or through creative
		 * invocation from the user). However, if there are several
		 * colon characters, then we infer the server name to be
		 * an explicit IPv6 address, and we do not try to extract
		 * a port number from it.
		 */
		int sj = sn.IndexOf(':');
		if (sj >= 0 && sj < (sn.Length - 1)
			&& sn.IndexOf(':', sj + 1) < 0)
		{
			try {
				ft.ServerPort = Int32.Parse(
					sn.Substring(sj + 1));
			} catch (Exception) {
				Usage();
			}
			sn = sn.Substring(0, sj);
		}
		ft.ServerName = sn;

		/*
		 * An explicit port number overrides the port value
		 * extracted from the server name (if applicable).
		 */
		if (args.Length == 2) {
			try {
				ft.ServerPort = Int32.Parse(args[1]);
			} catch (Exception) {
				Usage();
			}
		}

		ft.ReadTimeout = rtm;
		ft.ConnectionWait = cwait;
		if (proxString != null) {
			int j = proxString.IndexOf(':');
			if (j > 0) {
				try {
					string sp = proxString
						.Substring(j + 1).Trim();
					ft.ProxPort = Int32.Parse(sp);
				} catch (Exception) {
					Usage();
				}
				ft.ProxName = proxString.Substring(0, j).Trim();
			}
		}

		/*
		 * If there is no specified output, then use stdout.
		 */
		if (textOut == null && jsonOut == null) {
			textOut = "-";
		}

		if (logName != null) {
			if (logName == "-") {
				ft.DebugLog = Console.Out;
			} else {
				ft.DebugLog = File.CreateText(logName);
			}
		}

		Report rp = ft.Run();
		rp.ShowCertPEM = withCerts;

		if (textOut != null) {
			if (textOut == "-") {
				rp.Print(Console.Out);
			} else {
				using (TextWriter w =
					File.CreateText(textOut))
				{
					rp.Print(w);
				}
			}
		}
		if (jsonOut != null) {
			if (jsonOut == "-") {
				rp.Print(new JSON(Console.Out));
			} else {
				using (TextWriter w =
					File.CreateText(jsonOut))
				{
					rp.Print(new JSON(w));
				}
			}
		}

		if (logName != null) {
			ft.DebugLog.Flush();
			if (logName != "-") {
				ft.DebugLog.Close();
			}
		}
	}

	static int ParseVersion(string vs)
	{
		vs = vs.Trim().ToLowerInvariant();
		if (vs.StartsWith("0x")) {
			vs = vs.Substring(2);
			if (vs.Length == 0) {
				return -1;
			}
			int acc = 0;
			foreach (char c in vs) {
				int d;
				if (c >= '0' && c <= '9') {
					d = c - '0';
				} else if (c >= 'a' && c <= 'f') {
					d = c - ('a' - 10);
				} else {
					return -1;
				}
				if (acc > 0xFFF) {
					return -1;
				}
				acc = (acc << 4) + d;
			}
			return acc;
		}

		if (vs.StartsWith("ssl")) {
			vs = vs.Substring(3).Trim();
			if (vs.StartsWith("v")) {
				vs = vs.Substring(1).Trim();
			}
			switch (vs) {
			case "2":
			case "20":
			case "2.0":
				return M.SSLv20;
			case "3":
			case "30":
			case "3.0":
				return M.SSLv30;
			default:
				return -1;
			}
		} else if (vs.StartsWith("tls")) {
			vs = vs.Substring(3).Trim();
			if (vs.StartsWith("v")) {
				vs = vs.Substring(1).Trim();
			}
			int j = vs.IndexOf('.');
			string suff;
			if (j >= 0) {
				suff = vs.Substring(j + 1).Trim();
				vs = vs.Substring(0, j).Trim();
			} else {
				suff = "0";
			}
			int maj, min;
			if (!Int32.TryParse(vs, out maj)
				|| !Int32.TryParse(suff, out min))
			{
				return -1;
			}
			/*
			 * TLS 1.x is SSL 3.y with y == x+1.
			 * We suppose that TLS 2.x will be encoded
			 * as SSL 4.x, without the +1 thing.
			 */
			if (maj == 1) {
				min ++;
			}
			if (maj < 1 || maj > 253 || min < 0 || min > 255
				|| (maj == 1 && min > 254))
			{
				return -1;
			}
			return ((maj + 2) << 8) + min;
		}
		return -1;
	}
}
