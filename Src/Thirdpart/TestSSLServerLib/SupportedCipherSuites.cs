using System;
using System.Collections.Generic;

public class SupportedCipherSuites {

    public int[] Suites {
		get {
			return suites;
		}
		set {
			suites = value;
		}
	}

    public bool PrefClient {
		get {
			return prefClient;
		}
		set {
			prefClient = value;
		}
	}

    public bool PrefServer {
		get {
			return prefServer;
		}
		set {
			prefServer = value;
		}
	}

    public bool KXReuseDH {
		get {
			return kxReuseDH;
		}
		set {
			kxReuseDH = value;
		}
	}

    public bool KXReuseECDH {
		get {
			return kxReuseECDH;
		}
		set {
			kxReuseECDH = value;
		}
	}

	int[] suites;
	bool prefClient;
	bool prefServer;
	bool kxReuseDH;
	bool kxReuseECDH;

    public SupportedCipherSuites(int[] suites)
	{
		this.suites = suites;
		prefClient = false;
		prefServer = false;
		kxReuseDH = false;
		kxReuseECDH = false;
	}

    /*
	 * Among the supported cipher suites, get the list of suites
	 * that are known to use elliptic curves for the key exchange.
	 */
    public int[] GetKnownECSuites()
	{
		List<int> r = new List<int>();
		foreach (int s in suites) {
			CipherSuite cs;
			if (!CipherSuite.ALL.TryGetValue(s, out cs)) {
				continue;
			}
			if (cs.IsECDHE) {
				r.Add(s);
			}
		}
		return r.ToArray();
	}

    public bool Equals(SupportedCipherSuites scs)
	{
		if (scs == null) {
			return false;
		}
		if (prefClient != scs.prefClient
			|| prefServer != scs.prefServer)
		{
			return false;
		}
		if (kxReuseDH != scs.kxReuseDH
			|| kxReuseECDH != scs.kxReuseECDH)
		{
			return false;
		}
		return M.Equals(suites, scs.suites);
	}

    public static bool Equals(
		SupportedCipherSuites scs1, SupportedCipherSuites scs2)
	{
		if (scs1 == scs2) {
			return true;
		}
		if (scs1 == null || scs2 == null) {
			return false;
		}
		return scs1.Equals(scs2);
	}
}
