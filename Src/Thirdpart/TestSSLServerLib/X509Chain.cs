using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

/*
 * This class represents an X.509 certificate chain, as obtained from a
 * SSL/TLS server. Individual certificates may have failed to decode
 * properly.
 */

class X509Chain {

	/*
	 * Get the end-entity certificate. This is null if that certificate
	 * did not decode properly, or if the chain was empty.
	 */
	internal X509Cert EE {
		get {
			int n = elements.Length;
			return (n == 0) ? null : elements[n - 1];
		}
	}

	/*
	 * Get the chain elements in normal order (EE comes last).
	 * Undecodable certificates yield null values.
	 */
	internal X509Cert[] Elements {
		get {
			return elements;
		}
	}

	/*
	 * Get the chain elements in reverse order (EE comes first).
	 * Undecodable certificates yield null values.
	 */
	internal X509Cert[] ElementsRev {
		get {
			return elementsRev;
		}
	}

	/*
	 * Set to true if the chain decoded properly (non-empty, and
	 * all certificates were decoded).
	 */
	internal bool Decodable {
		get {
			return decodable;
		}
	}

	/*
	 * Set to true if all certificates were decoded and the
	 * subject/issuer names match all along the chain.
	 */
	internal bool NamesMatch {
		get {
			return goodNameChaining;
		}
	}

	/*
	 * Set to true if the chain is not empty and starts (ends, in
	 * reverse order) with an apparently self-issued certificate.
	 */
	internal bool IncludesRoot {
		get {
			return includesRoot;
		}
	}

	/*
	 * Get encoded certificates in "normal" order (EE comes last).
	 */
	internal byte[][] Encoded {
		get {
			return encoded;
		}
	}

	/*
	 * Get encoded certificates in "reverse" order (EE comes first).
	 */
	internal byte[][] EncodedRev {
		get {
			return encodedRev;
		}
	}

	/*
	 * Get certificates thumbprints in normal order (EE comes last).
	 * The thumbprint is the SHA-1 hash of the encoded certificate,
	 * expressed in uppercase hexadecimal.
	 */
	internal string[] Thumbprints {
		get {
			return thumbprints;
		}
	}

	/*
	 * Get certificates thumbprints in reverse order (EE comes first).
	 * The thumbprint is the SHA-1 hash of the encoded certificate,
	 * expressed in uppercase hexadecimal.
	 */
	internal string[] ThumbprintsRev {
		get {
			return thumbprintsRev;
		}
	}

	/*
	 * Get decoding issues (explanatory string message) for all
	 * certificates, in normal order (EE comes last). If a certificate
	 * decoded propery, then the corresponding string is null.
	 */
	internal string[] DecodingIssues {
		get {
			return decodingIssues;
		}
	}

	/*
	 * Get decoding issues (explanatory string message) for all
	 * certificates, in reverse order (EE comes first). If a certificate
	 * decoded propery, then the corresponding string is null.
	 */
	internal string[] DecodingIssuesRev {
		get {
			return decodingIssuesRev;
		}
	}

	/*
	 * This returns the list of hash algorithms used for signatures
	 * on certificates. The algorithms are returned in lexicographic
	 * order. Self-issued certificates are skipped.
	 *
	 * If some certificates failed to decode, then this property is
	 * null.
	 */
	internal string[] SignHashes {
		get {
			return signHashes;
		}
	}

	/*
	 * SHA-1 hash of the concatenation of the certificates, in reverse
	 * order; hash value is encoded in lowercase hexadecimal.
	 *
	 * Since certificates are DER-encoded, the concatenation is not
	 * ambiguous. Barring SHA-1 collisions (of which none is known
	 * right now), the hash should uniquely identify the chain.
	 */
	internal string Hash {
		get {
			return hash;
		}
	}

	bool decodable;
	X509Cert[] elements;
	X509Cert[] elementsRev;
	byte[][] encoded;
	byte[][] encodedRev;
	string[] thumbprints;
	string[] thumbprintsRev;
	string[] decodingIssues;
	string[] decodingIssuesRev;
	bool goodNameChaining;
	bool includesRoot;
	string hash;
	string[] signHashes;

	X509Chain(byte[][] encoded, byte[][] encodedRev)
	{
		this.encoded = encoded;
		this.encodedRev = encodedRev;
		int n = encoded.Length;
		elements = new X509Cert[n];
		elementsRev = new X509Cert[n];
		thumbprints = new string[n];
		thumbprintsRev = new string[n];
		decodingIssues = new string[n];
		decodingIssuesRev = new string[n];
		decodable = (n > 0);
		for (int i = 0; i < n; i ++) {
			X509Cert xc;
			string msg;
			try {
				xc = new X509Cert(encoded[i]);
				msg = null;
			} catch (Exception e) {
				xc = null;
				msg = e.Message;
				if (msg == null) {
					msg = e.GetType().FullName;
				}
				decodable = false;
			}
			elements[i] = xc;
			elementsRev[n - 1 - i] = xc;
			decodingIssues[i] = msg;
			decodingIssuesRev[n - 1 - i] = msg;
			string tt = M.DoSHA1(encoded[i]).ToUpperInvariant();
			thumbprints[i] = tt;
			thumbprintsRev[n - 1 - i] = tt;
		}
		if (decodable) {
			goodNameChaining = true;
			X509Cert lc = elementsRev[0];
			IDictionary<string, bool> sghf =
				new SortedDictionary<string, bool>(
					StringComparer.Ordinal);
			if (!lc.SelfIssued) {
				sghf[lc.HashAlgorithm] = true;
			}
			for (int i = 1; i < n; i ++) {
				X509Cert ca = elementsRev[i];
				if (!ca.SelfIssued) {
					sghf[ca.HashAlgorithm] = true;
				}
				if (!ca.Subject.Equals(lc.Issuer)) {
					goodNameChaining = false;
				}
				lc = ca;
			}
			includesRoot = lc.Subject.Equals(lc.Issuer);
			signHashes = new string[sghf.Count];
			int k = 0;
			foreach (string name in sghf.Keys) {
				signHashes[k ++] = name;
			}
		} else {
			goodNameChaining = false;
			includesRoot = false;
			signHashes = null;
		}
		hash = M.DoSHA1(encodedRev);
	}

	/*
	 * Create an instance over the provided sequence of encoded
	 * certificates. If 'reversed' is true, then the argument is
	 * expected to be in reverse order (EE comes first).
	 */
	internal static X509Chain Make(byte[][] chain, bool reversed)
	{
		int n = chain.Length;
		byte[][] chainRev = new byte[n][];
		for (int i = 0; i < n; i ++) {
			chainRev[i] = chain[n - 1 - i];
		}
		if (reversed) {
			return new X509Chain(chainRev, chain);
		} else {
			return new X509Chain(chain, chainRev);
		}
	}
}
