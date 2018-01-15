using System;

/*
 * This exception is thrown when a fatal alert is received from the
 * peer. While such an alert kills the connection, it also confirms
 * that a SSL/TLS server is indeed running at the designated address
 * and port.
 */

class SSLAlertException : Exception {

	internal int Alert {
		get {
			return alert;
		}
	}

	int alert;

	internal SSLAlertException(int alert)
	{
		this.alert = alert;
	}
}
