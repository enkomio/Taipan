### 2.0.0 - 04/11/2018
* Improved error reporting and enabled saving a txt format of the generated report
* Improved testing of multipart input, included file input
* Added integrity check when testing web form with password fields. If the values of the password fields is different there may be false negative
* Added HTTP Basic bruteforce plugin

### 1.7.0 - 06/08/2018
* Created Vulnerability Editor in order to create application vulnerabilities
* Improved system metrics generation
* Improved code to load signature by decreasing the load time
* Added more signatures and improved discovery process
* Fixed minor bug in Fingerprinter and Vulnerability Scanner
* Added web vulnerabilities
* Added support to Brotli decompression
* Updated TestSSL AddOn

### 1.6.0 - 28/03/2018
* Resolved resource leak in ChromeDriver usage
* Fixed some bugs (FPs, Mem leak, ...)
* Improved Reflected XSS AddOn
* Authentication HTTP Basic, Digest, Bearer
* Authentication via WebForm
* Adjusted versioning

### 1.2.5 - 06/02/2018
* Implemented Re-Crawling of identified web pages
* Minor bug fixes
* Added Stored Cross Site Scripting check
* Added Exposed Session Variables check

### 1.2.4 - 21/12/2017
* Added Blind SQL Injection check
* Added Missing HttpOnly cookie flag check
* Added Missing Secure cookie flag check
* Added Password sent over insecure channel check
* Added Password field with autocomplete enabled check

### 1.2.3 - 06/09/2017
* Implemented Javascript Engine
* Improved Scan information section
* Bug fixing
* Vulnerabilities added:
	- Woocommerce: Reflected XSS vulnerability in vendor_description parameter

### 1.2.2 - 25/07/2017
* Journey Scan implemented
* SQL Injection addOn
* Availability of HTML and JSON Report
* Added feature to set default value for specific parameters
* Added info on the connected Scan Managers and enabled the editing of specific properties
* Improved UX
* Improved resource discovery process
* Implemented process to satify anti-CSRF token submission during SQL Injection and Cross Site Scripting testing
* Vulnerabilities added:
	- Joomla: CVE-2015-8564, CVE-2015-8769, CVE-2016-8869, CVE-2016-8870, CVE-2016-9081, CVE-2016-9836, CVE-2017-8917
	- Wordpress: CVE-2015-2213, CVE-2016-6896, CVE-2017-9064, CVE-2017-5611, CVE-2016-7169
* Bug fixing and testing

### 1.2.0 - 22/09/2016
* Added more vulnerability AddOn checks
* Added more signatures
* General imrpovements

### 1.1.0 - 28/07/2016
* Added Crawler component
* Added vulnerability scanner component
* Added Directory Listing vulnerability addon
* Added more signature to the web application fingerprinter
* Improved hidden resource discoverer

### 1.0.0 - 10/06/2016
* First Beta Release.