# Run an authenticated Scan

By modifiying the profile file, it is possible to create an authenticated scan. To do this there are thre possibility:

* Add to Taipan an authenticated cookie
* Configure an HTTP Basic/Digest authentication
* Configure a Bearer (token based) authentication
* Configure the HTTP request that must be done in order to automatically authenticate to a web form login

## Add an authenticated cookie
This method is probably the easier one. The first step is to obtain a cookie that was authenticated. In order to do you can login into your web application and the nextract the value of the coookie that was returned by server in order to identify your session. To grab the cookie you can use one the many available HTTP proxy.

Once that you have the cookie you have to modify the given scan profile. In the profile you have to identify the XML element **AdditionalCookies** which is a children of the XML element **HttpRequestorSettings**. Once identified you have to add a new XML child named **Cookie** with two other children named **Name** and **Value**. An example of configuration is the following:

    <AdditionalCookies>
        <Cookie>
            <Name>Cookie Name</Name>
            <Value>Cookie Value</Value>
        </Cookie>
    </AdditionalCookies>
    
Once done that, *Taipan* will send the configured cookie in all its requests.
