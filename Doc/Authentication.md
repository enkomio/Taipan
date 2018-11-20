# Run an authenticated Scan

By modifiying the profile file, it is possible to create an authenticated scan. There are various kind of Authentication:

* Add to Taipan an authenticated cookie
* Configure an HTTP Basic/Digest authentication
* Configure a Bearer (token based) authentication
* Web form authentication

## Add an authenticated cookie
This method is probably the easier one. The first step is to obtain a cookie that was authenticated. In order to do you can login into your web application and then extracts the value of the coookie that was returned by server in order to identify your session. To grab the cookie you can use one the many available HTTP proxy.

Once that you have the cookie you have to modify the given scan profile. In the profile you have to identify the XML element **AdditionalCookies** which is a children of the XML element **HttpRequestorSettings**. Once identified you have to add a new XML child named **Cookie** with two other childrens named **Name** and **Value**. An example of configuration is the following:

    <AdditionalCookies>
        <Cookie>
            <Name>Cookie Name</Name>
            <Value>Cookie Value</Value>
        </Cookie>
    </AdditionalCookies>
    
If you need more than one cookie for the authentication just add more **Cookie** elements to the **AdditionalCookies** element. Once done that, *Taipan* will send the configured cookie in all its requests.

## Configure an HTTP Basic/Digest authentication
To configure an HTTP Basic/Digest authentication is necessary to modify the used scan profile. You have to identify the XML element **AuthenticationInfo** which is a children of the XML element **HttpRequestorSettings**. Once identified you have to add the childrens **Type**, **Username** and **Password**, where *Type* must assume the value **Basic** or **Digest**. All the other items must be empty. An example of configuration is the following:

    <AuthenticationInfo>
        <Type>Basic</Type>
        <Username>admin</Username>
        <Password>admin</Password>
        <Token></Token>
        <Enabled>true</Enabled>
        <LoginPattern />
        <LogoutPattern />
        <DynamicAuthParameterPatterns />
    </AuthenticationInfo>
    
## Configure a Bearer (token based) authentication
To configure an Bearer authentication (also known as token based authentication) is necessary to modify the used scan profile. You have to identify the XML element **AuthenticationInfo** which is a children of the XML element **HttpRequestorSettings**. Once identified you have to add the childrens **Type** and **Token**, where *Type* must assume the value **Bearer**. All the other items must be empty. An example of configuration is the following:

    <AuthenticationInfo>
        <Type>Bearer</Type>
        <Username></Username>
        <Password></Password>
        <Token>1234567890qwertyuiop</Token>
        <Enabled>true</Enabled>
        <LoginPattern />
        <LogoutPattern />
        <DynamicAuthParameterPatterns />
    </AuthenticationInfo>
    
## Web form authentication
