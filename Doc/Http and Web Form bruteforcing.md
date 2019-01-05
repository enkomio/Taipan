# Http and Web Form bruteforcing
This AddOn allows to execute an HTTP or Web Form authentication bruteforcing. In order to do so it verify the response code (in case of HTTP bruteforcing) or use a custom heuristic in order to identify if the page returned an authenticated content or not (in case of Web Form authentication).

Under the folder _Data\AddOnStorage\Web Form Bruteforcer AddOn_ you will find three XML files (the file format is self explanatory):
  * **Combinations.xml** contains the combination of user/password to use. This is useful to test for default account
  * **Usernames.xml** contaions the list of username to bruteforce. It is suggested to not include a long list, since for each username the entire password list is used in order to bruteforce it
  * **Passwords.xml** contains the password to use in order to bruteforce all usernames 
