# Implements a new Luca script to fingerprint web applications
The identification of a given Web Application is done through two diferent processes. The first one is signature based and the second one is via custom LUA script. It is possible to add new script by following some simple guidelines.

All LUA scripts are stored in **Data\Scripts\<language>** folder. Inside this folder there are the script that identify a specific directory. Each script is sotred in afolder with the same name as the identified application. For example the LUA script to fingerprint Wordpress is stored in the folder: **Data\Scripts\Php\Wordpress**.

To create a new script is necessary to create a new application folder insider the corresponding *language folder*. There are two files that must be defined, the first one is the descriptor file, which is an XML file that describe the script. Find below the script for theWordpress application:

    <LuaScriptSignature>
      <Id>10BEAE33-CAC7-4862-BD07-9E42A12258E6</Id>
      <ApplicationName>Wordpress</ApplicationName>
      <TargetLanguage>Php</TargetLanguage>
    </LuaScriptSignature>

The parameters meaning are: 
   * **Id** is a GUID and if the identifier of the script
   * **ApplicationName** The application name that is identified. This name will be displayed in the result report
   * **TargetLanguage** The language that was used to develop the application. For Wordpress is PHP
   
 WIP
