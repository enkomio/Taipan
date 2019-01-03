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
   
## Global vars
In order to report to Taipan the Application that was identified and its version, the script must set a couple of global vars that will be later used by the Taipan scanner. Each script must return a _Boolean_ result after its execution. The result meaning is:

* True: if the script was able to identify a given application version
* False: otherwise

If the script is able to identify the application, the version must be placed in a global vaiables named *appVersion*.

The format of this variable must be compliant to the <a href="https://semver.org/">Semantic Version</a> standard. For a sample of LUA script take a look at the <a href="https://github.com/enkomio/Taipan/blob/master/Src/ES.Taipan.Fingerprinter/Lua/Php/Joomla/joomla.lua">Joomla fingeprintg script</a>.

