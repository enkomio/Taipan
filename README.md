# Taipan - Web Application Security Scanner

_Taipan_ is a an automated web application scanner which allows to identify web vulnerabilities in an automatic fashion. This project is the core engine of a broader project which include other components, like a web dashboard where you can manage your scan or download a PDF report and and scanner agent to run on specific host. Below are some screenshots of the _Taipan_ dashboard:

<table>
 <tr>
  <td><img src="https://github.com/enkomio/Taipan/blob/master/Misc/Admin-info.png" width="200"></td>
  <td><img src="https://github.com/enkomio/Taipan/blob/master/Misc/Dashboard.png" width="200"></td>
  <td><img src="https://github.com/enkomio/Taipan/blob/master/Misc/Scan-details.png" width="200"></td>
 </tr>
 <tr>
  <td><img src="https://github.com/enkomio/Taipan/blob/master/Misc/Scan-summary.png" width="200"></td>
  <td><img src="https://github.com/enkomio/Taipan/blob/master/Misc/Scan-wizard.png" width="200"></td>
  <td><img src="https://github.com/enkomio/Taipan/blob/master/Misc/Settings.png" width="200"></td>
 </tr>
</table>


If you are interested in trying the full product, you can contact me at: aparata[AT]gmail.com

## Download
 - [Source code][1]
 - [Download binary][2]

## Using Taipan
_Taipan_ can run on both Windows (natively) and Linux (with mono). To run it in Linux you have to install mono in version >= 4.8.0.

### Scan Profile
_Taipan_ allow to scan the given web site by specifil different kind of profiles. Each profile enable or disable a specific scan feature, to show all the available profile just run _Taipan_ with the _--show-profiles_ option.

### Launch a scan
To launch a new scan you have to provide the _url_ and the _profile_ which must be used. It is not necessary to specify the full profile name, a prefix is enough. Below an example of execution:

<a href="https://asciinema.org/a/166362" target="_blank"><img src="https://asciinema.org/a/166362.png" /></a>


## License

.NET Core (including the coreclr repo) is licensed under the [MIT license](LICENSE.TXT).

License: GNU General Public License, version 2 or later; see LICENSE included in this archive for details.

  [1]: https://github.com/enkomio/Taipan/tree/master/Src
  [2]: https://github.com/enkomio/Taipan/releases/latest
