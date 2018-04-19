# TCP/IP network steganography framework

[![standard-readme compliant](https://img.shields.io/badge/readme%20style-standard-brightgreen.svg?style=flat-square)](https://github.com/microkost/Steganography-for-IP-networks)

Network steganography is approach how to invisible transfer data via IP computer network covered in datagram layers headers which are usually 
used for purposes of routing and switching to provide connectivity. This framework could **help with testing of security mechanism** via adding hidden
information to simulate steganography attack.


## Table of Contents
- [Methods](#Methods)
- [Install](#install)
- [How to run](#How-to-run)
    - [Console parameters](#Command-line-parameters)
- [Usage](#usage)
	- [Technical description](https://github.com/microkost/Steganography-for-IP-networks/blob/master/MethodDescription.txt)
- [Limitations](#Limitations)
- [Developer](#Developer)
- [Disclaimer and License](#Disclaimer)


## Methods
* IP steganography (v4)
* ICMP steganography
* TCP steganography
* DNS steganography
* HTTP steganography

Detailed information about used fields at headers and techniques in [technical description](https://github.com/microkost/Steganography-for-IP-networks/blob/master/MethodDescription.txt)


## Install
* Mandatory [install WinPcap](https://www.winpcap.org/install/default.htm) to your computer
* System library .Net Framework 4.6.1 and newer (Windows 10 native)
* Your network driver have to be able run in promicscious mode (try Wireshark for troubleshooting)
* For testing purposes you can add localhost interface [Microsoft Loopback Adapter to Microsoft KM-TEST Loopback Adapter](https://technet.microsoft.com/en-us/library/cc708322(v=ws.10).aspx) and set ip address for that interface from private IPv4 address range (px. 172.31.31.31)


### How to run
Compiled "click & run" files are in folder [Releases](https://github.com/microkost/Steganography-for-IP-networks/tree/master/Releases)
### Build
* Download solution and open in Visual Studio as standard projekt 
* Download solution and build it from command line
```sh
MsBuild.exe SteganographyFramework.sln /t:Build /m 
```


## Usage
* run command line app (SteganoNet.UI.Console)
  * select role of your computer (server / client)
  * select network interface
  * choose network parametres
  * choose steganographic method             
  * _prepare opposite node_
  * run
  * analyze result
* run GUI (SteganoNet.UI.WinForms) 
  * current WinForms GUI is _quite_ experimental
### Command line parameters
> cmd>X:\SteganoNet.UI.Console.exe
* -role c
* -ip 192.168.1.216
* -port 11011
* -ipremote 192.168.1.217
* -portremote 11001
* -methods: 301,703
* -runsame: n
* -serverTimeout: 60000
* -message: "secret message"


## Limitations
* IPv4 only
* Use in LAN or have reachable IP address to let it work properly (NAT principe)
* you need to **know which** steganography methods **are not conflicting** (you can't use ICMP and DNS simultaneously)
* project is x86 platform
* makes troubles on Virtual Machine - libraries missing (VmWare troubles, Azure/Hyper-V troubles, VirtualBox OK)


## Developer
* New methods of existing protocols needed be implemented only in [SteganoNet.Lib/NetSteganography.cs](https://github.com/microkost/Steganography-for-IP-networks/blob/master/SteganoNet.Lib/NetSteganography.cs)
* If needed install library from Nuget console by typing ```Install-Package PcapDotNet```


## Future ideas
* more methods - anytime
* multiplatformity by converting to .NetCore, now dependent on [PcapDotNet](https://github.com/PcapDotNet/Pcap.Net/) framework lock.
* improve [console wizard](https://medium.com/@tonerdo/a-better-keyboard-input-experience-for-net-console-apps-73a24f09cd0e) for humans
* there is no dynamic settings for timers and other constant public values


## Disclaimer
* Do not use this software to illegal activity! 
* Developed for academic purposes as Master Thesis at [VŠB - Technical University of Ostrava](https://www.vsb.cz/en/)
### Licence
* Creative Commons BY-NC-SA
