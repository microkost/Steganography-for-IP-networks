## Introduction
Network steganography is approach how to invisible transfer data via IP computer network covered in datagram layers headers which are usually 
used for purposes of routing and switching to provide connectivity. This framework could **help with testing of security mechanism** via adding hidden
information to simulate steganography attack.

## Methods
* IP steganography (v4)
* ICMP steganography

## Usage
* run GUI (SteganoNet.UI.WinForms) or command line app (SteganoNet.UI.Console)
* select role of your computer (server / client)
* select network interface
* choose network parametres
* choose steganographic method             
* _prepare opposite node_
* run
* analyze result

### Command line parameters
> cmd>X:\SteganoNet.UI.Console.exe
* -role c
* -ip 192.168.1.216 
* -port 11011
* -ipremote 192.168.1.216
* -portremote 11001
* -methods: 301,302
* -runsame: n
* -message: "secret message"

## Notes
* IPv4 only
* Use in LAN or have reachable IP address to let it work properly (NAT principe)
* you need to know which steganography methods are not conflicting (you can't use px. TCP and ICMP at the same datagram)
* project is x86 platform only.

## Prerequisites
* Mandatory [install WinPcap](https://www.winpcap.org/install/default.htm) to your computer!
* If needed install library from Nuget console to downloaded Visual Studio Solution by typing ```Install-Package PcapDotNet```
* Your network driver have to be able run in promicscious mode (try Wireshark for troubleshooting)
* For testing purposes you can add localhost interface [Microsoft Loopback Adapter to Microsoft KM-TEST Loopback Adapter](https://technet.microsoft.com/en-us/library/cc708322(v=ws.10).aspx) and set ip address for that interface from private IPv4 address range (px. 172.31.31.31)

## Disclaimer
* Do not use this software to illegal activity! 
* Developed for academic purposes as Master Thesis at [VŠB - Technical University of Ostrava](https://www.vsb.cz/en/)
