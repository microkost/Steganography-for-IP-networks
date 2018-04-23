$methodListSinle = ("333","335","703","705","703;705")
$message1 = ""

$role = "s"
$ipLocal = "84.251.221.209"
$ipRemote = "85.76.2.159"
$portLocal = "53"
$portRemote = "11000"
$serverTimeout = "0" #in miliSeconds
$pathToExe = "D:\Dropbox\Visual Studio Projects\Projects\Steganography-for-IP-networks\SteganoNet.UI.Console\bin\Release"
$wiresharkPath = "C:\Program Files\Wireshark"

&".\SteganoNetTester.ps1" -role $role -methods $methodListSinle -messages $message1 -ipLocal $ipLocal -portLocal $portLocal -ipremote $ipRemote -portremote $portRemote -runsame n -pathToExe $pathToExe -serverTimeout $serverTimeout -wiresharkPath $wiresharkPath