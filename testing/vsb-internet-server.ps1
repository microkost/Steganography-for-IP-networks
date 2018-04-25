$methodListIcmp = ("301","303","333","335","301;303;305;333;335","303;305;333;335","303;333;335","333;335")
$methodListDns = ("703","705","703;705","301;705")
$methodListHttp = ("733")
$message1 = ""

#assign
$methods = $methodListDns

$role = "s"
$ipLocal = "84.251.160.115"
$ipRemote = "158.196.194.30"
$portLocal = "11011"
$portRemote = "11000"
$serverTimeout = "0" #in miliSeconds
$pathToExe = "D:\Dropbox\Visual Studio Projects\Projects\Steganography-for-IP-networks\SteganoNet.UI.Console\bin\Release"
$wiresharkPath = "C:\Program Files\Wireshark"

&".\SteganoNetTester.ps1" -role $role -methods $methods -messages $message1 -ipLocal $ipLocal -portLocal $portLocal -ipremote $ipRemote -portremote $portRemote -runsame n -pathToExe $pathToExe -serverTimeout $serverTimeout -wiresharkPath $wiresharkPath