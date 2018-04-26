$methodListIcmp = ("301","333","335","301;303;305;333;335","303;305;333;335","303;333;335","333;335","303")
$methodListDns = ("703","705","703;705","301;705","303;705")
$methodListHttp = ("733")
$message1 = ""

#assign
$methods = $methodListIcmp

$role = "s"
$ipLocal = "172.31.31.31"
$ipRemote = "172.31.31.31"
$portLocal = "11011"
$portRemote = "11000"
$serverTimeout = "0" #in miliSeconds
$pathToExe = "C:\Users\ivo\Dropbox\Visual Studio Projects\Projects\Steganography-for-IP-networks\SteganoNet.UI.Console\bin\Release"
$wiresharkPath = "C:\Program Files\Wireshark"

&".\SteganoNetTester.ps1" -role $role -methods $methods -messages $message1 -ipLocal $ipLocal -portLocal $portLocal -ipremote $ipRemote -portremote $portRemote -runsame n -pathToExe $pathToExe -serverTimeout $serverTimeout -wiresharkPath $wiresharkPath