$methodListSingle = ("733") #"733" #"301","303","333","335"
$methodListCombi = ("301;303;305;333;335","703;705") #"301;733"
$message1 = ""

$role = "s"
$ipLocal = "10.211.232.125"
$ipRemote = "10.211.232.80"
$portLocal = "80"
$portRemote = "11000"
$serverTimeout = "0" #in miliSeconds
$pathToExe = "C:\Users\ivo\Dropbox\Visual Studio Projects\Projects\Steganography-for-IP-networks\SteganoNet.UI.Console\bin\Release"
$wiresharkPath = "C:\Program Files\Wireshark"

&".\SteganoNetTester.ps1" -role $role -methods $methodListSingle -messages $message1 -ipLocal $ipLocal -portLocal $portLocal -ipremote $ipRemote -portremote $portRemote -runsame n -pathToExe $pathToExe -serverTimeout $serverTimeout -wiresharkPath $wiresharkPath