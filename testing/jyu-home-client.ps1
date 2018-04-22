$methodListSinle = ("301","303") #,"305","333","335","703","705","733")
$message1 = "The quick brown fox jumps over the lazy dog";

$role = "c"
$ipLocal = "10.32.182.75"
$ipRemote = "84.251.221.209"
$portLocal = "11000"
$portRemote = "11011"
$serverTimeout = "0" #in miliSeconds
$pathToExe = "C:\Users\ivo\Dropbox\Visual Studio Projects\Projects\Steganography-for-IP-networks\SteganoNet.UI.Console\bin\Release"

&".\SteganoNetTester.ps1" -role $role -methods $methodListSinle -messages $message1 -ipLocal $ipLocal -portLocal $portLocal -ipremote $ipRemote -portremote $portRemote -runsame n -pathToExe $pathToExe -serverTimeout $serverTimeout