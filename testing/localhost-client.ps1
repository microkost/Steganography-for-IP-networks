$methodListIcmp = ("301","333","335","301;303;305;333;335","303;305;333;335","303;333;335","333;335","303")
$methodListDns = ("703","705","703;705","301;705","303;705")
$methodListHttp = ("733")
$message1 = "The quick brown fox jumps over the lazy dog";
#$message1 = "VSB - Technical University of Ostrava has long tradition in high quality engineering. Our study programmes stand on a tradition going back more than 165 years, but reflect current, state of the art technologies"

#assign
$methods = $methodListIcmp

$role = "c"
$ipLocal = "172.31.31.31"
$ipRemote = "172.31.31.31"
$portLocal = "11000"
$portRemote = "11011"
$serverTimeout = "0" #in miliSeconds
$pathToExe = "C:\Users\ivo\Dropbox\Visual Studio Projects\Projects\Steganography-for-IP-networks\SteganoNet.UI.Console\bin\Release"
$wiresharkPath = ""

&".\SteganoNetTester.ps1" -role $role -methods $methods -messages $message1 -ipLocal $ipLocal -portLocal $portLocal -ipremote $ipRemote -portremote $portRemote -runsame n -pathToExe $pathToExe -serverTimeout $serverTimeout -wiresharkPath $wiresharkPath