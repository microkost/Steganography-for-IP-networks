$methodListSingle = ("733") #"733" #"301","303","333","335"
$methodListCombi = ("301;303;305;333;335", "703;705") #"301;733"
$message1 = "The quick brown fox jumps over the lazy dog";
$message2 = "VSB - Technical University of Ostrava has long tradition in high quality engineering. Our study programmes stand on a tradition going back more than 165 years, but reflect current, state of the art technologies."

#specify
$message = $message1
$methods = $methodListSingle

$role = "c"
$ipLocal = "10.211.232.80"
$ipRemote = "10.211.232.125"
$portLocal = "11000"
$portRemote = "80"
$serverTimeout = "0" #in miliSeconds
$pathToExe = "C:\Users\ivo\Dropbox\Visual Studio Projects\Projects\Steganography-for-IP-networks\SteganoNet.UI.Console\bin\Release"
$wiresharkPath = ""

&".\SteganoNetTester.ps1" -role $role -methods $methods -messages $message -ipLocal $ipLocal -portLocal $portLocal -ipremote $ipRemote -portremote $portRemote -runsame n -pathToExe $pathToExe -serverTimeout $serverTimeout -wiresharkPath $wiresharkPath