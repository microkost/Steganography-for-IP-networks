$methods = ("703") #$methods = ("301","303","333","335","703","705","733","301;303;305;333;335","703;705","301;705")
$message1 = ""

$role = "s"
$ipLocal = "172.31.31.31"
$ipRemote = "172.31.31.31"
$portLocal = "53"
$portRemote = "11000"
$serverTimeout = "0" #in miliSeconds
$pathToExe = "C:\Users\ivo\Dropbox\Visual Studio Projects\Projects\Steganography-for-IP-networks\SteganoNet.UI.Console\bin\Release"
$wiresharkPath = "C:\Program Files\Wireshark"

&".\SteganoNetTester.ps1" -role $role -methods $methods -ipLocal $ipLocal -portLocal $portLocal -ipremote $ipRemote -portremote $portRemote -runsame n -pathToExe $pathToExe -serverTimeout $serverTimeout -wiresharkPath $wiresharkPath -messages $message1