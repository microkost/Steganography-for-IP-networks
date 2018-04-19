#-stego-config-
#$methodListSinle = ("301","303","305","333","335","703","705","733")
$methodListSinle = ("301")
$methodListCombination = ("305,333","333,703","333,335","301,303,305","305,705","703,705","333,733")
$message1 = "The quick brown fox jumps over the lazy dog";
$message2 = "VSB - Technical University of Ostrava has long tradition in high quality engineering. Our study programmes stand on a tradition going back more than 165 years, but reflect current, state of the art technologies.";
$messages = ($message1) #list of messages

#-config-zone--
$ipLocal = "172.31.31.31"
$ipRemote = "172.31.31.31"
$portLocal = "11011"
$portRemote = "11000"
$serverTimeout = "60000" #in miliSeconds
$pathToExe = "C:\github\Steganography-for-IP-networks\SteganoNet.UI.Console\bin\Release"

#--------------

$role = "client"
Write-Host ""
Write-Host "@@@@@@@ @@@      @@@ @@@@@@@@ @@@  @@@ @@@@@@@ "
Write-Host "!@@      @@!      @@! @@!      @@!@!@@@   @!!  " 
Write-Host "!@!      @!!      !!@ @!!!:!   @!@@!!@!   @!!  " 
Write-Host ":!!      !!:      !!: !!:      !!:  !!!   !!:  " 
Write-Host ":: :: : : ::.: : :   : :: ::  ::    :     :    "
Write-Host ""


#LOWER ARE ONLY PARAMS

#try {
#    Write-Host "READY to transmitt? Press any key to continue ....."
#    $x = $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") #don't work in ISE!
#}catch{}

foreach ($method in $methodListSinle)
{
    foreach ($message in $messages)
    {
        Write-Host "Method $method, $role, message: $message"
        Start-Process -Wait -FilePath "SteganoNet.Console.exe" -WorkingDirectory $pathToExe  -Args "-ip $ipLocal -port $portLocal -ipremote $ipRemote -portremote $portRemote -runsame n -message `"$message`" -role $role -methods $method"
        
        Write-Host "READY for next? ($role) Press any key to continue ....."
        $HOST.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") | OUT-NULL
        $HOST.UI.RawUI.Flushinputbuffer()  #don't work in ISE!        
     }
}