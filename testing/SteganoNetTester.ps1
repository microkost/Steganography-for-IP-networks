param([string]$role = "s",                          #server or client
      [string[]]$methods = "301,303",
      [string[]]$messages = "VSB - Technical University of Ostrava has long tradition in high quality engineering.",
      [string]$ipLocal = "172.31.31.31",
      [string]$ipRemote = "172.31.31.31",
      [string]$portLocal = "11000",
      [string]$portRemote = "11011",
      [string]$serverTimeout = "60000",             #in miliSeconds
      [string]$pathToExe = "%SYSTEMDRIVE%\temp",  #where is app   
      [string]$wiresharkPath = "%SYSTEMDRIVE%:\Program Files\Wireshark"  
     )

$methods = $methods.split(",").Trim() #making array from strings
#$messages = $messages.split(",").Trim() #making array from strings

Write-Host "Runing from $pathToExe"
if($role.StartsWith("s".ToLower()))
{
    Write-Host ""
    Write-Host " @@@@@@ @@@@@@@@ @@@@@@@  @@@  @@@ @@@@@@@@ @@@@@@@  "
    Write-Host "!@@     @@!      @@!  @@@ @@!  @@@ @@!      @@!  @@@ "
    Write-Host "!@@!!  @!!!:!   @!@!!@!  @!@  !@! @!!!:!   @!@!!@!   "
    Write-Host "    !:! !!:      !!: :!!   !: .:!  !!:      !!: :!!  "
    Write-Host "::.: :  : :: ::   :   : :    ::    : :: ::   :   : : "
    Write-Host ""
}
elseif($role.StartsWith("c".ToLower()))
{
    Write-Host ""
    Write-Host " @@@@@@@ @@@      @@@ @@@@@@@@ @@@  @@@ @@@@@@@ "
    Write-Host "!@@      @@!      @@! @@!      @@!@!@@@   @!!  " 
    Write-Host "!@!      @!!      !!@ @!!!:!   @!@@!!@!   @!!  " 
    Write-Host ":!!      !!:      !!: !!:      !!:  !!!   !!:  " 
    Write-Host ":: :: : : ::.: : :   : :: ::  ::    :     :    "
    Write-Host ""
}
else
{
    Write-Error "Not valid role selection"
}

foreach ($method in $methods)
{
    $method = $method -replace ';',',' #escape script parametres passing

    foreach ($message in $messages)
    {
        Write-Host "Method $method, $role"
        Write-Host "READY for next? Press any key to continue ....."
        $HOST.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") | OUT-NULL
        $HOST.UI.RawUI.Flushinputbuffer()  #don't work in ISE!        

        #start capturing
        if ($wiresharkPath.length -ne 0) 
        {
            $interfaceName = Get-NetIPAddress -IPAddress $ipLocal | select InterfaceAlias -ExpandProperty InterfaceAlias
            Start-Process -FilePath "Wireshark.exe" -WorkingDirectory $wiresharkPath -Args "-i $interfaceName -k"
        }

        #start stego
        Start-Process -Wait -FilePath "SteganoNet.Console.exe" -WorkingDirectory $pathToExe -Args "-ip $ipLocal -port $portLocal -ipremote $ipRemote -portremote $portRemote -runsame n -message `"$message`" -role $role -methods $method -serverTimeout $serverTimeout"
        #end stego

        #end capturing manually
     }
}