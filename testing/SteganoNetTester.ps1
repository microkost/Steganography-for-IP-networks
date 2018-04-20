param([string]$role = "s",                          #server or client
      [string[]]$methods = "301,303",
      [string[]]$messages = "VSB - Technical University of Ostrava has long tradition in high quality engineering.",
      [string]$ipLocal = "172.31.31.31",
      [string]$ipRemote = "172.31.31.31",
      [string]$portLocal = "11000",
      [string]$portRemote = "11011",
      [string]$serverTimeout = "60000",             #in miliSeconds
      [string]$pathToExe = "%SYSTEMDRIVE%\temp"  #where is app     
     )

$methods = $methods.split(",").Trim() #making array from strings
$messages = $messages.split(",").Trim() #making array from strings

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
    Write-Host "@@@@@@@ @@@      @@@ @@@@@@@@ @@@  @@@ @@@@@@@ "
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

Write-Host "Run from $pathToExe"

foreach ($method in $methods)
{
    foreach ($message in $messages)
    {
        Write-Host "Method $method, $role"
        Write-Host "READY for next? Press any key to continue ....."
        $HOST.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") | OUT-NULL
        $HOST.UI.RawUI.Flushinputbuffer()  #don't work in ISE!        

        #start capturing
        Start-Process -Wait -FilePath "SteganoNet.Console.exe" -WorkingDirectory $pathToExe -Args "-ip $ipLocal -port $portLocal -ipremote $ipRemote -portremote $portRemote -runsame n -message `"$message`" -role $role -methods $method -serverTimeout $serverTimeout"
        #end capturing
     }
}