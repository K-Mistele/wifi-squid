# Invoke-WifiSquid
A powershell tool to decrypt DPAPI-encrypted WiFi Passwords. This tool _must_ be run as `NT Authority\System`. Use Psexec I guess.

## How it Works
This is a 10,000 foot overview that I typed up very quickly - check out my medium blog kylemistele.medium.com for a full write-up. Link here: https://kylemistele.medium.com/dumping-stored-enterprise-wifi-credentials-with-invoke-wifisquid-5a7fe76f800

### WPA-PSK Passwords
* WPA-PSK network passwords are stored in subdirectories of `C:\programdata\Microsoft\Wlansvc\Profiles\Interfaces`
* the passwords are encrypted using the DPAPI's `CryptProtectData` function with the Local Machine Key, and can be decrypted by the `NT AUTHORITY\SYSTEM` user using the DPAPI's `CryptUnprotectData` function once they are parsed from the XML

### WPA2-Enterprise Credentials
* these are a lot harder - each user's WPA2-Enterprise Network Credentials are stored in their registry
* the credentials are stored as large binary blobs, and are protected with `CryptProtectData` with the Local Machine Key. These can be decrypted by the `NT AUTHORITY\SYSTEM` user.
* once decrypted, we get a large binary blob that has to be further parsed out to get the username, the domain name, and the encyrpted password
* the password is encrypted again with the `CryptProtectData` function, and can _only_ be decrypted by the user it belongs to 
* we can use a cleverly set-up powershell scheduled task to execute commands as the target user, so:
  * write the encrypted password to disk in a binary file
  * schedule a task to read the binary file, decrypt it, and write the plaintext password out to disk
  * sleep while we wait for the task to run, then read the password from disk
  * clean up

Then, once we grab and decrypt all the credentials we can, print them out and exit. 

## TODO
* rewrite it so everything is nice and readable (some syntax is inconsistent and the script is a mess - I'm not a big powershell guy and was kind of lazy)
* add more error handling because why not
* add command line arguments for generating output file
* 