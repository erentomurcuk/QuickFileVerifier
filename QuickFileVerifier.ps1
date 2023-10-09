<#
.DESCRIPTION

    This PowerShell script calculates the hash (checksum) of a selected file using different hash algorithms,
    including SHA-1, SHA-256, SHA-512, and MD5.
    It also checks for code signing and provides code signing information if applicable.
    Additionally, it checks if the selected file has a GPG signature file (.sig) and provides GPG signature information given that the public key is imported.
    To run the script with GPG signature information, you need to have GPG installed.

.NOTES

    Script Name: Quick File Verifier (QuickFileVerifier.ps1)
    Context menu name: Verify File with QFV

    Script creator: Eren Tomurcuk (GitHub: @erentomurcuk)

    If there are bugs, please open an issue on GitHub: <https://github.com/erentomurcuk/QuickFileVerifier/issues>

    Prerequisites: PowerShell >=5.1 & GPG (if checking GPG signatures, not necessary)

    Run the .reg file in the repository to run this script from the context menu.
    Make sure that you always check ANY .reg and .ps1 file before you run one!
    
#>

#>

param (
    [string]$filePath = $args[0],
    [switch]$version,
    [switch]$github,
    [switch]$help, 
    [switch]$toggleUpdateChecks,
    [switch]$checkForUpdates,
    [switch]$updateProgram
)

$currentVersion = "1.3"

try {
    # Get the directory where the script is located
$scriptDirectory = Split-Path -Parent $MyInvocation.MyCommand.Path

# Construct the full path to the configuration file
$configFilePath = Join-Path -Path $scriptDirectory -ChildPath "config.json"

} catch {
    Write-Host "Error occurred: Cannot find config.json" -ForegroundColor Red
}


if ($version) {
    Write-Host "Quick File Verifier $currentVersion`nCreated by Eren Tomurcuk`nGitHub: @erentomurcuk" -ForegroundColor Green
    exit
}


if ($github) {
    Write-Host "Quick File Verifier GitHub Repository: <https://github.com/erentomurcuk/QuickFileVerifier>" -ForegroundColor Green
    exit
}


if ($help) {
    Write-Host "`nThis script is for quickly checking the hash and signatures of a file either by terminal or the context menu." -ForegroundColor White

    Write-Host "`nContext Menu" -ForegroundColor Red
    Write-Host "To run the script from the context menu, edit and run the .reg file in the repository. You can find the details in the README.md file." -ForegroundColor White

    Write-Host "`nTerminal" -ForegroundColor Red
    Write-Host "Just run the script as `".\QuickFileVerifier.ps1 <File Name>`"" -ForegroundColor White

    Write-Host "`nOptions" -ForegroundColor Red
    Write-Host "You can run the script with the following switches:" -ForegroundColor White
    Write-Host "-version: Prints the version of the script." -ForegroundColor White
    Write-Host "-github: GitHub repository link of the script." -ForegroundColor White
    Write-Host "-help: Prints this help message." -ForegroundColor White
    Write-Host "-toggleUpdateChecks: Toggles whether the script checks for updates every time it is run. It is disabled by default. Can also be changed from the config file.`n" -ForegroundColor White
    Write-Host "-checkForUpdates: Checks for updates.`n" -ForegroundColor White
    Write-Host "-updateProgram: Downloads and installs the latest version of the script (Currently being tested!).`n" -ForegroundColor White

    exit

}

if ($toggleUpdateChecks) {
    try {
        $configContent = Get-Content -Path $configFilePath | ConvertFrom-Json
        $checkForUpdates = $configContent.CheckForUpdates
    } catch {
        Write-Host "Error occurred: Cannot read `"config.json`" or the CheckForUpdates variable." -ForegroundColor Red
    }
    
    if ($checkForUpdates -eq $false) {
        Write-Host "`nYou have allowed this script to check GitHub API to check whether you have the latest version." -ForegroundColor Green
        Write-Host "This script will check for updates every time you run it." -ForegroundColor White
        Write-Host "If you want to disable this, run the script with the -toggleUpdateChecks switch.`n" -ForegroundColor White
        $configContent.CheckForUpdates = $true
    } else {
        Write-Host "`nYou have disabled this script from checking GitHub API to check whether you have the latest version." -ForegroundColor Red
        Write-Host "This script will not check for updates every time you run it." -ForegroundColor White
        Write-Host "If you want to enable this, run the script with the -toggleUpdateChecks switch.`n" -ForegroundColor White
        $configContent.CheckForUpdates = $false
    }

    # Convert the updated configuration back to JSON format
    $updatedConfigJson = $configContent | ConvertTo-Json -Depth 4

    # Save the updated configuration back to the file
    $updatedConfigJson | Set-Content -Path $configFilePath
    exit
}

function CheckForUpdates {

    Write-Host "`nChecking for updates..." -ForegroundColor Yellow
    $latestVersion = Invoke-RestMethod -Uri "https://api.github.com/repos/erentomurcuk/QuickFileVerifier/releases/latest" -Method Get
    $latestVersion = $latestVersion.tag_name
    if ($latestVersion -ne $currentVersion) {
        Write-Host "There is a new version available: $latestVersion" -ForegroundColor Green
        Write-Host "You can download the latest version from: <https://github.com/erentomurcuk/QuickFileVerifier/releases>`n"
    } else {
        Write-Host "You have the latest version.`n" -ForegroundColor Green
    }
}

function Check-UpdateAllowance {

    try {
        $configContent = Get-Content -Path $configFilePath | ConvertFrom-Json
        $checkForUpdates = $configContent.CheckForUpdates
    } catch {
        Write-Host "Error occurred: Cannot read `"config.json`" or the CheckForUpdates variable." -ForegroundColor Red
    }

    if ($checkForUpdates -eq $true) {
        CheckForUpdates
    }

}

# Define the URL of the latest release zip file and the target directory
$releaseUrl = "https://github.com/erentomurcuk/QuickFileVerifier/releases/latest/download/QuickFileVerifier.zip"
$targetDirectory = Split-Path -Parent $MyInvocation.MyCommand.Path

# Function to download and extract a zip file
function Download-And-Extract {
    param (
        [string]$url,
        [string]$targetDirectory
    )
    
    # Create the target directory if it doesn't exist
    if (-not (Test-Path -Path $targetDirectory -PathType Container)) {
        New-Item -Path $targetDirectory -ItemType Directory
    }
    
    # Create a temporary file to store the downloaded zip
    $tempZipFile = [System.IO.Path]::Combine($env:TEMP, [System.Guid]::NewGuid().ToString() + ".zip")
    
    try {
        # Download the zip file
        Invoke-WebRequest -Uri $url -OutFile $tempZipFile
    
        # Extract the zip file to the target directory
        Expand-Archive -Path $tempZipFile -DestinationPath $targetDirectory -Force
    
        Write-Host "Update downloaded and extracted successfully to $targetDirectory" -ForegroundColor Green
    } catch {
        Write-Host "Failed to download or extract the update." -ForegroundColor Red
    } finally {
        # Clean up the temporary zip file
        Remove-Item -Path $tempZipFile -Force
    }
}

if ($checkForUpdates) {
    CheckForUpdates
    exit
}

if ($updateProgram) {

    Write-Host "`nThis command is being tested and may break the program. Type `"YES`" to continue." -ForegroundColor Yellow
    $continue = Read-Host

    if ($continue -eq "YES") {
        Write-Host "`nChecking for updates..." -ForegroundColor Yellow
        $latestVersion = Invoke-RestMethod -Uri "https://api.github.com/repos/erentomurcuk/QuickFileVerifier/releases/latest" -Method Get
        $latestVersion = $latestVersion.tag_name
        if ($latestVersion -ne $currentVersion) {
            Write-Host "There is a new version available: $latestVersion" -ForegroundColor Green
            Write-Host "Downloading and installing the latest version..."
            Download-And-Extract -url $releaseUrl -targetDirectory $targetDirectory
            exit
        } else {
            Write-Host "You have the latest version.`n" -ForegroundColor Green
            exit
        }
    } else {
        Write-Host "`nUpdate cancelled.`n" -ForegroundColor Red
        exit
    }

    
}

# Run the function to check for updates
Check-UpdateAllowance

# Function to check if GPG is installed
function Is-GPGInstalled {
    try {
        $gpgVersion = (gpg --version 2>&1)
        return $true
    } catch {
        return $false
    }
}

# Function to calculate the hash of a file
function Calculate-FileHash {
    param (
        [string]$filePath,
        [string]$algorithm
    )
    $hash = Get-FileHash -Path $filePath -Algorithm $algorithm
    return $hash.Hash
}

# Function to get code signing information
function Get-CodeSigningStatus {
    param (
        [string]$filePath
    )
    try {
        $signer = Get-AuthenticodeSignature -FilePath $filePath -ErrorAction Stop
        $signerName = $signer.SignerCertificate.Subject
        $signerIssuer = $signer.SignerCertificate.Issuer
        $signatureTimestamp = $signer.SignerCertificate.NotBefore
        $serialNumber = $signer.SignerCertificate.SerialNumber
    } catch {
        $signerName = $null
        $signerIssuer = $null
        $signatureTimestamp = $null
        $serialNumber = $null
    }

    return @{
        SignerName = $signerName
        SignerIssuer = $signerIssuer
        SignatureTimestamp = $signatureTimestamp
        SerialNumber = $serialNumber
    }
}

# Function to verify GPG signature
function Verify-GPGSignature {
    param (
        [string]$filePath
    )
    try {
        $signatureFilePath = "$filePath.sig"
        
        if (Test-Path -Path $signatureFilePath -PathType Leaf) {
            $result = gpg --verify $signatureFilePath $filePath 2>&1
            Write-Host "GPG Verification Output: $result" -ForegroundColor Cyan  # Log the GPG output
            
            if ($result -match "Good signature") {
                return "Signed"
            } else {
                return "Not signed correctly"
            }
        } else {
            return "No signature file found"
        }
    } catch {
        return "Error occurred during GPG signature check"
    }
}

function Get-StringLength {
    param (
        [string]$inputString
    )

    if ($inputString -ne $null) { 
        return $inputString.Length
    } else {
        Write-Output "Invalid String Length!" -ForegroundColor Red
    }
}

function Get-HashType {
    param (
        [string]$hashLength
    )

    if ($hashLength -eq $null -or $hashLength -eq "") {
        Write-Output "Invalid Hash Length!" -ForegroundColor Red
        return
    }

    switch ($hashLength) {
        32 {
            Write-Output "Hash type: MD5"
            return "MD5"
        }
        40 {
            Write-Output "Hash type: SHA-1"
            return "SHA1"
        }
        64 {
            Write-Output "Hash type: SHA-256"
            return "SHA256"
        }
        128 {
            Write-Output "Hash type: SHA-512"
            return "SHA512"
        }
        default {
            Write-Output "Unrecognized hash type. The hash length is $hashLength characters."
            return "!"
        }
    }
}

# Check if the file exists
if (Test-Path -Path $filePath -PathType Leaf) {
    Write-Host "`nFile: $filePath" -ForegroundColor Green
    Write-Host "`nChecking code signing..." -ForegroundColor Yellow
    
    # Get and display code signing status
    $codeSigningStatus = Get-CodeSigningStatus -filePath $filePath
    
    if ($codeSigningStatus.SignerName -ne $null) {
        Write-Host "Signer Name: $($codeSigningStatus.SignerName)" -ForegroundColor Cyan
        Write-Host "Signer Issuer: $($codeSigningStatus.SignerIssuer)" -ForegroundColor Cyan
        Write-Host "Signature Timestamp: $($codeSigningStatus.SignatureTimestamp)" -ForegroundColor Cyan
        Write-Host "Serial Number: $($codeSigningStatus.SerialNumber)`n" -ForegroundColor Cyan
    } else {
        Write-Host "Code signing not found.`n" -ForegroundColor Red
    }
    
    # Warn the user about GPG key import
    Write-Host "Note: If you have not imported the public key, GPG check may fail." -ForegroundColor Yellow
    
    # Check if GPG is installed
    if (Is-GPGInstalled) {
        Write-Host "`nChecking GPG signature..." -ForegroundColor Yellow
        
        # Get and display GPG signature status
        $gpgStatus = Verify-GPGSignature -filePath $filePath
        if ($gpgStatus -eq "Signed") {
            Write-Host "GPG Signature Status: $gpgStatus" -ForegroundColor Green
        } elseif ($gpgStatus -eq "Not signed correctly" -or $gpgStatus -eq "Failed") {
            Write-Host "GPG Signature Status: $gpgStatus" -ForegroundColor Red
        } else {
            Write-Host "GPG Signature Status: $gpgStatus" -ForegroundColor Yellow
        }
    } else {
        Write-Host "Error: GPG is not installed. Please install GPG to perform GPG signature checks." -ForegroundColor Red
    }


    # Calculate and display the hash
    $hash = Calculate-FileHash -filePath $filePath -algorithm MD5
    $fileMD5Hash = $hash
    Write-Host "`nMD5:    $hash" -ForegroundColor Magenta

    $hash = Calculate-FileHash -filePath $filePath -algorithm SHA1
    $fileSHA1Hash = $hash
    Write-Host "SHA1:   $hash" -ForegroundColor Green

    $hash = Calculate-FileHash -filePath $filePath -algorithm SHA256
    $fileSHA256Hash = $hash
    Write-Host "SHA256: $hash" -ForegroundColor Blue

    $hash = Calculate-FileHash -filePath $filePath -algorithm SHA512
    $fileSHA512Hash = $hash
    Write-Host "SHA512: $hash" -ForegroundColor Cyan


    # Prompt user to input their own hash for verification
    Write-Host "`nInput your own hash to compare. The script will automatically check for the correct hash type. (Press Enter to skip)"
    $userHash = Read-Host

    # Check if the user wants to compare hashes
    if ($userHash -ne "") {

        # Check the input hash length and determine the hash type

        $hashType = Get-HashType -hashLength (Get-StringLength -inputString $userHash)

    # Switch Case for printing and comparison

    switch ($hashType) {
        "MD5" {
            $hash = $fileMD5Hash
            Write-Host "`nType is MD5" -ForegroundColor Magenta
            Write-Host "File MD5 Hash: $hash" -ForegroundColor Magenta
            Write-Host "User MD5 Hash: $userHash" -ForegroundColor Magenta
        }
        "SHA1" {
            $hash = $fileSHA1Hash
            Write-Host "`nType is SHA1" -ForegroundColor Green
            Write-Host "File SHA1 Hash: $hash" -ForegroundColor Green
            Write-Host "User SHA1 Hash: $userHash" -ForegroundColor Green
        }
        "SHA256" {
            $hash = $fileSHA256Hash
            Write-Host "`nType is SHA256" -ForegroundColor Blue
            Write-Host "File SHA256 Hash: $hash" -ForegroundColor Blue
            Write-Host "User SHA256 Hash: $userHash" -ForegroundColor Blue
        }
        "SHA512" {
            $hash = $fileSHA512Hash
            Write-Host "`nType is SHA512" -ForegroundColor Cyan
            Write-Host "File SHA512 Hash: $hash" -ForegroundColor Cyan
            Write-Host "User SHA512 Hash: $userHash" -ForegroundColor Cyan
        }
        "!" {
            Write-Host "Invalid hash type/length." -ForegroundColor Red
        }
    }


        if ($userHash -eq $hash) {
            Write-Host "`nHashes match! The file is verified." -ForegroundColor Green
        } else {
            Write-Host "`nHashes do not match. The file may be altered or corrupted." -ForegroundColor Red
        }
    } else {
        Write-Host "`nSkipping hash comparison..." -ForegroundColor Yellow
    }
}

# Pause to prevent the terminal from closing immediately
Read-Host "Press Enter to exit"