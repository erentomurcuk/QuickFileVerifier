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
    Script version: 1.0

    Script creator: Eren Tomurcuk (GitHub: @erentomurcuk)

    If there are bugs, please open an issue on GitHub: <https://github.com/erentomurcuk/QuickFileVerifier/issues>

    Prerequisites: PowerShell >=5.1 & GPG (if checking GPG signatures, not necessary)

    Run the .reg file in the repository to run this script from the context menu.
    Make sure that you always check ANY .reg and .ps1 file before you run one!
    
#>

param (
    [string]$filePath = $args[0]
)

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
        $signer = Get-AuthenticodeSignature -FilePath $filePath
        $signatureStatus = "Signed"
        $signerName = $signer.SignerCertificate.Subject
        $signerIssuer = $signer.SignerCertificate.Issuer
        $signatureTimestamp = $signer.SignerCertificate.NotBefore
        $serialNumber = $signer.SignerCertificate.SerialNumber
    } catch {
        $signatureStatus = "Not signed"
        $signerName = $null
        $signerIssuer = $null
        $signatureTimestamp = $null
        $serialNumber = $null
    }

    return @{
        SignatureStatus = $signatureStatus
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
    Write-Host "File: $filePath" -ForegroundColor Green
    Write-Host "`nChecking code signing..." -ForegroundColor Yellow
    
    # Get and display code signing status
    $codeSigningStatus = Get-CodeSigningStatus -filePath $filePath
    Write-Host "Code Signing Status: $($codeSigningStatus.SignatureStatus)" -ForegroundColor Cyan
    
    if ($codeSigningStatus.SignatureStatus -eq "Signed") {
        Write-Host "Signer Name: $($codeSigningStatus.SignerName)" -ForegroundColor Cyan
        Write-Host "Signer Issuer: $($codeSigningStatus.SignerIssuer)" -ForegroundColor Cyan
        Write-Host "Signature Timestamp: $($codeSigningStatus.SignatureTimestamp)" -ForegroundColor Cyan
        Write-Host "Serial Number (Fingerprint): $($codeSigningStatus.SerialNumber)" -ForegroundColor Cyan
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
    
    # Select a hash algorithm
    #Write-Host "`nSelect a hash algorithm:" -ForegroundColor Yellow
    #Write-Host "1. SHA1"
    #Write-Host "2. SHA256"
    #Write-Host "3. SHA512"
    #Write-Host "4. MD5"
    
    # Prompt user to choose a hash algorithm by number
    # $choice = Read-Host "Enter the number corresponding to the desired hash algorithm (1-4)"

    #switch ($choice) {
    #    1 { $algorithm = "SHA1" }
    #    2 { $algorithm = "SHA256" }
    #    3 { $algorithm = "SHA512" }
    #    4 { $algorithm = "MD5" }
    #    default { Write-Host "Invalid choice. Exiting." -ForegroundColor Red; exit }
    #}

    # Calculate and display the hash
    $hash = Calculate-FileHash -filePath $filePath -algorithm SHA1
    $fileSHA1Hash = $hash
    Write-Host "SHA1: $hash" -ForegroundColor Green

    $hash = Calculate-FileHash -filePath $filePath -algorithm SHA256
    $fileSHA256Hash = $hash
    Write-Host "SHA256: $hash" -ForegroundColor Blue

    $hash = Calculate-FileHash -filePath $filePath -algorithm SHA512
    $fileSHA512Hash = $hash
    Write-Host "SHA512: $hash" -ForegroundColor Cyan

    $hash = Calculate-FileHash -filePath $filePath -algorithm MD5
    $fileMD5Hash = $hash
    Write-Host "MD5: $hash" -ForegroundColor Magenta


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
            $hash = fileMD5Hash
            Write-Host "`nType is MD5" -ForegroundColor Magenta
            Write-Host "File MD5 Hash: $hash" -ForegroundColor Magenta
            Write-Host "User MD5 Hash: $userHash" -ForegroundColor Magenta
        }
        "SHA1" {
            $hash = fileSHA1Hash
            Write-Host "`nType is SHA1" -ForegroundColor Green
            Write-Host "File SHA1 Hash: $hash" -ForegroundColor Green
            Write-Host "User SHA1 Hash: $userHash" -ForegroundColor Green
        }
        "SHA256" {
            $hash = fileSHA256Hash
            Write-Host "`nType is SHA256" -ForegroundColor Blue
            Write-Host "File SHA256 Hash: $hash" -ForegroundColor Blue
            Write-Host "User SHA256 Hash: $userHash" -ForegroundColor Blue
        }
        "SHA512" {
            $hash = fileSHA512Hash
            Write-Host "`nType is SHA512" -ForegroundColor Cyan
            Write-Host "File SHA512 Hash: $hash" -ForegroundColor Cyan
            Write-Host "User SHA512 Hash: $userHash" -ForegroundColor Cyan
        }
        "!" {
            Write-Host "Skipped or invalid hash type/length. Exiting." -ForegroundColor Red
            exit
        }
    }


        if ($userHash -eq $hash) {
            Write-Host "`nHashes match! The file is verified." -ForegroundColor Green
        } else {
            Write-Host "`nHashes do not match. The file may be altered or corrupted." -ForegroundColor Red
        }
    }
} else {
    Write-Host "File not found at the specified path: $filePath" -ForegroundColor Red
}

# Pause to prevent the terminal from closing immediately
Read-Host "Press Enter to exit"
