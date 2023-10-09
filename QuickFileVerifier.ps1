<#
.DESCRIPTION

    This PowerShell script calculates the hash (checksum) of a selected file using different hash algorithms,
    including SHA-1, SHA-256, SHA-512, and MD5.
    It also checks for code signing and provides code signing information if applicable.
    Additionally, it checks if the selected file has a GPG signature file (.sig) and provides GPG signature information.
    To run the script with GPG signature information, you need to have GPG installed.

.NOTES

    Script Name: Quick File Verifier (QuickFileVerifier.ps1)
    Context menu name: Verify File with QFV
    Script version: 1.0

    If there are bugs, please open an issue on GitHub.

    Prerequisites: PowerShell >=5.1 & GPG (if checking GPG signatures)

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
    Write-Host "`nSelect a hash algorithm:" -ForegroundColor Yellow
    Write-Host "1. SHA1"
    Write-Host "2. SHA256"
    Write-Host "3. SHA512"
    Write-Host "4. MD5"
    
    # Prompt user to choose a hash algorithm by number
    $choice = Read-Host "Enter the number corresponding to the desired hash algorithm (1-4)"

    switch ($choice) {
        1 { $algorithm = "SHA1" }
        2 { $algorithm = "SHA256" }
        3 { $algorithm = "SHA512" }
        4 { $algorithm = "MD5" }
        default { Write-Host "Invalid choice. Exiting." -ForegroundColor Red; exit }
    }

    # Calculate and display the hash
    $hash = Calculate-FileHash -filePath $filePath -algorithm $algorithm
    Write-Host "File Hash ($algorithm): $hash" -ForegroundColor Green

    # Prompt user to input their own hash for verification
    $userHash = Read-Host "Input your own hash to compare (Press Enter to skip)"
    
    # Check if the user wants to compare hashes
    if ($userHash -ne "") {
        if ($userHash -eq $hash) {
            Write-Host "Hashes match! The file is verified." -ForegroundColor Green
        } else {
            Write-Host "Hashes do not match. The file may be altered or corrupted." -ForegroundColor Red
        }
    }
} else {
    Write-Host "File not found at the specified path: $filePath" -ForegroundColor Red
}

# Pause to prevent the terminal from closing immediately
Read-Host "Press Enter to exit"
