# Builds answer.iso containing only Autounattend.xml

$iso = "answer.iso"
$xml = "Autounattend.xml"
$temp = "$PSScriptRoot\temp-iso"

# Check if the answer file exists
if (-Not (Test-Path $xml)) {
    Write-Error "❌ Missing $xml"
    exit 1
}

# Create temporary folder
New-Item -ItemType Directory -Path $temp -Force | Out-Null

# Copy the XML file into that folder
Copy-Item $xml -Destination $temp -Force

# Path to oscdimg.exe (adjust if your ADK is in a different location)
$oscdimg = "C:\Program Files (x86)\Windows Kits\10\Assessment and Deployment Kit\Deployment Tools\amd64\Oscdimg\oscdimg.exe"

# Build the ISO
& $oscdimg -u2 -udfver102 -lANS -m $temp $iso
Write-Host "✅ Created $iso"

# Clean up temporary folder
Remove-Item

