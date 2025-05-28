$vbox = "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe"

$vm   = "IT390R-Win10"
$iso  = "C:\ISO Folder\en-us_windows_10_consumer_editions_version_22h2_x64_dvd_8da72ab3.iso"
$ans  = "$PSScriptRoot\answer.iso"
$disk = "$env:TEMP\Win10-$env:USERNAME.vdi"

# Step 1: Remove old VM and disk
& $vbox unregistervm $vm --delete 2>$null
Remove-Item $disk -Force -ErrorAction SilentlyContinue

# Step 2: Create VM and storage
& $vbox createvm --name $vm --ostype Windows10_64 --register
& $vbox modifyvm $vm --memory 3072 --cpus 2 --ioapic on --boot1 dvd
& $vbox createhd --filename $disk --size 40000 --variant Standard
& $vbox storagectl $vm --add sata --name "SATA"

# Step 3: Attach disk and ISOs
& $vbox storageattach $vm --storagectl "SATA" --port 0 --type hdd     --medium $disk
& $vbox storageattach $vm --storagectl "SATA" --port 1 --type dvddrive --medium $iso
& $vbox storageattach $vm --storagectl "SATA" --port 2 --type dvddrive --medium $ans

# Step 4: Boot headless
& $vbox startvm $vm --type headless
Write-Host "✅ VM $vm started. Installation will complete in ~8 minutes."


