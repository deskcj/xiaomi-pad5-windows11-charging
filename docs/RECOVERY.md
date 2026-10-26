# Recovery before any activation

Each Stage/Activate invocation requires elevated native ARM64 PowerShell and saves the current package, complete SYSTEM hive and BCD to the internal Windows volume. The JSON record names the exact original and experimental oem*.inf packages and their hashes. Activate additionally requires the recovery directory of the successful tracked Stage operation.

Activate requires an external recovery destination and copies/verifies the **fresh Activate recovery directory before changing the live binding**, so the rescue copy exists even if activation fails immediately. It aborts if the external volume is unavailable or verification fails. The initial file-only backup remains useful, but changed PnP binding requires the new full snapshot/record. Do not rely on a backup reachable only inside an unbootable Windows partition.

`Restore-ExperimentOffline.ps1` defaults to preview and refuses the running Windows. With an independently verified mounted tablet Windows partition, its Apply mode removes only the recorded newly staged package through offline DISM, restores the saved baseline package and full SYSTEM snapshot, and preserves newer state in a rescue-undo directory. BCD is preserved for reference and is not overwritten, because the installer never changes it.

Restoring SYSTEM also rolls back unrelated system configuration changes after that snapshot. Do not mix driver experiments or system updates between activation and testing. Do not guess which oem*.inf to remove; abort if package identities or hashes do not match.

Neither offline Apply nor an actual failed-boot recovery has been exercised in this release. Confirm the recovery transport first. Fastboot alone does not offer NTFS file access: use a previously verified recovery/Android/mass-storage method for this particular device. Do not format partitions or flash a generic image to recover a driver.
