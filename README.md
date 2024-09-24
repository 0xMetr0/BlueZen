# BlueZen

Welcome to the culmination of my quest to not raise a finger when setting up for blue team competitions like HiveStorm and CCDC. BlueZen is a comprehensive PowerShell script designed for Windows system administrators and cybersecurity professionals. It provides a suite of tools and functions for system auditing, security hardening, and threat detection. Halfway through creating this I realized that its just the open-source bazzaro world version of Commando-vm by Mandiant and I'm here for it.
BlueZen is currently working on the following server versions:
    - Windows Server 2022
    - Windows Server 2019
    - Windows Server 2016
    - Windows Server 2012 R2

## Features

- **Quick Footprinting**: Analyze system components, network connections, and security settings.
- **Active Directory Hardening**: BlueZen provides a suite of tools primarily geared towards securing Active Directory enviroments but can help secure regular servers.
- **DOD GPOs**: Allows you to get an already hardened group policy. 

## Requirements
- PowerShell 5.1
- PowerShell as an Administrator
- Windows Defender should be disabled for 

## Usage
1. Download the script file (`MJ.ps1`) to your desired location.
1. Open PowerShell as an **Administrator** 
2. Allow the script by either running ```Get-ExecutionPolicy -Scope Unrestricted``` or copy the code into your own .ps1 file.
3. Navigate to the directory containing the script.
2. Run the script using the following command:
   ```
   .\MJ.ps1
   ```
3. Follow the on-screen menu to select and execute desired functions.


# BlueZen Menu Structure

```
Main Menu
├── 1. List Audit Functions
│   ├── 1. Find Duplicate DLLs
│   ├── 2. Test Internet Connection
│   ├── 3. Get PowerShell History
│   ├── 4. Get Installed Programs
│   ├── 5. Get Firewall Status
│   ├── 6. Get Windows Defender Status
│   ├── 7. Get Network Connections
│   ├── 8. Get Non-Ephemeral Ports in Use
│   ├── 9. Run all Audits
│   └── 10. Back to Main Menu
│
├── 2. List Tool Functions
│   ├── 1. Harden Kitty
│   │   ├── 1. Install HardeningKitty
│   │   ├── 2. Run Audit
│   │   ├── 3. Run Config
│   │   ├── 4. Run Default Hardening Kitty
│   │   ├── 5. Run Backup
│   │   ├── 6. Run HailMary
│   │   └── 7. Back to Tool Menu
│   │
│   ├── 2. Install PersistenceSniper
│   ├── 3. Install BlueSpawn
│   ├── 4. Install PingCastle
│   ├── 5. Chainsaw Functions
│   │   ├── 1. Install Chainsaw
│   │   ├── 2. Hunt Using Sigma Rules
│   │   ├── 3. SRUM Analysis
│   │   ├── 4. ShimCache Analysis
│   │   ├── 5. Event Log Searching
│   │   └── 6. Back to Tool Menu
│   │
│   ├── 6. Fail2Ban4Win Functions
│   │   ├── 1. Install Fail2Ban4Win
│   │   ├── 2. Configure Fail2Ban4Win
│   │   ├── 3. Run Fail2Ban4Win
│   │   └── 4. Back to Tool Menu
│   │
│   ├── 7. Install APTHunter
│   ├── 8. Install CobaltStrikeScan
│   ├── 9. Install DeepBlue
│   └── 10. Back to Main Menu
│
├── 3. List Utility Functions
│   ├── 1. Install Sysmon
│   ├── 2. Install Python3
│   ├── 3. Get Sysinternals
│   ├── 4. Install LAPS
│   ├── 5. Create A Restore Point
│   ├── 6. Create Backup Admin
│   ├── 7. Download all tools
│   ├── 8. Run all safe functions
│   ├── 9. Toggle Rainbow Output
│   └── 10. Back to Main Menu
│
├── 4. Let the DOD Handle GPOs
├── 5. Run All Functions
└── 6. Exit
```

## Important Notes

- I don't know what I am doing :3
- Many functions require administrative privileges. Always run the script as an administrator.
- This script is not safe and will not prevent you from bricking your system if you dont understand what you are running.
- Ensure you comply with the licensing terms of the various third-party tools
- Internet connection is required to download and run third-party tools.
- BlueSpawn is known to trigger most antivirus's so you may need to turn it off before downloading it
- The DOD GPOs will change your Administrators name to x_Admin the next time you log into the machine.

## Future Plans

Future plans and improvements are noted in comments in the script and have not been formally collected but some will be listed here:
- Automatically add BlueSpawns signiture to Windows Defender
- Create a rapid log enabling function
- Module support??
- Add a configuration file
- Add Fail2Ban4Win back in
- Create a more comprehensive system audit:
    - Full net scan
    - Everything AD (users, groups, group policy etc.)
    - User Privledges
    - Run smarter commands to avoid common obfuscation techniques

## Disclaimer

This script is provided "as is" without warranty of any kind. Use at your own risk. Always test in a non-production environment before using in critical systems.

## Contributing

Contributions to improve the script or add new features are welcome. Please submit pull requests or open issues on the project's repository.

## Credit
Aldaviva - Fail2Ban4Win
ION28 - BLUESPAWN
Apr4h - CobaltStrikeScan 
ahmedkhlief - APT-Hunter 
SANS Blue Team - DeepBlueCLI
Netwrix - PingCastle
last0x00 and dottoe_morte - PersistanceSniper
------------------------------------
This post was created by the Shadow Wizard PowerShell Gang
