function Get-Banner{
    $banners = @({Get-DefaultBanner},{Get-MetroBanner},{Get-BabyBanner},{Get-WashereBanner})
    $randomBanner = Get-Random -InputObject $banners
    & $randomBanner
}
function Get-WashereBanner{
    Write-Words "
                            ,,,
                           (o o)
            -----------oOO--( )--OOo-----------                 
               _____ _         _____            
              | __  | |_ _ ___|__   |___ ___    
              | __ -| | | | -_|   __| -_|   |   
             _|_____|_|___|___|_____|___|_|_|   
            | | | |___ ___   |  |  |___ ___ ___ 
            | | | | .'|_ -|  |     | -_|  _| -_|
            |_____|__,|___|  |__|__|___|_| |___|"}
                                        
    
                                        
    
function Get-BabyBanner {
    Write-Words "                                                                 
              ,=''=,
             c , _, {
             /\  @  )                __
            /  ^~~^\          <=.,__/ '}=
           (_/ ,, ,,)          \_ _>_/~
            ~\_(/-\)'-,_,_,_,-'(_)-(_)  -Naughty
           __      __   ___ __     ___  __  __ ___         
          |__) /\ |__)||__ /__    |__ ||__)/__  |          
          |__)/~~\|__)||___.__/   |   ||  \.__/ |          
      __  ___ ______     __  ___    __  __  __   __ ___
     |  \|__ |__|__ |\ |/__ |__    /__ /   |__)||__) | 
     |__/|___|  |___| \|.__/|___   .__/\__,|  \||    |  
         ______  _               ______             
         | ___ \| |             |___  /             
         | |_/ /| | _   _   ___    / /   ___  _ __  
         | ___ \| || | | | / _ \  / /   / _ \| '_ \ 
         | |_/ /| || |_| ||  __/./ /___|  __/| | | |
         \____/ |_| \__,_| \___|\_____/ \___||_| |_|"
} 
function Get-DefaultBanner{
    Write-Words -ForegroundColor DarkYellow "                       _oo0oo_"
    Write-Words -ForegroundColor DarkYellow "                      o8888888o"
    Write-Words -ForegroundColor DarkYellow "                      88`" . `"88"
    Write-Words -ForegroundColor DarkYellow "                      (| -_- |)"
    Write-Words -ForegroundColor DarkYellow "                      0\  =  /0"
    Write-Words -ForegroundColor DarkYellow "                    ___/`----'\___"
    Write-Words -ForegroundColor DarkYellow "                  .' \\|     |// '."
    Write-Words -ForegroundColor DarkYellow "                 / \\|||  :  |||// \"
    Write-Words -ForegroundColor DarkYellow "                / _||||| -:- |||||- \"
    Write-Words -ForegroundColor DarkYellow "               |   | \\\  -  /// |   |"
    Write-Words -ForegroundColor DarkYellow "               | \_|  ''\---/''  |_/ |"
    Write-Words -ForegroundColor DarkYellow "               \  .-\__  '-'  ___/-. /"
    Write-Words -ForegroundColor DarkYellow "             ___'. .'  /--.--\  `. .'___"
    Write-Words -ForegroundColor DarkYellow "          .`"`" '<  `.___\_<|>_/___.' >' `"`"."
    Write-Words -ForegroundColor DarkYellow "         | | :  `- \`.;`\ _ /`;.`/ - ` : | |"
    Write-Words -ForegroundColor DarkYellow "         \  \ `_.   \_ __\ /__ _/   .-` /  /"
    Write-Words -ForegroundColor DarkYellow "     =====`-.____`.___ \_____/___.-`___.-'====="
    Write-Words -ForegroundColor DarkYellow "                       `=---='"
    Write-Words "         ____  _              ______          "
    Write-Words "        |  _ \| |            |___  /          "
    Write-Words "        | |_) | |_   _  ___     / / ___ _ __  "
    Write-Words "        |  _ <| | | | |/ _ \   / / / _ \ '_ \ "
    Write-Words "        | |_) | | |_| |  __/  / /_|  __/ | | |"
    Write-Words "        |____/|_|\__,_|\___| /_____\___|_| |_|"
}
function Get-MetroBanner {
    Write-Host "
                                      :@.                                                               
                                    =@#  @@@@+#@@@@@@   @@@@@@=                                         
                                    @@                         @@@@                                     
                                   @@                              @                                    
                                  @@                               @@                                   
                                +@@                                 @@                                  
                               @@@                                  @@                                  
                              @@@                                    @                                  
                              @@                                    @@                                  
                             @@                                     @@                                  
                             @@                                     @@                                  
                             @@                                     @@                                  
                            #@@@@@@@@@@@@@@@@@@@@@@@@@@             @@                                  
                            @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@                                  
        =@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@:@                                 
         @@@@@@@                                       .    #@@@@@@@@ @  @@@*@@:                        
             @@@@@@@#                                                   @@@@@.  .@@@@@                  
                    @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@=@@@@@@@@#              @                 
                           @@@@@@@-     @@@@@@@@@+     @@@@@@ = @  @@@@-             .@                 
                          @*@ @@@@       @@@@@@@         @-   @    @@@=    =@@@@@@@@@:                  
                         @@ @ @@%        @@   @@         @.   @   @@@@:::::     #@@@@@@                 
                      @@@@@ @ @@@        ..   +@        @@    :@#  @@@     @@@@@@@#    @@@@@            
                    %@@  @*-@@@@.@     @@@   @ @@@@@@@@@*     :@ : @@     @:    @          @@*          
                  :@@:   @:-@+@@      = @@   @@ @@           @@: @@@@   @@    +@              @@@       
               :@@#      @@.@ *@       @@     @  @@         @=@  %@@@@  @    @@  .@@@@@@@@@@=    @:     
             @@@:        -@=@  @        @@@@%@@            @ @%  @@ @   @@@@@@  @:                @@    
            .@       =@@@@@@@*  @@@@@@@@@@@@@@@@@@         %+@ @ @ =-          @@                  @@%  
           @@    @@@@@@  @@@@@@*    :@@        @@@ %      @ @@@@@@ . @         @                    @@  
         @@*    @    @@@@    @     @@@@        :=@@       =+@ @ @@ #   *       @                     @= 
        @@      @    @@@@    @ @@@@* @@@  @@@@@@#@       @ +@ @@@#@ @*@-       @                     @@ 
       @@       @@@@@@@@@@@@@@@#      #@@@+       @@      @@@.@@ @@            @                    @@% 
      @@          @@@@    @          @@@@          @@    @ @.@@@@@          @                   %@@@@@  
     #@           @@@@@*           @@@@@            @@ @@ @@ @@ @@@       @ @=              @@@@    @@  
     @             @   @@@@@@@@@@@@@@                #@@@#@@  @* @ @#     @ @+ @    @@@@@:          @   
    @@              @@@%                                @@@@@@@# @  @      @@@@                    @.   
    @@             @@ @@@@@@@@@                          @@ @@@@.@ @       #@                     @@    
    @@             @@   *@@  . @@@@                      @@   @@@@         @@                    @@     
    @@            @@       =@@@    @@@                   @@     @@     @@@@@                     @      
    @@            @@    %      @@@   @@                 @@        -@@# :@ @                     @       
    @@            @      =@@@@@+:@@@@@@@@@@@@@:        @@             @@@@@                    @        
    @@           #@     @@           @@   %@@  @@@    @@                #@@@@                 @@        
    @@           @@   @@@ @@@@@@@@@@@       @@       @@                      #@@@            -@         
    @@           @@  @@@ @@@@@@@@@@           @@@   @@                           @@          @@         
    @@           @@          @@@                @@@@@                              @#       @@          
    @@           @@@        :@@=@               @                                          @@           
    @@          .@  @@@@@@@@@*+@                 @@                                        @            
    @@          @@            .@                   @@                                     @@            
    @@          @@            :@                     @@                                   @             
    @@          @             .@*                     @@                                 @%             
    @@          @              @                        @@                              @@              
    @%         @@              @                          @@                           @@               
   =@          @               @                           @@                          @                
   :@          @               @=                            %@@                      @#                
    @         @=              @@=                               @@                  +@                  
    @         @               @@                                  @@@              @@                   
    @#        @              #@@                                     @@@         @@                     
    @@       @=              @@@                                         @@@@= @@@                      
    @@       @               @@                                               =                         
    @@                       @@                                                                         
     @                      @@@                                                                         
     @                     @@@                                                                          
     @                     @@                                                                           
     @@                  #@# 
      =@*               @@                                                                              
        @@            +@: 
          @@@@@@@@@@@@%"
Write-Words "
  _____  __  __     __                       __  __      _ 
 |_   _|/ _| \ \   / /                      |  \/  |    | | 
   | | | |_   \ \_/ /__  _   _ _ __   ____  | \  / | ___| |_ _ __ ___  
   | | |  _|   \   / _ \| | | | '_ \ / _  | | |\/| |/ _ \ __| '__/ _ \ 
  _| |_| |      | | (_) | |_| | | | | (_| | | |  | |  __/ |_| | | (_) |
 |_____|_|      |_|\___/ \__,_|_|_|_|\__, | |_|  |_|\___|\__|_|  \___/ 
 |  __ \            ( ) |   |__   __| __/ |     | |   \ \   / /
 | |  | | ___  _ __ |/| |_     | |_ _|___/ _ ___| |_   \ \_/ /__  _   _ 
 | |  | |/ _ \| '_ \  | __|    | | '__| | | / __| __|   \   / _ \| | | |
 | |__| | (_) | | | | | |_     | | |  | |_| \__ \ |_     | | (_) | |_| |
 |_____/_\___/|_| |_|__\__|    |_|_|  _\__,_|___/\__| _ _|_|\___/ \__,_|
 |  _ \| |          |___  /           \ \        / (_) | |
 | |_) | |_   _  ___   / / ___ _ __    \ \  /\  / / _| | |
 |  _ <| | | | |/ _ \ / / / _ \ '_ \    \ \/  \/ / | | | |              
 | |_) | | |_| |  __// /_|  __/ | | |    \  /\  /  | | | |
 |____/|_|\__,_|\___/_____\___|_|_|_|  __ \/  \/   |_|_|_|
  / ____| |               | |   \ \   / /  
 | (___ | |__   ___   ___ | |_   \ \_/ /__  _   _ 
  \___ \| '_ \ / _ \ / _ \| __|   \   / _ \| | | |
  ____) | | | | (_) | (_) | |_     | | (_) | |_| |                      
 |_____/|_| |_|\___/ \___/ \__|    |_|\___/ \__,_| 
"
    
}

function Get-NonEphemeralPortsInUse {
    <#
    .SYNOPSIS
    Gathers all assignable ports, displays them, and outputs them to a file
    
    .DESCRIPTION
    Long description
    
    .NOTES
    Windows 2012 R2 currently doesn't like this implimentation 
    #>
    Write-Words "Gathering Ports..."
    $nonEphemeralPortRange = 1..49151
    $tcpConnections = Get-NetTCPConnection
    $udpConnections = Get-NetUDPEndpoint
    $usedPorts = @()
    $tcpConnections | ForEach-Object {if ($nonEphemeralPortRange -contains $_.LocalPort) {$usedPorts += $_.LocalPort}}
    $udpConnections | ForEach-Object {
        if ($nonEphemeralPortRange -contains $_.LocalPort) { 
            $usedPorts += $_.LocalPort 
        } 
    }
    $usedPorts = $usedPorts | Sort-Object -Unique
    $usedPorts.GetType()
    $filePath = "$MainFolderPath\Log\Portinspection.txt"
    Set-Content -Path $filePath -Value $usedPorts
    Write-Words "Ports in Use:"
    Write-Words $usedPorts
    Write-Words "List of non-ephemeral ports currently in use has been saved to $filePath"
}
function Enforce-GPO{
    <#
    .SYNOPSIS
    Downloads the DOD STIG GPOs and allows users to select which policy to apply to the machine.
    
    .NOTES
    This script currently statically downloads the April 2024.
    This script currently automatically downloads and applies the GPO.
    #>
    if ([System.IO.File]::Exists("$MainFolderPath\U_STIG_GPO_Package.zip" -eq $false)){ 
        Invoke-WebRequest "https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_STIG_GPO_Package_April_2024.zip" -Out "$MainFolderPath\U_STIG_GPO_Package.zip"
    }
    Expand-Archive -Path "$MainFolderPath\U_STIG_GPO_Package.zip" -Destination "$MainFolderPath\U_STIG_GPO_Package" -Force
    Import-Module GroupPolicy
    $serverVersions = @("Windows Server 2012", "Windows Server 2016", "Windows Server 2019", "Windows Server 2022")
    $versionChoice = $null
    while ($null -eq $versionChoice) {
        Write-Words "Select a Windows Server version:"
        for ($i = 0; $i -lt $serverVersions.Length; $i++) {
            Write-Words "$($i + 1). $($serverVersions[$i])"
        }

        $versionInput = Read-Host "Enter the number of your choice"
        if ($versionInput -match '^[1-4]$') { $versionChoice = $serverVersions[$versionInput - 1]} 
        else { Write-Words "Invalid choice, please try again." -ForegroundColor Red }
    }
    $UserVersionChoice = switch ($versionChoice) {
        "Windows Server 2012" { "DoD WinSvr 2012 R2 MS and DC V3R7" }
        "Windows Server 2016" { "DoD WinSvr 2016 MS and DC V2R8" }
        "Windows Server 2019" { "DoD WinSvr 2019 MS and DC V2R9" }
        "Windows Server 2022" { "DoD WinSvr 2022 MS and DC V1R5" }
    }
    $userSettings = @("MS User", "MS Computer", "DC User", "DC Computer")
    $settingChoice = $null
    while ($null -eq $settingChoice) {
        Write-Words "Select a user/computer setting (User Backups Not Available for 2022 Servers):"
        for ($i = 0; $i -lt $userSettings.Length; $i++) {Write-Words "$($i + 1). $($userSettings[$i])"}
        $settingInput = Read-Host "Enter the number of your choice"
        if ($settingInput -match '^[1-4]$') {$settingChoice = $userSettings[$settingInput - 1]} 
        else { Write-Words "Invalid choice, please try again." -ForegroundColor Red}
    }
    $gpoVersionPath = Join-Path -Path $MainFolderPath -ChildPath "U_STIG_GPO_Package\$UserVersionChoice\GPOs"
    $displayNames = @()
    $cutdisplayNames = @()
    $folderName = @()
    Get-ChildItem -Path $gpoVersionPath -Directory | ForEach-Object {
        $folderName += $_
        $folderPath = $_.FullName
        $backupFilePath = Join-Path -Path $folderPath -ChildPath "Backup.xml"
        if (Test-Path -Path $backupFilePath) {
            [xml]$xmlContent = Get-Content -Path $backupFilePath
            $displayName = $xmlContent.GroupPolicyBackupScheme.GroupPolicyObject.GroupPolicyCoreSettings.DisplayName.'#cdata-section'
            $displayNames += $displayName
        } else {Write-Words "Backup.xml not found in $folderPath" -ForegroundColor Yellow}
    }
    $pattern = '\b(\w+)\s+STIG\s+(\w+)\b'# Pattern to match the word before STIG, STIG itself, and the word after STIG
    foreach ($str in $displayNames) {
        if ($str -match $pattern) {  
            $beforeSTIG = $matches[1]; $afterSTIG = $matches[2]
            $result = "$beforeSTIG STIG $afterSTIG"
            $cutdisplayNames += $result
        } else { Write-Words "No match found in: $str" -ForegroundColor Red}
    }
    $UserSettingChoice = switch ($settingChoice) {
        "MS User" { "MS STIG User" }
        "MS Computer" { "MS STIG Comp" }
        "DC User" { "DC STIG User" }
        "DC Computer" { "DC STIG Comp" }
    }
    $counter = 0
    $settingsfolder = $null
    foreach ($Name in $cutdisplayNames){
        if($UserSettingChoice -eq $Name){
            $folderName[$counter]
            $settingsfolder = $folderName[$counter]
        }
        $counter++
    }
    $settingsId  = $settingsfolder -replace '[{}]', ''
    $gpoBackupPath = Join-Path -Path $MainFolderPath -ChildPath "U_STIG_GPO_Package\$UserVersionChoice\GPOs\"
    Write-Words "GPO Backup Path: $gpoBackupPath"
    
    $gpoName = $versionChoice + "_" + $settingChoice; Write-Words "The GPO will be named $gpoName"
    # Check if the specified GPO already exists
    $existingGpo = Get-GPO -Name $gpoName -ErrorAction SilentlyContinue
    if ($existingGpo) {
        Write-Words -ForegroundColor Yellow  "GPO '$gpoName' already exists. Importing settings from the backup."
        Import-GPO -BackupId $settingsId -Path $gpoBackupPath -TargetName "$gpoName" -CreateIfNeeded
    } else {
        Write-Words -ForegroundColor Yellow "GPO '$gpoName' does not exist. Creating and importing settings from the backup."
        New-GPO -Name $gpoName; 
        Import-GPO -BackupId $settingsId -Path "$gpoBackupPath" -TargetName "$gpoName"
    }
    Write-Words "GPO import completed successfully."
   
    $domainName = (Get-ADDomain).DistinguishedName # Get the domain name
    $gpo = Get-GPO -Name $gpoName -ErrorAction SilentlyContinue # Check if the specified GPO exists
    if (-not $gpo) { Write-Words "GPO '$gpoName' does not exist."; exit}
    try {New-GPLink -Name $gpoName -Target $domainName -Enforced Yes -LinkEnabled Yes; Write-Words -ForegroundColor Green "GPO '$gpoName' has been linked to the domain and enforced successfully."}
    catch {Write-Words "Failed to link and enforce GPO '$gpoName': $_"}
}
function Test-InternetConnection {
    Write-Words "Searching for a Connection..."
    $logFile = "$MainFolderPath\Log\InternetTest.txt"
    try {
        $connection = Test-Connection -ComputerName google.com -Count 1 -ErrorAction Stop
        if ($connection.StatusCode -eq 0) {Add-Content -Path $logFile -Value "Internet connection: Available"}
        Write-Words "---------------------------------------------"
        if ($connection.StatusCode -eq 0) {Write-Words -ForegroundColor Green "Internet connection: Available"}
        Write-Words "---------------------------------------------"
    } catch {
        Add-Content -Path $logFile -Value "Internet connection: Not available"
        Write-Words -ForegroundColor Red "Internet connection: Not available"
    }
}
function Get-PowerShellHistory {
    $logFile = "$MainFolderPath\Log\PowerShellHistory.txt"
    if (Get-Command -Name Get-History -ErrorAction SilentlyContinue) {
        $psHistory = Get-History
        Add-Content -Path $logFile -Value "PowerShell History:"
        $psHistory | ForEach-Object { Add-Content -Path $logFile -Value $_.CommandLine }
        Write-Words "These dumbasses left this in the PowerShell History:"
        Write-Words "----------------------------------------------------"
        $psHistory | ForEach-Object { Write-Words $_.CommandLine }
    } else {
        Add-Content -Path $logFile -Value "PowerShell history is not available."
        Write-Words -ForegroundColor Red "PowerShell history is not available."
    }
}
function Get-InstalledPrograms {
    $logFile = "$MainFolderPath\Log\InstalledPrograms.txt"
    if (-not (Test-Path -Path $logFile)) {New-Item -Path $logFile -ItemType File | Out-Null}
    Clear-Content -Path $logFile -Force
    "Installed Programs:" | Out-File -FilePath $logFile -Append
    $programs = Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*, HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* |
                Select-Object DisplayName,PSChildName,DisplayVersion, Publisher, InstallDate
    $programs | ForEach-Object {
        $programInfo = 
        "----------------------------
Name: $($_.DisplayName)
PSChildName: $($_.PSChildName)
Version: $($_.DisplayVersion)
Publisher: $($_.Publisher)
Install Date: $($_.InstallDate)"
        $programInfo | Out-File -FilePath $logFile -Append
        Write-Words $programInfo
    }
}
function Get-FirewallStatus {
    Write-Words "Checking Firewall Status..."
    $logFile = "$MainFolderPath\Log\FirewallStatus.txt"

    $firewallProfiles = Get-NetFirewallProfile -Profile Domain,Public,Private
    $firewallStatus = $firewallProfiles.Enabled -contains 1

    if ($firewallStatus) {
        Add-Content -Path $logFile -Value "Firewall: Enabled"
        Write-Words -ForegroundColor Green "Firewall: Enabled"
    } else {
        Add-Content -Path $logFile -Value "Firewall: Disabled"
        Write-Words -ForegroundColor Red "Firewall: Disabled"
        try {
            $firewallProfiles | ForEach-Object { Set-NetFirewallProfile -Profile $_.Name -Enabled True }
            $firewallStatusAfter = (Get-NetFirewallProfile -Profile Domain,Public,Private).Enabled -contains 1
            
            if ($firewallStatusAfter) {
                Add-Content -Path $logFile -Value "Firewall has been successfully enabled."
                Write-Words -ForegroundColor Green "Firewall has been successfully enabled."
            } else {
                Add-Content -Path $logFile -Value "Failed to enable the firewall. Please check your permissions and settings."
                Write-Words -ForegroundColor Red "Failed to enable the firewall. Please check your permissions and settings."
            }
        } catch {
            # Catch any errors that occur during the operation
            Add-Content -Path $logFile -Value "Failed to enable the firewall due to an error: $_"
            Write-Words -ForegroundColor Red "Failed to enable the firewall due to an error: $_"
        }
    }
}
function Get-WindowsDefenderStatus {
    $logFile = "$MainFolderPath\Log\WindowsDefender.txt"
    $defenderStatus = Get-MpComputerStatus
    if ($defenderStatus.AntivirusEnabled -eq $true) {
        Write-Words -ForegroundColor Green "Windows Defender is enabled."
        Add-Content -Path $logFile -Value "Windows Defender is enabled."
    } else {
        Write-Words -ForegroundColor Yellow "Windows Defender is disabled. Attempting to enable it..."
        Add-Content -Path $logFile -Value "Windows Defender is disabled. Attempting to enable it..."
        try {
            Set-MpPreference -DisableRealtimeMonitoring $false
            Start-Service -Name "WinDefend"
            $defenderStatus = Get-MpComputerStatus
            if ($defenderStatus.AntivirusEnabled -eq $true) {
                Add-Content -Path $logFile -Value "Windows Defender has been successfully enabled."
                Write-Words -ForegroundColor Green "Windows Defender has been successfully enabled."
            } else {
                Add-Content -Path $logFile -Value "Failed to enable Windows Defender. Status remains disabled."
                Write-Words -ForegroundColor Red "Failed to enable Windows Defender. Status remains disabled."
            }
        } catch {
            Write-Words -ForegroundColor Red "An error occurred while attempting to enable Windows Defender:"
            Write-Words -ForegroundColor Red $_.Exception.Message
            Add-Content -Path $logFile -Value "An error occurred while attempting to enable Windows Defender:"
            Add-Content -Path $logFile -Value $_.Exception.Message
        }
    }
}
function Get-NetworkConnections {
    $FileName = "$MainFolderPath\Log\NetworkConnections.txt"
    $connections = Get-NetTCPConnection
    Write-Words " TCP Network Connections:" | Out-File -FilePath $FileName
    Write-Words "Network Connections:"
    $connections | ForEach-Object {
        $process = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
        if ($process) {
            Write-Words "
            Protocol: TCP
            Local Address: $($_.LocalAddress):$($_.LocalPort)
            Remote Address: $($_.RemoteAddress):$($_.RemotePort)
            State: $($_.State)
            Program: $($process.Name)
            Program Path: $($process.Path)
            ============================================="
            "Protocol: TCP
            Local Address: $($_.LocalAddress):$($_.LocalPort)
            Remote Address: $($_.RemoteAddress):$($_.RemotePort)
            State: $($_.State)
            Program: $($process.Name)
            Program Path: $($process.Path)
            =============================================" | Out-File -FilePath $FileName -Append
        } else {
            "Unable to retrieve process information for PID $($_.OwningProcess)" | Out-File -FilePath $FileName -Append
            Write-Words -ForegroundColor Red "Unable to retrieve process information for PID $($_.OwningProcess)"
        }
    }
}
function Find-DuplicateDLLs {
    $OutputFile = "$MainFolderPath\Log\DuplicateDLLs.txt"
    if (Test-Path $OutputFile) {Remove-Item $OutputFile} # Clear output file if it exists
    # Function to get DLLs loaded by a process
    function Get-LoadedDLLs {
        param ($Process)
        try {$processModules = Get-Process -Id $Process.Id -ErrorAction Stop | Select-Object -ExpandProperty Modules -ErrorAction Stop | Select-Object -Property FileName; return $processModules.FileName} 
        catch {Write-Verbose "Could not retrieve modules for process $($Process.Id): $_"; return @()}
    }
    $processes = Get-Process # Get all running processes
    $dllPaths = @{} # Hash table to store DLLs and their paths
    $dllProcesses = @{} # Hash table to store DLLs and the processes using them
    Write-Words "Finding Loaded DLLs..."
    foreach ($process in $processes) {
        $dlls = Get-LoadedDLLs -Process $process

        foreach ($dll in $dlls) {
            $dllName = [System.IO.Path]::GetFileName($dll)
            if (-not $dllPaths.ContainsKey($dllName)) {
                $dllPaths[$dllName] = @()
                $dllProcesses[$dllName] = @()
            }
            $dllPaths[$dllName] += $dll
            $dllProcesses[$dllName] += $process.Name
        }
    }
    Write-Words "Checking for DLLs in multiple locations..."
    foreach ($dll in $dllPaths.Keys) {
        if ($dllPaths[$dll].Count -gt 1) {
            Add-Content -Path $OutputFile -Value "DLL: $dll"
            foreach ($path in $dllPaths[$dll]) {
                Add-Content -Path $OutputFile -Value "    Location: $path"
            }
            Add-Content -Path $OutputFile -Value "    Used by processes: $($dllProcesses[$dll] -join ', ')"
        }
    }
    Write-Words "Duplicate DLL locations have been written to $OutputFile"
}




Function Get-HardeningKittyFunction{
    function Show-HKMenu {
        Write-Words "
    =======================================================
    |           Hardening Kitty Functions Menu            |
    =======================================================
    |  1. Install the Damn Thing                          |
    |  2. Run Audit                                       |
    |  3. Run Config                                      |
    |  4. Run Default Hardening Kitty                     |
    |  5. Run Backup                                      |
    |  6. Run HailMary                                    |
    |  7. Back to Tool Menu                               |
    ======================================================="
        $choice = Read-Host "Enter the number of your choice"
        switch ($choice) {
            1 { Install-HardeningKitty; Show-HKMenu}
            2 { Run-HKAudit; Show-HKMenu }
            3 { Run-HKConfig; Show-HKMenu }
            4 { Run-HK; Show-HKMenu }
            5 { Run-HKBackup; Show-HKMenu }
            6 { if (Confirm-Action "Are you sure you want to run the hailmary mode? This has a good chance of breaking your machine." -DefaultYes) {Run-HKHailMary}; Show-HKMenu}
            7 { Show-ToolMenu }
            default { Write-Words "wat?? I don't think I heard you right." -ForegroundColor Red; Show-ToolMenu }
        }
    }
    Function Install-HardeningKitty() {
        $Version = (((Invoke-WebRequest "https://api.github.com/repos/scipag/HardeningKitty/releases/latest" -UseBasicParsing) | ConvertFrom-Json).Name).SubString(2)
        $HardeningKittyLatestVersionDownloadLink = ((Invoke-WebRequest "https://api.github.com/repos/scipag/HardeningKitty/releases/latest" -UseBasicParsing) | ConvertFrom-Json).zipball_url
        $ProgressPreference = 'SilentlyContinue'
        Set-Location $MainFolderPath
        Invoke-WebRequest $HardeningKittyLatestVersionDownloadLink -Out HardeningKitty$Version.zip
        Expand-Archive -Path ".\HardeningKitty$Version.zip" -Destination ".\HardeningKitty$Version" -Force
        $Folder = Get-ChildItem .\HardeningKitty$Version | Select-Object Name -ExpandProperty Name
        Copy-Item ".\HardeningKitty$Version\$Folder*" ".\HardeningKitty" -recurse -ErrorAction SilentlyContinue
        Remove-Item ".\HardeningKitty$Version\$Folder" -recurse -ErrorAction SilentlyContinue
        New-Item -Path $Env:ProgramFiles\WindowsPowerShell\Modules\HardeningKitty$Version -ItemType Directory -ErrorAction SilentlyContinue
        Copy-Item -Path $MainFolderPath\HardeningKitty\HardeningKitty.psd1,$MainFolderPath\HardeningKitty\HardeningKitty.psm1,$MainFolderPath\HardeningKitty\lists\ -Destination $Env:ProgramFiles\WindowsPowerShell\Modules\HardeningKitty$Version\ -Recurse -ErrorAction SilentlyContinue
        Import-Module "$Env:ProgramFiles\WindowsPowerShell\Modules\HardeningKitty$Version\HardeningKitty.psm1"
    }
    Function Run-HKAudit{Write-Words "Running Audit..."; Start-Process powershell -ArgumentList "Import-Module $MainFolderPath\HardeningKitty\HardeningKitty.psd1;Invoke-HardeningKitty -Mode Audit -Log -Report; Read-Host -Prompt 'Press any key to continue'"}
    Function Run-HKConfig{Write-Words "Running Config..."; Start-Process powershell -ArgumentList "Import-Module $MainFolderPath\HardeningKitty\HardeningKitty.psd1;Invoke-HardeningKitty -Mode Config -Report -ReportFile $MainFolderPath\my_hardeningkitty_report.csv; Read-Host -Prompt 'Press any key to continue'"}
    Function Run-HK{Write-Words "Running Default Scan..."; Start-Process powershell -ArgumentList "Import-Module $MainFolderPath\HardeningKitty\HardeningKitty.psd1;Invoke-HardeningKitty -EmojiSupport; Read-Host -Prompt 'Press any key to continue'"}
    Function Run-HKBackup{Write-Words "Creating a Backup..."; Start-Process powershell -ArgumentList "Import-Module $MainFolderPath\HardeningKitty\HardeningKitty.psd1;Invoke-HardeningKitty -Mode Config -Backup; Read-Host -Prompt 'Press any key to continue'"}
    Function Run-HKHailMary{Write-Words "Running a HailMary..."; Start-Process powershell -ArgumentList "Import-Module $MainFolderPath\HardeningKitty\HardeningKitty.psd1;Invoke-HardeningKitty -Mode HailMary -Log -Report -FileFindingList .\lists\finding_list_0x6d69636b_machine.csv -SkipRestorePoint; Read-Host -Prompt 'Press any key to continue'"}
    Show-HKMenu
}
function Install-PersistanceSniper{
    if ([System.IO.File]::Exists("$MainFolderPath\PS.zip") -eq $false){ 
        Invoke-WebRequest "https://github.com/last-byte/PersistenceSniper/archive/refs/heads/main.zip" -Out "$MainFolderPath\PS.zip"
    }
    Expand-Archive -Path $MainFolderPath\PS.zip -DestinationPath $MainFolderPath -Force
    Set-Location -Path $MainFolderPath\PersistenceSniper-main\PersistenceSniper
    Import-Module -Name "$MainFolderPath\PersistenceSniper-main\PersistenceSniper\PersistenceSniper.psm1"
    Import-Module -Name "$MainFolderPath\PersistenceSniper-main\PersistenceSniper\PersistenceSniper.psd1"
    Find-AllPersistence
}
function Install-BlueSpawn{
    if ([System.IO.File]::Exists("$MainFolderPath\BLUESPAWN-client-x64.exe") -eq $false){ 
        Invoke-WebRequest "https://github.com/ION28/BLUESPAWN/releases/download/v0.5.1-alpha/BLUESPAWN-client-x64.exe" -OutFile "$MainFolderPath\BLUESPAWN-client-x64.exe"
    }
    Start-Process cmd -ArgumentList "/c $MainFolderPath\BLUESPAWN-client-x64.exe --hunt -a intensive --log=console,xml & pause" #-o '$MainFolderPath\Log\ find a way to keep the log here
    Start-Process cmd -ArgumentList "/c $MainFolderPath\BLUESPAWN-client-x64.exe  --mitigate --mode=enforce --enforcement-level=all & pause" #-o '$MainFolderPath\Log\ find a way to keep the log here
}
function Install-PingCastle{
    if ([System.IO.File]::Exists("$MainFolderPath\PingCastle.zip") -eq $false){ 
        Invoke-WebRequest "https://github.com/vletoux/pingcastle/releases/download/3.2.0.1/PingCastle_3.2.0.1.zip" -Out "$MainFolderPath\PingCastle.zip"
    }
    Expand-Archive -Path $MainFolderPath\PingCastle.zip -Destination "$MainFolderPath\PingCastle" -Force
    Invoke-Expression "start $MainFolderPath\PingCastle\PingCastle.exe"
}
function Install-APTHunter {
    if ([System.IO.File]::Exists("$MainFolderPath\APT-Hunter.exe") -eq $false){ 
    Invoke-WebRequest "https://github.com/ahmedkhlief/APT-Hunter/releases/download/V3.2/APT-Hunter.exe" -Out "$MainFolderPath\APT-Hunter.exe"
    }
    $eventlogs = "C:\Windows\System32\winevt\Logs" 
    & "$MainFolderPath\APT-Hunter.exe" -allreport -p $eventlogs

}
function Install-CobaltStrikeScan {
    if ([System.IO.File]::Exists("$MainFolderPath\CobaltStrikeScan.exe") -eq $false){ 
        Invoke-WebRequest "https://github.com/Apr4h/CobaltStrikeScan/releases/download/1.1.2/CobaltStrikeScan.exe" -Out "$MainFolderPath\CobaltStrikeScan.exe"
    }
        Start-Process cmd -ArgumentList "/c start $MainFolderPath\CobaltStrikeScan.exe -p -d & pause"

}
function Install-DeepBlue{
    if ([System.IO.File]::Exists("$MainFolderPath\DeepBlueCLI.zip") -eq $false){  
        Invoke-WebRequest "https://github.com/sans-blue-team/DeepBlueCLI/archive/refs/heads/master.zip" -Out "$MainFolderPath\DeepBlueCLI.zip"
    }
    Expand-Archive -Path $MainFolderPath\DeepBlueCLI.zip -DestinationPath $MainFolderPath\ -Force
    Copy-Item "$MainFolderPath\DeepBlueCLI-master*" "$MainFolderPath\DeepBlue" -recurse
    Remove-Item $MainFolderPath\DeepBlueCLI-master -recurse
    Start-Process powershell -ArgumentList "Set-Location $MainFolderPath\DeepBlue\; $MainFolderPath\DeepBlue\DeepBlue.ps1; Read-Host -Prompt 'Press any key to continue'" -Verb RunAs
}
 
function Install-Python3 {
    $pythonInstallerUrl = "https://www.python.org/ftp/python/3.12.4/python-3.12.4-amd64.exe"
    $installerPath = "$MainFolderPath\python-3.12.4-amd64.exe"
    Write-Words "Downloading Python 3 installer..."
    if ([System.IO.File]::Exists("$MainFolderPath\python-3.12.4-amd64.exe") -eq $false){  
        Invoke-WebRequest -Uri $pythonInstallerUrl -OutFile $installerPath # Download the Python installer
    }
        #Check if the installer was downloaded successfully
    if (Test-Path $installerPath) {
        Write-Words "Download complete. Running the installer..."
        Start-Process -FilePath "powershell" -ArgumentList "-Command Start-Process -FilePath '$installerPath' -ArgumentList '/quiet InstallAllUsers=1 PrependPath=1' -Wait" -Verb RunAs -Wait
    } else {Write-Words "Failed to download the Python installer."}
}
function Get-Sysinternals{
    Write-Words "Downloading Sysinternals..."
    if ([System.IO.File]::Exists("$MainFolderPath\Sysinternals.zip") -eq $false){  
        Invoke-WebRequest -Uri "https://download.sysinternals.com/files/SysinternalsSuite.zip" -Out "$MainFolderPath\Sysinternals.zip"
    }
        Write-Words "Download Complete!"
    Expand-Archive -Path $MainFolderPath\Sysinternals.zip -DestinationPath "$MainFolderPath\Sysinternals" -Force
}
function Install-Laps{
    Write-Words "Downloading LAPS..."
    if ([System.IO.File]::Exists("$MainFolderPath\Sysinternals.zip") -eq $false){  
        Invoke-WebRequest -Uri "https://download.microsoft.com/download/C/7/A/C7AAD914-A8A6-4904-88A1-29E657445D03/LAPS.x64.msi" -Out "$MainFolderPath\LAPS.x64.msi"
    }
    Start-Process -FilePath "$MainFolderPath\LAPS.x64.msi"
}

function Install-NortonPowerEraser{
    Write-Words "Downloading Norton PowerEraser..."
    if ([System.IO.File]::Exists("$MainFolderPath\Sysinternals.zip") -eq $false){  
        Invoke-WebRequest -Uri "https://www.norton.com/npe_latest" -Out "$MainFolderPath\NPE.exe"
    }
    Start-Process -FilePath "$MainFolderPath\NPE.exe"
}

function Create-RecoveryPoints {
    $BackupLocation = $MainFolderPath
    # Check if the backup location exists, create if it doesn't
    if (-not (Test-Path -Path $BackupLocation)) {
        New-Item -ItemType Directory -Path $BackupLocation | Out-Null
    }
    # Check if the Windows Server Backup feature is installed
    if (-not (Get-WindowsFeature -Name Backup-Features)) {
        Write-Words "Windows Server Backup feature is not installed. Please install it first."
        return
    } try {
        $volumes = Get-Volume | Where-Object {$_.DriveLetter -ne $null} | ForEach-Object { $_.DriveLetter + ":" }
        foreach ($volume in $volumes) {
            WBADMIN START BACKUP -backupTarget:$BackupLocation -include:$volume -quiet
            Write-Words "Recovery point for volume $volume created successfully."
        }
        Write-Words "All recovery points created successfully."
    } catch {
        Write-Words "Failed to create recovery points. Error: $_"
    }
}
function Install-Sysmon {
    Write-Words "Downloading Sysmon..."
    $InstallPath = "$MainFolderPath\Sysmon"
    if (-not (Test-Path -Path $InstallPath)) { New-Item -ItemType Directory -Path $InstallPath -Force}
    $zipPath = "$MainFolderPath\Sysmon.zip"; $extractedPath = "$MainFolderPath\Sysmon"# Define paths for download and extraction
    if ([System.IO.File]::Exists($extractedPath) -eq $false){ 
        Invoke-WebRequest -Uri "https://download.sysinternals.com/files/Sysmon.zip" -OutFile $zipPath;Write-Words "Getting Eyes Up With Sysmon..."
    }
    if (Test-Path $zipPath) {
        Write-Words "Download complete!"
        Write-Words "Extracting Sysmon..."
        Expand-Archive -Path $zipPath -DestinationPath $extractedPath -Force # Extract the Sysmon zip file
        #Move-Item -Path "$extractedPath\*" -Destination $InstallPath -Force # Move the extracted files to the installation directory
        Remove-Item $zipPath -Force; 
        #Remove-Item $extractedPath -Recurse -Force # Remove the zip file and extracted temporary files
        $sysmonExe = Join-Path -Path $InstallPath -ChildPath "Sysmon64.exe" # Define the path to the Sysmon executable
        if (Test-Path $sysmonExe) {
            Write-Words "Installing Sysmon service..."
            Start-Process -FilePath $sysmonExe -ArgumentList "-accepteula -i" -Wait
            Write-Words "Sysmon installation completed successfully"
        } else {
            Write-Words "Sysmon executable not found after extraction"
        }
    } else {
        Write-Words "Failed to download the Sysmon zip file"
    }
}
function New-DomainAdmin {
    $Username = "Backup_Admin"
    $Password = Read-Host -Prompt "Enter password" -AsSecureString
    $domain = ([System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()).Name
    $Credential = New-Object System.Management.Automation.PSCredential ($Username, $Password)
    Import-Module ActiveDirectory
    if (Get-ADUser -Filter {SamAccountName -eq $Username}) {
        Write-Warning "User $Username already exists"
        return
    }
    New-ADUser -Name $Username -SamAccountName $Username -UserPrincipalName "$Username@$domain" -AccountPassword $Credential.Password -Enabled $true -PasswordNeverExpires $true -Path "OU=Admins,DC=$domain"
    Add-ADGroupMember -Identity "Domain Admins" -Members $Username
    Write-Words -ForegroundColor Green "$Username successfully created as a domain admin in domain $domain"
}
Function Write-Words {
    param (
        [Parameter()]
        [string]
        $Message,
        [Parameter()]
        [System.ConsoleColor]
        $ForegroundColor = $Host.UI.RawUI.ForegroundColor
    )
    if ($OutputSelector -eq 1){
        $Message | Out-Rainbow
    } elseif ($OutputSelector -eq 0) {
        if($ForegroundColor -ne "-1"){
            Write-Host $Message -ForegroundColor $ForegroundColor
        } else {
            Write-Host $Message
        }
    }
}
Function Out-Rainbow {
    <#
        .Synopsis
        Write rainbow colored output to the console with each pair of characters changing color.
        .Description
        This function takes string input and writes each pair of characters (skipping whitespace) in a rainbow sequence of colors to the host on the same line.
        The function works best with the PowerShell console.
        .Parameter Message
        The string of text to colorize.
        .Example
        PS C:\> "Take the first step in faith. You don't have to see the whole staircase,", "just take the first step.", "  --Martin Luther King, Jr." | Out-Rainbow
    #>
    Param (
        [Parameter(Position=0, Mandatory=$True, ValueFromPipeline=$True)]
        [string[]]$Message
    ) 
    $Message = $Message | Out-String
    # Define the colors of the rainbow
    $RainbowColors = @("Red", "Yellow", "Green", "Cyan", "Blue", "Magenta")
    # Save current background color
    $SavedBGColor = $Host.UI.RawUI.BackgroundColor
    ForEach ($m in $Message) {
        ForEach ($char in $m.ToCharArray()) {
            if ($char -match "\s") {Write-Host -NoNewline $char; continue}
            Write-Host -NoNewline $char -ForegroundColor $RainbowColors[$global:currentColorIndex]
            $global:skipCounter++
            # Change color every per x characters
            if ($global:skipCounter % 4 -eq 0) {$global:currentColorIndex = ($global:currentColorIndex + 1) % $RainbowColors.Count}
        }
        Write-Host ""
    }
    $Host.UI.RawUI.BackgroundColor = $SavedBGColor
}

function Show-MainMenu {
    Write-Words "
    ===================================================
    |                   Main Menu                     |
    ===================================================
    |  1. List Audit Functions                        |
    |  2. List Tool Functions                         |
    |  3. List Utility Functions                      |
    |  4. Let the DOD Handle GPOs                     |
    |  5. Run All Functions                           |
    |  6. Exit                                        |
    ===================================================
    "
    $choice = Read-Host "Enter the number of your choice"
    switch ($choice) {
        1 { Show-AuditMenu }
        2 { Show-ToolMenu }
        3 { Show-UtilityMenu } 
        4 { if (Confirm-Action "Are you sure you want to apply DOD STIG GPOs?" -DefaultYes) {Enforce-GPO}; Show-MainMenu}
        5 { if (Confirm-Action "Are you sure you want to run all functions?" -DefaultYes) {Run-AllFunctions}; Show-MainMenu}
        6 { Exit }
        default { Write-Words "Invalid choice, please try again" -ForegroundColor Red; Show-MainMenu }
    }
}

function Show-AuditMenu {
    Write-Words "
    ================================================
    |             Audit Functions Menu             |
    ================================================
    |  1. mmm, show me those DLLs~                 |
    |  2. Test Internet Connection                 |
    |  3. Get PS History                           |
    |  4. Get Installed Programs                   |
    |  5. Get Firewall Status                      |
    |  6. Get Windows Defender Status              |
    |  7. Get Network Connections                  |
    |  8. Get Non-Ephemeral Ports in Use           |
    |  9. Run all Audits                           |
    |  10. Back to Main Menu                       |
    ================================================     
    "
    $choice = Read-Host "Enter the number of your choice"
    switch ($choice) {
        1 { Find-DuplicateDLLs; Show-AuditMenu }
        2 { Test-InternetConnection; Show-AuditMenu }
        3 { Get-PowerShellHistory; Show-AuditMenu }
        4 { Get-InstalledPrograms; Show-AuditMenu }
        5 { Get-FirewallStatus; Show-AuditMenu }
        6 { Get-WindowsDefenderStatus; Show-AuditMenu }
        7 { Get-NetworkConnections; Show-AuditMenu }
        8 { Get-NonEphemeralPortsInUse; Show-AuditMenu }
        9 { Run-AllAudits;Show-AuditMenu}
        10 { Show-MainMenu }
        default { Write-Words "Invalid choice, please try again." -ForegroundColor Red; Show-AuditMenu }
    }
}
function Show-UtilityMenu {
    Write-Words "
    ================================================
    |             Utility Functions Menu           |
    ================================================
    |  1. Install-Sysmon                           |
    |  2. Install-Python3                          |
    |  3. Get-Sysinternals                         |
    |  4. Install-Laps                             |
    |  5. Create A Restore Point (working kinda)   |
    |  6. Create Backup Admin (Chance to Fail)     |
    |  7. Download all tools                       |
    |  8. Run all safe functions                   |
    |  9. Be Gay                                   |
    |  10. Back to Main Menu                       |
    ================================================     
    "
    $choice = Read-Host "Enter the number of your choice"
    switch ($choice) {
        1 { Install-Sysmon; Show-UtilityMenu }
        2 { Install-Python3; Show-UtilityMenu }
        3 { Get-Sysinternals; Show-UtilityMenu }
        4 { Install-Laps ; Show-UtilityMenu }
        5 { if (Confirm-Action "Are you sure you want to create a recovey point?" -DefaultYes) {Create-RecoveryPoints}; Show-UtilityMenu }
        6 { if (Confirm-Action "Are you sure you want to create a backup administrator?" -DefaultYes) {New-DomainAdmin}; Show-UtilityMenu }
        7 { if (Confirm-Action "Are you sure you want to download all progams used by BlueZen?" -DefaultYes) {Get-BlueZenTools}; Show-UtilityMenu }
        8 { Run-SafeFunctions; Show-UtilityMenu }
        9 { if($OutputSelector-ne1){$OutputSelector=1}elseif($OutputSelector-eq1){$OutputSelector=0}; Show-UtilityMenu}
        10 { Show-MainMenu }
        default { Write-Words "Invalid choice, please try again." -ForegroundColor Red; Show-UtilityMenu }
    }
}
Function Get-BlueZenTools{
    <#
    .Notes
    Needs HardeningKitty
    #>
    if ([System.IO.File]::Exists("$MainFolderPath\Sysinternals.zip") -eq $false){  Invoke-WebRequest -Uri "https://download.sysinternals.com/files/SysinternalsSuite.zip" -Out "$MainFolderPath\Sysinternals.zip"}
    if ([System.IO.File]::Exists("$MainFolderPath\Sysmon.zip") -eq $false){  Invoke-WebRequest -Uri "https://download.sysinternals.com/files/Sysmon.zip" -OutFile "$MainFolderPath\Sysmon.zip";Write-Words "Getting Eyes Up With Sysmon..."}
    if ([System.IO.File]::Exists("$MainFolderPath\LAPS.x64.msi") -eq $false){  Invoke-WebRequest -Uri "https://download.microsoft.com/download/C/7/A/C7AAD914-A8A6-4904-88A1-29E657445D03/LAPS.x64.msi" -Out "$MainFolderPath\LAPS.x64.msi"}
    if ([System.IO.File]::Exists("$MainFolderPath\BLUESPAWN-client-x64.exe") -eq $false){  Invoke-WebRequest "https://github.com/ION28/BLUESPAWN/releases/download/v0.5.1-alpha/BLUESPAWN-client-x64.exe" -OutFile "$MainFolderPath\BLUESPAWN-client-x64.exe"}
    if ([System.IO.File]::Exists("$MainFolderPath\PingCastle.zip") -eq $false){  Invoke-WebRequest "https://github.com/vletoux/pingcastle/releases/download/3.2.0.1/PingCastle_3.2.0.1.zip" -Out "$MainFolderPath\PingCastle.zip"}
    if ([System.IO.File]::Exists("$MainFolderPath\PS.zip") -eq $false){  Invoke-WebRequest "https://github.com/last-byte/PersistenceSniper/archive/refs/heads/main.zip" -Out "$MainFolderPath\PS.zip"}
    if ([System.IO.File]::Exists("$MainFolderPath\APT-Hunter.exe") -eq $false){  Invoke-WebRequest "https://github.com/ahmedkhlief/APT-Hunter/releases/download/V3.2/APT-Hunter.exe" -Out "$MainFolderPath\APT-Hunter.exe"}
    if ([System.IO.File]::Exists("$MainFolderPath\Chainsaw.zip") -eq $false){  Invoke-WebRequest "https://github.com/WithSecureLabs/chainsaw/releases/download/v2.9.1/chainsaw_all_platforms+rules+examples.zip" -Out "$MainFolderPath\Chainsaw.zip"}
    if ([System.IO.File]::Exists("$MainFolderPath\CobaltStrikeScan.exe") -eq $false){  Invoke-WebRequest "https://github.com/Apr4h/CobaltStrikeScan/releases/download/1.1.2/CobaltStrikeScan.exe" -Out "$MainFolderPath\CobaltStrikeScan.exe"}
    if ([System.IO.File]::Exists("$MainFolderPath\DeepBlueCLI.zip") -eq $false){  Invoke-WebRequest "https://github.com/sans-blue-team/DeepBlueCLI/archive/refs/heads/master.zip" -Out "$MainFolderPath\DeepBlueCLI.zip"}
    if ([System.IO.File]::Exists("$MainFolderPath\U_STIG_GPO_Package.zip") -eq $false){  Invoke-WebRequest "https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_STIG_GPO_Package_April_2024.zip" -Out "$MainFolderPath\U_STIG_GPO_Package.zip"}
    if ([System.IO.File]::Exists("$MainFolderPath\Fail2Ban4Win.zip") -eq $false){  Invoke-WebRequest "https://github.com/Aldaviva/Fail2Ban4Win/releases/download/1.2.0/Fail2Ban4Win.zip" -Out "$MainFolderPath\Fail2Ban4Win.zip"}
    if ([System.IO.File]::Exists("$MainFolderPath\NPE.exe") -eq $false){  Invoke-WebRequest -Uri "https://www.norton.com/npe_latest" -Out "$MainFolderPath\NPE.exe"}

}
function Run-AllAudits {
    Find-DuplicateDLLs
    Test-InternetConnection
    Get-PowerShellHistory
    Get-InstalledPrograms
    Get-FirewallStatus
    Get-WindowsDefenderStatus
    Get-NetworkConnections
    Get-NonEphemeralPortsInUse 
}
function Show-ToolMenu {
    Write-Words "
    ==============================================
    |             Tool Functions Menu            |
    ==============================================
    |  1. Harden Kitty:3                         |
    |  2. Pweez dont Snipe my persistance mista~ |
    |  3. Mods, Spawn Blue Balls (BlueSpawn)     |
    |  4. Ping in the High Castle (PingCastle)   |
    |  5. Rip it Up With Chainsaw (Chainsaw)     |
    |  6. Fail2Ban4Win 4 the Win                 |
    |  7. Install APTHunter                      |
    |  8. Install CobaltStrikeScan               |
    |  9. Install DeepBlue                       |
    |  10. Back to Main Menu                     |
    ==============================================
    "
    $choice = Read-Host "Enter the number of your choice"
    switch ($choice) {
        1 { Get-HardeningKittyFunction; Show-ToolMenu }
        2 { Install-PersistanceSniper; Show-ToolMenu }
        3 { if (Confirm-Action "Are you sure you want to install BlueSpawn? File may be blocked by antivirus." -DefaultYes) {Install-BlueSpawn}; Show-ToolMenu }
        4 { Install-PingCastle; Show-ToolMenu }
        5 { Get-ChainsawFunctions}
        6 { Get-F2B4WFunctions}
        7 { Install-APTHunter; Show-ToolMenu}
        8 { Install-CobaltStrikeScan; Show-ToolMenu}
        9 { Install-DeepBlue; Show-ToolMenu}
        10 { Show-MainMenu }
        default { Write-Words "Invalid choice, please try again." -ForegroundColor Red; Show-ToolMenu }
    }
}


function Get-ChainsawFunctions{
    function Show-ChainsawMenu {
        Write-Words "
    =======================================================
    |                Chainsaw Functions Menu              |
    =======================================================
    |  1. Install the Damn Thing                          |
    |  2. Hunt Using the Sigma Grindset (simga rules hunt)|
    |  3. Just Rip and Tear The Srum (srum Analysis)      |
    |  4. Check for SHIMmed locks (shimcache Analysis)    |
    |  5. Look on Logs for Sus Movement(Event Searching)  |
    |  6. Back to Main Menu                               |
    ======================================================="
        $choice = Read-Host "Enter the number of your choice"
        switch ($choice) {
            1 { Install-Chainsaw; Show-ChainsawMenu}
            2 { Get-SigmaHunt; Show-ChainsawMenu }
            3 { Get-SrumHunt; Show-ChainsawMenu }
            4 { Get-ShimAnalysis; Show-ChainsawMenu }
            5 { Get-SearchedEvents; Show-ChainsawMenu }
            6 { Show-MainMenu }
            default { Write-Words "wat?? I don't think I heard you right." -ForegroundColor Red; Show-ToolMenu }
        }
    }
    function Install-Chainsaw{
        Write-Words "Revving up Chainsaw..."
        if ([System.IO.File]::Exists("$MainFolderPath\Chainsaw.zip") -eq $false){  
            Invoke-WebRequest "https://github.com/WithSecureLabs/chainsaw/releases/download/v2.9.1/chainsaw_all_platforms+rules+examples.zip" -Out "$MainFolderPath\Chainsaw.zip"
        }
        Expand-Archive -Path $MainFolderPath\Chainsaw.zip -DestinationPath $MainFolderPath
        Start-Process cmd -ArgumentList "/c $MainFolderPath\chainsaw\chainsaw_x86_64-pc-windows-msvc.exe"
    }
    function Get-SearchedEvents {
        $userchoice1 = Get-ValidInput -Prompt "Search by Regex(1) or by Event ID(2)" -ValidPattern "^[12]$" -ErrorMessage "Please enter either 1 or 2."
        if ($userchoice1 -eq "1") {
            $userchoice2 = Get-ValidInput -Prompt "Enter Regex string (i.e. Logon)" -ValidPattern "^.+$" -ErrorMessage "Please enter a valid regex string."; $outputFile = "$MainFolderPath\Log\ChainsawSearchRegex$userchoice2.txt"
            & "$MainFolderPath\chainsaw\chainsaw_x86_64-pc-windows-msvc.exe" search -e $userchoice2 $eventLogPath --output $outputFile

        } else {
            $userchoice2 = Get-ValidInput -Prompt "Enter Event ID (i.e. 4104, 4624)" -ValidPattern "^\d+$" -ErrorMessage "Please enter a valid numeric Event ID."; $outputFile = "$MainFolderPath\Log\ChainsawSearchID$userchoice2.txt"
            & "$MainFolderPath\chainsaw\chainsaw_x86_64-pc-windows-msvc.exe" search -t "Event.System.EventID: =$userchoice2" $eventLogPath --output $outputFile
        }

        # Check if the output file exists and contains data
        if (Test-Path $outputFile) {
            $fileContent = Get-Content $outputFile
            if ($fileContent.Count -gt 0) {
                Write-Words "Success: Search completed and results were found." -ForegroundColor Green
            } else {
                Write-Words "Error: Search completed, but no results were found." -ForegroundColor Yellow
            }
        } else {
            Write-Words "Error: Output file was not created. The search may have failed." -ForegroundColor Red
        }
        if ((Test-Path $outputFile) -and ((Get-Content $outputFile).Count -gt 0)) {
            $displayContent = Confirm-Action "Do you want to display the search results?"
            if ($displayContent -eq "Y" -or $displayContent -eq "y") {
                Get-Content $outputFile | Out-Host
            } else {
                Write-Words "Search output has been saved to: $outputFile" -ForegroundColor Green
            }
        }
    }

    function Get-ShimAnalysis { 
        #Create Regex File
        $content = @"
^[a-z]:\\windows\\temp\\.+\\\.be\\vc_redist\.x86\.exe$
^[a-z]:\\windows\\temp\\.+\\\.cr\\vcredist_x86\.exe$
^[a-z]:\\windows\\temp\\.+\\\.be\\vc_redist\.x64\.exe$
^[a-z]:\\windows\\temp\\.+\\\.cr\\vcredist_x64\.exe$
^[a-z]:\\users\\.+\\appdata\\local\\temp\\.+~setup\\vcredist_x64.exe$
^[a-z]:\\users\\.+\\appdata\\local\\temp\\.+~setup\\vcredist_x86.exe$
^[a-z]:\\windows\\psexesvc.exe$
^[a-z]:\\users\\.+\\appdata\\local\\microsoft\\onedrive\\.+\\filesyncconfig.exe$
^[a-z]:\\program files \(x86\)\\microsoft\\edgeupdate\\install\\.+\\.+\.tmp\\setup\.exe$
^[a-z]:\\program files \(x86\)\\microsoft\\temp\\.+\.tmp\\microsoftedgeupdate\.exe$
^[a-z]:\\program files \(x86\)\\microsoft\\edgeupdate\\install\\.+\\microsoftedge_x64_.+\.exe$
^[a-z]:\\program files \(x86\)\\microsoft\\edgeupdate\\install\\.+\\microsoftedgeupdatesetup_x86_.+\.exe$
^[a-z]:\\windows\\softwaredistribution\\download\\install\\am_delta_patch_.+\.exe$
^[a-z]:\\windows\\softwaredistribution\\download\\install\\am_engine_patch_.+\.exe$
^[a-z]:\\program files\\google\\chrome\\application\\.+\\installer\\chrmstp\.exe$
"@
        $content | Out-File -FilePath "$MainFolderPath\chainsaw\shimcache_patterns.txt" -Encoding utf8
        #Create Registry Copy
        reg save HKLM\SYSTEM "$MainFolderPath\SYSTEM_copy"
        & "$MainFolderPath\chainsaw\chainsaw_x86_64-pc-windows-msvc.exe" analyse shimcache "$MainFolderPath\SYSTEM_copy" --regexfile "$MainFolderPath\chainsaw\shimcache_patterns.txt" --output "$MainFolderPath\Log\ChainsawShimAnalysis.csv"
        #Clean up
        Remove-Item "$MainFolderPath\SYSTEM_copy"
        Remove-Item "$MainFolderPath\chainsaw\shimcache_patterns.txt"
        Write-Words -ForegroundColor Green "Output saved to: $MainFolderPath\Log\ChainsawShimAnalysis.csv"
    }

    function Get-SigmaHunt { 
        Start-Process "$MainFolderPath\chainsaw\chainsaw_x86_64-pc-windows-msvc.exe" -Verb Runas -ArgumentList "hunt -r $MainFolderPath\chainsaw\rules\ $eventLogPath -s $MainFolderPath\chainsaw\sigma\rules --mapping $MainFolderPath\chainsaw\mappings\sigma-event-logs-all.yml --output $MainFolderPath\Log\ChainsawSigmaSearch.txt" 
        Write-Words "Output: $MainFolderPath\Log\ChainsawSigmaSearch.txt" -ForegroundColor Green
    }


    function Get-SrumHunt {
        # Define paths
        $softwareCopyPath = "$MainFolderPath\SOFTWARE_copy"
        $srudbPath = "C:\Windows\System32\sru\SRUDB.dat"
        $outputPath = "$MainFolderPath\Log\Chainsaw-SRUM-Output.json"
        # Check if SRUDB.dat exists
        if (-not (Test-Path $srudbPath)) {Write-Words "SRUDB.dat file not found at $srudbPath" -ForegroundColor Red; return}
        try {
            # Create a copy of the SOFTWARE hive
            Write-Words "Creating a copy of the SOFTWARE hive..." -ForegroundColor Yellow
            $regSaveResult = reg save HKLM\SOFTWARE $softwareCopyPath
            if ($LASTEXITCODE -ne 0) {throw "Failed to create a copy of the SOFTWARE hive. Make sure you're running as Administrator."}
            # Execute the command
            Write-Words "Running Chainsaw SRUM analysis..." -ForegroundColor Yellow
            & "$MainFolderPath\chainsaw\chainsaw_x86_64-pc-windows-msvc.exe" analyse srum --software "$softwareCopyPath" "$srudbPath" --output "$outputPath"
            if (Test-Path $outputPath) {Write-Words "Analysis complete. Output saved to: $outputPath" -ForegroundColor Green} 
            else {Write-Words "Analysis failed or no output was generated." -ForegroundColor Red}
        } catch {Write-Words "An error occurred: $_" -ForegroundColor Red}
        finally {
            if (Test-Path $softwareCopyPath) {
                Write-Words "Cleaning up temporary SOFTWARE copy..." -ForegroundColor Yellow
                Remove-Item $softwareCopyPath -Force
                Write-Words "Cleanup complete." -ForegroundColor Green
            }
        }
    }

    $eventLogPath =  "C:\Windows\System32\winevt\Logs" #Can be changed to a dynamic location later
    Show-ChainsawMenu
}

function Get-F2B4WFunctions {
    #maybe add report generator
    Function Get-F2B4WMenu {
        Write-Words "
        =======================================================
        |            Fail2Ban4Win Functions Menu              |
        =======================================================
        |  1. Install the Damn Thing                          |
        |  2. Configure F2B4W                                 |
        |  3. Run Fail2Ban4Win                                |
        |  4. Back to Main Menu                               |
        ======================================================="
        $choice = Read-Host "Enter the number of your choice"
        switch ($choice) {
            1 { Install-Fail2Ban4Win; Show-F2B4WFunctions}
            2 { Configure-Fail2Ban4Win; Show-F2B4WFunctions }
            3 { Run-Fail2Ban4Win; Show-F2B4WFunctions }
            4 { Show-ToolMenu }
            default { Write-Words "wat?? I don't think I heard you right." -ForegroundColor Red; Show-F2B4WFunctions }
        }
    }
    function Configure-Fail2Ban4Win{
        <#
        .SYNOPSIS
        Master function for configuring fail2ban4win
        
        .DESCRIPTION
        Long description
        Show-F2B4WConfigMenu
        
        .EXAMPLE
        Configure-Fail2Ban4Win
        
        .NOTES
        Maybe combine this with running and install functions
        maybe add banRepeatedOffenseMax
        maybe add banRepeatedOffenseCoefficient
        maybe add neverBanReservedSubnets
        maybe add View-F2B4WConfig
        Currently assumes that Fail2Ban4Win is in C:\Program Files (x86)
        #>
        function Show-F2B4WConfigMenu {
            Write-Words "
            ====================================================================================
            |                            F2B4W Functions Menu                                  |
            ====================================================================================
            |  1. isDryRun (Firewall rules will only be created or deleted when this is false.)|
            |  2. maxAllowedFailures (If IP range exceeds the number of failures, it's banned) |
            |  3. failureWindow (How long to consider auth failures, The format is d.hh:mm:ss.)|
            |  4. banPeriod (Time in which ban will be removed. The format is d.hh:mm:ss.)     |
            |  5. banSubnetBits (Optional CIDR subnet aggregation size when counting failures) |
            |  6. neverBanSubnets (Optional whitelist of IP ranges that should never be banned)|
            |  7. logLevel (Optionally adjust the logging verbosity)                           |
            |  8. eventLogSelectors (Required list of events to listen for in Event Log.)      |
            |  9. Configure all                                                                | 
            |  10. Back to Main Menu                                                           |
            ====================================================================================
            "
            $choice = Read-Host "Enter the number of your choice"
            switch ($choice) {
                1 { Set-isDryRun; Show-F2B4WConfigMenu}
                2 { Set-maxAllowedFailures; Show-F2B4WConfigMenu }
                3 { Set-failureWindow; Show-F2B4WConfigMenu }
                4 { Set-banPeriod; Show-F2B4WConfigMenu }
                5 { Set-banSubnetBits; Show-F2B4WConfigMenu }
                6 { Set-neverBanSubnets; Show-F2B4WConfigMenu }
                7 { Set-logLevel; Show-F2B4WConfigMenu }
                8 { Set-eventLogSelectors; Show-F2B4WConfigMenu }
                9 { Configure-AllF2B4W; Show-F2B4WConfigMenu }
                10 { Show-MainMenu }
                default { Write-Words "wat?? I don't think I heard you right." -ForegroundColor Red; Show-F2B4WConfigMenu }
            }
        }
        function Configure-AllF2B4W {
            if (Confirm-Action "Are you sure you want to configure all Fail2Ban4Win settings?" -DefaultYes) {
                Set-isDryRun
                Set-maxAllowedFailures
                Set-failureWindow
                Set-banPeriod
                Set-banSubnetBits
                Set-neverBanSubnets
                Set-logLevel
                Set-eventLogSelectors
                Write-Words "All Fail2Ban4Win settings have been configured." -ForegroundColor Green
            } else {
                Write-Words "Configuration cancelled." -ForegroundColor Yellow
            }
        }
        
        function Set-isDryRun {
            $isDryRun = Get-ValidInput -Prompt "Enter new value for isDryRun (true/false)" -ValidPattern "^(true|false)$" -ErrorMessage "Invalid input. Please enter 'true' or 'false'."
            $config.isDryRun = [bool]::Parse($isDryRun)
            Save-Config
        }
        
        function Set-maxAllowedFailures {
            $maxAllowedFailures = Get-ValidInput -Prompt "Enter new value for maxAllowedFailures (integer)" -ValidPattern "^\d+$" -ErrorMessage "Invalid input. Please enter a valid integer."
            $config.maxAllowedFailures = [int]$maxAllowedFailures
            Save-Config
        }
        
        function Set-failureWindow {
            $failureWindow = Get-ValidInput -Prompt "Enter new value for failureWindow (in format dd.hh:mm:ss)" -ValidPattern "^\d{1,2}\.\d{2}:\d{2}:\d{2}$" -ErrorMessage "Invalid input. Please enter in the format dd.hh:mm:ss."
            $config.failureWindow = $failureWindow
            Save-Config
        }
        function Set-banPeriod {
            $banPeriod = Get-ValidInput -Prompt "Enter new value for banPeriod (in format dd.hh:mm:ss)" -ValidPattern "^\d{1,2}\.\d{2}:\d{2}:\d{2}$" -ErrorMessage "Invalid input. Please enter in the format dd.hh:mm:ss."
            $config.banPeriod = $banPeriod
            Save-Config
        }
    
        function Set-banSubnetBits {
            $banSubnetBits = Get-ValidInput -Prompt "Enter new value for banSubnetBits (integer)" -ValidPattern "^\d+$" -ErrorMessage "Invalid input. Please enter a valid integer."
            $config.banSubnetBits = [int]$banSubnetBits
            Save-Config
        }
        
        function Set-neverBanSubnets {
            $neverBanSubnets = Get-ValidInput -Prompt "Enter new value for neverBanSubnets (comma-separated IPs/CIDRs)" -ValidPattern "^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/\d{1,2})(,\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/\d{1,2})*$" -ErrorMessage "Invalid input. Please enter a comma-separated list of IPs/CIDRs."
            $config.neverBanSubnets = $neverBanSubnets -split ","
            Save-Config
        }
        
        function Set-logLevel {
            $logLevel = Get-ValidInput -Prompt "Enter new value for logLevel (Trace, Debug, Info, Warn, Error, Fatal)" -ValidPattern "^(Trace|Debug|Info|Warn|Error|Fatal)$" -ErrorMessage "Invalid input. Please enter one of the following: Trace, Debug, Info, Warn, Error, Fatal."
            $config.logLevel = $logLevel
            Save-Config
        }
        
        function Set-eventLogSelectors {
            $eventLogSelectors = @()
            while ($true) {
                $logName = Read-Host "Enter logName (or press Enter to finish)"
                if ($logName -eq "") { break }
                $eventId = Get-ValidInput -Prompt "Enter eventId (integer)" -ValidPattern "^\d+$" -ErrorMessage "Invalid input. Please enter a valid integer for eventId."
                $ipAddressEventDataName = Read-Host "Enter ipAddressEventDataName (optional, press Enter to skip)"
                $ipAddressPattern = Read-Host "Enter ipAddressPattern (optional, press Enter to skip)"
                $selector = @{
                    logName = $logName
                    eventId = [int]$eventId
                }
                if ($ipAddressEventDataName) { $selector.ipAddressEventDataName = $ipAddressEventDataName }
                if ($ipAddressPattern) { $selector.ipAddressPattern = $ipAddressPattern }
                $eventLogSelectors += $selector
            }
            $config.eventLogSelectors = $eventLogSelectors
            Save-Config
        }
        $configFilePath = "C:\'Program Files (x86)'\Fail2Ban4Win\configuration.json"
        try { $config = Get-Content -Raw -Path $configFilePath | ConvertFrom-Json} 
        catch { Write-Words "Error loading configuration file: $_" -ForegroundColor Red; return }
        Show-F2B4WConfigMenu
    
       
    }
    function Install-Fail2Ban4Win{
        if (Confirm-Action "Do you want to install Fail2Ban4Win?" -DefaultYes) {
            Write-Words "Starting Fail2Ban4Win installation..."
            if ([System.IO.File]::Exists("$MainFolderPath\Fail2Ban4Win.zip") -eq $false){ 
                Invoke-WebRequest "https://github.com/Aldaviva/Fail2Ban4Win/releases/download/1.2.0/Fail2Ban4Win.zip" -Out "$MainFolderPath\Fail2Ban4Win.zip"
            }
            Expand-Archive -Path $MainFolderPath\Fail2Ban4Win.zip -DestinationPath "C:\'Program Files (x86)'\Fail2Ban4Win\"
            Set-ExecutionPolicy Unrestricted -Scope Process -Force
            C:\'Program Files (x86)'\Fail2Ban4Win\'Install service.ps1'
            Set-ExecutionPolicy Default -Scope Process -Force
            Write-Words "Fail2Ban4Win installation completed." -ForegroundColor Green
        } else {
            Write-Words "Installation cancelled." -ForegroundColor Yellow
        }
    }
    Function Run-Fail2Ban4Win {Start-Process cmd -ArgumentList "/c start C:\'Program Files (x86)'\Fail2Ban4Win\Fail2Ban4Win.exe & pause"}
    Function Get-Fail2Ban4WinReport {Write-Words "This is not functioning currently"}
    $config = Get-Content -Raw -Path $configFilePath | ConvertFrom-Json
    Get-F2B4WMenu
}

function Get-ValidInput {
    param (
        [string]$Prompt,
        [string]$ValidPattern,
        [string]$ErrorMessage,
        [string]$Default = $null
    )
    do {
        $input = Read-Host $Prompt
        if ($input -eq "" -and $Default -ne $null) {
            return $Default
        }
        if ($input -notmatch $ValidPattern) {
            Write-Words $ErrorMessage -ForegroundColor Yellow
        }
    } while ($input -notmatch $ValidPattern)
    return $input
}

function Update-PowerShell {
    [CmdletBinding()]
    param()
    $version = $PSVersionTable.PSVersion
    if ($version.Major -lt 5 -or ($version.Major -eq 5 -and $version.Minor -lt 1)) {
        Write-Words -ForegroundColor Red "PowerShell is outdated. Current version: $($version.ToString())"
        Write-Words "Attempting to update PowerShell..."
        try {
            if ([Environment]::Is64BitOperatingSystem) {
                $downloadUrl = "https://go.microsoft.com/fwlink/?linkid=839516"
            } else {
                $downloadUrl = "https://go.microsoft.com/fwlink/?linkid=839513"
            }
            $installerPath = "$env:TEMP\Win7AndW2K8R2-KB3191566-x64.msu"
            # Download the installer
            if ([System.IO.File]::Exists("$env:TEMP\Win7AndW2K8R2-KB3191566-x64.msu") -eq $false){ 
                Invoke-WebRequest -Uri $downloadUrl -OutFile $installerPath
            }
            # Install the update
            Start-Process -FilePath "wusa.exe" -ArgumentList "$installerPath /quiet /norestart" -Wait
            Write-Words -ForegroundColor Yellow "PowerShell has been updated. Please restart your system to complete the installation."
        }
        catch {Write-Words -ForegroundColor Red "Failed to update PowerShell: $_"}
    }
    else {Write-Words -ForegroundColor Green "PowerShell is up to date. Current version: $($version.ToString())"}
}

function Confirm-Action {
    param (
        [string]$Message,
        [switch]$DefaultYes
    )
    $defaultPrompt = if ($DefaultYes) { " (Y/n)" } else { " (y/N)" }
    $defaultValue = if ($DefaultYes) { "Y" } else { "N" }
    
    $confirmation = Get-ValidInput -Prompt "$Message$defaultPrompt" -ValidPattern "^[YNyn]?$" -Default $defaultValue -ErrorMessage "Invalid input. Please enter Y or N."
    return $confirmation.ToUpper() -eq "Y"
}

function Run-SafeFunctions {
    Get-NonEphemeralPortsInUse
    Test-InternetConnection
    Get-PowerShellHistory
    Get-InstalledPrograms
    Get-FirewallStatus
    Get-WindowsDefenderStatus
    Get-NetworkConnections
    Find-DuplicateDLLs
    Install-Sysmon
    Install-Laps
    Get-Sysinternals
    Install-PingCastle
    Install-PersistanceSniper
    Write-Words "All functions have been executed."
}


# Main script execution
if ($MyInvocation.MyCommand.Path) {
    $scriptPath = $MyInvocation.MyCommand.Path
    try {
        $bytes = Get-Content -Path $scriptPath -Encoding Byte -TotalCount 4
        $currentEncoding = if ($bytes[0] -eq 0xef -and $bytes[1] -eq 0xbb -and $bytes[2] -eq 0xbf) {"UTF8-BOM"} else {"Unknown"}
        Write-Host "Current encoding detected as: $currentEncoding"
        if ($currentEncoding -ne "UTF8-BOM") {
            Write-Host "Converting to UTF-8..."
            # Read content and ensure we have it
            $content = Get-Content -Path $scriptPath -Raw
            if ([string]::IsNullOrEmpty($content)) {throw "Failed to read script content"}
            # Convert to UTF-8 with BOM
            $utf8WithBOM = New-Object System.Text.UTF8Encoding $true
            [System.IO.File]::WriteAllLines($scriptPath, $content, $utf8WithBOM)
            $newBytes = Get-Content -Path $scriptPath -Encoding Byte -TotalCount 4
            Write-Host "Script encoding has been converted to UTF-8. Please run the script again."
            Start-Sleep -Seconds 2
            Exit 1
        }
    }
    catch {
        Write-Host "Error during encoding conversion: $_"
        if (Test-Path "$scriptPath.backup") {
            Write-Host "Restoring from backup..."
            Copy-Item -Path "$scriptPath.backup" -Destination $scriptPath -Force
        }
        Exit 1
    }
}
#To enable TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
#To enable all security protocols
#[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls
$skipCounter = 1
$currentColorIndex = 0
$OutputSelector = 0
Get-Banner
$scriptDirectory = Split-Path -Parent $MyInvocation.MyCommand.Path
$MainFolderPath = Get-ChildItem -Path $scriptDirectory -Filter "BlueZen" -Directory | Select-Object -ExpandProperty FullName
if ([string]::IsNullOrEmpty($MainFolderPath)){
    Write-Words "Main Folder not found. Creating BlueZen at scripts location."
    $MainFolderPath = Get-Childitem –Path C:\Users -Include *MJ.ps1 -Recurse -ErrorAction SilentlyContinue
    New-Item -Path $scriptDirectory -Name "BlueZen" -ItemType Directory | Out-Null
    $MainFolderPath = $scriptDirectory
    $MainFolderPath = "$MainFolderPath\BlueZen"
    New-Item -Path $MainFolderPath -Name "Log" -ItemType Directory | Out-Null
}
Update-PowerShell
Show-MainMenu
