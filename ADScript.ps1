# Import required modules
Import-Module ActiveDirectory
Import-Module GroupPolicy

# Global variables and encoding
$OutputEncoding = [Console]::OutputEncoding = [System.Text.Encoding]::GetEncoding('utf-8')
chcp 65001 | Out-Null

# Global variables
$LogPath = "$PSScriptRoot\Logs"
$LogFile = "$LogPath\$(Get-Date -Format yyyy-MM-dd_HH-mm-ss)_ADManagement.log"

# Create log directory if it doesn't exist
if (-not (Test-Path $LogPath)) {
    New-Item -ItemType Directory -Path $LogPath | Out-Null
}

# Improved logging function with severity levels
function Write-Log {
    param (
        [Parameter(Mandatory=$true)]
        [string]$Message,
        [ValidateSet('Info','Warning','Error')]
        [string]$Severity = 'Info'
    )
      $TimeStamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $LogMessage = "$TimeStamp [$Severity] - $Message"
    $LogMessage | Out-File -Append -FilePath $LogFile
    
    # Write to console with color coding based on severity
    $color = switch ($Severity) {
        'Info'    { 'Green' }
        'Warning' { 'Yellow' }
        'Error'   { 'Red' }
    }
    Write-Host $LogMessage -ForegroundColor $color
}

# Function to validate domain input
function Test-DomainPath {
    param ([string]$Path)
    try {
        Get-ADDomain -Identity $Path
        return $true
    }
    catch {
        return $false
    }
}

# Function to convert domain name to distinguished name format
function Convert-ToDN {
    param ([string]$DomainName)
    $parts = $DomainName.Split('.')
    return "DC=" + ($parts -join ',DC=')
}

# Enhanced menu functions
function Show-MainMenu {
    Clear-Host
    Write-Host "=========================================" -ForegroundColor Green
    Write-Host "        System Management Console        " -ForegroundColor Green
    Write-Host "=========================================" -ForegroundColor Green
    Write-Host "1. Active Directory Management" -ForegroundColor Cyan
    Write-Host "2. System Statistics" -ForegroundColor Cyan
    Write-Host "3. Exit" -ForegroundColor Red
    Write-Host "=========================================" -ForegroundColor Green
}

function Show-ADMenu {
    if (-not $script:Domain) {
        $domainInput = Read-Host "Enter domain name (e.g. bbw.lab)"
        $script:Domain = Convert-ToDN $domainInput
        
        if (-not (Test-DomainPath $script:Domain)) {
            Write-Log "Invalid domain: $domainInput" -Severity Error
            $script:Domain = $null
            return "exit"
        }
        Write-Log "Connected to domain: $domainInput" -Severity Info
    }

    Clear-Host
    Write-Host "=========================================" -ForegroundColor Green
    Write-Host "     Active Directory Management Tool    " -ForegroundColor Green
    Write-Host "     Domain: $($script:Domain.Replace('DC=','.').Replace(',','').TrimStart('.'))" -ForegroundColor Yellow
    Write-Host "=========================================" -ForegroundColor Green
    Write-Host "1.  OU Management" -ForegroundColor Cyan
    Write-Host "2.  Group Management" -ForegroundColor Cyan
    Write-Host "3.  User Management" -ForegroundColor Cyan
    Write-Host "4.  Computer Account Management" -ForegroundColor Cyan
    Write-Host "5.  Group Membership Management" -ForegroundColor Cyan
    Write-Host "6.  View Groups" -ForegroundColor Cyan
    Write-Host "7.  View OU Structure" -ForegroundColor Cyan
    Write-Host "8.  Search AD Objects" -ForegroundColor Cyan
    Write-Host "9.  Account Lockout Management" -ForegroundColor Cyan
    Write-Host "10. Set Wallpaper Policy" -ForegroundColor Cyan
    Write-Host "11. Set Password Policy" -ForegroundColor Cyan
    Write-Host "12. View Current Settings" -ForegroundColor Cyan
    Write-Host "13. Change Domain" -ForegroundColor Yellow
    Write-Host "14. Return to Main Menu" -ForegroundColor Red
    Write-Host "=========================================" -ForegroundColor Green
}

function Show-StatsMenu {
    Clear-Host
    Write-Host "=========================================" -ForegroundColor Green
    Write-Host "        System Statistics Monitor        " -ForegroundColor Green
    Write-Host "=========================================" -ForegroundColor Green
    Write-Host "1. Show CPU Usage" -ForegroundColor Cyan
    Write-Host "2. Show Memory Usage" -ForegroundColor Cyan
    Write-Host "3. Show Disk Usage" -ForegroundColor Cyan
    Write-Host "4. Show IP Address" -ForegroundColor Cyan
    Write-Host "5. Show System Uptime" -ForegroundColor Cyan
    Write-Host "6. Show Top Processes" -ForegroundColor Cyan
    Write-Host "7. Show Network Status" -ForegroundColor Cyan
    Write-Host "8. Show Critical Services" -ForegroundColor Cyan
    Write-Host "9. Show Recent System Events" -ForegroundColor Cyan
    Write-Host "10. Show All Statistics" -ForegroundColor Yellow
    Write-Host "11. Return to Main Menu" -ForegroundColor Red
    Write-Host "=========================================" -ForegroundColor Green
}

# Enhanced password policy function with validation
function Set-CustomPasswordPolicy {
    $minLength = Read-Host "Enter minimum password length (10-16)"
    if ($minLength -lt 10 -or $minLength -gt 16) {
        Write-Log "Invalid password length specified: $minLength" -Severity Warning
        return
    }

    $maxAge = Read-Host "Enter maximum password age in days (30-730)"
    if ($maxAge -lt 30 -or $maxAge -gt 730) {
        Write-Log "Invalid password age specified: $maxAge" -Severity Warning
        return
    }

    try {
        Set-ADDefaultDomainPasswordPolicy -Identity $script:Domain `
            -ComplexityEnabled $true `
            -MaxPasswordAge ([TimeSpan]::FromDays($maxAge)) `
            -MinPasswordAge ([TimeSpan]::FromDays(1)) `
            -MinPasswordLength $minLength `
            -PasswordHistoryCount 24 `
            -ReversibleEncryptionEnabled $false

        Write-Log "Password policy updated successfully" -Severity Info
    }
    catch {
        Write-Log "Failed to set password policy: $_" -Severity Error
    }
}

function Get-SystemUptime {
    $os = Get-WmiObject Win32_OperatingSystem
    $uptime = (Get-Date) - ($os.ConvertToDateTime($os.LastBootUpTime))
    return @{
        Days = $uptime.Days
        Hours = $uptime.Hours
        Minutes = $uptime.Minutes
    }
}

function Get-TopProcesses {
    return Get-Process | Sort-Object CPU -Descending | Select-Object -First 5 | ForEach-Object {
        @{
            Name = $_.ProcessName
            CPU = [math]::Round($_.CPU, 2)
            Memory = [math]::Round($_.WorkingSet / 1MB, 2)
            ID = $_.Id
        }
    }
}

function Get-NetworkStatus {
    try {
        return Get-NetAdapter | ForEach-Object {
            $adapterName = $_.Name
            $ipConfig = $null
            try {
                # Get IP configuration
                $ipConfig = $_ | Get-NetIPAddress -ErrorAction Stop | 
                    Where-Object AddressFamily -eq "IPv4"
                
                # Get network statistics using performance counters
                $bytesReceivedCounter = Get-Counter "\Network Interface($adapterName)\Bytes Received/sec" -ErrorAction Stop
                $bytesSentCounter = Get-Counter "\Network Interface($adapterName)\Bytes Sent/sec" -ErrorAction Stop
                $packetsReceivedCounter = Get-Counter "\Network Interface($adapterName)\Packets Received/sec" -ErrorAction Stop
                $packetsSentCounter = Get-Counter "\Network Interface($adapterName)\Packets Sent/sec" -ErrorAction Stop

                $bytesReceived = $bytesReceivedCounter.CounterSamples.CookedValue
                $bytesSent = $bytesSentCounter.CounterSamples.CookedValue
                $packetsReceived = $packetsReceivedCounter.CounterSamples.CookedValue
                $packetsSent = $packetsSentCounter.CounterSamples.CookedValue
            }
            catch {
                Write-Log "Could not get statistics for adapter $($_.Name): $_" -Severity Warning
            }

            @{
                Name = $_.Name
                Status = $_.Status
                Speed = if ($_.LinkSpeed) { $_.LinkSpeed } else { "N/A" }
                MediaType = $_.MediaType
                MacAddress = $_.MacAddress
                IPAddress = if ($ipConfig) { $ipConfig.IPAddress } else { "N/A" }
                BytesReceived = if ($bytesReceived) { [math]::Round($bytesReceived / 1MB, 2) } else { "N/A" }
                BytesSent = if ($bytesSent) { [math]::Round($bytesSent / 1MB, 2) } else { "N/A" }
                PacketsReceived = if ($packetsReceived) { [math]::Round($packetsReceived, 0) } else { "N/A" }
                PacketsSent = if ($packetsSent) { [math]::Round($packetsSent, 0) } else { "N/A" }
                InterfaceDescription = $_.InterfaceDescription
                AdminStatus = $_.AdminStatus
                MediaConnectionState = $_.MediaConnectionState
            }
        }
    }
    catch {
        Write-Log "Failed to get network adapter information: $_" -Severity Error
        return @()
    }
}

function Get-CriticalServices {
    $importantServices = @('Spooler', 'wuauserv', 'BITS', 'Schedule', 'EventLog')
    return Get-Service $importantServices | ForEach-Object {
        @{
            Name = $_.DisplayName
            Status = $_.Status
            StartType = $_.StartType
        }
    }
}

function Get-RecentEvents {
    return Get-EventLog -LogName System -EntryType Error,Warning -Newest 5 | ForEach-Object {
        @{
            TimeGenerated = $_.TimeGenerated
            Source = $_.Source
            EventID = $_.EventID
            Message = $_.Message.Substring(0, [Math]::Min(100, $_.Message.Length)) + "..."
        }
    }
}

function Get-CPUUsage {
    try {
        $cpuUsage = Get-Counter '\Processor(_Total)\% Processor Time' -SampleInterval 1 -MaxSamples 1
        return [math]::Round($cpuUsage.CounterSamples.CookedValue, 2)
    }
    catch {
        Write-Log "Failed to get CPU usage: $_" -Severity Error
        return "N/A"
    }
}

function Get-MemoryUsage {
    try {
        $os = Get-CimInstance Win32_OperatingSystem
        $total = [math]::Round($os.TotalVisibleMemorySize / 1MB, 2)
        $free = [math]::Round($os.FreePhysicalMemory / 1MB, 2)
        $used = [math]::Round(($total - $free), 2)
        $percent = [math]::Round(($used / $total) * 100, 2)
        
        return @{
            Total = $total
            Used = $used
            Free = $free
            Percent = $percent
        }
    }
    catch {
        Write-Log "Failed to get memory usage: $_" -Severity Error
        return $null
    }
}

function Get-DiskUsage {
    try {
        return Get-WmiObject Win32_LogicalDisk -Filter "DriveType=3" | ForEach-Object {
            $total = [math]::Round($_.Size / 1GB, 2)
            $free = [math]::Round($_.FreeSpace / 1GB, 2)
            $used = [math]::Round(($total - $free), 2)
            $percent = [math]::Round(($used / $total) * 100, 2)
            
            @{
                Drive = $_.DeviceID
                Total = $total
                Used = $used
                Free = $free
                Percent = $percent
            }
        }
    }
    catch {
        Write-Log "Failed to get disk usage: $_" -Severity Error
        return $null
    }
}

function Get-IPAddress {
    try {
        return Get-NetIPAddress | Where-Object {
            $_.AddressFamily -eq "IPv4" -and 
            $_.InterfaceAlias -notmatch "Loopback"
        } | Select-Object -ExpandProperty IPAddress
    }
    catch {
        Write-Log "Failed to get IP addresses: $_" -Severity Error
        return @()
    }
}

# Update your Show-AllStats function to include new components
function Show-AllStats {
    try {
        # CPU Usage
        Write-Host "`nCPU Usage:" -ForegroundColor Yellow
        try {
            $cpuUsage = Get-Counter '\Processor(_Total)\% Processor Time' -SampleInterval 1 -MaxSamples 1
            Write-Host "$([math]::Round($cpuUsage.CounterSamples.CookedValue, 2))%`n"
        }
        catch {
            Write-Host "Unable to retrieve CPU usage`n" -ForegroundColor Red
        }
        
        # Memory Usage
        Write-Host "Memory Usage:" -ForegroundColor Yellow
        try {
            $os = Get-CimInstance Win32_OperatingSystem
            $total = [math]::Round($os.TotalVisibleMemorySize / 1MB, 2)
            $free = [math]::Round($os.FreePhysicalMemory / 1MB, 2)
            $used = [math]::Round(($total - $free), 2)
            $percent = [math]::Round(($used / $total) * 100, 2)
            
            Write-Host "Total: $total GB"
            Write-Host "Used: $used GB"
            Write-Host "Free: $free GB"
            Write-Host "Usage: $percent%`n"
        }
        catch {
            Write-Host "Unable to retrieve memory information`n" -ForegroundColor Red
        }
        
        # Disk Usage
        Write-Host "Disk Usage:" -ForegroundColor Yellow
        try {
            $disks = Get-WmiObject Win32_LogicalDisk -Filter "DriveType=3"
            foreach ($disk in $disks) {
                $total = [math]::Round($disk.Size / 1GB, 2)
                $free = [math]::Round($disk.FreeSpace / 1GB, 2)
                $used = [math]::Round(($total - $free), 2)
                $percent = [math]::Round(($used / $total) * 100, 2)
                
                Write-Host "Drive $($disk.DeviceID):"
                Write-Host "Total: $total GB"
                Write-Host "Used: $used GB"
                Write-Host "Free: $free GB"
                Write-Host "Usage: $percent%`n"
            }
        }
        catch {
            Write-Host "Unable to retrieve disk information`n" -ForegroundColor Red
        }
        
        # System Uptime
        Write-Host "System Uptime:" -ForegroundColor Yellow
        try {
            $os = Get-WmiObject Win32_OperatingSystem
            $uptime = (Get-Date) - ($os.ConvertToDateTime($os.LastBootUpTime))
            Write-Host "Days: $($uptime.Days)"
            Write-Host "Hours: $($uptime.Hours)"
            Write-Host "Minutes: $($uptime.Minutes)`n"
        }
        catch {
            Write-Host "Unable to retrieve system uptime`n" -ForegroundColor Red
        }
        
        # Top Processes
        Write-Host "Top CPU-Consuming Processes:" -ForegroundColor Yellow
        try {
            Get-Process | Sort-Object CPU -Descending | Select-Object -First 5 | ForEach-Object {
                Write-Host "$($_.ProcessName) (PID: $($_.Id)) - CPU: $([math]::Round($_.CPU, 2))%, Memory: $([math]::Round($_.WorkingSet / 1MB, 2)) MB"
            }
            Write-Host ""
        }
        catch {
            Write-Host "Unable to retrieve process information`n" -ForegroundColor Red
        }        # Network Status
        Write-Host "`nNetwork Interfaces:" -ForegroundColor Yellow
        try {
            $adapters = Get-NetworkStatus
            if ($adapters.Count -eq 0) {
                Write-Host "No network adapters found.`n" -ForegroundColor Yellow
            }
            else {
                foreach ($adapter in $adapters) {
                    Write-Host ("=" * 50) -ForegroundColor Cyan
                    Write-Host "Interface: $($adapter.Name)" -ForegroundColor Green
                    Write-Host "Description: $($adapter.InterfaceDescription)"
                    Write-Host "Status: $($adapter.Status) (Admin: $($adapter.AdminStatus))"
                    Write-Host "Connection State: $($adapter.MediaConnectionState)"
                    Write-Host "Media Type: $($adapter.MediaType)"
                    Write-Host "MAC Address: $($adapter.MacAddress)"
                    Write-Host "IP Address: $($adapter.IPAddress)"
                    Write-Host "Speed: $($adapter.Speed)"
                    Write-Host "`nTraffic Statistics:"
                    Write-Host "----------------"
                    Write-Host "Data Received: $($adapter.BytesReceived) MB"
                    Write-Host "Data Sent: $($adapter.BytesSent) MB"
                    Write-Host "Packets Received: $($adapter.PacketsReceived)"
                    Write-Host "Packets Sent: $($adapter.PacketsSent)`n"
                }
                Write-Host ("=" * 50) -ForegroundColor Cyan
            }
        }
        catch {
            Write-Host "Unable to retrieve network information`n" -ForegroundColor Red
            Write-Log "Error getting network status: $_" -Severity Error
        }
        
        # IP Addresses
        Write-Host "IP Addresses:" -ForegroundColor Yellow
        try {
            Get-NetIPAddress | Where-Object {
                $_.AddressFamily -eq "IPv4" -and 
                $_.InterfaceAlias -notmatch "Loopback"
            } | ForEach-Object {
                Write-Host $_.IPAddress
            }
            Write-Host ""
        }
        catch {
            Write-Host "Unable to retrieve IP information`n" -ForegroundColor Red
        }
    }
    catch {
        Write-Log "Error in Show-AllStats: $_" -Severity Error
    }
    finally {
        Write-Host "`nPress any key to continue..." -ForegroundColor Cyan
        $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    }
}

# Add these new AD management functions

function Show-OUStructure {
    try {
        $ous = Get-ADOrganizationalUnit -Filter * -Properties CanonicalName | 
            Select-Object CanonicalName | Sort-Object CanonicalName
        
        Write-Host "`nActive Directory OU Structure:" -ForegroundColor Yellow
        foreach ($ou in $ous) {
            $level = ($ou.CanonicalName.Split('/')).Count - 1
            $indent = "  " * $level
            Write-Host "$indent$($ou.CanonicalName)" -ForegroundColor Cyan
        }
    }
    catch {
        Write-Log "Failed to retrieve OU structure: $_" -Severity Error
    }
}

function Search-ADObjects {
    $searchTerm = Read-Host "Enter search term"
    $objectType = Read-Host "Enter object type (User/Group/Computer/OU/All)"
    
    try {
        Write-Host "`nSearch Results:" -ForegroundColor Yellow
        switch ($objectType.ToLower()) {
            "user" { 
                Get-ADUser -Filter "Name -like '*$searchTerm*' -or SamAccountName -like '*$searchTerm*'" -Properties * |
                    Format-Table Name, SamAccountName, Enabled, LastLogonDate
            }
            "group" { 
                Get-ADGroup -Filter "Name -like '*$searchTerm*'" |
                    Format-Table Name, GroupCategory, GroupScope
            }
            "computer" { 
                Get-ADComputer -Filter "Name -like '*$searchTerm*'" -Properties * |
                    Format-Table Name, Enabled, LastLogonDate
            }
            "ou" { 
                Get-ADOrganizationalUnit -Filter "Name -like '*$searchTerm*'" -Properties * |
                    Format-Table Name, DistinguishedName
            }
            "all" {
                Write-Host "Users:" -ForegroundColor Cyan
                Get-ADUser -Filter "Name -like '*$searchTerm*'" | Format-Table Name, Enabled
                Write-Host "Groups:" -ForegroundColor Cyan
                Get-ADGroup -Filter "Name -like '*$searchTerm*'" | Format-Table Name
                Write-Host "Computers:" -ForegroundColor Cyan
                Get-ADComputer -Filter "Name -like '*$searchTerm*'" | Format-Table Name
                Write-Host "OUs:" -ForegroundColor Cyan
                Get-ADOrganizationalUnit -Filter "Name -like '*$searchTerm*'" | Format-Table Name
            }
        }
    }
    catch {
        Write-Log "Search failed: $_" -Severity Error
    }
}

function Set-ComputerAccounts {
    Write-Host "1. Add Computer Account" -ForegroundColor Cyan
    Write-Host "2. Remove Computer Account" -ForegroundColor Cyan
    Write-Host "3. Move Computer Account" -ForegroundColor Cyan
    Write-Host "4. Enable/Disable Computer Account" -ForegroundColor Cyan
    $choice = Read-Host "Select an option (1-4)"

    switch ($choice) {
        "1" {
            $name = Read-Host "Enter computer name"
            $path = Read-Host "Enter OU path (optional)"
            if ([string]::IsNullOrEmpty($path)) { $path = $script:Domain }
            New-ADComputer -Name $name -Path $path
            Write-Log "Computer account $name created" -Severity Info
        }
        "2" {
            $name = Read-Host "Enter computer name"
            Remove-ADComputer -Identity $name -Confirm:$false
            Write-Log "Computer account $name removed" -Severity Info
        }
        "3" {
            $name = Read-Host "Enter computer name"
            $newPath = Read-Host "Enter new OU path"
            Get-ADComputer $name | Move-ADObject -TargetPath $newPath
            Write-Log "Computer account $name moved to $newPath" -Severity Info
        }
        "4" {
            $name = Read-Host "Enter computer name"
            $action = Read-Host "Enable or Disable? (E/D)"
            if ($action -eq "E") {
                Get-ADComputer $name | Enable-ADAccount
                Write-Log "Computer account $name enabled" -Severity Info
            }
            else {
                Get-ADComputer $name | Disable-ADAccount
                Write-Log "Computer account $name disabled" -Severity Info
            }
        }
    }
}

function Add-GroupMembership {
    param(
        [Parameter(Mandatory = $true)]
        [string]$GroupName,
        [Parameter(Mandatory = $true)]
        [string]$MemberName,
        [switch]$IsGroup
    )
    
    try {
        # Validate that both groups exist
        $group = Get-ADGroup -Identity $GroupName
        $member = if ($IsGroup) {
            Get-ADGroup -Identity $MemberName
        } else {
            Get-ADUser -Identity $MemberName
        }
        
        # If adding a group, check for circular references
        if ($IsGroup) {
            if (Test-GroupNestingCircular -GroupName $MemberName -TargetGroup $GroupName) {
                Write-Log "Cannot add group '$MemberName' to '$GroupName': Would create a circular reference" -Severity Error
                return
            }
        }
        
        # Add the member to the group
        Add-ADGroupMember -Identity $GroupName -Members $member
        Write-Log "Successfully added $($member.Name) to group $GroupName" -Severity Information
        
        # Show updated group structure
        Show-GroupNestingStructure -GroupName $GroupName
    }
    catch {
        Write-Log "Error adding member to group: $_" -Severity Error
    }
}

function Remove-GroupMembership {
    param(
        [Parameter(Mandatory = $true)]
        [string]$GroupName,
        [Parameter(Mandatory = $true)]
        [string]$MemberName
    )
    
    try {
        # Check if member exists in group
        $group = Get-ADGroup -Identity $GroupName -Properties Members
        $member = Get-ADObject -Filter {Name -eq $MemberName}
        
        if (-not $member) {
            Write-Log "Member $MemberName not found" -Severity Error
            return
        }
        
        Remove-ADGroupMember -Identity $GroupName -Members $member -Confirm:$false
        Write-Log "Successfully removed $MemberName from group $GroupName" -Severity Information
        
        # Show updated group structure
        Show-GroupNestingStructure -GroupName $GroupName
    }
    catch {
        Write-Log "Error removing member from group: $_" -Severity Error
    }
}

function Get-GroupMembers {
    param(
        [Parameter(Mandatory = $true)]
        [string]$GroupName,
        [switch]$ShowNested
    )
    
    try {
        if ($ShowNested) {
            Show-GroupNestingStructure -GroupName $GroupName
        } else {
            $group = Get-ADGroup -Identity $GroupName -Properties Members
            $members = foreach ($member in $group.Members) {
                $obj = Get-ADObject -Identity $member -Properties objectClass, name
                [PSCustomObject]@{
                    Name = $obj.name
                    Type = $obj.objectClass
                }
            }
            
            Write-Host "`nDirect Members of Group: $GroupName" -ForegroundColor Yellow
            $members | Format-Table -AutoSize
            Write-Host "Use -ShowNested switch to see full nested structure" -ForegroundColor Cyan
        }
    }
    catch {
        Write-Log "Error getting group members: $_" -Severity Error
    }
}

function Show-ADGroups {
    Write-Host "`nView Active Directory Groups" -ForegroundColor Yellow
    Write-Host "1. View All Groups" -ForegroundColor Cyan
    Write-Host "2. View Security Groups" -ForegroundColor Cyan
    Write-Host "3. View Distribution Groups" -ForegroundColor Cyan
    Write-Host "4. Search Groups by Name" -ForegroundColor Cyan
    Write-Host "5. View Group Details" -ForegroundColor Cyan
    $choice = Read-Host "`nSelect an option (1-5)"

    try {
        switch ($choice) {
            "1" {
                Write-Host "`nAll Active Directory Groups:" -ForegroundColor Yellow
                Get-ADGroup -Filter * -Properties Description, GroupCategory, GroupScope |
                    Format-Table Name, GroupCategory, GroupScope, Description -AutoSize -Wrap
            }
            "2" {
                Write-Host "`nSecurity Groups:" -ForegroundColor Yellow
                Get-ADGroup -Filter {GroupCategory -eq 'Security'} -Properties Description, GroupScope |
                    Format-Table Name, GroupScope, Description -AutoSize -Wrap
            }
            "3" {
                Write-Host "`nDistribution Groups:" -ForegroundColor Yellow
                Get-ADGroup -Filter {GroupCategory -eq 'Distribution'} -Properties Description, GroupScope |
                    Format-Table Name, GroupScope, Description -AutoSize -Wrap
            }
            "4" {
                $searchTerm = Read-Host "Enter group name to search (wildcards allowed)"
                Write-Host "`nSearch Results:" -ForegroundColor Yellow
                Get-ADGroup -Filter "Name -like '*$searchTerm*'" -Properties Description, GroupCategory, GroupScope |
                    Format-Table Name, GroupCategory, GroupScope, Description -AutoSize -Wrap
            }
            "5" {
                $groupName = Read-Host "Enter group name"
                try {
                    $group = Get-ADGroup -Identity $groupName -Properties *
                    Write-Host "`nGroup Details for: $groupName" -ForegroundColor Yellow
                    Write-Host "Name: $($group.Name)"
                    Write-Host "Category: $($group.GroupCategory)"
                    Write-Host "Scope: $($group.GroupScope)"
                    Write-Host "Description: $($group.Description)"
                    Write-Host "Distinguished Name: $($group.DistinguishedName)"
                    Write-Host "Created: $($group.Created)"
                    Write-Host "Modified: $($group.Modified)"
                    Write-Host "`nMembers:" -ForegroundColor Cyan
                    Get-GroupMembers -GroupName $groupName
                }
                catch {
                    Write-Log "Group not found: $groupName" -Severity Error
                }
            }
            default {
                Write-Log "Invalid option selected for View-ADGroups: $choice" -Severity Warning
            }
        }
    }
    catch {
        Write-Log "Error in View-ADGroups: $_" -Severity Error
    }
    finally {
        Write-Host "`nPress any key to continue..." -ForegroundColor Cyan
        $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    }
}

# Helper function for user confirmations
function Confirm-Action {
    param(
        [string]$Message = "Möchten Sie fortfahren?"
    )
    
    $yes = New-Object System.Management.Automation.Host.ChoiceDescription "&Ja"
    $no = New-Object System.Management.Automation.Host.ChoiceDescription "&Nein"
    $options = [System.Management.Automation.Host.ChoiceDescription[]]($yes, $no)
    
    $result = $host.ui.PromptForChoice("Bestätigung", $Message, $options, 1)
    return $result -eq 0
}

# Functions for managing nested groups
function Get-NestedGroupMembers {
    param(
        [Parameter(Mandatory = $true)]
        [string]$GroupName,
        [int]$Level = 0
    )

    try {
        $indent = "  " * $Level
        $group = Get-ADGroup -Identity $GroupName -Properties Members
        $members = foreach ($member in $group.Members) {
            $obj = Get-ADObject -Identity $member -Properties objectClass
            
            Write-Host "$indent- $($obj.Name) [$($obj.objectClass)]" -ForegroundColor $(if ($obj.objectClass -eq 'group') { 'Cyan' } else { 'White' })
            
            # Recursively get members if the object is a group
            if ($obj.objectClass -eq 'group') {
                Get-NestedGroupMembers -GroupName $obj.Name -Level ($Level + 1)
            }
        }
        return $members
    }
    catch {
        Write-Log "Error getting nested group members for $GroupName : $_" -Severity Error
        return $null
    }
}

function Show-GroupNestingStructure {
    param(
        [Parameter(Mandatory = $true)]
        [string]$GroupName
    )
    
    try {
        Write-Host "`nNested Group Structure for: $GroupName" -ForegroundColor Yellow
        Write-Host "$GroupName (Root Group)" -ForegroundColor Green
        Get-NestedGroupMembers -GroupName $GroupName
    }
    catch {
        Write-Log "Error displaying group nesting structure: $_" -Severity Error
    }
}

function Test-GroupNestingCircular {
    param(
        [Parameter(Mandatory = $true)]
        [string]$GroupName,
        [string]$TargetGroup,
        [System.Collections.ArrayList]$VisitedGroups = @()
    )
    
    try {
        # Check if we've already visited this group (circular reference)
        if ($VisitedGroups -contains $GroupName) {
            return $true
        }
        
        # Add current group to visited list
        [void]$VisitedGroups.Add($GroupName)
        
        # Get all groups that this group is a member of
        $parentGroups = Get-ADPrincipalGroupMembership -Identity $GroupName
        
        foreach ($parent in $parentGroups) {
            if ($parent.Name -eq $TargetGroup) {
                return $true
            }
            
            if (Test-GroupNestingCircular -GroupName $parent.Name -TargetGroup $TargetGroup -VisitedGroups $VisitedGroups) {
                return $true
            }
        }
        
        return $false
    }
    catch {
        Write-Log "Error checking circular group nesting: $_" -Severity Error
        return $true # Return true to prevent potentially dangerous group nesting
    }
}

# Main script execution
try {
    $script:Domain = $null
    Write-Log "Script started" -Severity Info

    # Main menu loop
    do {
        Show-MainMenu
        $mainChoice = Read-Host "`nSelect an option (1-3)"
        
        switch ($mainChoice) {
            '1' { 
                # AD Management Submenu
                do {
                    $menuResult = Show-ADMenu
                    if ($menuResult -eq "exit") { break }
                    
                    $adChoice = Read-Host "`nSelect an option (1-14)"
                    switch ($adChoice) {
                        '1' { Set-ADOrganizationalUnit }
                        '2' { Set-ADGroup }
                        '3' { Set-ADUserManagement }
                        '4' { Set-ComputerAccounts }
                        '5' { Set-GroupMembership }
                        '6' { Show-ADGroups }
                        '7' { Show-OUStructure; pause }
                        '8' { Search-ADObjects; pause }
                        '9' { Reset-AccountLockouts }
                        '10' { Set-UserWallpaper }
                        '11' { Set-CustomPasswordPolicy }
                        '12' { Get-ADDefaultDomainPasswordPolicy | Format-List; pause }
                        '13' { $script:Domain = $null }
                        '14' { break }
                        default { Write-Log "Invalid AD menu option selected: $adChoice" -Severity Warning }
                    }
                } until ($adChoice -eq '14')
            }
            '2' { 
                # System Statistics Submenu
                do {
                    Show-StatsMenu
                    $statsChoice = Read-Host "`nSelect an option (1-11)"
                    
                    switch ($statsChoice) {
                        '1' { 
                            Write-Host "`nCPU Usage: $(Get-CPUUsage)%" -ForegroundColor Yellow
                            pause
                        }
                        '2' { 
                            $memory = Get-MemoryUsage
                            Write-Host "`nMemory Usage:" -ForegroundColor Yellow
                            Write-Host "Total: $($memory.Total) GB"
                            Write-Host "Used: $($memory.Used) GB"
                            Write-Host "Free: $($memory.Free) GB"
                            Write-Host "Usage: $($memory.Percent)%"
                            pause
                        }
                        '3' { 
                            Write-Host "`nDisk Usage:" -ForegroundColor Yellow
                            Get-DiskUsage | ForEach-Object {
                                Write-Host "`nDrive $($_.Drive):"
                                Write-Host "Total: $($_.Total) GB"
                                Write-Host "Used: $($_.Used) GB"
                                Write-Host "Free: $($_.Free) GB"
                                Write-Host "Usage: $($_.Percent)%"
                            }
                            pause
                        }
                        '4' {
                            Write-Host "`nIP Addresses:" -ForegroundColor Yellow
                            Get-IPAddress | ForEach-Object { Write-Host $_ }
                            pause
                        }
                        '5' {
                            $uptime = Get-SystemUptime
                            Write-Host "`nSystem Uptime:" -ForegroundColor Yellow
                            Write-Host "Days: $($uptime.Days)"
                            Write-Host "Hours: $($uptime.Hours)"
                            Write-Host "Minutes: $($uptime.Minutes)"
                            pause
                        }
                        '6' {
                            Write-Host "`nTop CPU-Consuming Processes:" -ForegroundColor Yellow
                            Get-TopProcesses | ForEach-Object {
                                Write-Host "$($_.Name) (PID: $($_.ID)) - CPU: $($_.CPU)%, Memory: $($_.Memory) MB"
                            }
                            pause
                        }
                        '7' {
                            Write-Host "`nNetwork Interfaces:" -ForegroundColor Yellow
                            Get-NetworkStatus | ForEach-Object {
                                Write-Host "Interface: $($_.Name)"
                                Write-Host "Status: $($_.Status)"
                                Write-Host "Speed: $($_.Speed)"
                                Write-Host "Data Received: $($_.BytesReceived) MB"
                                Write-Host "Data Sent: $($_.BytesSent) MB`n"
                            }
                            pause
                        }
                        '8' {
                            Write-Host "`nCritical Services:" -ForegroundColor Yellow
                            Get-CriticalServices | ForEach-Object {
                                Write-Host "$($_.Name) - Status: $($_.Status), Start Type: $($_.StartType)"
                            }
                            pause
                        }
                        '9' {
                            Write-Host "`nRecent System Events:" -ForegroundColor Yellow
                            Get-RecentEvents | ForEach-Object {
                                Write-Host "Time: $($_.TimeGenerated)"
                                Write-Host "Source: $($_.Source)"
                                Write-Host "Event ID: $($_.EventID)"
                                Write-Host "Message: $($_.Message)`n"
                            }
                            pause
                        }
                        '10' { Show-AllStats }
                        '11' { break }
                        default {
                            Write-Log "Invalid statistics menu option selected: $statsChoice" -Severity Warning
                        }
                    }
                } until ($statsChoice -eq '11')
            }
            '3' { 
                Write-Log "Script terminated by user" -Severity Info
                break
            }
            default {
                Write-Log "Invalid main menu option selected: $mainChoice" -Severity Warning
            }
        }
    } until ($mainChoice -eq '3')
}
catch {
    Write-Log "Critical error: $_" -Severity Error
    exit 1
}
