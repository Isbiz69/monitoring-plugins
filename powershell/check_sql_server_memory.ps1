######################## check_sql_server_memory.ps1 #########################
######################## Author: Isaac NOURI #################################
######################## Date: 2025-05-05 ####################################
######################## Version: 1.0 ########################################

######################## CHANGELOG ############################################

param(
    [Parameter(Mandatory = $true)]
    [string]$Instance,

    [Parameter(Mandatory = $true)]
    [string]$Username,

    [Parameter(Mandatory = $true)]
    [string]$Password,

    [int]$WarningThreshold = 80,
    [int]$CriticalThreshold = 90
)

$Status_OK = 0
$Status_WARNING = 1
$Status_CRITICAL = 2
$Status_UNKNOWN = 3

# First SQL query: retrieves the memory currently used and allocated by SQL Server in MB
$sql1 = @"
SELECT
  (committed_kb / 1024.0) AS Total_Server_Memory_MB,
  (committed_target_kb / 1024.0) AS Target_Server_Memory_MB
FROM sys.dm_os_sys_info;
"@

# Second SQL query: retrieves the total physical memory of the server in MB
$sql2 = @"
SELECT
  (total_physical_memory_kb / 1024.0) AS Total_OS_Memory_MB
FROM sys.dm_os_sys_memory;
"@

$connection = $null
$reader1 = $null
$reader2 = $null

try {
    if ($WarningThreshold -lt 0 -or $WarningThreshold -gt 100 -or
        $CriticalThreshold -lt 0 -or $CriticalThreshold -gt 100 -or
        $WarningThreshold -ge $CriticalThreshold) {
        Write-Output "[UNKNOWN] - Invalid thresholds | 'sql_ram_total_gb'=0; 'sql_ram_used_gb'=0; 'sql_ram_allocated_gb'=0;"
        exit $Status_UNKNOWN
    }

    $fullInstance = "$env:COMPUTERNAME\$Instance"
    $connectionString = "Server=$fullInstance;Database=master;User ID=$Username;Password=$Password;Trusted_Connection=False;"

    $connection = New-Object System.Data.SqlClient.SqlConnection $connectionString
    $connection.Open()

    # SQL Server memory
    $cmd1 = $connection.CreateCommand()
    $cmd1.CommandText = $sql1
    $reader1 = $cmd1.ExecuteReader()

    if (-not $reader1.Read()) {
        Write-Output "[UNKNOWN] - Unable to read SQL Server memory | 'sql_ram_total_gb'=0; 'sql_ram_used_gb'=0; 'sql_ram_allocated_gb'=0;"
        exit $Status_UNKNOWN
    }

    $usedMB = [math]::Round($reader1["Total_Server_Memory_MB"], 2)
    $allocatedMB = [math]::Round($reader1["Target_Server_Memory_MB"], 2)
    $reader1.Close()
    $reader1 = $null

    if ($allocatedMB -eq 0) {
        Write-Output "[UNKNOWN] - Allocated SQL Server memory is zero | 'sql_ram_total_gb'=0; 'sql_ram_used_gb'=0; 'sql_ram_allocated_gb'=0;"
        exit $Status_UNKNOWN
    }

    # Physical server memory
    $cmd2 = $connection.CreateCommand()
    $cmd2.CommandText = $sql2
    $reader2 = $cmd2.ExecuteReader()

    if (-not $reader2.Read()) {
        Write-Output "[UNKNOWN] - Unable to read physical server memory | 'sql_ram_total_gb'=0; 'sql_ram_used_gb'=0; 'sql_ram_allocated_gb'=0;"
        exit $Status_UNKNOWN
    }

    $totalOSMB = [math]::Round($reader2["Total_OS_Memory_MB"], 2)
    $reader2.Close()
    $reader2 = $null

    # Convert MB to GB
    $usedGB = [math]::Round($usedMB / 1024, 2)
    $allocatedGB = [math]::Round($allocatedMB / 1024, 2)
    $totalOSGB = [math]::Round($totalOSMB / 1024, 0)

    # Calculate the percentage of allocated SQL Server memory currently in use
    $percentUsedOverAllocated = [math]::Round(($usedMB / $allocatedMB) * 100, 2)

    # Performance data for Icinga, Nagios, InfluxDB and Grafana
    $perfdata = "'sql_ram_total_gb'=${totalOSGB}; 'sql_ram_used_gb'=${usedGB}; 'sql_ram_allocated_gb'=${allocatedGB};"

    # Plugin output message
    $message = "- SQL Server memory: $percentUsedOverAllocated% used ($usedGB GB / $allocatedGB GB) - Total server RAM: $totalOSGB GB | $perfdata"

    if ($percentUsedOverAllocated -ge $CriticalThreshold) {
        Write-Output "[CRITICAL] $message"
        exit $Status_CRITICAL
    }
    elseif ($percentUsedOverAllocated -ge $WarningThreshold) {
        Write-Output "[WARNING] $message"
        exit $Status_WARNING
    }
    else {
        Write-Output "[OK] $message"
        exit $Status_OK
    }
}
catch {
    Write-Output "[UNKNOWN] - SQL Server query failed: $($_.Exception.Message) | 'sql_ram_total_gb'=0; 'sql_ram_used_gb'=0; 'sql_ram_allocated_gb'=0;"
    exit $Status_UNKNOWN
}
finally {
    if ($reader1 -and -not $reader1.IsClosed) {
        $reader1.Close()
    }

    if ($reader2 -and -not $reader2.IsClosed) {
        $reader2.Close()
    }

    if ($connection -and $connection.State -ne [System.Data.ConnectionState]::Closed) {
        $connection.Close()
    }
}
