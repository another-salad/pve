# Helpers for disk management

Import-Module ./helpers/helpers.psm1

function Get-Disks {
    [CmdletBinding()]
    param (
        $PveDataCenter,
        [string[]]$nodeName = ""
    )
    return Get-NodeData $PveDataCenter GET disks/list $nodeName
}

# Full fat smart data, likely too much for casual drive checking
function Get-SmartData {
    [CmdletBinding()]
    param (
        $PveDataCenter,
        [string[]]$diskName = "",
        [string[]]$nodeName = ""
    )
    if (-not $diskName) {
        $smartData = @{}
        $disks = Get-Disks $PveDataCenter $nodeName
        # iterate through the disks and get the smart data for each
        $disks.GetEnumerator() | ForEach-Object {
            $smartData[$_.Name] = Get-NodeData $PveDataCenter GET "disks/smart?disk=$($_.Value.devpath)" $_.Name
        }
        return $smartData
    } elseif (-not $nodeName) {
        Write-Error "You must specify a node name if you specify a disk name"
        return
    }
    return Get-NodeData $PveDataCenter GET "disks/smart?disk=$($diskName)" $nodeName
}

function Print-DiskData {
    [CmdletBinding()]
    param (
        $PveDataCenter,
        [string[]]$nodeName = ""
    )
    $disks = Get-Disks $PveDataCenter $nodeName
    $disks.GetEnumerator() | ForEach-Object {
        $node = $_.Name
        $_.Value
    } | Format-Table -AutoSize -Property (
        @{Label="node"; Expression={$node}},
        @{Label="devpath"; Expression={$_.devpath}},
        @{Label="used"; Expression={$_.used}},
        @{Label="model"; Expression={$_.model}},
        @{Label="type"; Expression={$_.type}},
        @{Label="size"; Expression={$_.size}},
        @{Label="vendor"; Expression={$_.vendor}},
        @{Label="serial"; Expression={$_.serial}},
        @{Label="health"; Expression={$_.health}},
        @{Label="wearout"; Expression={$_.wearout}}
    )
}