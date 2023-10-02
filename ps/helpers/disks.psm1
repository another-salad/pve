# Helpers for disk management

Import-Module ./helpers/helpers.psm1

function Get-SmartData {
    [CmdletBinding()]
    param (
        $PveDataCenter,
        [string[]]$diskName,
        [string[]]$nodeName = ""
    )
    return Get-NodeData $PveDataCenter GET "disks/smart?disk=$($diskName)" $nodeName
}
