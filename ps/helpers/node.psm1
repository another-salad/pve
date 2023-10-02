Import-Module ./helpers/helpers.psm1

# https://pve.proxmox.com/pve-docs/api-viewer/index.html#/nodes/{node}
# Top level node api calls, for example:
# https://pve.proxmox.com/pve-docs/api-viewer/index.html#/nodes/{node}/status


function Get-Nodes {
    [CmdletBinding()]
    param (
        [Parameter(ValueFromPipeline=$true)]
        $pveDataCenter
    )
    $apiResp = PveApi $pveDataCenter GET nodes
    return $apiResp.data
}

Function Get-NodeStatus {
    [CmdletBinding()]
    param (
        $PveDataCenter,
        [string[]]$nodeName = ""
    )
    return Get-NodeData $PveDataCenter GET status $nodeName
}

Function Print-NodeInfo {
    [CmdletBinding()]
    param (
        $PveDataCenter,
        [string[]]$nodeName = ""
    )
    $nodeStatus = Get-NodeStatus $PveDataCenter $nodeName
    $nodeStatus.GetEnumerator() | ForEach-Object {
            $node = $_.Name
            $nodeStatus.$node
        } | Format-Table -AutoSize -Property (
            @{Label="node"; Expression={$node}},
            @{Label="cpuModel"; Expression={$_.cpuinfo.model}},
            @{Label="cpuCores"; Expression={$_.cpuinfo.cores}},
            @{Label="kernel"; Expression={$_.kversion}},
            @{Label="pveVersion"; Expression={$_.pveversion}},
            @{Label="uptime"; Expression={$_.uptime}},
            @{Label="memory"; Expression={$_.memory}},
            @{Label="loadavg"; Expression={$_.loadavg}},
            @{Label="filesystem"; Expression={$_.rootfs}},
            @{Label="wait"; Expression={$_.wait}}
        )
}

Function Print-NodeStatus {
    [CmdletBinding()]
    param (
        [Parameter(ValueFromPipeline=$true)]
        $PveDataCenter
    )
    Get-Nodes $PveDataCenter | Sort-Object node | Format-Table -AutoSize -Property (
        @{Label="node"; Expression={$_.node}},
        @{Label="status"; Expression={$_.status}}
    )
}
