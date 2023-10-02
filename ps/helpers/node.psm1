Import-Module ./helpers/helpers.psm1

# https://pve.proxmox.com/pve-docs/api-viewer/index.html#/nodes/{node}
# Top level node api calls, for example:
# https://pve.proxmox.com/pve-docs/api-viewer/index.html#/nodes/{node}/status

Function Get-Node {
    [CmdletBinding()]
    param (
        $PveDataCenter,
        [string[]]$method,
        [string[]]$endpoint = "",
        [string[]]$nodeName = ""
    )
    $nodeResponse = @{}
    $nodes = Get-NodeNames $PveDataCenter $nodeName
    foreach ($node in $nodes.split(" ")) {
        $resp = PveApi $PveDataCenter $method "nodes/$($node)/$($endpoint)"
        $nodeResponse[$node] = $resp.data
    }
    $nodeResponse
}

Function Get-NodeStatus {
    [CmdletBinding()]
    param (
        $PveDataCenter,
        [string[]]$nodeName = ""
    )
    return Get-Node $PveDataCenter GET status $nodeName
}

Function Print-NodeStatus {
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
