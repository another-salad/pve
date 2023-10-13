Import-Module ./helpers/helpers.psm1

# https://pve.proxmox.com/pve-docs/api-viewer/index.html#/nodes/{node}/lxc

Function Get-Lxc {
    [CmdletBinding()]
    param (
        $PveDataCenter,
        [string[]]$method = "GET",
        [string[]]$endpoint = "",
        [string[]]$nodeName = ""
    )
    return Get-NodeData $PveDataCenter $method "lxc/$($endpoint)" $nodeName
}

Function Get-Lxc-Status {
    [CmdletBinding()]
    param (
        $PveDataCenter,
        [string[]]$nodeName = ""
    )
    return Get-Lxc $PveDataCenter GET -nodename $nodeName
}

Function Print-Lxc-Status {
    [CmdletBinding()]
    param (
        $PveDataCenter,
        [string[]]$nodeName = ""
    )
    $lxcStatus = Get-Lxc-Status $PveDataCenter $nodeName
    $attributes = @("name","vmid","status","uptime","cpus","mem","swap","diskwrite","disk","netin","netout")
    foreach ($node in $lxcStatus.keys) {
        Write-Output "-------- (LXC) Containers on node: [$($node)] --------"
        if ($lxcStatus.$node) {
            $lxcStatus.$node | Sort-Object $attributes | Format-Table -AutoSize -Property $attributes
        } else {
            Write-Output "`nNo containers found.`n"
        }
    }
}
