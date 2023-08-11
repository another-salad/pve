
# Parent API Qemu endpoint for each PVE Node. Allows intergtion of the nodes VMs and their various configurations/states.
# https://pve.proxmox.com/pve-docs/api-viewer/index.html#/nodes/{node}/qemu
Function Get-Qemu {
    [CmdletBinding()]
    param (
        $PveDataCenter,
        [string[]]$method,
        [string[]]$endpoint = "",
        [string[]]$nodeName = ""
    )
    $qemuResponse = @{}
    if (-not $nodeName) {
        $nodes = $PveDataCenter.nodeNames
    } else {
        $nodes = $nodeName
    }
    foreach ($node in $nodes.split(" ")) {
        $resp = PveApi $PveDataCenter $method "nodes/$($node)/qemu/$($endpoint)"
        $qemuResponse[$node] = $resp.data
    }
    $qemuResponse
}

Function Get-Vms {
    [CmdletBinding()]
    param (
        $PveDataCenter,
        [string[]]$nodeName = ""
    )
    $nodeVmData = Get-Qemu $PveDataCenter GET -nodeName $nodeName
    $vms = @{}
    foreach ($node in $nodeVmData.keys) {
        $vms[$node] = $nodeVmData.$node | Select-Object -Property vmid,name
    }
    $vms
}

Function Get-VmNetworkInterfaces {
    [CmdletBinding()]
    param (
        $pveNPveDataCenterode,
        [string[]]$nodeName = ""
    )
    $nodeVms = Get-Vms $pveNPveDataCenterode -nodeName $nodeName
    $vmInterfaces = New-Object System.Collections.Generic.List[PSCustomObject]
    foreach ($node in $nodeVms.keys) {
        $allNodeVms = $nodeVms.$node
        foreach ($vm in $allNodeVms) {
            $qemuResp = Get-Qemu $pveNPveDataCenterode GET -nodeName $node "$($vm.vmid)/agent/network-get-interfaces"
            $vmInterface = [PSCustomObject]@{
                node = $node
                vmid = $vm.vmid
                friendlyname = $vm.name
                interfaces = $qemuResp.Values.result
            }
            $vmInterfaces.Add($vmInterface)
        }
    }
    $vmInterfaces
}

Function Print-VmNetworkInterfaces {
    [CmdletBinding()]
    param (
        [Parameter(ValueFromPipeline=$true)]
        $pveNPveDataCenterode
    )
    $allVms = Get-VmNetworkInterfaces $pveNPveDataCenterode | Sort-Object vmid | Sort-Object node
    foreach ($vm in $allVms) {
        Write-Output "-------- Network Interfaces for [$($vm.node)::$($vm.friendlyname)::$($vm.vmid)] --------"
        foreach ($interface in $vm) {
            Write-Output $interface.interfaces | Select-Object name,@{Name="ip-addresses"; Expression={$_."ip-addresses" | ForEach-Object {$_."ip-address"}}}| Sort-Object name | Format-Table -AutoSize
        }
    }
}
