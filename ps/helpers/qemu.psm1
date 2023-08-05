
# Parent API Qemu endpoint for each PVE Node. Allows intergtion of the nodes VMs and their various configurations/states.
# https://pve.proxmox.com/pve-docs/api-viewer/index.html#/nodes/{node}/qemu
Function Get-Qemu {
    [CmdletBinding()]
    param (
        $pveNode,
        [string[]]$method,
        [string[]]$endpoint = ""
    )
    return PveApi $pveNode $method "nodes/$($pveNode.nodeName)/qemu/$($endpoint)"
}

Function Get-NodeVms {
    [CmdletBinding()]
    param (
        [Parameter(ValueFromPipeline=$true)]
        $pveNode
    )
    $qemuResp = PveApi $pveNode GET "nodes/$($pveNode.nodeName)/qemu/"
    return $qemuResp.data | Select-Object -Property vmid,name
}

Function Get-VmNetworkInterfaces {
    [CmdletBinding()]
    param (
        [Parameter(ValueFromPipeline=$true)]
        $pveNode
    )
    $nodeVms = $pveNode | Get-NodeVms
    $vmInterfaces = New-Object System.Collections.Generic.List[PSCustomObject]
    foreach ($vm in $nodeVms) {
        $qemuResp = Get-Qemu $pveNode GET "$($vm.vmid)/agent/network-get-interfaces"
        $vmInterface = [PSCustomObject]@{
            vmid = $vm.vmid
            friendlyname = $vm.name
            interfaces = $qemuResp.data.result
        }
        $vmInterfaces.Add($vmInterface)
    }
    $vmInterfaces
}

Function Print-VmNetworkInterfaces {
    [CmdletBinding()]
    param (
        [Parameter(ValueFromPipeline=$true)]
        $pveNode
    )
    $allVms = $pveNode | Get-VmNetworkInterfaces | Sort-Object vmid
    foreach ($vm in $allVms) {
        Write-Output "-------- Network Interfaces for VM [$($vm.friendlyname) :: $($vm.vmid)] --------"
        foreach ($interface in $vm) {
            Write-Output $interface.interfaces | Select-Object name,@{Name="ip-addresses"; Expression={$_."ip-addresses" | ForEach-Object {$_."ip-address"}}}| Sort-Object name | Format-Table -AutoSize
        }
    }
}
