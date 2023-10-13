Import-Module ./helpers/helpers.psm1

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
    return Get-NodeData $PveDataCenter $method "qemu/$($endpoint)" $nodeName
}

Function Get-Vms {
    [CmdletBinding()]
    param (
        [Parameter(ValueFromPipeline=$true)]
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
        [Parameter(ValueFromPipeline=$true)]
        $PveDataCenter,
        [string[]]$nodeName = ""
    )
    $nodeVms = Get-Vms $PveDataCenter -nodeName $nodeName
    $vmInterfaces = New-Object System.Collections.Generic.List[PSCustomObject]
    foreach ($node in $nodeVms.keys) {
        $allNodeVms = $nodeVms.$node
        foreach ($vm in $allNodeVms) {
            try {
                $qemuResp = Get-Qemu $PveDataCenter GET -nodeName $node "$($vm.vmid)/agent/network-get-interfaces"
            } catch {
                $qemuResp = @{}
            }
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
        $PveDataCenter
    )
    $allVms = Get-VmNetworkInterfaces $PveDataCenter | Sort-Object vmid | Sort-Object node
    foreach ($vm in $allVms) {
        Write-Output "-------- Network Interfaces for [$($vm.node)::$($vm.friendlyname)::$($vm.vmid)] --------"
        foreach ($interface in $vm) {
            if ($interface.interfaces) {
                Write-Output $interface.interfaces | Select-Object name,@{Name="ip-addresses"; Expression={$_."ip-addresses" | ForEach-Object {$_."ip-address"}}}| Sort-Object name | Format-Table -AutoSize
            } else {
                Write-Output "`nNo network interfaces found.`n"
            }
        }
    }
}

function Get-VmCurrentStatus {
    [CmdletBinding()]
    param (
        [Parameter(ValueFromPipeline=$true)]
        $PveDataCenter,
        [string[]]$nodeName = ""
    )
    $nodes = Get-NodeNames $PveDataCenter -nodeName $nodeName
    $allVmStatus = @{}
    foreach ($node in $nodes.split(" ")) {
        $allVmStatus[$node] = New-Object System.Collections.Generic.List[PSCustomObject]
        $vms = Get-Vms $PveDataCenter -nodeName $node
        foreach ($vm in $vms.$node) {
            $vmStatus = [PSCustomObject]@{
                vmid = $vm.vmid
                data = (Get-Qemu $PveDataCenter GET -nodeName $node "$($vm.vmid)/status/current").Values
            }
            $allVmStatus[$node].Add($vmStatus)
        }
    }
    $allVmStatus
}

function Print-VmCurrentStatus {
    [CmdletBinding()]
    param (
        [Parameter(ValueFromPipeline=$true)]
        $PveDataCenter
    )
    $allVmStatus = Get-VmCurrentStatus $PveDataCenter
    $attributes = @("name","vmid","status","uptime","running-qemu","cpu","freemem","netin","netout")
    foreach ($node in $allVmStatus.keys) {
        Write-Output "-------- VMs on node: [$($node)] --------"
        $allVmStatus.$node.data | Sort-Object $attributes | Select-Object $attributes | Format-Table -AutoSize
    }
}
