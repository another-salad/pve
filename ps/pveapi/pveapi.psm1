
# Third party MS
Import-Module Microsoft.PowerShell.SecretManagement
Import-Module Microsoft.PowerShell.SecretStore

function Read-DockerSecrets {
    $secretsWithValues = @{}
    foreach ($secret in Get-ChildItem /run/secrets/) {
        $secretsWithValues[$secret.Name] = (Get-Content -Raw $secret).Trim()
    }
    $secretsWithValues
}

function Get-ApiTokenFromDockerSecrets {
    [CmdletBinding()]
    param (
        [Parameter(ValueFromPipeline=$true)]
        [hashtable[]]$secrets
    )
    @{Authorization = "PVEAPIToken=$($secrets.PveAuthToken)=$($secrets.PveAuthSecret)"}
}

# This will require a vault to be configured, and the secret to be stored in it.
# Might be preferable to use docker secrets. Either way, you have two options.
# More info on Microsoft.PowerShell.SecretManagement and SecretStore:
# https://learn.microsoft.com/en-us/powershell/utility-modules/secretmanagement/get-started/using-secretstore?view=ps-modules
function Get-ApiTokenFromVault {
    [CmdletBinding()]
    param (
        $secretName,
        $vaultName = ""
    )
    $secret = Get-Secret -Name $secretName -Vault $vaultName -AsPlainText
    @{Authorization = "PVEAPIToken=$($secret)"}
}

# I'll be American here as it seems the right thing to do
class PveDataCenterConfig {
    [hashtable]$authToken
    [string]$hostName
    [int]$port = 8006
    [string[]]$nodeNames = @()
    [bool]$SkipCertificateCheck = $false
}

function Get-ActivePveNodeNames {
    [CmdletBinding()]
    param (
        [Parameter(ValueFromPipeline=$true)]
        $pveDataCenter
    )
    return (($pveDataCenter | Get-Nodes | Where-Object {$_.status -eq "online"}).node).Split(" ")
}

function New-DataCenterConfig {
    [OutputType([PveDataCenterConfig])]
    [CmdletBinding()]
    param(
        [hashtable]$authToken,
        [string]$hostName,
        [int]$port = 8006,
        [switch]$SkipCertificateCheck
    )
    $pveDc = [PveDataCenterConfig]::new()
    $pveDc.authToken = $authToken
    $pveDc.hostName = $hostName
    $pveDc.port = $port
    $pveDc.SkipCertificateCheck = $SkipCertificateCheck
    $pveDc.nodeNames = Get-ActivePveNodeNames $pveDc
    $pveDc
}

function New-PveApiCall {
    [CmdletBinding()]
    param(
        $pveDc,
        [string[]]$method,
        [string[]]$endpoint
    )
    $params = @{
        Uri = "https://$($pveDc.hostName):$($pveDc.port)/api2/json/$($endpoint)"
        Method = $method
        SkipCertificateCheck = $pveDc.SkipCertificateCheck
        # Without -SkipHeaderValidation we fall into the issue mentioned here: https://github.com/PowerShell/PowerShell/issues/5818
        # due to the '!' character in the Proxmox authorization header.
        SkipHeaderValidation = $true
        Headers = $pveDc.authToken
    }
    Invoke-RestMethod @params
}

Function Get-NodeNames {
    [CmdletBinding()]
    param (
        [Parameter(ValueFromPipeline=$true)]
        $pveDc,
        [string]$nodeName = ""
    )
    if (-not $nodeName) {
        $nodes = $pveDc.nodeNames
    } else {
        $nodes = $nodeName
    }
    $nodes
}

# NOTE TO SELF, THIS WILL BREAK EVERYTHING SITTING ON TOP OF IT
Function ForEachNode {
    param (
        [Parameter(Mandatory=$true)]
        $PveDataCenter,
        [Parameter(Mandatory=$false)]
        $NodeName = "",
        [Parameter(Mandatory=$true)]
        [scriptblock]$ScriptBlock
    )
    $nodes = Get-NodeNames $PveDataCenter $NodeName
    foreach ($node in $nodes) {
        & $ScriptBlock $node
    }
}

Function Get-NodeData {
    [CmdletBinding()]
    param (
        $PveDataCenter,
        [string]$method,
        [string]$endpoint,
        [string]$nodeName = ""
    )
    $nodeResponse = New-Object PSObject
    ForEachNode -PveDataCenter $PveDataCenter -NodeName $nodeName -ScriptBlock {
        param($node)
        $resp = New-PveApiCall $PveDataCenter $method "nodes/$($node)/$($endpoint)"
        $nodeResponse | Add-Member -MemberType NoteProperty -Name $node -Value $resp.data
    }
    $nodeResponse
}

function Get-DisksRaw {
    [CmdletBinding()]
    param (
        $PveDataCenter,
        [string]$ApiEndpoint,
        [string]$NodeName = ""
    )
    return Get-NodeData $PveDataCenter GET "disks/$ApiEndpoint" $NodeName
}

Function Get-DisksList {
    [CmdletBinding()]
    param (
        [Parameter(ValueFromPipeline=$true)]
        $PveDataCenter,
        [string]$NodeName = ""
    )
    return Get-DisksRaw $PveDataCenter "list" $NodeName
}

Function Get-SmartDiskDataRaw {
    [CmdletBinding()]
    param (
        $PveDataCenter,
        [string]$DevPath,
        [string]$NodeName
    )
    return Get-DisksRaw $PveDataCenter "smart?disk=$($DevPath)" $NodeName
}

Function Get-DisksSmart {
    [CmdletBinding()]
    param (
        [Parameter(ValueFromPipeline=$true)]
        $PveDataCenter,
        [string]$NodeName = ""
    )
    $disks = Get-Disks $PveDataCenter $nodeName
    ForEachNode -PveDataCenter $PveDataCenter -NodeName $nodeName -ScriptBlock {
        param($node)
        Get-SmartDiskDataRaw $PveDataCenter $disks.$node.devpath $node
    }

}

# Full fat smart data, likely too much for casual drive checking
function Get-SmartData {
    [CmdletBinding()]
    param (
        [Parameter(ValueFromPipeline=$true)]
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
    return Get-NodeData $PveDataCenter GET "disks/smart?disk=$diskName" $nodeName
}

function Show-DiskStatus {
    [CmdletBinding()]
    param (
        [Parameter(ValueFromPipeline=$true)]
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

# https://pve.proxmox.com/pve-docs/api-viewer/index.html#/nodes/{node}
# Top level node api calls, for example:
# https://pve.proxmox.com/pve-docs/api-viewer/index.html#/nodes/{node}/status
function Get-Nodes {
    [CmdletBinding()]
    param (
        [Parameter(ValueFromPipeline=$true)]
        $pveDataCenter
    )
    $apiResp = New-PveApiCall $pveDataCenter GET nodes
    return $apiResp.data
}

Function Get-NodeStatus {
    [CmdletBinding()]
    param (
        [Parameter(ValueFromPipeline=$true)]
        $PveDataCenter,
        [string[]]$nodeName = ""
    )
    return Get-NodeData $PveDataCenter GET status $nodeName
}

Function Show-NodeInfo {
    [CmdletBinding()]
    param (
        [Parameter(ValueFromPipeline=$true)]
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

Function Show-NodeStatus {
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

Function Show-VmNetworkInterfaces {
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
    foreach ($node in $nodes) {
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

function Show-VmCurrentStatus {
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

# https://pve.proxmox.com/pve-docs/api-viewer/index.html#/nodes/{node}/lxc
Function Get-Lxc {
    [CmdletBinding()]
    param (
        [Parameter(ValueFromPipeline=$true)]
        $PveDataCenter,
        [string[]]$method = "GET",
        [string[]]$endpoint = "",
        [string[]]$nodeName = ""
    )
    return Get-NodeData $PveDataCenter $method "lxc/$($endpoint)" $nodeName
}

Function Get-LxcStatus {
    [CmdletBinding()]
    param (
        [Parameter(ValueFromPipeline=$true)]
        $PveDataCenter,
        [string[]]$nodeName = ""
    )
    return Get-Lxc $PveDataCenter GET -nodename $nodeName
}

Function Show-LxcStatus {
    [CmdletBinding()]
    param (
        [Parameter(ValueFromPipeline=$true)]
        $PveDataCenter,
        [string[]]$nodeName = ""
    )
    $lxcStatus = Get-LxcStatus $PveDataCenter $nodeName
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