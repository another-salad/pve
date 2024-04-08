
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
    $pveDc
}

# The next two require some thought, bootstrapping innit.
function Find-ActiveNodeNames {
    [CmdletBinding()]
    param ()
    return (((New-PveApiCall GET nodes).data | Where-Object {$_.status -eq "online"}).node).Split(" ")
}

function New-PveSession {
    [CmdletBinding()]
    param (
        [Parameter(ValueFromPipeline, Mandatory)]
        $pveDataCenter
    )
    process {
        $script:PveDCConfiguration = $pveDataCenter
        $script:PveDCConfiguration.nodeNames = Find-ActiveNodeNames
    }
}

function New-PveApiCall {
    [CmdletBinding()]
    param(
        [string]$method,
        [string]$endpoint
    )
    $params = @{
        Uri = "https://$($script:PveDCConfiguration.hostName):$($script:PveDCConfiguration.port)/api2/json/$($endpoint)"
        Method = $method
        SkipCertificateCheck = $script:PveDCConfiguration.SkipCertificateCheck
        # Without -SkipHeaderValidation we fall into the issue mentioned here: https://github.com/PowerShell/PowerShell/issues/5818
        # due to the '!' character in the Proxmox authorization header.
        SkipHeaderValidation = $true
        Headers = $script:PveDCConfiguration.authToken
    }
    Invoke-RestMethod @params
}

Function Get-NodeNames {
    [CmdletBinding()]
    param (
        [Parameter(ValueFromPipeline=$true)]
        [string]$nodeName
    )
    process {
        if ($nodeName) {
            $nodes = $nodeName
        } else {
            $nodes = $script:PveDCConfiguration.nodeNames
        }
    }
    end {
        $nodes
    }
}

# NOTE TO SELF, THIS WILL BREAK EVERYTHING SITTING ON TOP OF IT
Function ForEachNode {
    param (
        [Parameter(Mandatory=$true)]
        $NodeName,
        [scriptblock]$ScriptBlock
    )
    $nodes = Get-NodeNames $NodeName
    foreach ($node in $nodes) {
        & $ScriptBlock $node
    }
}

Function Get-NodeData {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$Method,
        [Parameter(Mandatory=$true)]
        [string]$Endpoint,
        [string]$NodeName
    )
    $nodeResponse = New-Object PSObject
    ForEachNode -NodeName $NodeName -ScriptBlock {
        param($node)
        $resp = New-PveApiCall $Method "nodes/$($node)/$($Endpoint)"
        $nodeResponse | Add-Member -MemberType NoteProperty -Name $node -Value $resp.data
    }
    $nodeResponse
}

function Get-DisksRaw {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$ApiEndpoint,
        [string]$NodeName
    )
    return Get-NodeData GET "disks/$ApiEndpoint" $NodeName
}

Function Get-DisksList {
    [CmdletBinding()]
    param (
        [Parameter(ValueFromPipeline=$true)]
        [string]$NodeName
    )
    process {
        return Get-DisksRaw "list" $NodeName
    }
}

Function Format-TablePve {
    [CmdletBinding()]
    param (
        [Parameter(ValueFromPipeline=$true)]
        $Blob
    )
    process {
        $noteProperties = $Blob | Get-Member -MemberType NoteProperty
        $tableList = @()
        foreach ($noteProperty in $noteProperties) {
            $obj = New-Object -Type PSObject
            $obj | Add-Member -MemberType NoteProperty -Name "NodeName" -Value $noteProperty.Name
            $nestedNoteProperties = $Blob.$($noteProperty.Name) | Get-Member -MemberType NoteProperty
            foreach ($nestedNoteProperty in $nestedNoteProperties) {
                $obj | Add-Member -MemberType NoteProperty -Name $nestedNoteProperty.Name -Value ($Blob.$($noteProperty.Name).$($nestedNoteProperty.Name))
            }
            $tableList += $obj
        }
        $tableList | Format-Table -AutoSize
    }
}

Function Get-SmartDiskDataRaw {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        $PveDataCenter,
        [Parameter(Mandatory=$true)]
        [string]$DevPath,
        [Parameter(Mandatory=$true)]
        [string]$NodeName
    )
    return Get-DisksRaw $PveDataCenter "smart?disk=$($DevPath)" $NodeName
}

Function Get-DisksSmart {
    [CmdletBinding()]
    param (
        $PveDataCenter,
        [Parameter(Mandatory=$true)]
        [string]$NodeName
    )
    $disks = $NodeName | Get-DisksList
    $DisksObj = New-Object PSObject
    ForEachNode -NodeName $nodeName -ScriptBlock {
        param($node)
        $DisksObj | Add-Member -MemberType NoteProperty -Name $node -Value (Get-SmartDiskDataRaw $disks.$node.devpath $node).$node
    }
    $DisksObj
}


# https://pve.proxmox.com/pve-docs/api-viewer/index.html#/nodes/{node}
# Top level node api calls, for example:
# https://pve.proxmox.com/pve-docs/api-viewer/index.html#/nodes/{node}/status
Function Get-NodeStatus {
    [CmdletBinding()]
    param ()
    return Get-NodeData GET status
}


Function Get-NodeCpuInfo {
    [CmdletBinding()]
    param ()
    $nodeData = Get-NodeStatus
    $ParentObject = New-Object -Type PSObject
    foreach ($prop in ($nodeData | Get-Member -MemberType NoteProperty)) {
        $PropMap = @{
            model = $nodeData.$($prop.Name).cpuinfo.model
            cores = $nodeData.$($prop.Name).cpuinfo.cores
            sockets = $nodeData.$($prop.Name).cpuinfo.sockets
            mhz = $nodeData.$($prop.Name).cpuinfo.mhz
        }
        $nestedObject = New-Object -Type PSObject
        foreach ($key in $PropMap.Keys) {
            $nestedObject | Add-Member -MemberType NoteProperty -Name $key -Value $PropMap.$key
        }
        $ParentObject | Add-Member -MemberType NoteProperty -Name $prop.Name -Value $nestedObject
    }
    $ParentObject
}

Function Get-NodeMemory {
    [CmdletBinding()]
    param ()
    $nodeData = Get-NodeStatus
    $ParentObject = New-Object -Type PSObject
    foreach ($prop in ($nodeData | Get-Member -MemberType NoteProperty)) {
        $nestedObject = New-Object -Type PSObject
        $nestedObject | Add-Member -MemberType NoteProperty -Name "total" -Value $nodeData.$($prop.Name).memory.total
        $nestedObject | Add-Member -MemberType NoteProperty -Name "free" -Value $nodeData.$($prop.Name).memory.free
        $nestedObject | Add-Member -MemberType NoteProperty -Name "used" -Value $nodeData.$($prop.Name).memory.used
        $nestedObject | Add-Member -MemberType NoteProperty -Name "PercentUsed" -Value ($nodeData.$($prop.Name).memory.used / $nodeData.$($prop.Name).memory.total * 100)
        $ParentObject | Add-Member -MemberType NoteProperty -Name $prop.Name -Value $nestedObject
    }
    $ParentObject
}

# Parent API Qemu endpoint for each PVE Node. Allows intergtion of the nodes VMs and their various configurations/states.
# https://pve.proxmox.com/pve-docs/api-viewer/index.html#/nodes/{node}/qemu
Function Get-Qemu {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$Method,
        [Parameter(Mandatory=$true)]
        [string]$nodeName,
        [string]$endpoint
    )
    return Get-NodeData $Method "qemu/$Endpoint" $NodeName
}

Function Get-Vms {
    [CmdletBinding()]
    param (
        [Parameter(ValueFromPipeline=$true)]
        [string]$nodeName
    )
    $nodeVmData = Get-Qemu GET -nodeName $nodeName
    $vms = @{}
    foreach ($node in $nodeVmData.keys) {
        $vms[$node] = $nodeVmData.$node | Select-Object -Property vmid,name
    }
    $vms
}

Function Get-VmNetworkInterfaces {
    [CmdletBinding()]
    param (
        [string]$nodeName
    )
    $nodeVms = $nodeName | Get-Vms
    $vmInterfaces = New-Object System.Collections.Generic.List[PSCustomObject]
    foreach ($node in $nodeVms.keys) {
        $allNodeVms = $nodeVms.$node
        foreach ($vm in $allNodeVms) {
            try {
                $qemuResp = Get-Qemu GET -nodeName $node "$($vm.vmid)/agent/network-get-interfaces"
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

function Get-VmCurrentStatus {
    [CmdletBinding()]
    param (
        [string]$nodeName
    )
    $nodes = Get-NodeNames -nodeName $nodeName
    $allVmStatus = @{}
    foreach ($node in $nodes) {
        $allVmStatus[$node] = New-Object System.Collections.Generic.List[PSCustomObject]
        $vms = Get-Vms -nodeName $node
        foreach ($vm in $vms.$node) {
            $vmStatus = [PSCustomObject]@{
                vmid = $vm.vmid
                data = (Get-Qemu GET -nodeName $node "$($vm.vmid)/status/current").Values
            }
            $allVmStatus[$node].Add($vmStatus)
        }
    }
    $allVmStatus
}

# https://pve.proxmox.com/pve-docs/api-viewer/index.html#/nodes/{node}/lxc
Function Get-Lxc {
    [CmdletBinding()]
    param (
        [string]$method = "GET",
        [string]$endpoint,
        [string]$nodeName
    )
    return Get-NodeData $method "lxc/$($endpoint)" $nodeName
}

Function Get-LxcStatus {
    [CmdletBinding()]
    param (
        [Parameter(ValueFromPipeline=$true)]
        [string]$nodeName
    )
    return Get-Lxc GET -nodename $nodeName
}
