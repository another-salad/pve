
Import-Module ./helpers/qemu.psm1

function Read-DockerSecrets {
    $secretsWithValues = @{}
    foreach ($secret in Get-ChildItem /run/secrets/) {
        $secretsWithValues[$secret.Name] = (Get-Content -Raw $secret).Trim()
    }
    $secretsWithValues
}

function Get-Api-Token {
    [CmdletBinding()]
    param (
        [Parameter(ValueFromPipeline=$true)]
        [hashtable[]]$secrets
    )
    @{Authorization = "PVEAPIToken=$($secrets.PveAuthToken)=$($secrets.PveAuthSecret)"}
}

class PveNodeConfig {
    [hashtable]$authToken
    [string]$hostName
    [int]$port = 8006
    [string]$nodeName = ""
    [bool]$SkipCertificateCheck = $false
}

function Get-PveNodeName {
    [CmdletBinding()]
    param (
        [Parameter(ValueFromPipeline=$true)]
        [PveNodeConfig]$pveNode
    )
    $apiResp = PveApi $pveNode GET nodes
    return $apiResp.data.node
}

function Get-PveNodeConfig {
    [OutputType([PveNodeConfig])]
    [CmdletBinding()]
    param(
        [hashtable]$authToken,
        [string]$hostName,
        [int]$port = 8006,
        [switch]$SkipCertificateCheck
    )
    $pveNode = [PveNodeConfig]::new()
    $pveNode.authToken = $authToken
    $pveNode.hostName = $hostName
    $pveNode.port = $port
    $pveNode.SkipCertificateCheck = $SkipCertificateCheck
    $pveNode.nodeName = Get-PveNodeName $pveNode
    $pveNode
}

function PveApi {
    [CmdletBinding()]
    param(
        [PveNodeConfig]$pveNode,
        [string[]]$method,
        [string[]]$endpoint
    )
    $params = @{
        Uri = "https://$($pveNode.hostName):$($pveNode.port)/api2/json/$($endpoint)"
        Method = $method
        SkipCertificateCheck = $pveNode.SkipCertificateCheck
        # Without -SkipHeaderValidation we fall into the issue mentioned here: https://github.com/PowerShell/PowerShell/issues/5818
        # due to the '!' character in the Proxmox authorization header.
        SkipHeaderValidation = $true
        Headers = $pveNode.authToken
    }
    Invoke-RestMethod @params
}