
Import-Module ./helpers/qemu.psm1
Import-Module ./helpers/node.psm1

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

# I'll be American here as it seems the right thing to do
class PveDataCenterConfig {
    [hashtable]$authToken
    [string]$hostName
    [int]$port = 8006
    [string]$nodeNames = ""
    [bool]$SkipCertificateCheck = $false
}

function Get-ActivePveNodeNames {
    [CmdletBinding()]
    param (
        [Parameter(ValueFromPipeline=$true)]
        [PveDataCenterConfig]$pveDataCenter
    )
    $apiResp = PveApi $pveDataCenter GET nodes
    return ($apiResp.data | Where-Object {$_.status -eq "online"}).node
}

function Get-DataCenterConfig {
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

function PveApi {
    [CmdletBinding()]
    param(
        [PveDataCenterConfig]$pveDc,
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
