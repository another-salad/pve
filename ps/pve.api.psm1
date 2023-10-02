
# Third party MS
Import-Module Microsoft.PowerShell.SecretManagement
Import-Module Microsoft.PowerShell.SecretStore

Import-Module ./helpers/qemu.psm1
Import-Module ./helpers/node.psm1

function Read-DockerSecrets {
    $secretsWithValues = @{}
    foreach ($secret in Get-ChildItem /run/secrets/) {
        $secretsWithValues[$secret.Name] = (Get-Content -Raw $secret).Trim()
    }
    $secretsWithValues
}

function Get-Api-Token-From-Docker-Secrets {
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
function Get-Api-Token-From-Vault {
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
    [string]$nodeNames = ""
    [bool]$SkipCertificateCheck = $false
}

function Get-ActivePveNodeNames {
    [CmdletBinding()]
    param (
        [Parameter(ValueFromPipeline=$true)]
        [PveDataCenterConfig]$pveDataCenter
    )
    return ($pveDataCenter | Get-Nodes | Where-Object {$_.status -eq "online"}).node
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
