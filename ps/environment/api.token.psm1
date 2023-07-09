# Assumption is we are in our container with the docker secrets we required sitting in /run/secrets

function Read-Secrets {
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
