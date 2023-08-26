# Helper for determining if we are interacting with a single of multiole nodes
Function Get-NodeNames {
    [CmdletBinding()]
    param (
        $pveDc,
        [string[]]$nodeName = ""
    )
    if (-not $nodeName) {
        $nodes = $pveDc.nodeNames
    } else {
        $nodes = $nodeName
    }
    $nodes
}
