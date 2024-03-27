# Helper for determining if we are interacting with a single of multiole nodes
Function Get-NodeNames {
    [CmdletBinding()]
    param (
        [Parameter(ValueFromPipeline=$true)]
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

Function Get-NodeData {
    [CmdletBinding()]
    param (
        $PveDataCenter,
        [string[]]$method,
        [string[]]$endpoint = "",
        [string[]]$nodeName = ""
    )
    $nodeResponse = @{}
    $nodes = Get-NodeNames $PveDataCenter $nodeName
    foreach ($node in $nodes.split(" ")) {
        $resp = PveApi $PveDataCenter $method "nodes/$($node)/$($endpoint)"
        $nodeResponse[$node] = $resp.data
    }
    $nodeResponse
}