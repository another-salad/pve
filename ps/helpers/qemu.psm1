
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

