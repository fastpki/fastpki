output "node_ips" {
  value       = { for k, n in local.nodes : n.name => n.mgmt_ip }
  description = "Management address of each node."
}

output "console_urls" {
  value       = { for k, n in local.nodes : n.name => "https://${n.mgmt_ip}:8090/" }
  description = "The management console on each node."
}

output "interconnect_ips" {
  value       = { for k, n in local.nodes : n.name => n.interconnect_ip if n.interconnect_ip != "" }
  description = "Replication addresses, when an interconnect bridge was given."
}

output "mesh_join" {
  value       = var.node_count < 2 ? "" : "deploy/mesh-join.sh -i <your ssh key> ${join(" ", [for k, n in local.nodes : "alpine@${n.mgmt_ip}"])}"
  description = <<-EOT
    The command that connects the nodes, to run from your own machine once every node is up.
    The first run tells every node about the others and stops because no CA exists yet;
    create the CAs, then run it again and it finishes (docs/deployment.md 9.0, steps 3 and 9).
    This module does not run it itself: it needs every peer, so it cannot run while the first
    node is still being created. Each node is a complete CA on its own until it does.
  EOT
}

output "next_steps" {
  value       = <<-EOT
    Nodes: ${join(", ", [for k, n in local.nodes : "${n.name} (${n.mgmt_ip})"])}

    1. First boot takes a minute or two. It has finished when
       /var/log/fastpki-firstboot.rc reads 0 — anything else means the installer failed
       and /var/log/fastpki-firstboot.log says why.
    2. The console answers on port 8090 over HTTPS with the certificate the node issued
       itself at first boot, so expect a trust warning until you replace it.
    3. Escalate with `doas`, not sudo: Alpine's cloud image has shipped no sudo since 3.16.
    4. ${var.node_count > 1 ? "Mesh them with the command in the mesh_join output, run twice: once before creating the CAs and once after." : "Single node: nothing to mesh."}
    5. Create a CA (docs/deployment.md 4.3), then finish the deployment with
       `fastpki-ca renew-service-certs --create-missing --re-issue-self-signed`: it issues
       the OCSP responder, CMP RA and SCEP RA credentials, and replaces the self-signed
       listener certificates mentioned in step 2 with CA-issued ones. Until that runs, OCSP
       answers internalerror and CMP refuses every transaction.
  EOT
  description = "What to do once apply finishes."
}
