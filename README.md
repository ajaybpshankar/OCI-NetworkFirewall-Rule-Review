# OCI-NetworkFirewall-Rule-Review
Real-time validation of OCI Network Firewall rules to detect risky configurations like 0.0.0.0/0, ANY-ANY access, and sensitive port exposure using OCI Functions.

Important Notes

1️⃣ Authentication (VERY IMPORTANT)

This uses:oci.auth.signers.get_resource_principals_signer()

Works only when:

Function runs inside OCI
IAM policy is configured

2️⃣ Required IAM Policy

Add:Allow dynamic-group <your-function-dg> to read network-firewall-family in compartment <compartment-name>

3️⃣ Event Payload Requirement

Your Event Rule must send:UpdateNetworkFirewallPolicy
