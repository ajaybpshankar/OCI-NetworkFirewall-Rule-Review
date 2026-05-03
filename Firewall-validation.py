import json
import oci


# Allowed CIDR prefixes (your environment)
ALLOWED_PREFIXES = ["172.16", "172.20"]

# Sensitive ports
SENSITIVE_PORTS = [22, 3389]


def is_public_ip(ip):
    return ip == "0.0.0.0/0"


def is_any(value):
    return str(value).lower() == "any"


def is_allowed_ip(ip):
    return any(ip.startswith(prefix) for prefix in ALLOWED_PREFIXES)


def validate_rule(rule, address_lists):
    alerts = []

    rule_name = rule.get("name", "unknown")

    source_ref = rule.get("source_address")
    dest_ref = rule.get("destination_address")
    service = rule.get("service")

    # Resolve address list references
    source_ips = address_lists.get(source_ref, [source_ref])
    dest_ips = address_lists.get(dest_ref, [dest_ref])

    # Normalize service string
    service_str = str(service)

    # 🔍 Check source IPs
    for ip in source_ips:
        if is_public_ip(ip):
            alerts.append(f"[{rule_name}] ❌ Public access detected: {ip}")

        elif not is_allowed_ip(ip):
            alerts.append(f"[{rule_name}] ⚠️ Unauthorized IP range: {ip}")

    # 🔍 Check ANY → ANY
    if is_any(source_ref) and is_any(dest_ref):
        alerts.append(f"[{rule_name}] ❌ ANY → ANY rule detected")

    # 🔍 Check sensitive ports
    for port in SENSITIVE_PORTS:
        if str(port) in service_str:
            alerts.append(f"[{rule_name}] ⚠️ Sensitive port exposed: {port}")

    return alerts


def handler(ctx, data: io.BytesIO = None):
    try:
        body = json.loads(data.getvalue())
        print("Received Event:", body)

        resource_id = body.get("data", {}).get("resourceId")

        if not resource_id:
            return {"message": "No resourceId found"}

        # OCI config (use resource principal in real deployment)
        signer = oci.auth.signers.get_resource_principals_signer()
        client = oci.network_firewall.NetworkFirewallClient({}, signer=signer)

        # Fetch firewall policy
        response = client.get_network_firewall_policy(resource_id)
        policy = response.data

        rules = policy.security_rules or []
        address_lists = policy.address_lists or {}

        all_alerts = []

        for rule in rules:
            alerts = validate_rule(rule.__dict__, address_lists)
            all_alerts.extend(alerts)

        if all_alerts:
            print("🚨 ALERTS DETECTED:")
            for alert in all_alerts:
                print(alert)

            return {
                "status": "ALERT",
                "details": all_alerts
            }

        else:
            print("✅ No issues found")
            return {
                "status": "OK",
                "message": "All rules are compliant"
            }

    except Exception as e:
        print("Error:", str(e))
        return {"error": str(e)}
