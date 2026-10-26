/**
 * Realistic sample history for the Hindsight memory bank.
 * Uses the real devices / APIs that ship with ZENTRA (server/sample-configs.ts, data/zentra-db.json).
 * Shared by `npm run seed:memory` (scripts/seed-memory.ts) and POST /api/memory/seed.
 */
import { rememberBatch } from './hindsight.ts';

export interface SeedEvent {
  content: string;
  context: string;
  daysAgo: number; // spread across the last ~6 months
  metadata: Record<string, string>;
}

const E = (context: string, daysAgo: number, metadata: Record<string, string>, content: string): SeedEvent => ({
  context,
  daysAgo,
  metadata,
  content,
});

export const SEED_EVENTS: SeedEvent[] = [
  /* ----------------------- 6 past audit findings and how each was resolved ----------------------- */
  E('finding-decision', 172, { kind: 'finding-resolved', findingId: 'ZEN-F-1001', api: 'User Management API' },
    "Finding ZEN-F-1001 'Broken Object Level Authorization (BOLA / IDOR)' on User Management API (Access Control, CRITICAL) changed from OPEN to RESOLVED by Marcus Chen (DEVELOPER). Resolution: added an ownership-check middleware that compares the JWT subject with resource.ownerId; validated by requesting a tenant B record as tenant A and getting HTTP 403."),
  E('finding-decision', 158, { kind: 'finding-resolved', findingId: 'ZEN-F-1002', api: 'Authentication & SSO Service' },
    "Finding ZEN-F-1002 'Excessive JWT Token Lifetime & Weak Algorithm Support' on Authentication & SSO Service (Authentication, HIGH) changed from OPEN to RESOLVED by Dr. Elena Rostova (SECURITY_ANALYST). Resolution: access token lifetime cut from 72h to 15 minutes, RS256 only (HS256 and alg=none rejected), refresh-token rotation enabled. Mobile clients needed a forced re-login after the change."),
  E('finding-decision', 141, { kind: 'finding-resolved', findingId: 'ZEN-F-1003', api: 'Payment Gateway API' },
    "Finding ZEN-F-1003 'Missing Rate Limiting on Payment Ingestion Endpoint' on Payment Gateway API (Rate Limiting, HIGH) changed from IN_PROGRESS to RESOLVED by Marcus Chen (DEVELOPER). Resolution: Redis token bucket at 100 requests/min per client token. The first rollout throttled the nightly settlement batch job, so the batch service account was moved to a separate 1000/min bucket."),
  E('finding-decision', 118, { kind: 'finding-resolved', findingId: 'ZEN-F-1005', api: 'Notification & Webhook Dispatcher' },
    "Finding ZEN-F-1005 'Permissive Wildcard CORS Configuration on Internal API' on Notification & Webhook Dispatcher (CORS, MEDIUM) changed from OPEN to RESOLVED by Marcus Chen (DEVELOPER). Resolution: replaced Access-Control-Allow-Origin * with an explicit allowlist of three internal origins and disabled credentials for any origin outside the list."),
  E('finding-decision', 96, { kind: 'finding-resolved', device: 'CORE-CAT9300-SFO', control: 'CIS-NET-1.1' },
    "Audit finding on device CORE-CAT9300-SFO (Cisco Catalyst 9300-48P, IOS-XE): CIS-NET-1.1 Telnet still enabled on VTY lines. Resolved by Dr. Elena Rostova (SECURITY_ANALYST) after setting 'transport input ssh' on line vty 0 15; re-evaluation passed against CIS, NIST 800-53 and ISO 27001."),
  E('finding-decision', 74, { kind: 'finding-resolved', device: 'SONIC-SPINE-01', control: 'CIS-NET-1.8' },
    "Audit finding on device SONIC-SPINE-01 (Celestica DX010, SONiC): CIS-NET-1.8 no remote syslog host configured. Resolved by Alex Vance (ADMIN) with 'sudo config syslog add 10.250.0.15' followed by 'sudo config save -y'; the change was lost after the first reboot until 'config save' had been run."),

  /* ----------------------- 5 accepted-risk decisions ----------------------- */
  E('finding-decision', 165, { kind: 'accepted-risk', api: 'Order Fulfillment API', approver: 'Alex Vance' },
    "Finding 'Static API Key Lacks Scope Delegation, Key Rotation, and Claim Expiry' on Order Fulfillment API (Authentication, HIGH) changed from OPEN to ACCEPTED_RISK by Alex Vance (ADMIN). Reason: legacy warehouse barcode scanners cannot perform OAuth2. Compensating controls: IP allowlist for the three warehouse subnets and 30-day key rotation. Review date 2027-03-31, when the scanner fleet is replaced."),
  E('finding-decision', 133, { kind: 'accepted-risk', device: 'PA-3220-EDGE-FW01', approver: 'Dr. Elena Rostova' },
    "Finding on PA-3220-EDGE-FW01 (Palo Alto PA-3220, PAN-OS): STIG-NET-000070 approved warning banner not set, changed from OPEN to ACCEPTED_RISK by Dr. Elena Rostova (SECURITY_ANALYST). Reason: the firewall is outside DoD scope and the commercial login banner is enforced on the jump host; revisit at the next annual audit."),
  E('finding-decision', 109, { kind: 'accepted-risk', device: 'LEAF01-POD2', approver: 'Alex Vance' },
    "Finding on LEAF01-POD2 (Arista DCS-7050SX3-48YC8, EOS 4.28.2F): CIS-NET-1.12 administrative session idle timeout is 30 minutes instead of 15, changed from OPEN to ACCEPTED_RISK by Alex Vance (ADMIN). Reason: the network operations team runs long packet captures from the console. Compensating controls: access only through the MFA-protected jump host, and every session is logged."),
  E('finding-decision', 87, { kind: 'accepted-risk', api: 'Notification & Webhook Dispatcher', approver: 'Alex Vance' },
    "Finding 'Insecure Authentication: Basic Auth Transmitted Over API Perimeter' on Notification & Webhook Dispatcher (Authentication, HIGH) changed from OPEN to ACCEPTED_RISK by Alex Vance (ADMIN) for 90 days. Reason: the third-party SMS provider webhook receiver only supports HTTP Basic. Compensating controls: traffic runs through an mTLS tunnel and is restricted to the provider's published IP range."),
  E('finding-decision', 52, { kind: 'accepted-risk', device: 'SRX345-DC-GATEWAY', approver: 'Priya Nair' },
    "Finding on SRX345-DC-GATEWAY (Juniper SRX345, JunOS): CIS-NET-1.10 SNMPv2c community string in use, changed from OPEN to ACCEPTED_RISK by Priya Nair (CISO). Reason: the monitoring appliance cannot speak SNMPv3 until its 2027 refresh. Compensating controls: read-only community, bound to the management routing instance and a /32 ACL for the collector."),

  /* ----------------------- 6 remediation outcomes (3 FAILED) ----------------------- */
  E('remediation-outcome', 150, { worked: 'false', vendor: 'Arista EOS', hostname: 'LEAF01-POD2', controlId: 'CIS-NET-1.12' },
    "Remediation of CIS-NET-1.12 on Arista EOS LEAF01-POD2 FAILED. Notes: the SSH idle-timeout change under 'management ssh' did not take effect after 'write memory'. The SSH service had to be restarted (shutdown then no shutdown under management ssh), otherwise existing sessions kept the old timeout. SSH timeout change needs a service reload on Arista EOS."),
  E('remediation-outcome', 126, { worked: 'false', vendor: 'Juniper JunOS', hostname: 'SRX345-DC-GATEWAY', controlId: 'CIS-NET-1.2' },
    "Remediation of CIS-NET-1.2 on Juniper JunOS SRX345-DC-GATEWAY FAILED. Notes: 'set system services ssh protocol-version v2' followed by 'commit and-quit' failed because another administrator held the exclusive configuration lock. Use 'commit confirmed 5' from a non-exclusive 'configure' session and confirm afterwards."),
  E('remediation-outcome', 104, { worked: 'false', vendor: 'Palo Alto PAN-OS', hostname: 'PA-3220-EDGE-FW01', controlId: 'CIS-NET-1.3' },
    "Remediation of CIS-NET-1.3 on Palo Alto PAN-OS PA-3220-EDGE-FW01 FAILED. Notes: the generated command 'set deviceconfig system services service-http disable' was rejected as invalid syntax. The working command is 'set deviceconfig system service disable-http yes' followed by 'commit', which takes 2 to 4 minutes on the PA-3220."),
  E('remediation-outcome', 92, { worked: 'true', vendor: 'Cisco IOS-XE / IOS', hostname: 'CORE-CAT9300-SFO', controlId: 'CIS-NET-1.2' },
    "Remediation of CIS-NET-1.2 on Cisco IOS-XE / IOS CORE-CAT9300-SFO WORKED. Notes: 'ip ssh version 2' was only accepted after a domain name was set and a 2048-bit RSA key pair existed ('crypto key generate rsa modulus 2048'). Always run those two prerequisites first."),
  E('remediation-outcome', 61, { worked: 'true', vendor: 'SONiC Open Networking NOS', hostname: 'SONIC-SPINE-01', controlId: 'CIS-NET-1.8' },
    "Remediation of CIS-NET-1.8 on SONiC Open Networking NOS SONIC-SPINE-01 WORKED. Notes: 'sudo config syslog add 10.250.0.15' then 'sudo config save -y' persisted across a reboot. Verified with 'show syslog'."),
  E('remediation-outcome', 33, { worked: 'true', vendor: 'Arista EOS', hostname: 'LEAF01-POD2', controlId: 'CIS-NET-1.9' },
    "Remediation of CIS-NET-1.9 on Arista EOS LEAF01-POD2 WORKED. Notes: 'ntp server 10.30.1.1' plus 'write memory'. Clock synchronised within about 90 seconds; checked with 'show ntp status'."),

  /* ----------------------- 4 vendor quirks ----------------------- */
  E('vendor-quirk', 148, { vendor: 'Cisco IOS-XE / IOS' },
    "Vendor quirk, Cisco IOS-XE / IOS (CORE-CAT9300-SFO): 'ip ssh version 2' is silently ignored or rejected unless a hostname and ip domain-name are configured and an RSA key of at least 768 bits (we use 2048) exists. Generate the key pair before enforcing SSH version 2."),
  E('vendor-quirk', 128, { vendor: 'Juniper JunOS' },
    "Vendor quirk, Juniper JunOS (SRX345-DC-GATEWAY): never finish a remote change with a plain 'commit and-quit'. Use 'commit confirmed 5' so a bad change rolls back automatically, and expect 'commit' to fail if another user holds the exclusive configuration lock."),
  E('vendor-quirk', 100, { vendor: 'Palo Alto PAN-OS' },
    "Vendor quirk, Palo Alto PAN-OS (PA-3220-EDGE-FW01): management service toggles live under 'deviceconfig system service' (singular), for example 'disable-http yes' and 'disable-telnet yes'. Nothing is active until 'commit', and a commit on the PA-3220 can take 2 to 4 minutes, so do not retry while one is running."),
  E('vendor-quirk', 70, { vendor: 'SONiC Open Networking NOS' },
    "Vendor quirk, SONiC (SONIC-SPINE-01): changes made with sonic-db-cli or 'config' commands are only held in the running CONFIG_DB. They are lost on reboot unless 'sudo config save -y' is run, and SSH_SERVER changes also need the ssh service restarted before they apply."),

  /* ----------------------- 4 analyst teachings ----------------------- */
  E('analyst-teaching', 160, { analyst: 'Dr. Elena Rostova', vendor: 'Arista EOS' },
    "Analyst teaching from Dr. Elena Rostova (SECURITY_ANALYST): on Arista EOS, lines mentioning the TerminAttr daemon are streaming telemetry to CloudVision and must not be classified as an insecure management service."),
  E('analyst-teaching', 122, { analyst: 'Dr. Elena Rostova', vendor: 'Cisco IOS-XE / IOS' },
    "Analyst teaching from Dr. Elena Rostova (SECURITY_ANALYST): on Cisco IOS-XE, 'service tcp-keepalives-in' and 'service tcp-keepalives-out' are connection hygiene and do not satisfy the administrative idle session timeout control (session_timeout). Only 'exec-timeout' on line con and line vty counts."),
  E('analyst-teaching', 80, { analyst: 'Alex Vance', vendor: 'ALL' },
    "Analyst teaching from Alex Vance (ADMIN): on every vendor, a line containing 'snmp-server community public' or 'community public' means snmp_community_default is true. The default community string must always fail the control, even when an ACL is attached."),
  E('analyst-teaching', 41, { analyst: 'Dr. Elena Rostova', vendor: 'SONiC Open Networking NOS' },
    "Analyst teaching from Dr. Elena Rostova (SECURITY_ANALYST): in SONiC config_db.json the value of SSH_SERVER|global session_timeout is in seconds, so 600 satisfies the 10 minute idle timeout control. Do not compare it with minutes."),
];

/** Event list with absolute timestamps (spread over the last ~6 months). */
export function buildSeedEvents() {
  const now = Date.now();
  return SEED_EVENTS.map((e) => ({
    content: e.content,
    context: e.context,
    metadata: { ...e.metadata, source: 'zentra-seed' },
    timestamp: new Date(now - e.daysAgo * 24 * 60 * 60 * 1000),
  }));
}

export async function seedMemory(): Promise<{ total: number; stored: number; failed: number }> {
  const events = buildSeedEvents();
  // force: load sample history even if the Memory toggle is OFF (the demo turns it OFF to show "before").
  const { stored, failed } = await rememberBatch(events, { force: true });
  return { total: events.length, stored, failed };
}
