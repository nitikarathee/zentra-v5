// 5 Realistic Sample Network Configurations across Vendors

export interface SampleDeviceConfig {
  filename: string;
  vendorName: string;
  expectedModel: string;
  expectedHostname: string;
  description: string;
  content: string;
}

export const SAMPLE_DEVICE_CONFIGS: SampleDeviceConfig[] = [
  // 1. Cisco IOS-XE - Enterprise Core Switch
  {
    filename: 'cisco-core-catalyst9300.cfg',
    vendorName: 'Cisco IOS-XE / IOS',
    expectedModel: 'Catalyst 9300-48P',
    expectedHostname: 'CORE-CAT9300-SFO',
    description: 'Cisco Catalyst 9300 Core Switch running IOS-XE 17.6 with AAA, SSHv2, strong secret hashing, and TLS 1.2.',
    content: `!
version 17.6
service timestamps debug datetime msec
service timestamps log datetime msec
service password-encryption
service tcp-keepalives-in
service tcp-keepalives-out
!
hostname CORE-CAT9300-SFO
!
boot-start-marker
boot-end-marker
!
! Chassis Serial Number: FOC2438L01B
! Model Number: Catalyst 9300-48P
!
security passwords min-length 14
enable secret 9 $9$vD8M$yJm3P89312.441908
!
aaa new-model
aaa authentication login default group radius local
aaa authorization exec default group radius local
!
no ip source-route
no ip http server
ip http secure-server
ip http secure-active-session-tls-version TLSv1.2
ip ssh version 2
ip ssh time-out 60
ip ssh authentication-retries 3
!
logging host 10.100.1.50
logging host 10.100.1.51
ntp server 10.100.2.1
ntp server 10.100.2.2
!
snmp-server group SECURE_V3 v3 priv
snmp-server user secadmin SECURE_V3 v3 auth sha MyAuthKey2026 priv aes 256 MyPrivKey2026
!
banner motd ^C
===================================================================
AUTHORIZED ACCESS ONLY. ALL CONNECTIONS ARE MONITORED AND AUDITED.
UNAUTHORIZED ENTRY WILL BE PROSECUTED TO FULL EXTENT OF LAW.
===================================================================
^C
!
ip access-list extended MGMT-CONTROL-PLANE
 permit tcp 10.100.0.0 0.0.255.255 any eq 22
 deny   ip any any log
!
line con 0
 exec-timeout 10 0
 stopbits 1
line vty 0 4
 transport input ssh
 exec-timeout 10 0
line vty 5 15
 transport input ssh
 exec-timeout 10 0
!
end`,
  },

  // 2. Palo Alto Networks PAN-OS - Next-Gen Firewall
  {
    filename: 'paloalto-pa3220-edge.conf',
    vendorName: 'Palo Alto PAN-OS',
    expectedModel: 'PA-3220',
    expectedHostname: 'PA-3220-EDGE-FW01',
    description: 'Palo Alto Networks PA-3220 Next-Generation Perimeter Firewall running PAN-OS 10.2 with TLS 1.3, strict idle timeout, and hardened admin management.',
    content: `set deviceconfig system hostname PA-3220-EDGE-FW01
set deviceconfig system serial-number 015301004892
set deviceconfig system model PA-3220
set deviceconfig system sw-version 10.2.4-h2
set deviceconfig system domain corp.net
set deviceconfig system ip-address 192.168.1.1 netmask 255.255.255.0 default-gateway 192.168.1.254
set deviceconfig system login-banner "RESTRICTED SECURITY ASSET - PALO ALTO ENTERPRISE FIREWALL. ALL ACTIVITIES LOGGED."
set deviceconfig system idle-timeout 10
set deviceconfig system minimum-password-length 14
set deviceconfig system password-complexity-profile enforce-complexity yes
set deviceconfig system password-complexity-profile minimum-length 14
set deviceconfig system services service-http disable
set deviceconfig system services service-https enable
set deviceconfig system services service-telnet disable
set deviceconfig system services service-ssh enable
set deviceconfig system services tls-version-min 1.2
set deviceconfig system ntp-servers primary-ntp-server 10.200.1.5
set deviceconfig system ntp-servers secondary-ntp-server 10.200.1.6
set shared log-settings syslog SYSLOG-SPLUNK server 10.200.1.50 port 514
set deviceconfig system snmp-setting version v3
set deviceconfig system authentication-profile RADIUS-CORPORATE-MFA
set security-profile vulnerability STRICT-MITIGATION action reset-both
set zone trust network layer3 ethernet1/2
set zone untrust network layer3 ethernet1/1`,
  },

  // 3. Juniper JunOS - SRX Services Gateway
  {
    filename: 'juniper-srx345-dc.conf',
    vendorName: 'Juniper JunOS',
    expectedModel: 'SRX345-SYS-JB',
    expectedHostname: 'SRX345-DC-GATEWAY',
    description: 'Juniper Networks SRX345 Branch/DC Firewall running JunOS 21.4 with SHA-512 passwords, TLS 1.2 management, and filtered control plane.',
    content: `## Last-Changed: 2026-10-24 02:15:00 UTC
version 21.4R3-S2;
system {
    host-name SRX345-DC-GATEWAY;
    domain-name datacenter.corp;
    root-authentication {
        encrypted-password "$6$kO88$X98.aJ8qL4m19wK04ZqmKxQvC7wA21.hE"; ## SECRET-DATA
    }
    login {
        message "=====================================================\\nRESTRICTED GATEWAY - AUTHORIZED IT AUDIT ACCESS ONLY\\n=====================================================";
        idle-timeout 10;
        password {
            format sha-512;
            minimum-password-length 14;
        }
        class network-admin {
            permissions all;
        }
    }
    services {
        ssh {
            protocol-version v2;
            max-sessions-per-connection 4;
            connection-limit 10;
            rate-limit 3;
        }
        web-management {
            https {
                port 443;
                tls-version tlsv1.2;
                pki-local-certificate dc-cert;
            }
        }
    }
    syslog {
        host 192.168.10.25 {
            any notice;
            authorization info;
        }
    }
    ntp {
        server 192.168.10.1;
        server 192.168.10.2;
    }
}
snmp {
    v3 {
        usm {
            local-engine {
                user secops {
                    authentication-sha {
                        authentication-key "$9$9wK04ZqmKxQ";
                    }
                    privacy-aes128 {
                        privacy-key "$9$9wK04ZqmKxQpriv";
                    }
                }
            }
        }
    }
}
firewall {
    family inet {
        filter EDGE-MGMT-PROTECT {
            term ALLOW-SSH {
                from {
                    source-address {
                        192.168.0.0/16;
                    }
                    protocol tcp;
                    destination-port 22;
                }
                then accept;
            }
            term DROP-ALL {
                then {
                    count drop-counter;
                    discard;
                }
            }
        }
    }
}`,
  },

  // 4. Arista EOS - Data Center Spine/Leaf Switch
  {
    filename: 'arista-7050sx3-leaf01.eos',
    vendorName: 'Arista EOS',
    expectedModel: 'DCS-7050SX3-48YC8',
    expectedHostname: 'LEAF01-POD2',
    description: 'Arista 7050SX3 Leaf Switch running EOS 4.28 with eAPI HTTPS, CloudVision TerminAttr telemetry agent, and AAA radius.',
    content: `! Command: show running-config
! device: LEAF01-POD2 (DCS-7050SX3-48YC8, EOS-4.28.2F)
! serial-number: JPE19240811
!
transceiver qsfp default-mode 4x10G
!
hostname LEAF01-POD2
ip domain-name pod2.internal
!
spanning-tree mode mstp
!
service password-encryption
!
username netadmin privilege 15 role network-admin secret sha512 $6$rounds=50000$Arista$Z9P029314810aBcDeFgHiJkLmNoPqRsTuVwXyZ
!
management ssh
   protocol 2
   idle-timeout 10
   no shutdown
!
management api http-commands
   protocol https
   no shutdown
!
logging host 10.30.1.10
logging host 10.30.1.11
ntp server 10.30.1.1
ntp server 10.30.1.2
!
banner motd
===============================================================
ARISTA CLOUD FABRIC LEAF 01 - MONITORED INFRASTRUCTURE ASSET
UNAUTHORIZED ACCESS WILL BE REPORTED AND INVESTIGATED.
===============================================================
EOF
!
ip access-list standard CONTROL-PLANE-ACL
   10 permit 10.0.0.0/8
   20 deny any log
!
daemon TerminAttr
   exec /usr/bin/TerminAttr -cvaddr=10.30.1.100:9910 -cvauth=token,/tmp/token -taillogs
   no shutdown
!
end`,
  },

  // 5. SONiC (Software for Open Networking in the Cloud) - Open Source Linux Whitebox NOS
  {
    filename: 'sonic-spine01-config_db.json',
    vendorName: 'SONiC Open Networking NOS',
    expectedModel: 'Celestica-DX010 (x86_64)',
    expectedHostname: 'SONIC-SPINE-01',
    description: 'Open-source Linux-based SONiC (Software for Open Networking in the Cloud) configuration in JSON database format (config_db.json).',
    content: `{
  "DEVICE_METADATA": {
    "localhost": {
      "hostname": "SONIC-SPINE-01",
      "platform": "x86_64-cel_seastone-r0",
      "mac": "70:72:cf:91:22:00",
      "type": "SpineRouter",
      "hwsku": "Celestica-DX010",
      "docker_routing_config_mode": "unified",
      "default_pfcwd_status": "disable",
      "default_bgp_status": "up"
    }
  },
  "AAA": {
    "authentication": {
      "login": "local",
      "failthrough": "True"
    }
  },
  "SSH_SERVER": {
    "global": {
      "port": "22",
      "protocol_version": "2",
      "permit_root_login": "no",
      "password_authentication": "yes",
      "session_timeout": "600",
      "max_auth_retries": "3"
    }
  },
  "HTTP_SERVER": {
    "global": {
      "status": "disabled",
      "secure_status": "enabled",
      "ssl_version": "TLSv1.2",
      "idle_timeout": "10"
    }
  },
  "PASSWORD": {
    "policy": {
      "min_length": "14",
      "encryption": "SHA-512",
      "enforce_complexity": "true"
    }
  },
  "SYSLOG_SERVER": {
    "10.250.0.15": {
      "port": "514"
    },
    "10.250.0.16": {
      "port": "514"
    }
  },
  "NTP_SERVER": {
    "10.250.0.1": {},
    "10.250.0.2": {}
  },
  "BANNER": {
    "motd": {
      "text": "WARNING: Restricted Cloud Spine Switch (SONiC Linux). Authorized Network Personnel Only."
    }
  },
  "SNMP_SERVER": {
    "global": {
      "version": "v3",
      "community_default": "disabled"
    }
  },
  "ACL_TABLE": {
    "CONTROL_PLANE_PROTECT": {
      "policy_desc": "Control plane inbound ACL protection",
      "type": "L3",
      "ports": ["eth0"]
    }
  }
}`,
  },
];
