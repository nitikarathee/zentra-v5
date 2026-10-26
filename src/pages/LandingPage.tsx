import React, { useState, useEffect, useRef } from 'react';
import {
  ShieldCheck,
  ShieldAlert,
  Cpu,
  Terminal,
  FileCheck2,
  FileText,
  Archive,
  ArrowRight,
  CheckCircle2,
  XCircle,
  AlertTriangle,
  Sparkles,
  Layers,
  Lock,
  Server,
  Zap,
  Copy,
  Check,
  ChevronRight,
  ExternalLink,
  GraduationCap,
  Play,
  RotateCw,
  Eye,
  Database,
  Radio,
} from 'lucide-react';
import { Logo } from '../components/common/Logo';

// Optional video background URL (falls back cleanly to animated canvas if empty or fails)
const HERO_VIDEO_URL = '';

interface LandingPageProps {
  onEnter: () => void;
}

// Data for Core Challenge Interactive Terminal
interface ChallengeVendorSample {
  vendorId: string;
  vendorName: string;
  deviceModel: string;
  hostname: string;
  rawCli: string;
  normalizedJson: string;
  failedCheck: {
    controlId: string;
    framework: string;
    title: string;
    severity: 'CRITICAL' | 'HIGH' | 'MEDIUM';
    detected: string;
    expected: string;
    impact: string;
  };
  cliFix: string;
}

const CHALLENGE_SAMPLES: ChallengeVendorSample[] = [
  {
    vendorId: 'cisco',
    vendorName: 'Cisco IOS-XE',
    deviceModel: 'Catalyst 9300-48P',
    hostname: 'CORE-SW01-DENVER',
    rawCli: `! Cisco IOS-XE Software, Version 17.06.01
hostname CORE-SW01-DENVER
!
no service password-encryption
enable secret 5 $1$9a8b$xG72...
!
no ip http secure-server
ip http server
ip ssh version 1
!
line vty 0 4
 transport input telnet ssh
 exec-timeout 0 0
!
ntp server 10.0.0.1`,
    normalizedJson: `{
  "hostname": "CORE-SW01-DENVER",
  "vendor": "Cisco",
  "model": "Catalyst 9300-48P",
  "baseline": {
    "ssh_version": { "value": "1", "confidence": 0.99 },
    "telnet_enabled": { "value": true, "confidence": 0.98 },
    "http_server_enabled": { "value": true, "confidence": 0.99 },
    "https_enabled": { "value": false, "confidence": 0.99 },
    "password_encryption": { "value": false, "confidence": 0.98 },
    "min_password_length": { "value": null, "confidence": 0.90 },
    "aaa_enabled": { "value": false, "confidence": 0.95 }
  }
}`,
    failedCheck: {
      controlId: 'CIS 2.1.2 & NIST AC-17',
      framework: 'CIS Cisco Benchmark & NIST SP 800-53',
      title: 'Insecure Cleartext Management Protocols Active (Telnet & HTTP)',
      severity: 'CRITICAL',
      detected: 'Telnet enabled on vty 0-4; Cleartext HTTP enabled; SSH v1 active',
      expected: 'Only SSH v2 permitted (transport input ssh); HTTPS enabled; HTTP disabled',
      impact: 'Cleartext management credentials can be intercepted via network sniffing or ARP poisoning.',
    },
    cliFix: `configure terminal
! 1. Disable legacy Telnet and enforce SSHv2
line vty 0 4
 no transport input telnet
 transport input ssh
 exec-timeout 10 0
! 2. Enforce secure web administration
no ip http server
ip http secure-server
! 3. Enforce cryptographic password hashing
service password-encryption
ip ssh version 2
end
write memory`,
  },
  {
    vendorId: 'juniper',
    vendorName: 'Juniper JunOS',
    deviceModel: 'QFX5100-48S Spine',
    hostname: 'SPINE01-DC-EAST',
    rawCli: `## Last commit: 2026-09-15 11:20:00 UTC
system {
    host-name SPINE01-DC-EAST;
    services {
        telnet;
        ssh {
            protocol-version v1;
        }
        web-management {
            http {
                interface [ em0.0 ge-0/0/0.0 ];
            }
        }
    }
}`,
    normalizedJson: `{
  "hostname": "SPINE01-DC-EAST",
  "vendor": "Juniper",
  "model": "QFX5100-48S Spine",
  "baseline": {
    "ssh_version": { "value": "1", "confidence": 0.99 },
    "telnet_enabled": { "value": true, "confidence": 0.99 },
    "http_server_enabled": { "value": true, "confidence": 0.98 },
    "https_enabled": { "value": false, "confidence": 0.98 },
    "logging_hosts": { "value": [], "confidence": 0.92 }
  }
}`,
    failedCheck: {
      controlId: 'DISA STIG NET-0440',
      framework: 'DoD DISA Network STIG',
      title: 'Telnet & Weak SSH Protocol Version Allowed',
      severity: 'CRITICAL',
      detected: 'services { telnet; ssh { protocol-version v1; } }',
      expected: 'Delete telnet; Set protocol-version v2',
      impact: 'Allows DoD enclave network compromise through unencrypted remote command injection.',
    },
    cliFix: `configure
# Delete insecure telnet service
delete system services telnet
# Enforce modern SSH protocol version 2
set system services ssh protocol-version v2
# Disable cleartext HTTP management and enable HTTPS
delete system services web-management http
set system services web-management https system-generated-certificate
commit comment "Remediate DISA STIG NET-0440 Telnet/HTTP violation"`,
  },
  {
    vendorId: 'arista',
    vendorName: 'Arista EOS',
    deviceModel: '7050SX3 Leaf Switch',
    hostname: 'LEAF-RACK04-EOS',
    rawCli: `! Arista EOS 4.28.2F
hostname LEAF-RACK04-EOS
!
management api http-commands
   no shutdown
   protocol http
!
management ssh
   no shutdown
   cipher aes128-cbc
!
snmp-server community public ro`,
    normalizedJson: `{
  "hostname": "LEAF-RACK04-EOS",
  "vendor": "Arista",
  "model": "7050SX3 Leaf Switch",
  "baseline": {
    "ssh_version": { "value": "2", "confidence": 0.95 },
    "http_server_enabled": { "value": true, "confidence": 0.99 },
    "snmp_community_default": { "value": true, "confidence": 0.99 },
    "snmp_version": { "value": "v2c", "confidence": 0.94 }
  }
}`,
    failedCheck: {
      controlId: 'ISO 27001 A.13.1.2',
      framework: 'ISO/IEC 27001:2022 Network Security',
      title: 'Default SNMP Community String & Insecure Management API',
      severity: 'HIGH',
      detected: 'snmp-server community public ro; management api protocol http',
      expected: 'Delete default "public" community; enforce protocol https',
      impact: 'Reveals full internal network topology and interface state to unauthorized network peers.',
    },
    cliFix: `enable
configure
! Remove default well-known SNMP community string
no snmp-server community public
snmp-server group SECURE_RO v3 priv
! Enforce HTTPS for eAPI management
management api http-commands
   protocol https
   no protocol http
exit
copy running-config startup-config`,
  },
];

export function LandingPage({ onEnter }: LandingPageProps) {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const [videoFailed, setVideoFailed] = useState(false);
  const [activeStage, setActiveStage] = useState<'RAW' | 'NORMALIZED' | 'AUDIT' | 'REMEDIATION'>('AUDIT');
  const [selectedVendorIndex, setSelectedVendorIndex] = useState(0);
  const [copiedCode, setCopiedCode] = useState(false);

  const activeSample = CHALLENGE_SAMPLES[selectedVendorIndex];

  // Listen for global Enter key to launch
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      const target = e.target as HTMLElement;
      if (target.tagName === 'INPUT' || target.tagName === 'TEXTAREA') return;
      if (e.key === 'Enter') {
        e.preventDefault();
        onEnter();
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [onEnter]);

  // Network Topology Interactive Canvas Background
  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    let animationFrameId: number;
    let width = (canvas.width = canvas.parentElement?.clientWidth || window.innerWidth);
    let height = (canvas.height = canvas.parentElement?.clientHeight || window.innerHeight);

    // Responsive resize handler
    const handleResize = () => {
      if (!canvas || !canvas.parentElement) return;
      width = canvas.width = canvas.parentElement.clientWidth;
      height = canvas.height = canvas.parentElement.clientHeight;
    };
    window.addEventListener('resize', handleResize);

    // Mouse coordinates for gentle interaction
    let mouse = { x: -1000, y: -1000 };
    const handleMouseMove = (e: MouseEvent) => {
      const rect = canvas.getBoundingClientRect();
      mouse = { x: e.clientX - rect.left, y: e.clientY - rect.top };
    };
    window.addEventListener('mousemove', handleMouseMove);

    // Generate Network Topology Nodes
    const NODE_COUNT = Math.min(65, Math.floor((width * height) / 18000) + 25);
    interface NetNode {
      x: number;
      y: number;
      vx: number;
      vy: number;
      radius: number;
      isVulnerable: boolean;
      role: 'core' | 'spine' | 'leaf' | 'firewall';
      pulse: number;
      pulseSpeed: number;
      label?: string;
    }

    const nodes: NetNode[] = [];
    for (let i = 0; i < NODE_COUNT; i++) {
      const isVuln = i === 4 || i === 12 || i === 23;
      nodes.push({
        x: Math.random() * width,
        y: Math.random() * height,
        vx: (Math.random() - 0.5) * 0.45,
        vy: (Math.random() - 0.5) * 0.45,
        radius: isVuln ? 4.5 : Math.random() * 2.5 + 2,
        isVulnerable: isVuln,
        role: isVuln ? 'firewall' : i % 5 === 0 ? 'core' : i % 3 === 0 ? 'spine' : 'leaf',
        pulse: Math.random() * Math.PI * 2,
        pulseSpeed: 0.035 + Math.random() * 0.02,
        label: isVuln ? (i === 4 ? 'TELNET' : i === 12 ? 'CIS-FAIL' : 'WEAK-PW') : undefined,
      });
    }

    // Packet particles traversing links
    interface Packet {
      fromIndex: number;
      toIndex: number;
      progress: number;
      speed: number;
      color: string;
    }
    const packets: Packet[] = [];
    const MAX_PACKETS = 14;

    const spawnPacket = () => {
      if (packets.length >= MAX_PACKETS || nodes.length < 2) return;
      const from = Math.floor(Math.random() * nodes.length);
      // Find a connected or close neighbor
      let to = -1;
      let minD = 180;
      for (let j = 0; j < nodes.length; j++) {
        if (j === from) continue;
        const dx = nodes[j].x - nodes[from].x;
        const dy = nodes[j].y - nodes[from].y;
        const dist = Math.sqrt(dx * dx + dy * dy);
        if (dist < minD) {
          minD = dist;
          to = j;
        }
      }
      if (to !== -1) {
        packets.push({
          fromIndex: from,
          toIndex: to,
          progress: 0,
          speed: 0.008 + Math.random() * 0.012,
          color: nodes[from].isVulnerable || nodes[to].isVulnerable ? '#f43f5e' : '#10b981',
        });
      }
    };

    // Animation Loop
    let lastTime = performance.now();
    const render = () => {
      const now = performance.now();
      lastTime = now;

      ctx.clearRect(0, 0, width, height);

      // Subtle network grid background pattern
      ctx.strokeStyle = 'rgba(15, 23, 42, 0.6)';
      ctx.lineWidth = 1;

      // Update and draw links
      const LINK_DIST = 160;
      for (let i = 0; i < nodes.length; i++) {
        const nA = nodes[i];
        for (let j = i + 1; j < nodes.length; j++) {
          const nB = nodes[j];
          const dx = nB.x - nA.x;
          const dy = nB.y - nA.y;
          const dist = Math.sqrt(dx * dx + dy * dy);

          if (dist < LINK_DIST) {
            const alpha = (1 - dist / LINK_DIST) * 0.28;
            ctx.beginPath();
            ctx.moveTo(nA.x, nA.y);
            ctx.lineTo(nB.x, nB.y);

            if (nA.isVulnerable || nB.isVulnerable) {
              ctx.strokeStyle = `rgba(244, 63, 94, ${alpha * 0.9})`;
            } else {
              ctx.strokeStyle = `rgba(6, 182, 212, ${alpha})`;
            }
            ctx.lineWidth = 1;
            ctx.stroke();
          }
        }
      }

      // Update and draw packets
      if (Math.random() < 0.08) spawnPacket();
      for (let p = packets.length - 1; p >= 0; p--) {
        const pkt = packets[p];
        pkt.progress += pkt.speed;

        if (pkt.progress >= 1) {
          packets.splice(p, 1);
          continue;
        }

        const nA = nodes[pkt.fromIndex];
        const nB = nodes[pkt.toIndex];
        if (!nA || !nB) {
          packets.splice(p, 1);
          continue;
        }

        const px = nA.x + (nB.x - nA.x) * pkt.progress;
        const py = nA.y + (nB.y - nA.y) * pkt.progress;

        // Glowing packet dot
        ctx.beginPath();
        ctx.arc(px, py, 2.2, 0, Math.PI * 2);
        ctx.fillStyle = pkt.color;
        ctx.shadowColor = pkt.color;
        ctx.shadowBlur = 6;
        ctx.fill();
        ctx.shadowBlur = 0; // reset
      }

      // Update and draw nodes
      for (let i = 0; i < nodes.length; i++) {
        const n = nodes[i];

        // Move
        n.x += n.vx;
        n.y += n.vy;

        // Bounce walls
        if (n.x < 10) { n.x = 10; n.vx *= -1; }
        if (n.x > width - 10) { n.x = width - 10; n.vx *= -1; }
        if (n.y < 10) { n.y = 10; n.vy *= -1; }
        if (n.y > height - 10) { n.y = height - 10; n.vy *= -1; }

        // Mouse avoidance/attraction
        const mdx = mouse.x - n.x;
        const mdy = mouse.y - n.y;
        const mdist = Math.sqrt(mdx * mdx + mdy * mdy);
        if (mdist < 100 && mdist > 0) {
          n.x -= (mdx / mdist) * 0.6;
          n.y -= (mdy / mdist) * 0.6;
        }

        n.pulse += n.pulseSpeed;

        if (n.isVulnerable) {
          // Radiating warning pulse ring
          const ringRad = n.radius + (Math.sin(n.pulse) + 1) * 8;
          const ringAlpha = 0.45 * (1 - (ringRad - n.radius) / 16);

          ctx.beginPath();
          ctx.arc(n.x, n.y, Math.max(0, ringRad), 0, Math.PI * 2);
          ctx.strokeStyle = `rgba(244, 63, 94, ${Math.max(0, ringAlpha)})`;
          ctx.lineWidth = 1.2;
          ctx.stroke();

          // Vulnerable node core
          ctx.beginPath();
          ctx.arc(n.x, n.y, n.radius, 0, Math.PI * 2);
          ctx.fillStyle = '#f43f5e';
          ctx.shadowColor = '#f43f5e';
          ctx.shadowBlur = 10;
          ctx.fill();
          ctx.shadowBlur = 0;

          // Tiny warning badge text
          if (n.label) {
            ctx.font = '9px monospace';
            ctx.fillStyle = 'rgba(254, 205, 211, 0.85)';
            ctx.fillText(n.label, n.x + 8, n.y + 3);
          }
        } else {
          // Standard node
          ctx.beginPath();
          ctx.arc(n.x, n.y, n.radius, 0, Math.PI * 2);
          ctx.fillStyle = n.role === 'core' ? '#38bdf8' : n.role === 'spine' ? '#06b6d4' : '#64748b';
          ctx.fill();
        }
      }

      animationFrameId = requestAnimationFrame(render);
    };

    render();

    return () => {
      cancelAnimationFrame(animationFrameId);
      window.removeEventListener('resize', handleResize);
      window.removeEventListener('mousemove', handleMouseMove);
    };
  }, []);

  const handleCopyCode = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedCode(true);
    setTimeout(() => setCopiedCode(false), 2000);
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col font-sans selection:bg-cyan-500/30 selection:text-cyan-200 overflow-x-hidden">
      {/* 1. TOP NAVIGATION BAR */}
      <header className="sticky top-0 z-50 w-full bg-slate-950/85 backdrop-blur-md border-b border-slate-800/80">
        <div className="max-w-[1600px] mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <Logo size="sm" />
            <span className="hidden sm:inline-block px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-cyan-950/80 text-cyan-300 border border-cyan-500/30">
              v3.2 COMPLIANCE ENGINE
            </span>
          </div>

          <nav className="hidden md:flex items-center gap-6 text-xs text-slate-300">
            <a href="#challenge" className="hover:text-cyan-400 transition-colors">
              The Challenge
            </a>
            <a href="#workflow" className="hover:text-cyan-400 transition-colors">
              4-Step Workflow
            </a>
            <a href="#features" className="hover:text-cyan-400 transition-colors">
              Engine Capabilities
            </a>
            <a href="#vendors" className="hover:text-cyan-400 transition-colors">
              Supported Vendors
            </a>
          </nav>

          <div className="flex items-center gap-3">
            <button
              onClick={onEnter}
              className="px-4 py-2 text-xs font-semibold rounded-lg bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-slate-950 shadow-lg shadow-cyan-500/20 transition-all flex items-center gap-2 cursor-pointer font-mono"
            >
              <span>Launch ZENTRA</span>
              <ArrowRight className="w-3.5 h-3.5" />
            </button>
          </div>
        </div>
      </header>

      {/* 2. FULL-SCREEN HERO SECTION WITH NETWORK TOPOLOGY CANVAS */}
      <section className="relative min-h-[92vh] flex items-center justify-center px-4 sm:px-6 lg:px-8 overflow-hidden">
        {/* Optional Video Background if configured */}
        {HERO_VIDEO_URL && !videoFailed && (
          <video
            autoPlay
            loop
            muted
            playsInline
            onError={() => setVideoFailed(true)}
            className="absolute inset-0 w-full h-full object-cover opacity-20 pointer-events-none z-0"
          >
            <source src={HERO_VIDEO_URL} type="video/mp4" />
          </video>
        )}

        {/* Network Topology Canvas Background */}
        <canvas
          ref={canvasRef}
          className="absolute inset-0 w-full h-full pointer-events-auto z-0"
        />

        {/* Radial Vignette & Grid Overlay */}
        <div className="absolute inset-0 bg-gradient-to-b from-slate-950/60 via-slate-950/80 to-slate-950 pointer-events-none z-10" />
        <div className="absolute inset-0 bg-[radial-gradient(ellipse_at_center,_var(--tw-gradient-stops))] from-cyan-950/20 via-transparent to-transparent pointer-events-none z-10" />

        {/* Hero Central Content */}
        <div className="relative z-20 max-w-5xl mx-auto text-center py-16 sm:py-24 space-y-8">
          {/* Pill Badge */}
          <div className="inline-flex items-center gap-2 px-3.5 py-1.5 rounded-full text-xs font-mono font-semibold bg-slate-900/90 border border-cyan-500/40 text-cyan-300 shadow-[0_0_20px_rgba(6,182,212,0.25)] backdrop-blur-md">
            <span className="w-2 h-2 rounded-full bg-cyan-400 animate-pulse" />
            <span>CIS • NIST SP 800-53 • DISA STIG • ISO 27001</span>
          </div>

          {/* Primary Headline */}
          <h1 className="text-4xl sm:text-6xl lg:text-7xl font-extrabold text-white tracking-tight leading-[1.1]">
            One engine to audit{' '}
            <span className="bg-gradient-to-r from-cyan-400 via-teal-300 to-blue-500 bg-clip-text text-transparent">
              every network device
            </span>
          </h1>

          {/* Subtitle */}
          <p className="max-w-3xl mx-auto text-base sm:text-lg text-slate-300 leading-relaxed font-normal">
            Automate configuration compliance across Cisco, Palo Alto, Juniper, Arista, and SONiC. Normalizes disparate CLI dialects into standardized baseline models, audits against global standards, and synthesizes syntax-accurate CLI remediation in seconds.
          </p>

          {/* Primary Action Button & Enter Hint */}
          <div className="flex flex-col sm:flex-row items-center justify-center gap-4 pt-2">
            <button
              onClick={onEnter}
              className="w-full sm:w-auto px-8 py-4 rounded-xl text-sm font-bold bg-gradient-to-r from-cyan-400 via-teal-400 to-blue-500 hover:from-cyan-300 hover:to-blue-400 text-slate-950 shadow-[0_0_30px_rgba(6,182,212,0.4)] transition-all flex items-center justify-center gap-3 cursor-pointer group active:scale-95 font-mono"
            >
              <Zap className="w-4 h-4 fill-slate-950 group-hover:scale-110 transition-transform" />
              <span>LAUNCH ZENTRA KERNEL</span>
              <ArrowRight className="w-4 h-4 group-hover:translate-x-1 transition-transform" />
            </button>

            <a
              href="#challenge"
              className="w-full sm:w-auto px-6 py-4 rounded-xl text-sm font-semibold bg-slate-900/80 hover:bg-slate-850 text-slate-200 border border-slate-700/80 transition-all flex items-center justify-center gap-2 cursor-pointer font-mono"
            >
              <Terminal className="w-4 h-4 text-cyan-400" />
              <span>Interactive CLI Demo</span>
            </a>
          </div>

          {/* Keyboard Enter Hint with Blinking Cursor */}
          <div className="flex items-center justify-center gap-2 text-xs font-mono text-slate-400 pt-1">
            <span>Press</span>
            <kbd className="px-2 py-0.5 rounded bg-slate-900 border border-slate-700 text-cyan-300 shadow-sm font-bold">
              Enter ↵
            </kbd>
            <span>to launch app</span>
            <span className="w-1.5 h-3 bg-cyan-400 animate-pulse ml-0.5" />
          </div>

          {/* 4 Stat Cards */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3 sm:gap-4 pt-8 text-left">
            <div className="p-4 rounded-xl bg-slate-900/70 border border-slate-800/90 backdrop-blur-md">
              <div className="text-2xl sm:text-3xl font-extrabold font-mono text-cyan-400">100+</div>
              <div className="text-xs font-semibold text-slate-200 mt-1">Baseline Security Checks</div>
              <div className="text-[11px] text-slate-400 mt-0.5">CIS, NIST, DISA STIG & ISO</div>
            </div>

            <div className="p-4 rounded-xl bg-slate-900/70 border border-slate-800/90 backdrop-blur-md">
              <div className="text-2xl sm:text-3xl font-extrabold font-mono text-emerald-400">7+</div>
              <div className="text-xs font-semibold text-slate-200 mt-1">Enterprise Vendors</div>
              <div className="text-[11px] text-slate-400 mt-0.5">Cisco, Juniper, Arista, PAN-OS</div>
            </div>

            <div className="p-4 rounded-xl bg-slate-900/70 border border-slate-800/90 backdrop-blur-md">
              <div className="text-2xl sm:text-3xl font-extrabold font-mono text-blue-400">&lt; 2s</div>
              <div className="text-xs font-semibold text-slate-200 mt-1">Audit Evaluation Latency</div>
              <div className="text-[11px] text-slate-400 mt-0.5">Instant parallel matrix scoring</div>
            </div>

            <div className="p-4 rounded-xl bg-slate-900/70 border border-slate-800/90 backdrop-blur-md">
              <div className="text-2xl sm:text-3xl font-extrabold font-mono text-purple-400">100%</div>
              <div className="text-xs font-semibold text-slate-200 mt-1">Automated CLI Remediation</div>
              <div className="text-[11px] text-slate-400 mt-0.5">Syntax-accurate copy & paste</div>
            </div>
          </div>
        </div>
      </section>

      {/* 3. SECTION A: THE CORE CHALLENGE (INTERACTIVE FAKE TERMINAL) */}
      <section id="challenge" className="py-20 px-4 sm:px-6 lg:px-8 border-t border-slate-800 bg-slate-900/30">
        <div className="max-w-[1400px] mx-auto space-y-10">
          <div className="text-center max-w-3xl mx-auto space-y-3">
            <div className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-mono font-semibold bg-rose-950/60 text-rose-300 border border-rose-800/60">
              <AlertTriangle className="w-3.5 h-3.5 text-rose-400" />
              <span>THE HETEROGENEOUS FLEET PROBLEM</span>
            </div>
            <h2 className="text-3xl sm:text-4xl font-bold text-white tracking-tight">
              From Vendor Tower of Babel to Certified Baseline
            </h2>
            <p className="text-sm text-slate-400">
              Every vendor writes configuration differently. ZENTRA ingests raw configurations, standardizes them into normalized JSON models, runs multi-framework compliance tests, and outputs exact vendor remediation CLI commands.
            </p>
          </div>

          {/* Vendor Tabs + Stage Selector */}
          <div className="flex flex-col md:flex-row items-center justify-between gap-4 p-3 rounded-xl bg-slate-900 border border-slate-800">
            {/* Vendor Switcher */}
            <div className="flex items-center gap-1.5 overflow-x-auto w-full md:w-auto pb-1 md:pb-0">
              <span className="text-xs font-mono text-slate-500 mr-2 uppercase">Vendor:</span>
              {CHALLENGE_SAMPLES.map((sample, idx) => (
                <button
                  key={sample.vendorId}
                  onClick={() => setSelectedVendorIndex(idx)}
                  className={`px-3 py-1.5 rounded-lg text-xs font-mono font-medium transition cursor-pointer shrink-0 ${
                    selectedVendorIndex === idx
                      ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40'
                      : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800'
                  }`}
                >
                  {sample.vendorName}
                </button>
              ))}
            </div>

            {/* Pipeline Stage Buttons */}
            <div className="flex items-center gap-1 bg-slate-950 p-1 rounded-lg border border-slate-800 w-full md:w-auto overflow-x-auto">
              <button
                onClick={() => setActiveStage('RAW')}
                className={`px-3 py-1 rounded-md text-xs font-mono font-medium transition cursor-pointer shrink-0 ${
                  activeStage === 'RAW' ? 'bg-slate-800 text-white shadow' : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                1. Raw CLI
              </button>
              <button
                onClick={() => setActiveStage('NORMALIZED')}
                className={`px-3 py-1 rounded-md text-xs font-mono font-medium transition cursor-pointer shrink-0 ${
                  activeStage === 'NORMALIZED' ? 'bg-cyan-950 text-cyan-300 border border-cyan-500/40' : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                2. Normalized JSON
              </button>
              <button
                onClick={() => setActiveStage('AUDIT')}
                className={`px-3 py-1 rounded-md text-xs font-mono font-medium transition cursor-pointer shrink-0 ${
                  activeStage === 'AUDIT' ? 'bg-rose-950 text-rose-300 border border-rose-500/40' : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                3. CIS Audit FAIL
              </button>
              <button
                onClick={() => setActiveStage('REMEDIATION')}
                className={`px-3 py-1 rounded-md text-xs font-mono font-medium transition cursor-pointer shrink-0 ${
                  activeStage === 'REMEDIATION' ? 'bg-emerald-950 text-emerald-300 border border-emerald-500/40' : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                4. Tailored Fix CLI
              </button>
            </div>
          </div>

          {/* Interactive Terminal Window */}
          <div className="rounded-2xl border border-slate-800 bg-slate-950 shadow-2xl overflow-hidden font-mono text-xs">
            {/* Window Titlebar */}
            <div className="px-4 py-3 bg-slate-900 border-b border-slate-800 flex items-center justify-between">
              <div className="flex items-center gap-2">
                <div className="flex items-center gap-1.5">
                  <span className="w-3 h-3 rounded-full bg-rose-500/80 inline-block" />
                  <span className="w-3 h-3 rounded-full bg-amber-500/80 inline-block" />
                  <span className="w-3 h-3 rounded-full bg-emerald-500/80 inline-block" />
                </div>
                <span className="text-slate-400 text-xs ml-3">
                  zentra-compliance-kernel — {activeSample.hostname} ({activeSample.vendorName})
                </span>
              </div>

              <div className="flex items-center gap-3">
                <span className="text-[10px] text-slate-500 uppercase">
                  Stage: {activeStage}
                </span>
                <button
                  onClick={() =>
                    handleCopyCode(
                      activeStage === 'RAW'
                        ? activeSample.rawCli
                        : activeStage === 'NORMALIZED'
                        ? activeSample.normalizedJson
                        : activeStage === 'AUDIT'
                        ? JSON.stringify(activeSample.failedCheck, null, 2)
                        : activeSample.cliFix
                    )
                  }
                  className="px-2 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 text-[11px] flex items-center gap-1 transition cursor-pointer"
                  title="Copy terminal contents"
                >
                  {copiedCode ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3 text-slate-400" />}
                  <span>{copiedCode ? 'Copied' : 'Copy'}</span>
                </button>
              </div>
            </div>

            {/* Terminal Body */}
            <div className="p-6 bg-slate-950 text-slate-200 min-h-[340px] overflow-x-auto">
              {activeStage === 'RAW' && (
                <div className="space-y-2">
                  <div className="text-slate-500 font-mono text-[11px] mb-2">
                    # [INPUT] Raw device configuration snippet ingested from {activeSample.hostname} ({activeSample.deviceModel}):
                  </div>
                  <pre className="text-slate-300 whitespace-pre-wrap leading-relaxed">
                    {activeSample.rawCli}
                  </pre>
                </div>
              )}

              {activeStage === 'NORMALIZED' && (
                <div className="space-y-2">
                  <div className="text-slate-500 font-mono text-[11px] mb-2">
                    # [NORMALIZATION] Extracted standardized security model with confidence metrics:
                  </div>
                  <pre className="text-cyan-300 whitespace-pre-wrap leading-relaxed">
                    {activeSample.normalizedJson}
                  </pre>
                </div>
              )}

              {activeStage === 'AUDIT' && (
                <div className="space-y-4">
                  <div className="flex items-center gap-2 text-rose-400 font-bold text-sm">
                    <XCircle className="w-5 h-5 text-rose-400" />
                    <span>AUDIT FAILED: {activeSample.failedCheck.controlId}</span>
                  </div>

                  <div className="p-4 rounded-xl bg-rose-950/20 border border-rose-900/40 space-y-2">
                    <div className="text-slate-200 font-bold text-xs">
                      {activeSample.failedCheck.title}
                    </div>
                    <div className="text-slate-400 text-xs">
                      <span className="text-slate-500 font-bold">Framework Standard: </span>
                      {activeSample.failedCheck.framework}
                    </div>
                    <div className="text-rose-300 text-xs">
                      <span className="text-slate-500 font-bold">Detected Configuration: </span>
                      {activeSample.failedCheck.detected}
                    </div>
                    <div className="text-emerald-300 text-xs">
                      <span className="text-slate-500 font-bold">Expected Baseline: </span>
                      {activeSample.failedCheck.expected}
                    </div>
                    <div className="text-slate-400 text-xs pt-1 border-t border-rose-900/30">
                      <span className="text-slate-500 font-bold">Risk Impact: </span>
                      {activeSample.failedCheck.impact}
                    </div>
                  </div>
                </div>
              )}

              {activeStage === 'REMEDIATION' && (
                <div className="space-y-3">
                  <div className="flex items-center gap-2 text-emerald-400 font-bold text-sm">
                    <CheckCircle2 className="w-5 h-5 text-emerald-400" />
                    <span>SYNTHESIZED CLI REMEDIATION SCRIPT ({activeSample.vendorName.toUpperCase()})</span>
                  </div>
                  <div className="text-slate-400 text-xs">
                    Paste these commands directly into your device console or deploy via SSH Ansible/Netmiko playbook:
                  </div>
                  <pre className="p-4 rounded-xl bg-slate-900 border border-emerald-900/40 text-emerald-300 whitespace-pre-wrap leading-relaxed">
                    {activeSample.cliFix}
                  </pre>
                </div>
              )}
            </div>

            {/* Terminal Footer Bar */}
            <div className="px-4 py-2 bg-slate-900/90 border-t border-slate-800 text-[11px] text-slate-400 flex items-center justify-between">
              <div className="flex items-center gap-2">
                <span className="w-2 h-2 rounded-full bg-emerald-400" />
                <span>Deterministic Normalizer Active</span>
              </div>
              <button
                onClick={onEnter}
                className="text-cyan-400 hover:text-cyan-300 flex items-center gap-1 font-semibold cursor-pointer"
              >
                <span>Audit your own fleet in ZENTRA</span>
                <ChevronRight className="w-3.5 h-3.5" />
              </button>
            </div>
          </div>
        </div>
      </section>

      {/* 4. SECTION B: FOUR-STEP FLOW (INGEST -> NORMALIZE -> EVALUATE -> REMEDIATE) */}
      <section id="workflow" className="py-20 px-4 sm:px-6 lg:px-8 border-t border-slate-800">
        <div className="max-w-[1400px] mx-auto space-y-12">
          <div className="text-center max-w-2xl mx-auto space-y-3">
            <span className="text-xs font-mono font-semibold uppercase tracking-wider text-cyan-400">
              Continuous Pipeline
            </span>
            <h2 className="text-3xl sm:text-4xl font-bold text-white tracking-tight">
              4-Step Automated Compliance Workflow
            </h2>
            <p className="text-sm text-slate-400">
              From raw text dump to cryptographically verifiable compliance certificate in seconds.
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
            {/* Step 1 */}
            <div className="p-6 rounded-2xl bg-slate-900/60 border border-slate-800 hover:border-cyan-500/40 transition-all group flex flex-col justify-between">
              <div>
                <div className="w-12 h-12 rounded-xl bg-cyan-500/10 border border-cyan-500/20 text-cyan-400 flex items-center justify-center font-mono font-bold text-lg mb-4 group-hover:scale-105 transition-transform">
                  01
                </div>
                <h3 className="text-base font-bold text-slate-100 mb-2">Ingest Fleet Configs</h3>
                <p className="text-xs text-slate-400 leading-relaxed">
                  Upload raw files, paste CLI snippets, or drop entire compressed `.zip` fleet packages. Supports Cisco, Juniper, Arista, Fortinet, VyOS, and generic network OS without pre-formatting.
                </p>
              </div>
              <div className="mt-6 pt-4 border-t border-slate-800 text-[11px] font-mono text-cyan-300 flex items-center gap-1">
                <span>ZIP & Text Drag & Drop</span>
              </div>
            </div>

            {/* Step 2 */}
            <div className="p-6 rounded-2xl bg-slate-900/60 border border-slate-800 hover:border-cyan-500/40 transition-all group flex flex-col justify-between">
              <div>
                <div className="w-12 h-12 rounded-xl bg-blue-500/10 border border-blue-500/20 text-blue-400 flex items-center justify-center font-mono font-bold text-lg mb-4 group-hover:scale-105 transition-transform">
                  02
                </div>
                <h3 className="text-base font-bold text-slate-100 mb-2">Normalize to Baseline</h3>
                <p className="text-xs text-slate-400 leading-relaxed">
                  Deterministic regex rules extract management protocol versions, AAA policies, SNMP communities, password encryption states, and ACL bounds into unified JSON models with line attribution.
                </p>
              </div>
              <div className="mt-6 pt-4 border-t border-slate-800 text-[11px] font-mono text-blue-300 flex items-center gap-1">
                <span>Deterministic AST Normalization</span>
              </div>
            </div>

            {/* Step 3 */}
            <div className="p-6 rounded-2xl bg-slate-900/60 border border-slate-800 hover:border-cyan-500/40 transition-all group flex flex-col justify-between">
              <div>
                <div className="w-12 h-12 rounded-xl bg-purple-500/10 border border-purple-500/20 text-purple-400 flex items-center justify-center font-mono font-bold text-lg mb-4 group-hover:scale-105 transition-transform">
                  03
                </div>
                <h3 className="text-base font-bold text-slate-100 mb-2">Multi-Framework Audit</h3>
                <p className="text-xs text-slate-400 leading-relaxed">
                  Simultaneously scores each device configuration against CIS Controls v8, NIST SP 800-53 r5, DISA STIG, and ISO 27001 rule matrices, calculating granular pass/fail compliance ratios.
                </p>
              </div>
              <div className="mt-6 pt-4 border-t border-slate-800 text-[11px] font-mono text-purple-300 flex items-center gap-1">
                <span>4 Parallel Security Baselines</span>
              </div>
            </div>

            {/* Step 4 */}
            <div className="p-6 rounded-2xl bg-slate-900/60 border border-slate-800 hover:border-cyan-500/40 transition-all group flex flex-col justify-between">
              <div>
                <div className="w-12 h-12 rounded-xl bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 flex items-center justify-center font-mono font-bold text-lg mb-4 group-hover:scale-105 transition-transform">
                  04
                </div>
                <h3 className="text-base font-bold text-slate-100 mb-2">Remediate & Export</h3>
                <p className="text-xs text-slate-400 leading-relaxed">
                  Synthesizes syntax-accurate vendor CLI commands for every failed control check. Generates executive PDF audit certificates and bulk ZIP packages with findings CSV & JSON.
                </p>
              </div>
              <div className="mt-6 pt-4 border-t border-slate-800 text-[11px] font-mono text-emerald-300 flex items-center gap-1">
                <span>Per-Device PDF & ZIP Package</span>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* 5. SECTION C: SIX FEATURE CARDS MATCHING PROBLEM STATEMENT */}
      <section id="features" className="py-20 px-4 sm:px-6 lg:px-8 border-t border-slate-800 bg-slate-900/20">
        <div className="max-w-[1400px] mx-auto space-y-12">
          <div className="text-center max-w-2xl mx-auto space-y-3">
            <span className="text-xs font-mono font-semibold uppercase tracking-wider text-cyan-400">
              Core Capabilities
            </span>
            <h2 className="text-3xl sm:text-4xl font-bold text-white tracking-tight">
              Engineered for Enterprise Network Governance
            </h2>
            <p className="text-sm text-slate-400">
              Everything required to enforce continuous configuration baselines across physical switches, cloud routers, and perimeter firewalls.
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
            {/* Card 1 */}
            <div className="p-6 rounded-2xl bg-slate-900/80 border border-slate-800 hover:border-slate-700 transition space-y-3">
              <div className="w-10 h-10 rounded-lg bg-cyan-500/10 text-cyan-400 flex items-center justify-center">
                <Archive className="w-5 h-5" />
              </div>
              <h3 className="text-base font-bold text-slate-100">Unified Multi-Format Ingestion</h3>
              <p className="text-xs text-slate-400 leading-relaxed">
                Ingest single device configurations or drag and drop compressed `.zip` fleet packages containing hundreds of network device backups. Automatically unpacks and batch-normalizes in parallel.
              </p>
            </div>

            {/* Card 2 */}
            <div className="p-6 rounded-2xl bg-slate-900/80 border border-slate-800 hover:border-slate-700 transition space-y-3">
              <div className="w-10 h-10 rounded-lg bg-amber-500/10 text-amber-400 flex items-center justify-center">
                <GraduationCap className="w-5 h-5" />
              </div>
              <h3 className="text-base font-bold text-slate-100">AI Parser Training Module</h3>
              <p className="text-xs text-slate-400 leading-relaxed">
                Identify unrecognized CLI lines across proprietary or emerging network OS versions. Train custom regex patterns on the fly with live AST hot-reloading and instant regression testing.
              </p>
            </div>

            {/* Card 3 */}
            <div className="p-6 rounded-2xl bg-slate-900/80 border border-slate-800 hover:border-slate-700 transition space-y-3">
              <div className="w-10 h-10 rounded-lg bg-emerald-500/10 text-emerald-400 flex items-center justify-center">
                <FileCheck2 className="w-5 h-5" />
              </div>
              <h3 className="text-base font-bold text-slate-100">Multi-Framework Matrix Engine</h3>
              <p className="text-xs text-slate-400 leading-relaxed">
                Single-pass parallel evaluation against CIS Benchmark v2.0, NIST SP 800-53 r5, DoD DISA STIG, and ISO/IEC 27001. Maintain unified audit ledgers with zero framework lock-in.
              </p>
            </div>

            {/* Card 4 */}
            <div className="p-6 rounded-2xl bg-slate-900/80 border border-slate-800 hover:border-slate-700 transition space-y-3">
              <div className="w-10 h-10 rounded-lg bg-indigo-500/10 text-indigo-400 flex items-center justify-center">
                <FileText className="w-5 h-5" />
              </div>
              <h3 className="text-base font-bold text-slate-100">Per-Device PDF Reports & ZIP Bundles</h3>
              <p className="text-xs text-slate-400 leading-relaxed">
                Export formal multi-page compliance certificates per device with hardware serial inventory, framework matrices, and CLI commands. Export full fleet archives into downloadable ZIP bundles.
              </p>
            </div>

            {/* Card 5 */}
            <div className="p-6 rounded-2xl bg-slate-900/80 border border-slate-800 hover:border-slate-700 transition space-y-3">
              <div className="w-10 h-10 rounded-lg bg-purple-500/10 text-purple-400 flex items-center justify-center">
                <Cpu className="w-5 h-5" />
              </div>
              <h3 className="text-base font-bold text-slate-100">Vendor-Agnostic Fleet Scalability</h3>
              <p className="text-xs text-slate-400 leading-relaxed">
                Native normalization for Cisco IOS, IOS-XE, NX-OS, Juniper Junos, Arista EOS, Palo Alto PAN-OS, Fortinet FortiOS, VyOS, and SONiC. Standardized schema abstracts away all CLI syntactic quirks.
              </p>
            </div>

            {/* Card 6 */}
            <div className="p-6 rounded-2xl bg-slate-900/80 border border-slate-800 hover:border-slate-700 transition space-y-3">
              <div className="w-10 h-10 rounded-lg bg-cyan-500/10 text-cyan-400 flex items-center justify-center">
                <Sparkles className="w-5 h-5" />
              </div>
              <h3 className="text-base font-bold text-slate-100">Gemini-Powered CLI Synthesis</h3>
              <p className="text-xs text-slate-400 leading-relaxed">
                Advanced AI analysis translates failed security controls into exact, vendor-accurate configuration commands ready for immediate deployment or change ticket inclusion.
              </p>
            </div>
          </div>
        </div>
      </section>

      {/* 6. SECTION D: AUTO-SCROLLING VENDOR MARQUEE */}
      <section id="vendors" className="py-14 border-t border-slate-800 overflow-hidden bg-slate-950">
        <div className="max-w-[1400px] mx-auto px-4 sm:px-6 lg:px-8 mb-6 text-center">
          <span className="text-xs font-mono uppercase tracking-wider text-slate-500">
            Multi-Vendor Configuration Ecosystem Support
          </span>
        </div>

        {/* Continuous ticker track */}
        <div className="relative w-full overflow-hidden">
          <div className="animate-marquee flex items-center gap-6 text-xs font-mono text-slate-300">
            {[
              'Cisco IOS / IOS-XE / NX-OS',
              'Juniper JunOS (SRX & QFX)',
              'Arista EOS Leaf/Spine',
              'Palo Alto PAN-OS Firewalls',
              'Fortinet FortiOS Gateway',
              'Microsoft SONiC Network OS',
              'VyOS Linux Router',
              'Linux Netfilter / IPTables',
              'Cisco IOS / IOS-XE / NX-OS',
              'Juniper JunOS (SRX & QFX)',
              'Arista EOS Leaf/Spine',
              'Palo Alto PAN-OS Firewalls',
              'Fortinet FortiOS Gateway',
              'Microsoft SONiC Network OS',
              'VyOS Linux Router',
              'Linux Netfilter / IPTables',
            ].map((vendor, i) => (
              <div
                key={i}
                className="flex items-center gap-2.5 px-4 py-2.5 rounded-xl bg-slate-900/80 border border-slate-800/90 whitespace-nowrap shadow-sm hover:border-cyan-500/50 hover:text-cyan-300 transition shrink-0"
              >
                <Cpu className="w-4 h-4 text-cyan-400" />
                <span className="font-semibold">{vendor}</span>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* 7. SECTION E: FINAL CALL TO ACTION (CTA) */}
      <section className="py-20 px-4 sm:px-6 lg:px-8 border-t border-slate-800 bg-gradient-to-b from-slate-900/40 via-cyan-950/20 to-slate-950">
        <div className="max-w-4xl mx-auto text-center space-y-6 p-8 sm:p-12 rounded-3xl border border-cyan-500/30 bg-slate-900/80 backdrop-blur-xl shadow-[0_0_50px_rgba(6,182,212,0.15)]">
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full text-xs font-mono text-cyan-300 bg-cyan-950 border border-cyan-500/40">
            <ShieldCheck className="w-3.5 h-3.5 text-cyan-400" />
            <span>ENTERPRISE NETWORK AUDIT READY</span>
          </div>

          <h2 className="text-3xl sm:text-5xl font-extrabold text-white tracking-tight">
            Ready to audit and secure your network fleet?
          </h2>

          <p className="text-sm sm:text-base text-slate-300 max-w-2xl mx-auto leading-relaxed">
            Launch ZENTRA now to ingest configurations, evaluate multi-framework compliance baselines, and download automated CLI remediation scripts and ZIP report bundles.
          </p>

          <div className="pt-2 flex flex-col sm:flex-row items-center justify-center gap-4">
            <button
              onClick={onEnter}
              className="w-full sm:w-auto px-8 py-4 rounded-xl text-sm font-bold bg-gradient-to-r from-cyan-400 via-teal-400 to-blue-500 hover:from-cyan-300 hover:to-blue-400 text-slate-950 shadow-[0_0_30px_rgba(6,182,212,0.4)] transition-all flex items-center justify-center gap-3 cursor-pointer group active:scale-95 font-mono"
            >
              <Zap className="w-4 h-4 fill-slate-950 group-hover:scale-110 transition-transform" />
              <span>LAUNCH ZENTRA NOW</span>
              <ArrowRight className="w-4 h-4 group-hover:translate-x-1 transition-transform" />
            </button>
          </div>

          <div className="flex items-center justify-center gap-2 text-xs font-mono text-slate-400">
            <span>Or press</span>
            <kbd className="px-2 py-0.5 rounded bg-slate-950 border border-slate-700 text-cyan-300 font-bold">
              Enter ↵
            </kbd>
            <span>at any time</span>
          </div>
        </div>
      </section>

      {/* 8. FOOTER */}
      <footer className="border-t border-slate-900 bg-slate-950 py-8 px-4 sm:px-6 lg:px-8 text-xs text-slate-500 font-mono">
        <div className="max-w-[1600px] mx-auto flex flex-col sm:flex-row items-center justify-between gap-4">
          <div className="flex items-center gap-2">
            <Logo size="sm" />
            <span>• Multi-Framework Network Security Baseline Compliance Platform</span>
          </div>
          <div>
            ZENTRA Kernel v3.2 • CIS Benchmark • NIST SP 800-53 • DISA STIG • ISO 27001
          </div>
        </div>
      </footer>
    </div>
  );
}
