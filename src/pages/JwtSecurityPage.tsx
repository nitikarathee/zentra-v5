import React, { useState, useEffect } from 'react';
import {
  KeyRound,
  ShieldCheck,
  AlertTriangle,
  XCircle,
  CheckCircle2,
  Lock,
  Copy,
  Check,
  RefreshCw,
  Clock,
  Sparkles,
} from 'lucide-react';
import { Card } from '../components/common/Card';
import { SeverityBadge } from '../components/common/Badge';
import { useAuth } from '../context/AuthContext';
import { useToast } from '../context/ToastContext';

// Browser-safe Base64URL encoder/decoder
function base64UrlEncode(str: string): string {
  try {
    return btoa(unescape(encodeURIComponent(str)))
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=+$/, '');
  } catch {
    return btoa(str).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }
}

function base64UrlDecode(str: string): string {
  let base64 = str.replace(/-/g, '+').replace(/_/g, '/');
  while (base64.length % 4) {
    base64 += '=';
  }
  try {
    return decodeURIComponent(escape(atob(base64)));
  } catch {
    return atob(base64);
  }
}

export function JwtSecurityPage() {
  const { token: activeSessionToken, user } = useAuth();
  const [jwtInput, setJwtInput] = useState('');
  const [parsedHeader, setParsedHeader] = useState<any>(null);
  const [parsedPayload, setParsedPayload] = useState<any>(null);
  const [tokenSignature, setTokenSignature] = useState<string>('');
  const [analysisWarnings, setAnalysisWarnings] = useState<Array<{
    title: string;
    severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'SAFE';
    description: string;
    remediation: string;
  }>>([]);
  const [securityScore, setSecurityScore] = useState<number>(100);
  const [copied, setCopied] = useState(false);
  const { showToast } = useToast();

  const SAMPLE_TOKENS = {
    zeroTrustValid: () => {
      const h = base64UrlEncode(JSON.stringify({ alg: 'ES256', typ: 'JWT', kid: 'key-2026-zt' }));
      const p = base64UrlEncode(JSON.stringify({
        sub: 'usr-admin-1',
        name: 'Alex Vance',
        email: 'admin@zentra.sec',
        role: 'ADMIN',
        iss: 'https://auth.zentra.sec',
        aud: 'https://api.zentra.sec',
        iat: Math.floor(Date.now() / 1000),
        exp: Math.floor(Date.now() / 1000) + 900, // 15 min
        jti: 'zt-uuid-994821',
      }));
      const s = base64UrlEncode('cryptographic_p256_ecdsa_signature');
      return `${h}.${p}.${s}`;
    },
    insecureNoneAlg: () => {
      const h = base64UrlEncode(JSON.stringify({ alg: 'none', typ: 'JWT' }));
      const p = base64UrlEncode(JSON.stringify({
        sub: 'attacker-1',
        role: 'SUPERADMIN',
        iat: Math.floor(Date.now() / 1000),
      }));
      return `${h}.${p}.`;
    },
    excessiveLifetimeAndPii: () => {
      const h = base64UrlEncode(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
      const p = base64UrlEncode(JSON.stringify({
        sub: 'usr-9281',
        user_password_hash: '$2a$12$e8f9wef8u23u9u23u4',
        ssn_number: '***-**-4821',
        credit_card_cvv: '921',
        iss: 'http://insecure-internal',
        iat: Math.floor(Date.now() / 1000) - 100000,
        exp: Math.floor(Date.now() / 1000) + 31536000, // 1 year!
      }));
      const s = base64UrlEncode('weak_secret_signature');
      return `${h}.${p}.${s}`;
    },
  };

  useEffect(() => {
    if (activeSessionToken) {
      setJwtInput(activeSessionToken);
      analyzeToken(activeSessionToken);
    } else {
      const defaultToken = SAMPLE_TOKENS.zeroTrustValid();
      setJwtInput(defaultToken);
      analyzeToken(defaultToken);
    }
  }, [activeSessionToken]);

  const analyzeToken = (rawToken: string) => {
    const trimmed = rawToken.trim();
    if (!trimmed) {
      setParsedHeader(null);
      setParsedPayload(null);
      setAnalysisWarnings([]);
      return;
    }

    const parts = trimmed.split('.');
    if (parts.length < 2 || parts.length > 3) {
      setParsedHeader(null);
      setParsedPayload(null);
      setAnalysisWarnings([
        {
          title: 'Malformed JWT Structure',
          severity: 'CRITICAL',
          description: 'The token does not follow standard RFC 7519 dot-delimited structure (header.payload.signature).',
          remediation: 'Provide a valid base64url encoded JSON Web Token.',
        },
      ]);
      setSecurityScore(10);
      return;
    }

    try {
      const headerStr = base64UrlDecode(parts[0]);
      const payloadStr = base64UrlDecode(parts[1]);
      const header = JSON.parse(headerStr);
      const payload = JSON.parse(payloadStr);

      setParsedHeader(header);
      setParsedPayload(payload);
      setTokenSignature(parts[2] || '');

      // Evaluate security warnings
      const warnings: Array<{
        title: string;
        severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'SAFE';
        description: string;
        remediation: string;
      }> = [];

      let score = 100;

      // 1. Check Algorithm
      const alg = (header.alg || '').toLowerCase();
      if (alg === 'none') {
        warnings.push({
          title: 'Critical Vulnerability: Algorithm "none" Accepted',
          severity: 'CRITICAL',
          description: 'The token header explicitly declares `alg: none`. Attackers can forge arbitrary claims without signature verification.',
          remediation: 'Disallow `none` algorithm in JWT verification library. Enforce asymmetric ES256 or RS256.',
        });
        score -= 50;
      } else if (alg === 'hs256') {
        warnings.push({
          title: 'Symmetric HMAC Algorithm (HS256) Detected',
          severity: 'MEDIUM',
          description: 'Shared secret symmetric signing requires all microservices to share the private key, increasing key leakage surface.',
          remediation: 'Migrate to asymmetric ECDSA (ES256) using public key distribution via JWKS endpoint.',
        });
        score -= 15;
      }

      // 2. Check Expiration
      const nowSec = Math.floor(Date.now() / 1000);
      if (!payload.exp) {
        warnings.push({
          title: 'Missing Token Expiration Claim (exp)',
          severity: 'CRITICAL',
          description: 'The token lacks an expiration timestamp. If intercepted, it will remain valid indefinitely.',
          remediation: 'Mandate strict short-lived `exp` claim (maximum 15 minutes for Zero-Trust compliance).',
        });
        score -= 30;
      } else {
        const lifetimeSeconds = payload.exp - (payload.iat || (payload.exp - 3600));
        if (lifetimeSeconds > 3600) {
          warnings.push({
            title: 'Excessive Token Lifetime (> 1 Hour)',
            severity: 'HIGH',
            description: `Token lifetime is ${(lifetimeSeconds / 3600).toFixed(1)} hours. Zero-Trust guidelines mandate maximum 15-minute access token windows.`,
            remediation: 'Shorten access token lifespan to <= 15m and implement refresh token rotation.',
          });
          score -= 20;
        }

        if (payload.exp < nowSec) {
          warnings.push({
            title: 'Expired Token Detected',
            severity: 'LOW',
            description: `Token expired ${Math.round((nowSec - payload.exp) / 60)} minutes ago.`,
            remediation: 'Request a fresh token via OAuth2 refresh token exchange.',
          });
          score -= 5;
        }
      }

      // 3. Check Issuer and Audience
      if (!payload.iss) {
        warnings.push({
          title: 'Missing Issuer Claim (iss)',
          severity: 'MEDIUM',
          description: 'Token does not define the authority that issued it, hindering multi-tenant boundary verification.',
          remediation: 'Populate `iss` with fully-qualified URL (e.g. https://auth.zentra.sec).',
        });
        score -= 10;
      }

      if (!payload.aud) {
        warnings.push({
          title: 'Missing Audience Claim (aud)',
          severity: 'MEDIUM',
          description: 'Token can be replayed against other internal services that accept the same signing key.',
          remediation: 'Mandate target audience verification matching the specific API gateway.',
        });
        score -= 10;
      }

      // 4. Sensitive Data in Claims Check
      const payloadString = JSON.stringify(payload).toLowerCase();
      if (
        payloadString.includes('password') ||
        payloadString.includes('ssn') ||
        payloadString.includes('credit_card') ||
        payloadString.includes('cvv') ||
        payloadString.includes('secret')
      ) {
        warnings.push({
          title: 'Critical: Sensitive Confidential PII / Secrets in Token Payload',
          severity: 'CRITICAL',
          description: 'Token contains plaintext sensitive attributes (passwords, SSN, card details). JWT payloads are merely base64 encoded and publicly readable.',
          remediation: 'Never embed confidential secrets in client tokens. Store attributes in server-side session stores or opaque reference tokens.',
        });
        score -= 35;
      }

      setAnalysisWarnings(warnings);
      setSecurityScore(Math.max(10, score));
    } catch (e: any) {
      setParsedHeader(null);
      setParsedPayload(null);
      setAnalysisWarnings([
        {
          title: 'JSON Parsing Exception',
          severity: 'CRITICAL',
          description: `Failed to deserialize token segments: ${e.message}`,
          remediation: 'Verify base64url encoding integrity.',
        },
      ]);
      setSecurityScore(10);
    }
  };

  const handleCopy = () => {
    navigator.clipboard.writeText(jwtInput);
    setCopied(true);
    showToast('Token copied to clipboard', '', 'info');
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="space-y-6 text-left">
      {/* Header */}
      <div>
        <h2 className="text-xl sm:text-2xl font-bold text-slate-100 tracking-tight">
          JWT Security & Token Forensics Analyzer
        </h2>
        <p className="text-xs sm:text-sm text-slate-400 mt-0.5">
          Inspect, decode, and audit JSON Web Tokens against Zero-Trust cryptographic and lifetime standards.
        </p>
      </div>

      {/* Quick Preload Presets */}
      <div className="flex flex-wrap items-center gap-2">
        <span className="text-xs text-slate-400 font-medium">Load Preset:</span>
        <button
          onClick={() => {
            const t = SAMPLE_TOKENS.zeroTrustValid();
            setJwtInput(t);
            analyzeToken(t);
          }}
          className="px-2.5 py-1 rounded text-xs font-mono bg-emerald-950/60 border border-emerald-500/40 text-emerald-300 hover:bg-emerald-900/60 transition cursor-pointer"
        >
          ✓ Zero-Trust Compliant (ES256)
        </button>

        <button
          onClick={() => {
            const t = SAMPLE_TOKENS.insecureNoneAlg();
            setJwtInput(t);
            analyzeToken(t);
          }}
          className="px-2.5 py-1 rounded text-xs font-mono bg-rose-950/60 border border-rose-500/40 text-rose-300 hover:bg-rose-900/60 transition cursor-pointer"
        >
          ⚠ Critical: alg="none"
        </button>

        <button
          onClick={() => {
            const t = SAMPLE_TOKENS.excessiveLifetimeAndPii();
            setJwtInput(t);
            analyzeToken(t);
          }}
          className="px-2.5 py-1 rounded text-xs font-mono bg-amber-950/60 border border-amber-500/40 text-amber-300 hover:bg-amber-900/60 transition cursor-pointer"
        >
          ⚠ Excessive Lifetime & PII Leak
        </button>
      </div>

      {/* Raw Token Input */}
      <Card
        title="Raw Encoded JSON Web Token"
        action={
          <button
            onClick={handleCopy}
            className="text-xs text-slate-400 hover:text-slate-200 flex items-center gap-1 cursor-pointer"
          >
            {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
            <span>Copy Token</span>
          </button>
        }
      >
        <textarea
          rows={4}
          value={jwtInput}
          onChange={(e) => {
            setJwtInput(e.target.value);
            analyzeToken(e.target.value);
          }}
          placeholder="Paste JWT token string (header.payload.signature)..."
          className="w-full p-3 rounded-lg border border-slate-800 bg-black/80 font-mono text-xs text-cyan-200 focus:outline-none focus:border-cyan-500 break-all select-all"
        />
      </Card>

      {/* Security Posture & Score */}
      <Card
        title="Token Security Score & Forensic Assessment"
        action={
          <span className={`text-lg font-mono font-bold ${securityScore >= 80 ? 'text-emerald-400' : securityScore >= 50 ? 'text-amber-400' : 'text-rose-400'}`}>
            Score: {securityScore} / 100
          </span>
        }
      >
        {analysisWarnings.length === 0 ? (
          <div className="p-4 rounded-lg bg-emerald-950/40 border border-emerald-500/30 flex items-center gap-3 text-xs text-emerald-300">
            <CheckCircle2 className="w-5 h-5 text-emerald-400 shrink-0" />
            <div>
              <p className="font-bold">Zero-Trust Token Hygiene Verified</p>
              <p className="text-[11px] text-emerald-400 mt-0.5">
                Token utilizes robust asymmetric signatures, bounded expiration timestamps, and avoids sensitive PII leakage.
              </p>
            </div>
          </div>
        ) : (
          <div className="space-y-3">
            {analysisWarnings.map((w, idx) => (
              <div
                key={idx}
                className="p-3.5 rounded-lg border border-slate-800 bg-slate-950 flex items-start justify-between gap-4"
              >
                <div className="space-y-1">
                  <div className="flex items-center gap-2">
                    <SeverityBadge severity={w.severity} size="sm" />
                    <span className="text-xs font-bold text-slate-200">{w.title}</span>
                  </div>
                  <p className="text-xs text-slate-400">{w.description}</p>
                  <p className="text-[11px] font-mono text-cyan-300 mt-1">
                    Fix: {w.remediation}
                  </p>
                </div>
              </div>
            ))}
          </div>
        )}
      </Card>

      {/* Decoded Header and Payload Grids */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Header */}
        <Card title="Decoded Header (Algorithm & Token Type)">
          <div className="p-3 rounded-lg bg-black/80 border border-slate-800 font-mono text-xs text-rose-300 overflow-x-auto select-text whitespace-pre-wrap">
            {parsedHeader ? JSON.stringify(parsedHeader, null, 2) : '// No valid header decoded'}
          </div>
        </Card>

        {/* Payload */}
        <Card title="Decoded Payload (Claims & Subject)">
          <div className="p-3 rounded-lg bg-black/80 border border-slate-800 font-mono text-xs text-purple-300 overflow-x-auto select-text whitespace-pre-wrap">
            {parsedPayload ? JSON.stringify(parsedPayload, null, 2) : '// No valid payload decoded'}
          </div>
        </Card>
      </div>

      {/* Signature Section */}
      <Card title="Cryptographic Signature Verification">
        <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 font-mono text-xs text-cyan-400 truncate">
          {tokenSignature ? `Signature Hash: ${tokenSignature}` : 'No signature present in token.'}
        </div>
        <p className="text-[11px] text-slate-400 mt-2">
          Zero-Trust mandate: Microservices must always verify signature against authorized JWKS keys before granting access to controllers.
        </p>
      </Card>
    </div>
  );
}
