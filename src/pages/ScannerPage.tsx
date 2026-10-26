import React, { useState, useEffect, useRef } from 'react';
import {
  Radar,
  Play,
  Terminal,
  CheckCircle2,
  AlertTriangle,
  ShieldAlert,
  ShieldCheck,
  RefreshCw,
  ArrowRight,
  Server,
  FileCode,
  Upload,
  Copy,
  Check,
  Search,
  Filter,
  Layers,
  KeyRound,
  Lock,
  Globe,
  Database,
  ExternalLink,
  Info,
  Archive,
  Download,
} from 'lucide-react';
import JSZip from 'jszip';
import { Card } from '../components/common/Card';
import { SeverityBadge, StatusBadge } from '../components/common/Badge';
import { ApiItem, ScanRecord, SecurityFinding } from '../types';
import { apiService } from '../services/api';
import { useToast } from '../context/ToastContext';

// Preset sample specifications
const SAMPLE_SPECS = {
  vulnerable: `openapi: 3.0.3
info:
  title: Apex Retail Commerce API
  version: 1.0.0
  description: High-throughput e-commerce microservices with product catalogs, shopping carts, and customer checkout.
servers:
  - url: http://api.apexretail.internal/v1
    description: Insecure HTTP cleartext internal gateway
paths:
  /admin/users:
    get:
      summary: Retrieve all platform administrators and customers
      responses:
        '200':
          description: List of user accounts
          content:
            application/json:
              schema:
                type: array
                items:
                  type: object
                  properties:
                    id:
                      type: string
                    email:
                      type: string
                    password_hash:
                      type: string
                      description: BCrypt user password hash
                    social_security:
                      type: string
                      description: Government PII
    post:
      summary: Provision new administrative account
      security: []
      requestBody:
        content:
          application/json:
            schema:
              type: object
              additionalProperties: true
      responses:
        '201':
          description: User created
  /payments/process:
    post:
      summary: Direct credit card charge gateway
      parameters:
        - name: amount
          in: query
          required: true
          schema:
            type: number
        - name: customer_reference
          in: query
          required: false
          schema:
            type: string
      responses:
        '200':
          description: Settlement confirmed
          content:
            application/json:
              schema:
                type: object
                properties:
                  transaction_id:
                    type: string
                  credit_card:
                    type: string
                  cvv:
                    type: string
components:
  securitySchemes:
    BasicAuth:
      type: http
      scheme: basic
      description: RFC 7617 Basic Authentication over perimeter
    QueryApiKey:
      type: apiKey
      name: api_key
      in: query
      description: Insecure query parameter API key
x-cors:
  allowOrigin: "*"
  allowCredentials: true`,

  fintech: `{
  "openapi": "3.0.1",
  "info": {
    "title": "NovaBank Core Ledger API",
    "version": "2.4.0",
    "description": "Interbank settlement, account balance verification, and wire transfer processing."
  },
  "servers": [
    {
      "url": "https://api.novabank.corp/ledger/v2",
      "description": "Production encrypted endpoint"
    }
  ],
  "security": [
    {
      "OAuth2Security": []
    }
  ],
  "paths": {
    "/accounts/{accountId}/transfer": {
      "post": {
        "summary": "Initiate interbank wire transfer",
        "security": [
          {
            "OAuth2Security": []
          }
        ],
        "parameters": [
          {
            "name": "accountId",
            "in": "path",
            "required": true,
            "schema": {
              "type": "string"
            }
          }
        ],
        "requestBody": {
          "required": true,
          "content": {
            "application/json": {
              "schema": {
                "type": "object",
                "properties": {
                  "recipientIban": {
                    "type": "string"
                  },
                  "amount": {
                    "type": "number"
                  }
                }
              }
            }
          }
        },
        "responses": {
          "200": {
            "description": "Transfer queued successfully"
          }
        }
      }
    },
    "/accounts/{accountId}/balance": {
      "get": {
        "summary": "Check account ledger balance",
        "parameters": [
          {
            "name": "accountId",
            "in": "path",
            "required": true,
            "schema": {
              "type": "string",
              "maxLength": 36,
              "pattern": "^[0-9a-fA-F-]+$"
            }
          }
        ],
        "responses": {
          "200": {
            "description": "Current verified balance",
            "content": {
              "application/json": {
                "schema": {
                  "type": "object",
                  "properties": {
                    "balance": {
                      "type": "number"
                    },
                    "currency": {
                      "type": "string",
                      "enum": ["USD", "EUR", "GBP"]
                    }
                  }
                }
              }
            }
          }
        }
      }
    }
  },
  "components": {
    "securitySchemes": {
      "OAuth2Security": {
        "type": "oauth2",
        "description": "Central OAuth 2.0 authorization server",
        "flows": {
          "authorizationCode": {
            "authorizationUrl": "https://auth.novabank.corp/oauth/authorize",
            "tokenUrl": "https://auth.novabank.corp/oauth/token",
            "scopes": {
              "ledger:read": "Read account balances",
              "ledger:write": "Execute wire transfers"
            }
          }
        }
      }
    }
  }
}`,

  hardened: `openapi: 3.0.3
info:
  title: HealthMatrix Clinical Records API
  version: 3.1.0
  description: HIPAA-compliant electronic health records (EHR) gateway with cryptographic Zero-Trust posture.
servers:
  - url: https://records.healthmatrix.internal/v1
    description: Production mTLS mutual authenticated gateway
security:
  - BearerJWT:
      - ehr:read
paths:
  /patients/{patientId}/records:
    get:
      summary: Query clinical consultation history
      security:
        - BearerJWT:
            - ehr:read
      parameters:
        - name: patientId
          in: path
          required: true
          schema:
            type: string
            pattern: "^PAT-[0-9]{8}$"
            maxLength: 12
        - name: limit
          in: query
          required: false
          schema:
            type: integer
            minimum: 1
            maximum: 100
      responses:
        '200':
          description: Encrypted clinical consultation entries
          content:
            application/json:
              schema:
                type: object
                additionalProperties: false
                properties:
                  patientId:
                    type: string
                  recordsCount:
                    type: integer
                  consultations:
                    type: array
                    maxItems: 100
                    items:
                      type: object
                      properties:
                        timestamp:
                          type: string
                        department:
                          type: string
        '429':
          description: Throttling quota exceeded
          headers:
            Retry-After:
              schema:
                type: integer
              description: Seconds to wait before retry
components:
  securitySchemes:
    BearerJWT:
      type: http
      scheme: bearer
      bearerFormat: JWT
      description: Signed ES256 JSON Web Token with claims attestation`,
};

interface ScannerPageProps {
  initialApiId?: string | null;
  onNavigateTab: (tab: string) => void;
  onSelectFinding: (id: string) => void;
}

export function ScannerPage({ initialApiId, onNavigateTab, onSelectFinding }: ScannerPageProps) {
  // Navigation Tabs
  const [activeMode, setActiveMode] = useState<'MANAGED_SCAN' | 'SPEC_ANALYSIS'>('SPEC_ANALYSIS');

  // Mode 1: Managed Inventory API Scan State
  const [apis, setApis] = useState<ApiItem[]>([]);
  const [selectedApiId, setSelectedApiId] = useState<string>(initialApiId || '');
  const [scanProfile, setScanProfile] = useState<'STANDARD' | 'DEEP_CIS' | 'AI_HEURISTIC'>('DEEP_CIS');
  const [isScanning, setIsScanning] = useState(false);
  const [progress, setProgress] = useState(0);
  const [currentStep, setCurrentStep] = useState('');
  const [consoleLogs, setConsoleLogs] = useState<string[]>([]);
  const [completedScan, setCompletedScan] = useState<ScanRecord | null>(null);
  const [discoveredFindings, setDiscoveredFindings] = useState<SecurityFinding[]>([]);
  const [scanHistory, setScanHistory] = useState<ScanRecord[]>([]);

  // Mode 2: OpenAPI / Swagger Specification Static Analysis State
  const [specContent, setSpecContent] = useState<string>(SAMPLE_SPECS.vulnerable);
  const [isAnalyzingSpec, setIsAnalyzingSpec] = useState(false);
  const [specEnvironment, setSpecEnvironment] = useState<'Production' | 'Staging' | 'Development'>('Production');
  const [saveToInventory, setSaveToInventory] = useState(true);
  const [saveFindings, setSaveFindings] = useState(true);
  const [analysisResult, setAnalysisResult] = useState<any | null>(null);
  const [endpointSearch, setEndpointSearch] = useState('');
  const [methodFilter, setMethodFilter] = useState('ALL');
  const [findingSeverityFilter, setFindingSeverityFilter] = useState('ALL');

  const fileInputRef = useRef<HTMLInputElement>(null);
  const terminalEndRef = useRef<HTMLDivElement>(null);
  const { showToast } = useToast();

  useEffect(() => {
    async function loadData() {
      try {
        const [apisList, history] = await Promise.all([
          apiService.getApis(),
          apiService.getScans(),
        ]);
        setApis(apisList);
        setScanHistory(history);
        if (!selectedApiId && apisList.length > 0) {
          setSelectedApiId(apisList[0].id);
        }
      } catch (err: any) {
        showToast('Error loading scanner data', err.message, 'error');
      }
    }
    loadData();
  }, []);

  useEffect(() => {
    if (initialApiId) {
      setSelectedApiId(initialApiId);
      setActiveMode('MANAGED_SCAN');
    }
  }, [initialApiId]);

  useEffect(() => {
    terminalEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [consoleLogs]);

  // Execute Managed API Scan
  const runScan = async () => {
    const target = apis.find((a) => a.id === selectedApiId);
    if (!target) {
      showToast('Select an API', 'Please choose a target API to initiate scanning.', 'warning');
      return;
    }

    setIsScanning(true);
    setProgress(5);
    setConsoleLogs([
      `[${new Date().toISOString()}] ZENTRA Zero-Trust Security Scanner Daemon v2.4 initialized.`,
      `[${new Date().toISOString()}] Binding session to target: ${target.name} (${target.baseUrl})...`,
    ]);
    setCompletedScan(null);
    setDiscoveredFindings([]);

    try {
      const steps = [
        { pct: 15, msg: 'Extracting declared endpoints and route boundaries...' },
        { pct: 30, msg: `Auditing authentication boundary [${target.authType}] in [${target.environment}]...` },
        { pct: 50, msg: 'Probing RBAC role scopes and Broken Object Level Authorization (BOLA)...' },
        { pct: 70, msg: 'Testing rate-limiting enforcement thresholds and HTTP security headers...' },
        { pct: 85, msg: 'Evaluating against CIS API Security Benchmark v1.2 & custom Knowledge Rules...' },
        { pct: 95, msg: 'Executing SHA-256 cryptographic audit chain attestation...' },
      ];

      for (const s of steps) {
        await new Promise((r) => setTimeout(r, 400));
        setProgress(s.pct);
        setCurrentStep(s.msg);
        setConsoleLogs((prev) => [...prev, `[${new Date().toISOString()}] ${s.msg}`]);
      }

      const result = await apiService.startScan(target.id);

      setProgress(100);
      setCompletedScan(result.scan);
      setDiscoveredFindings(result.findings);
      setConsoleLogs((prev) => [
        ...prev,
        `[${new Date().toISOString()}] Scan completed. Discovered ${result.findings.length} security finding(s).`,
        `[${new Date().toISOString()}] Cryptographic audit log entry committed with SHA-256 forward hash.`,
      ]);

      const history = await apiService.getScans();
      setScanHistory(history);

      showToast('Scan Completed', `Discovered ${result.findings.length} finding(s) for ${target.name}.`, 'success');
    } catch (err: any) {
      showToast('Scan Failed', err.message, 'error');
      setConsoleLogs((prev) => [...prev, `[ERROR] Scan terminated prematurely: ${err.message}`]);
    } finally {
      setIsScanning(false);
    }
  };

  // Execute OpenAPI / Swagger Spec Static Analysis
  const handleAnalyzeSpec = async () => {
    if (!specContent.trim()) {
      showToast('Specification Empty', 'Please paste or upload an OpenAPI/Swagger document.', 'warning');
      return;
    }

    setIsAnalyzingSpec(true);
    try {
      const res = await apiService.analyzeSpec({
        spec: specContent,
        saveToInventory,
        saveFindings,
        environment: specEnvironment,
      });

      setAnalysisResult(res);

      if (saveToInventory) {
        const apisList = await apiService.getApis();
        setApis(apisList);
      }
      if (saveFindings) {
        const history = await apiService.getScans();
        setScanHistory(history);
      }

      showToast(
        'Specification Analyzed',
        `Parsed "${res.parsed.title}" (${res.parsed.endpointsCount} endpoints). Discovered ${res.findings.length} finding(s).`,
        'success'
      );
    } catch (err: any) {
      showToast('Spec Analysis Error', err.message, 'error');
    } finally {
      setIsAnalyzingSpec(false);
    }
  };

  // ZIP Spec Archive State
  const [unzippedSpecs, setUnzippedSpecs] = useState<Array<{ name: string; content: string }>>([]);
  const [selectedUnzippedIndex, setSelectedUnzippedIndex] = useState<number>(0);
  const [isExportingScanZip, setIsExportingScanZip] = useState<boolean>(false);

  // Handle file upload with ZIP unpack support
  const handleFileUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    if (file.name.toLowerCase().endsWith('.zip') || file.type.includes('zip')) {
      try {
        const zip = await JSZip.loadAsync(file);
        const specsFound: Array<{ name: string; content: string }> = [];

        for (const [path, entry] of Object.entries(zip.files)) {
          if (!entry.dir && !path.includes('__MACOSX') && !path.startsWith('.')) {
            const lower = path.toLowerCase();
            if (lower.endsWith('.json') || lower.endsWith('.yaml') || lower.endsWith('.yml')) {
              const text = await entry.async('text');
              if (
                text.includes('openapi') ||
                text.includes('swagger') ||
                text.includes('paths') ||
                text.includes('info')
              ) {
                specsFound.push({ name: path.split('/').pop() || path, content: text });
              }
            }
          }
        }

        if (specsFound.length > 0) {
          setUnzippedSpecs(specsFound);
          setSelectedUnzippedIndex(0);
          setSpecContent(specsFound[0].content);
          showToast(
            'ZIP Specs Extracted',
            `Discovered ${specsFound.length} OpenAPI specification(s) in ${file.name}. Loaded "${specsFound[0].name}".`,
            'success'
          );
        } else {
          showToast(
            'No OpenAPI Specs Found in ZIP',
            'The archive did not contain recognizable OpenAPI/Swagger YAML/JSON files.',
            'warning'
          );
        }
      } catch (err: any) {
        showToast('ZIP Extraction Error', err.message, 'error');
      }
      return;
    }

    const reader = new FileReader();
    reader.onload = (event) => {
      const text = event.target?.result as string;
      if (text) {
        setSpecContent(text);
        setUnzippedSpecs([]);
        showToast('Document Loaded', `Uploaded ${file.name} (${Math.round(file.size / 1024)} KB).`, 'info');
      }
    };
    reader.readAsText(file);
  };

  // Export static scan findings & remediation package as ZIP
  const handleExportScanZip = async () => {
    if (!analysisResult) return;
    try {
      setIsExportingScanZip(true);
      const zip = new JSZip();

      // 1. Raw Specification
      const isYaml = specContent.trim().startsWith('openapi:') || specContent.trim().startsWith('swagger:');
      zip.file(`spec.${isYaml ? 'yaml' : 'json'}`, specContent);

      // 2. Parsed Endpoints
      zip.file('endpoints.json', JSON.stringify(analysisResult.parsed?.endpoints || [], null, 2));

      // 3. Security Findings
      zip.file('findings.json', JSON.stringify(analysisResult.findings || [], null, 2));

      // 4. Remediation Markdown Playbook
      let md = `# ZENTRA Security Scan Remediation Guide\n\n`;
      md += `**Target API:** ${analysisResult.parsed?.title || 'API Specification'}\n`;
      md += `**Version:** ${analysisResult.parsed?.version || '1.0.0'}\n`;
      md += `**Security Score:** ${analysisResult.score}%\n`;
      md += `**Findings Summary:** ${analysisResult.summary?.critical || 0} Critical, ${analysisResult.summary?.high || 0} High, ${analysisResult.summary?.medium || 0} Medium, ${analysisResult.summary?.low || 0} Low\n\n`;
      md += `## Identified Vulnerabilities & Required Actions\n\n`;
      (analysisResult.findings || []).forEach((f: SecurityFinding, idx: number) => {
        md += `### ${idx + 1}. [${f.severity}] ${f.title}\n`;
        md += `- **Endpoint:** \`${f.method} ${f.endpoint}\`\n`;
        md += `- **Category:** ${f.category}\n`;
        md += `- **Description:** ${f.description}\n`;
        md += `- **Impact:** ${f.impact}\n`;
        md += `- **Recommended Fix:** ${f.recommendation}\n`;
        md += `- **Implementation Guide:**\n\`\`\`\n${f.implementationGuide}\n\`\`\`\n\n`;
      });
      zip.file('remediation-playbook.md', md);

      // 5. Summary Manifest
      const manifest = {
        archiveType: 'ZENTRA Static Spec Analysis Package',
        timestamp: new Date().toISOString(),
        score: analysisResult.score,
        summary: analysisResult.summary,
        parsed: {
          title: analysisResult.parsed?.title,
          version: analysisResult.parsed?.version,
          endpointsCount: analysisResult.parsed?.endpointsCount,
        },
      };
      zip.file('scan-manifest.json', JSON.stringify(manifest, null, 2));

      const blob = await zip.generateAsync({ type: 'blob' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      const cleanTitle = (analysisResult.parsed?.title || 'api-spec').replace(/[^a-zA-Z0-9_-]/g, '_');
      a.download = `zentra-spec-scan-${cleanTitle}.zip`;
      a.click();
      URL.revokeObjectURL(url);

      showToast('Scan Package Exported', 'Downloaded full security findings and remediation ZIP archive.', 'success');
    } catch (err: any) {
      showToast('Export Error', err.message, 'error');
    } finally {
      setIsExportingScanZip(false);
    }
  };

  const selectedApi = apis.find((a) => a.id === selectedApiId);

  // Filtered parsed endpoints
  const filteredEndpoints = (analysisResult?.parsed?.endpoints || []).filter((ep: any) => {
    const matchesMethod = methodFilter === 'ALL' || ep.method === methodFilter;
    const matchesSearch =
      ep.path.toLowerCase().includes(endpointSearch.toLowerCase()) ||
      (ep.summary && ep.summary.toLowerCase().includes(endpointSearch.toLowerCase()));
    return matchesMethod && matchesSearch;
  });

  // Filtered findings from analysis
  const filteredSpecFindings = (analysisResult?.findings || []).filter((f: SecurityFinding) => {
    return findingSeverityFilter === 'ALL' || f.severity === findingSeverityFilter;
  });

  return (
    <div className="space-y-6 text-left">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h2 className="text-xl sm:text-2xl font-bold text-slate-100 tracking-tight">
            Zero-Trust API Security Scanner
          </h2>
          <p className="text-xs sm:text-sm text-slate-400 mt-0.5">
            Static OpenAPI/Swagger specification analysis & automated Zero-Trust vulnerability discovery.
          </p>
        </div>

        {/* Mode Switcher */}
        <div className="flex items-center p-1 rounded-xl bg-slate-900 border border-slate-800 self-start sm:self-auto">
          <button
            onClick={() => setActiveMode('SPEC_ANALYSIS')}
            className={`flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs font-semibold transition cursor-pointer ${
              activeMode === 'SPEC_ANALYSIS'
                ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/30'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <FileCode className="w-3.5 h-3.5" />
            <span>OpenAPI / Swagger Spec Import</span>
          </button>
          <button
            onClick={() => setActiveMode('MANAGED_SCAN')}
            className={`flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs font-semibold transition cursor-pointer ${
              activeMode === 'MANAGED_SCAN'
                ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/30'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <Radar className="w-3.5 h-3.5" />
            <span>Target Inventory API Scan</span>
          </button>
        </div>
      </div>

      {/* =========================================================================
          MODE 1: OPENAPI / SWAGGER SPECIFICATION STATIC ANALYSIS
          ========================================================================= */}
      {activeMode === 'SPEC_ANALYSIS' && (
        <div className="space-y-6">
          {/* Spec Input Card */}
          <Card
            title={
              <div className="flex items-center gap-2">
                <FileCode className="w-4 h-4 text-cyan-400" />
                <span>Import OpenAPI / Swagger Document (JSON or YAML)</span>
              </div>
            }
            subtitle="Analyze declared security schemes, unauthenticated routes, weak auth, rate limits, PII exposure, and schema bounds"
            action={
              <div className="flex items-center gap-2">
                <input
                  type="file"
                  ref={fileInputRef}
                  onChange={handleFileUpload}
                  accept=".json,.yaml,.yml,.zip,application/zip"
                  className="hidden"
                />
                <button
                  onClick={() => fileInputRef.current?.click()}
                  className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-slate-700 bg-slate-800 hover:bg-slate-700 text-xs font-medium text-slate-200 transition cursor-pointer"
                  title="Upload OpenAPI/Swagger YAML or JSON file, or a .zip archive of multiple specs"
                >
                  <Upload className="w-3.5 h-3.5" />
                  <span>Upload Spec / ZIP</span>
                </button>
              </div>
            }
          >
            <div className="space-y-4">
              {/* If unpacked from ZIP, show spec switcher */}
              {unzippedSpecs.length > 0 && (
                <div className="p-3 bg-cyan-950/40 border border-cyan-500/40 rounded-xl flex flex-col sm:flex-row sm:items-center justify-between gap-2 text-xs">
                  <div className="flex items-center gap-2 text-cyan-300">
                    <Archive className="w-4 h-4 text-cyan-400 shrink-0" />
                    <span className="font-semibold">Extracted Specs from ZIP Archive:</span>
                    <span className="text-slate-400 font-mono text-[11px]">{unzippedSpecs.length} files</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <span className="text-slate-400 text-xs">Active Spec:</span>
                    <select
                      value={selectedUnzippedIndex}
                      onChange={(e) => {
                        const idx = Number(e.target.value);
                        setSelectedUnzippedIndex(idx);
                        setSpecContent(unzippedSpecs[idx].content);
                      }}
                      className="bg-slate-900 border border-slate-700 text-slate-200 text-xs rounded-lg px-2.5 py-1 focus:outline-none focus:border-cyan-500 font-mono"
                    >
                      {unzippedSpecs.map((s, idx) => (
                        <option key={idx} value={idx}>
                          {s.name}
                        </option>
                      ))}
                    </select>
                  </div>
                </div>
              )}

              {/* Preset Selector */}
              <div className="flex flex-wrap items-center gap-2 text-xs">
                <span className="text-slate-400 font-mono text-[11px]">Load Sample Spec:</span>
                <button
                  type="button"
                  onClick={() => setSpecContent(SAMPLE_SPECS.vulnerable)}
                  className="px-2.5 py-1 rounded-md bg-rose-950/40 border border-rose-500/40 text-rose-300 hover:bg-rose-900/50 transition cursor-pointer font-mono text-[11px]"
                >
                  Vulnerable E-Commerce (High Risk)
                </button>
                <button
                  type="button"
                  onClick={() => setSpecContent(SAMPLE_SPECS.fintech)}
                  className="px-2.5 py-1 rounded-md bg-amber-950/40 border border-amber-500/40 text-amber-300 hover:bg-amber-900/50 transition cursor-pointer font-mono text-[11px]"
                >
                  Fintech Banking Gateway (OAuth2 Scopes)
                </button>
                <button
                  type="button"
                  onClick={() => setSpecContent(SAMPLE_SPECS.hardened)}
                  className="px-2.5 py-1 rounded-md bg-emerald-950/40 border border-emerald-500/40 text-emerald-300 hover:bg-emerald-900/50 transition cursor-pointer font-mono text-[11px]"
                >
                  Hardened Healthcare (Zero-Trust Compliant)
                </button>
              </div>

              {/* Code Editor Textarea */}
              <div className="relative">
                <textarea
                  rows={14}
                  value={specContent}
                  onChange={(e) => setSpecContent(e.target.value)}
                  placeholder="Paste OpenAPI 3.x or Swagger 2.0 definition in YAML or JSON..."
                  className="w-full p-4 rounded-xl border border-slate-800 bg-black/90 font-mono text-xs text-cyan-200 placeholder-slate-600 focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500 transition leading-relaxed select-text"
                  spellCheck={false}
                />
                <div className="absolute right-3 bottom-3 text-[10px] font-mono text-slate-500 bg-slate-900/80 px-2 py-0.5 rounded border border-slate-800">
                  {specContent.split('\n').length} lines • {specContent.length} chars
                </div>
              </div>

              {/* Ingestion & Persistence Controls */}
              <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 pt-2 border-t border-slate-800/80">
                <div className="flex flex-col justify-center gap-1.5">
                  <label className="flex items-center gap-2 cursor-pointer text-xs text-slate-300">
                    <input
                      type="checkbox"
                      checked={saveToInventory}
                      onChange={(e) => setSaveToInventory(e.target.checked)}
                      className="rounded border-slate-700 bg-slate-900 text-cyan-500 focus:ring-0"
                    />
                    <span>Auto-register API into Inventory</span>
                  </label>
                  <label className="flex items-center gap-2 cursor-pointer text-xs text-slate-300">
                    <input
                      type="checkbox"
                      checked={saveFindings}
                      onChange={(e) => setSaveFindings(e.target.checked)}
                      className="rounded border-slate-700 bg-slate-900 text-cyan-500 focus:ring-0"
                    />
                    <span>Persist Discovered Findings to Database</span>
                  </label>
                </div>

                <div>
                  <label className="block text-[11px] font-semibold text-slate-400 mb-1">
                    Target Environment Context
                  </label>
                  <select
                    value={specEnvironment}
                    onChange={(e) => setSpecEnvironment(e.target.value as any)}
                    className="w-full px-3 py-1.5 rounded-lg border border-slate-800 bg-slate-950 text-xs text-slate-200 focus:outline-none focus:border-cyan-500"
                  >
                    <option value="Production">Production (Enforce Strict mTLS & Scopes)</option>
                    <option value="Staging">Staging (Pre-Release Validation)</option>
                    <option value="Development">Development (Testing Sandbox)</option>
                  </select>
                </div>

                <div className="flex items-end">
                  <button
                    onClick={handleAnalyzeSpec}
                    disabled={isAnalyzingSpec || !specContent.trim()}
                    className="w-full flex items-center justify-center gap-2 px-4 py-2.5 rounded-lg bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white text-xs font-semibold shadow-lg shadow-cyan-900/30 transition disabled:opacity-50 cursor-pointer"
                  >
                    {isAnalyzingSpec ? (
                      <>
                        <RefreshCw className="w-4 h-4 animate-spin" />
                        <span>Parsing & Auditing...</span>
                      </>
                    ) : (
                      <>
                        <Play className="w-4 h-4 fill-white" />
                        <span>Parse & Perform Static Security Analysis</span>
                      </>
                    )}
                  </button>
                </div>
              </div>
            </div>
          </Card>

          {/* Analysis Results Display */}
          {analysisResult && (
            <div className="space-y-6">
              {/* Header Action Bar */}
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 p-4 rounded-xl border border-slate-800 bg-slate-900/60">
                <div className="flex items-center gap-2.5">
                  <span className="p-1.5 rounded-lg bg-cyan-950/80 border border-cyan-500/40 text-cyan-400">
                    <ShieldCheck className="w-5 h-5" />
                  </span>
                  <div>
                    <h3 className="text-sm font-bold text-slate-100">
                      Static Security Scan & Vulnerability Audit
                    </h3>
                    <p className="text-[11px] text-slate-400">
                      Zero-Trust evaluation for {analysisResult.parsed.title} (v{analysisResult.parsed.version})
                    </p>
                  </div>
                </div>

                <div className="flex items-center gap-2">
                  <button
                    onClick={handleExportScanZip}
                    disabled={isExportingScanZip}
                    className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold bg-cyan-600 hover:bg-cyan-500 text-white shadow-lg shadow-cyan-900/30 transition disabled:opacity-50 cursor-pointer"
                    title="Export raw specification, endpoints, findings JSON, and Markdown remediation guide in a ZIP archive"
                  >
                    <Archive className="w-3.5 h-3.5" />
                    <span>{isExportingScanZip ? 'Packaging ZIP...' : 'Export Scan Package (.zip)'}</span>
                  </button>
                </div>
              </div>

              {/* Parsed API Meta Banner */}
              <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
                <Card className="p-4 bg-slate-950/80">
                  <span className="text-[10px] font-mono text-slate-500 uppercase block">API Title & Version</span>
                  <h3 className="font-bold text-slate-100 text-sm mt-0.5 truncate">{analysisResult.parsed.title}</h3>
                  <div className="flex items-center gap-2 mt-1">
                    <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-slate-800 text-cyan-300">
                      v{analysisResult.parsed.version}
                    </span>
                    <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-slate-800 text-slate-400">
                      Spec: {analysisResult.parsed.specVersion}
                    </span>
                  </div>
                </Card>

                <Card className="p-4 bg-slate-950/80">
                  <span className="text-[10px] font-mono text-slate-500 uppercase block">Base Server URL</span>
                  <div className="flex items-center gap-1.5 mt-0.5">
                    <Globe className="w-3.5 h-3.5 text-cyan-400 shrink-0" />
                    <span className="font-mono text-xs text-slate-200 truncate">{analysisResult.parsed.baseUrl}</span>
                  </div>
                  {analysisResult.parsed.baseUrl.startsWith('http://') ? (
                    <span className="text-[10px] font-mono text-rose-400 block mt-1">⚠️ Insecure HTTP Transport</span>
                  ) : (
                    <span className="text-[10px] font-mono text-emerald-400 block mt-1">✓ TLS Transport Scheme</span>
                  )}
                </Card>

                <Card className="p-4 bg-slate-950/80">
                  <span className="text-[10px] font-mono text-slate-500 uppercase block">Surface Dimensions</span>
                  <div className="grid grid-cols-2 gap-2 mt-1">
                    <div>
                      <span className="text-base font-bold text-slate-100">{analysisResult.parsed.endpointsCount}</span>
                      <span className="text-[10px] text-slate-400 block">Endpoints</span>
                    </div>
                    <div>
                      <span className="text-base font-bold text-cyan-300">
                        {analysisResult.parsed.securitySchemesCount}
                      </span>
                      <span className="text-[10px] text-slate-400 block">Security Schemes</span>
                    </div>
                  </div>
                </Card>

                <Card className="p-4 bg-slate-950/80">
                  <span className="text-[10px] font-mono text-slate-500 uppercase block">Zero-Trust Spec Score</span>
                  <div className="flex items-center justify-between mt-1">
                    <span
                      className={`text-2xl font-bold font-mono ${
                        analysisResult.score >= 80
                          ? 'text-emerald-400'
                          : analysisResult.score >= 60
                          ? 'text-amber-400'
                          : 'text-rose-400'
                      }`}
                    >
                      {analysisResult.score}%
                    </span>
                    <div className="flex items-center gap-1 font-mono text-[10px]">
                      {analysisResult.summary.critical > 0 && (
                        <span className="px-1.5 py-0.5 rounded bg-rose-950 text-rose-400 font-bold border border-rose-500/30">
                          {analysisResult.summary.critical} Crit
                        </span>
                      )}
                      {analysisResult.summary.high > 0 && (
                        <span className="px-1.5 py-0.5 rounded bg-amber-950 text-amber-400 font-bold border border-amber-500/30">
                          {analysisResult.summary.high} High
                        </span>
                      )}
                    </div>
                  </div>
                </Card>
              </div>

              {/* Declared Security Schemes */}
              {analysisResult.parsed.securitySchemes.length > 0 && (
                <Card
                  title="Declared Security Schemes"
                  subtitle="Parsed authentication and identity providers from components.securitySchemes"
                >
                  <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-3">
                    {analysisResult.parsed.securitySchemes.map((s: any, idx: number) => (
                      <div
                        key={idx}
                        className="p-3 rounded-lg border border-slate-800 bg-slate-950/60 space-y-1.5 text-xs font-mono"
                      >
                        <div className="flex items-center justify-between">
                          <span className="font-bold text-cyan-300 font-sans">{s.name}</span>
                          <span className="text-[10px] px-1.5 py-0.5 rounded bg-slate-800 text-slate-300">
                            {s.type}
                          </span>
                        </div>
                        {s.scheme && <p className="text-slate-400 text-[11px]">Scheme: <strong className="text-slate-200">{s.scheme}</strong></p>}
                        {s.in && <p className="text-slate-400 text-[11px]">Location: <strong className="text-slate-200">in: {s.in}</strong></p>}
                        {s.bearerFormat && <p className="text-slate-400 text-[11px]">Bearer Format: <strong className="text-slate-200">{s.bearerFormat}</strong></p>}
                        {s.scopes && s.scopes.length > 0 && (
                          <div className="pt-1">
                            <span className="text-[10px] text-slate-500 uppercase block">Declared Scopes:</span>
                            <div className="flex flex-wrap gap-1 mt-0.5">
                              {s.scopes.map((scope: string) => (
                                <span key={scope} className="text-[9px] px-1 rounded bg-slate-900 text-cyan-400 border border-slate-800">
                                  {scope}
                                </span>
                              ))}
                            </div>
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                </Card>
              )}

              {/* Parsed Endpoints Table */}
              <Card
                title={`Parsed Endpoints & Operations (${filteredEndpoints.length})`}
                subtitle="Extracted paths, HTTP methods, parameters, request bodies, and authentication requirements"
              >
                <div className="space-y-3">
                  <div className="flex flex-col sm:flex-row items-center justify-between gap-3">
                    <div className="relative flex-1 w-full sm:w-auto">
                      <Search className="w-3.5 h-3.5 text-slate-400 absolute left-3 top-2.5" />
                      <input
                        type="text"
                        placeholder="Search endpoints or summary..."
                        value={endpointSearch}
                        onChange={(e) => setEndpointSearch(e.target.value)}
                        className="w-full pl-8 pr-3 py-1.5 rounded-lg border border-slate-800 bg-slate-950 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500"
                      />
                    </div>
                    <div className="flex items-center gap-2 w-full sm:w-auto">
                      <span className="text-xs text-slate-400">Method:</span>
                      <select
                        value={methodFilter}
                        onChange={(e) => setMethodFilter(e.target.value)}
                        className="px-2.5 py-1.5 rounded-lg border border-slate-800 bg-slate-950 text-xs text-slate-300 focus:outline-none focus:border-cyan-500"
                      >
                        <option value="ALL">All Methods</option>
                        <option value="GET">GET</option>
                        <option value="POST">POST</option>
                        <option value="PUT">PUT</option>
                        <option value="DELETE">DELETE</option>
                        <option value="PATCH">PATCH</option>
                      </select>
                    </div>
                  </div>

                  <div className="overflow-x-auto">
                    <table className="w-full text-left text-xs">
                      <thead>
                        <tr className="border-b border-slate-800 text-slate-400 font-mono uppercase text-[10px]">
                          <th className="pb-2 pr-3">Method</th>
                          <th className="pb-2 pr-3">Path</th>
                          <th className="pb-2 pr-3">Security Requirement</th>
                          <th className="pb-2 pr-3">Parameters & Bounds</th>
                          <th className="pb-2 pr-3">Request Body</th>
                          <th className="pb-2 text-right">Responses</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-slate-800/60 font-mono">
                        {filteredEndpoints.map((ep: any, idx: number) => {
                          const isUnsecured = ep.security.length === 0;
                          return (
                            <tr key={idx} className="hover:bg-slate-850/50">
                              <td className="py-2.5 pr-3">
                                <span
                                  className={`text-[10px] font-bold px-1.5 py-0.5 rounded ${
                                    ep.method === 'GET'
                                      ? 'text-blue-400 bg-blue-950/40 border border-blue-500/30'
                                      : ep.method === 'POST'
                                      ? 'text-emerald-400 bg-emerald-950/40 border border-emerald-500/30'
                                      : ep.method === 'PUT' || ep.method === 'PATCH'
                                      ? 'text-amber-400 bg-amber-950/40 border border-amber-500/30'
                                      : 'text-rose-400 bg-rose-950/40 border border-rose-500/30'
                                  }`}
                                >
                                  {ep.method}
                                </span>
                              </td>
                              <td className="py-2.5 pr-3 font-semibold text-slate-200">
                                {ep.path}
                                {ep.summary && (
                                  <span className="block font-sans font-normal text-[11px] text-slate-400 truncate max-w-xs">
                                    {ep.summary}
                                  </span>
                                )}
                              </td>
                              <td className="py-2.5 pr-3">
                                {isUnsecured ? (
                                  <span className="text-[10px] font-bold text-rose-400 bg-rose-950/40 px-1.5 py-0.5 rounded border border-rose-500/30">
                                    NONE (Unsecured)
                                  </span>
                                ) : (
                                  <span className="text-[10px] text-emerald-400 bg-emerald-950/40 px-1.5 py-0.5 rounded border border-emerald-500/30">
                                    {ep.security.join(', ')}
                                  </span>
                                )}
                              </td>
                              <td className="py-2.5 pr-3 text-slate-300 text-[11px]">
                                {ep.parametersCount === 0 ? (
                                  <span className="text-slate-500">0 parameters</span>
                                ) : (
                                  <span>
                                    {ep.parametersCount} params{' '}
                                    {ep.parameters.some((p: any) => !p.hasConstraints) ? (
                                      <span className="text-amber-400 text-[10px]">(bounds missing)</span>
                                    ) : (
                                      <span className="text-emerald-400 text-[10px]">(bounded)</span>
                                    )}
                                  </span>
                                )}
                              </td>
                              <td className="py-2.5 pr-3 text-[11px]">
                                {ep.hasRequestBody ? (
                                  <span className="text-cyan-300">{ep.requestBodyTypes.join(', ')}</span>
                                ) : (
                                  <span className="text-slate-500">None</span>
                                )}
                              </td>
                              <td className="py-2.5 text-right text-[11px] text-slate-400">
                                {ep.responses.map((r: any) => r.status).join(', ') || 'Default'}
                              </td>
                            </tr>
                          );
                        })}
                      </tbody>
                    </table>
                  </div>
                </div>
              </Card>

              {/* Static Security Findings Discovered */}
              <Card
                title={
                  <div className="flex items-center gap-2">
                    <ShieldAlert className="w-4 h-4 text-rose-400" />
                    <span>Static Security Analysis Findings ({filteredSpecFindings.length})</span>
                  </div>
                }
                subtitle="Deterministic vulnerabilities discovered based strictly on evidence in the specification"
                action={
                  <div className="flex items-center gap-2">
                    <span className="text-xs text-slate-400">Severity:</span>
                    <select
                      value={findingSeverityFilter}
                      onChange={(e) => setFindingSeverityFilter(e.target.value)}
                      className="px-2.5 py-1 rounded-lg border border-slate-800 bg-slate-950 text-xs text-slate-300 focus:outline-none focus:border-cyan-500"
                    >
                      <option value="ALL">All ({analysisResult.findings.length})</option>
                      <option value="CRITICAL">Critical ({analysisResult.summary.critical})</option>
                      <option value="HIGH">High ({analysisResult.summary.high})</option>
                      <option value="MEDIUM">Medium ({analysisResult.summary.medium})</option>
                      <option value="LOW">Low ({analysisResult.summary.low})</option>
                    </select>
                  </div>
                }
              >
                {filteredSpecFindings.length === 0 ? (
                  <div className="p-8 text-center border border-slate-800 rounded-xl bg-slate-950/40">
                    <CheckCircle2 className="w-8 h-8 text-emerald-400 mx-auto mb-2" />
                    <h4 className="text-sm font-semibold text-slate-200">Zero Findings in Selected Filter</h4>
                    <p className="text-xs text-slate-400 mt-1">
                      No security misconfigurations or policy violations identified for this category.
                    </p>
                  </div>
                ) : (
                  <div className="space-y-3">
                    {filteredSpecFindings.map((f: SecurityFinding) => (
                      <div
                        key={f.id}
                        className="p-4 rounded-xl border border-slate-800 bg-slate-950/80 hover:border-slate-700 transition space-y-3"
                      >
                        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                          <div className="flex items-center gap-2.5 flex-wrap">
                            <span className="font-mono text-xs font-bold text-cyan-400">{f.findingId}</span>
                            <span className="text-sm font-semibold text-slate-100">{f.title}</span>
                            <span className="text-xs font-mono text-slate-400">
                              • {f.method} {f.endpoint}
                            </span>
                          </div>
                          <div className="flex items-center gap-2">
                            <SeverityBadge severity={f.severity} size="sm" />
                            <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-300">
                              {f.category}
                            </span>
                          </div>
                        </div>

                        <p className="text-xs text-slate-300 leading-relaxed">{f.description}</p>

                        {/* Concrete Evidence Box */}
                        <div className="p-2.5 rounded-lg bg-black/60 border border-slate-800 font-mono text-[11px] text-amber-300">
                          <strong className="text-slate-400 uppercase text-[10px] block mb-0.5">
                            Specification Evidence Trace:
                          </strong>
                          <span>{f.evidence}</span>
                        </div>

                        <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs">
                          <div className="p-2.5 rounded-lg bg-rose-950/20 border border-rose-500/20 text-slate-300 space-y-1">
                            <span className="font-mono text-[10px] text-rose-400 uppercase font-bold block">
                              Impact Vector:
                            </span>
                            <p>{f.impact}</p>
                          </div>
                          <div className="p-2.5 rounded-lg bg-emerald-950/20 border border-emerald-500/20 text-slate-300 space-y-1">
                            <span className="font-mono text-[10px] text-emerald-400 uppercase font-bold block">
                              Remediation Recommendation:
                            </span>
                            <p>{f.recommendation}</p>
                          </div>
                        </div>

                        {/* Implementation Guide Snippet */}
                        {f.implementationGuide && (
                          <div>
                            <span className="text-[10px] font-mono text-slate-400 block mb-1">
                              Specification & Implementation Fix:
                            </span>
                            <pre className="p-2.5 rounded-lg bg-black border border-slate-800 font-mono text-[11px] text-cyan-200 overflow-x-auto select-text whitespace-pre-wrap">
                              {f.implementationGuide}
                            </pre>
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                )}
              </Card>

              {/* Navigation Action */}
              <div className="flex items-center justify-between p-4 rounded-xl border border-slate-800 bg-slate-900/60">
                <div className="text-xs text-slate-400 font-mono">
                  Analysis completed across {analysisResult.parsed.endpointsCount} operations. Discovered {analysisResult.findings.length} finding(s).
                </div>
                <button
                  onClick={() => onNavigateTab('findings')}
                  className="flex items-center gap-2 px-4 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-semibold transition cursor-pointer"
                >
                  <span>View Findings in Central Registry</span>
                  <ArrowRight className="w-4 h-4" />
                </button>
              </div>
            </div>
          )}
        </div>
      )}

      {/* =========================================================================
          MODE 2: MANAGED INVENTORY API SCANNER
          ========================================================================= */}
      {activeMode === 'MANAGED_SCAN' && (
        <div className="space-y-6">
          {/* Target Configuration Panel */}
          <Card title="Scan Configuration & Parameters">
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              <div>
                <label className="block text-xs font-semibold text-slate-300 mb-1">
                  Select Target API *
                </label>
                <select
                  value={selectedApiId}
                  disabled={isScanning}
                  onChange={(e) => setSelectedApiId(e.target.value)}
                  className="w-full px-3 py-2 rounded-lg border border-slate-800 bg-slate-950 text-xs text-slate-200 focus:outline-none focus:border-cyan-500"
                >
                  {apis.map((a) => (
                    <option key={a.id} value={a.id}>
                      {a.name} ({a.environment} - {a.authType})
                    </option>
                  ))}
                </select>
              </div>

              <div>
                <label className="block text-xs font-semibold text-slate-300 mb-1">
                  Scan Profile & Depth
                </label>
                <select
                  value={scanProfile}
                  disabled={isScanning}
                  onChange={(e) => setScanProfile(e.target.value as any)}
                  className="w-full px-3 py-2 rounded-lg border border-slate-800 bg-slate-950 text-xs text-slate-200 focus:outline-none focus:border-cyan-500"
                >
                  <option value="DEEP_CIS">Full Zero-Trust & CIS Benchmark Audit</option>
                  <option value="AI_HEURISTIC">Knowledge Base & AI Pattern Analysis</option>
                  <option value="STANDARD">Fast Surface & Token Discovery</option>
                </select>
              </div>

              <div className="flex items-end">
                <button
                  onClick={runScan}
                  disabled={isScanning || !selectedApiId}
                  className="w-full flex items-center justify-center gap-2 px-4 py-2.5 rounded-lg bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white text-xs font-semibold shadow-lg shadow-cyan-900/30 transition disabled:opacity-50 cursor-pointer active:scale-95"
                >
                  {isScanning ? (
                    <>
                      <RefreshCw className="w-4 h-4 animate-spin" />
                      <span>Executing Scan Engine...</span>
                    </>
                  ) : (
                    <>
                      <Play className="w-4 h-4 fill-white" />
                      <span>Start Security Scan</span>
                    </>
                  )}
                </button>
              </div>
            </div>

            {selectedApi && (
              <div className="mt-4 pt-3 border-t border-slate-800/80 flex flex-wrap items-center gap-4 text-xs text-slate-400 font-mono">
                <span>Base URL: <strong className="text-slate-200">{selectedApi.baseUrl}</strong></span>
                <span>Auth Scheme: <strong className="text-cyan-400">{selectedApi.authType}</strong></span>
                <span>Current Score: <strong className="text-emerald-400">{selectedApi.securityScore}%</strong></span>
                <span>Environment: <strong className="text-amber-400">{selectedApi.environment}</strong></span>
              </div>
            )}
          </Card>

          {/* Progress & Live Scanner Terminal */}
          <Card
            title={
              <div className="flex items-center gap-2">
                <Terminal className="w-4 h-4 text-cyan-400" />
                <span>Interactive Scanner Console</span>
              </div>
            }
            subtitle={isScanning ? currentStep : 'Terminal standby'}
            action={
              isScanning && (
                <div className="flex items-center gap-2">
                  <div className="w-24 h-2 rounded-full bg-slate-800 overflow-hidden">
                    <div
                      className="h-full bg-cyan-500 transition-all duration-300"
                      style={{ width: `${progress}%` }}
                    />
                  </div>
                  <span className="font-mono text-xs text-cyan-400">{progress}%</span>
                </div>
              )
            }
          >
            <div className="p-4 rounded-xl bg-black border border-slate-800 font-mono text-xs text-slate-300 h-64 overflow-y-auto space-y-1.5 select-text">
              {consoleLogs.length === 0 ? (
                <div className="text-slate-600 italic">
                  Scanner ready. Select a target API and click "Start Security Scan".
                </div>
              ) : (
                consoleLogs.map((log, idx) => (
                  <div
                    key={idx}
                    className={
                      log.includes('[ERROR]')
                        ? 'text-rose-400'
                        : log.includes('Discovered')
                        ? 'text-amber-300 font-semibold'
                        : log.includes('Cryptographic')
                        ? 'text-emerald-400 font-semibold'
                        : 'text-slate-300'
                    }
                  >
                    {log}
                  </div>
                ))
              )}
              <div ref={terminalEndRef} />
            </div>
          </Card>

          {/* Discovered Findings from Scan */}
          {completedScan && (
            <Card
              title={
                <div className="flex items-center gap-2">
                  <ShieldAlert className="w-5 h-5 text-rose-400" />
                  <span>Scan Results: {completedScan.apiName}</span>
                </div>
              }
              subtitle={`Scan completed with ${discoveredFindings.length} discovered finding(s)`}
              action={
                <div className="flex items-center gap-2">
                  <span className="font-mono text-xs text-slate-400">Security Score:</span>
                  <span className="font-mono text-sm font-bold text-emerald-400">
                    {completedScan.securityScoreResult}%
                  </span>
                </div>
              }
            >
              <div className="space-y-4">
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-center font-mono">
                  <div className="p-3 rounded-lg bg-rose-950/30 border border-rose-500/30">
                    <span className="text-xl font-bold text-rose-400">{completedScan.criticalCount}</span>
                    <span className="text-[10px] text-slate-400 uppercase block mt-0.5">Critical</span>
                  </div>
                  <div className="p-3 rounded-lg bg-amber-950/30 border border-amber-500/30">
                    <span className="text-xl font-bold text-amber-400">{completedScan.highCount}</span>
                    <span className="text-[10px] text-slate-400 uppercase block mt-0.5">High</span>
                  </div>
                  <div className="p-3 rounded-lg bg-blue-950/30 border border-blue-500/30">
                    <span className="text-xl font-bold text-blue-400">{completedScan.mediumCount}</span>
                    <span className="text-[10px] text-slate-400 uppercase block mt-0.5">Medium</span>
                  </div>
                  <div className="p-3 rounded-lg bg-slate-900 border border-slate-800">
                    <span className="text-xl font-bold text-slate-300">{completedScan.lowCount}</span>
                    <span className="text-[10px] text-slate-400 uppercase block mt-0.5">Low</span>
                  </div>
                </div>

                <div className="space-y-2">
                  <h4 className="text-xs font-semibold text-slate-300 uppercase tracking-wider font-mono">
                    Discovered Vulnerabilities & Warnings ({discoveredFindings.length})
                  </h4>
                  <div className="space-y-2">
                    {discoveredFindings.map((f) => (
                      <div
                        key={f.id}
                        onClick={() => onSelectFinding(f.id)}
                        className="p-3 rounded-lg border border-slate-800 bg-slate-950 hover:border-slate-700 transition cursor-pointer flex items-center justify-between gap-3 text-left"
                      >
                        <div className="min-w-0">
                          <div className="flex items-center gap-2">
                            <span className="font-mono text-xs font-bold text-cyan-400">{f.findingId}</span>
                            <span className="text-xs font-semibold text-slate-200 truncate">{f.title}</span>
                          </div>
                          <p className="text-[11px] text-slate-400 mt-0.5 line-clamp-1">{f.description}</p>
                        </div>
                        <SeverityBadge severity={f.severity} size="sm" />
                      </div>
                    ))}
                  </div>
                </div>

                <div className="flex items-center justify-end gap-3 pt-3 border-t border-slate-800">
                  <button
                    onClick={() => onNavigateTab('findings')}
                    className="flex items-center gap-2 px-4 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-semibold transition cursor-pointer"
                  >
                    <span>View Full Findings Registry</span>
                    <ArrowRight className="w-4 h-4" />
                  </button>
                </div>
              </div>
            </Card>
          )}

          {/* Prior Scan History */}
          <Card title="Recent Scan History" subtitle="Audit trail of previous automated and manual security scans">
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead>
                  <tr className="border-b border-slate-800 text-slate-400 font-mono uppercase tracking-wider text-[10px]">
                    <th className="pb-3 pr-4">Timestamp</th>
                    <th className="pb-3 pr-4">Target API</th>
                    <th className="pb-3 pr-4">Initiator</th>
                    <th className="pb-3 pr-4">Findings Found</th>
                    <th className="pb-3 pr-4">Score Result</th>
                    <th className="pb-3 text-right">Status</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60 font-mono">
                  {scanHistory.map((h) => (
                    <tr key={h.id} className="hover:bg-slate-850/50">
                      <td className="py-3 pr-4 text-slate-400">{new Date(h.startedAt).toLocaleString()}</td>
                      <td className="py-3 pr-4 font-sans font-semibold text-slate-200">{h.apiName}</td>
                      <td className="py-3 pr-4 text-slate-400 font-sans">{h.initiatedBy}</td>
                      <td className="py-3 pr-4">
                        <span className="text-rose-400 font-bold">{h.findingsDiscovered}</span> items
                      </td>
                      <td className="py-3 pr-4 text-cyan-300 font-bold">{h.securityScoreResult}%</td>
                      <td className="py-3 text-right text-emerald-400 font-bold">{h.status}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </Card>
        </div>
      )}
    </div>
  );
}
