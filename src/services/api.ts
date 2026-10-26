import {
  ApiItem,
  ApiEndpoint,
  SecurityFinding,
  ScanRecord,
  CISControl,
  ZeroTrustPillar,
  ZeroTrustAssessmentResponse,
  KnowledgeRule,
  AuditLogEntry,
  ReportItem,
  DashboardStats,
  User,
  RoleType,
  NetworkDevice,
  SecurityFramework,
  DeviceFrameworkEvaluation,
  LearnedRule,
  TrainingCoverageDiff,
  VendorPack,
  VendorPackRule,
} from '../types';

export interface MemoryStatus {
  enabled: boolean;
  configured: boolean;
  connected: boolean;
  bankId: string;
  host: string;
  lastError: string | null;
  journalCount: number;
}

export interface RecalledMemory {
  id?: string;
  text: string;
  type?: string;
  date?: string | null;
}

export interface MemoryJournalEntry {
  id: string;
  at: string;
  context: string;
  content: string;
  metadata: Record<string, string>;
  synced: boolean;
}

function getAuthHeader(): Record<string, string> {
  const token = localStorage.getItem('zentra_token');
  return token ? { Authorization: `Bearer ${token}` } : {};
}

async function request<T>(endpoint: string, options: RequestInit = {}): Promise<T> {
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    ...getAuthHeader(),
    ...((options.headers as Record<string, string>) || {}),
  };

  const response = await fetch(`/api${endpoint}`, {
    ...options,
    headers,
  });

  if (!response.ok) {
    let errorMsg = `HTTP Error ${response.status}`;
    try {
      const data = await response.json();
      if (data.error) errorMsg = data.error;
    } catch {
      // ignore
    }
    throw new Error(errorMsg);
  }

  return response.json();
}

export const apiService = {
  // AI engine status (offline / Gemini) & runtime mode switch
  getAiStatus: () =>
    request<{ mode: string; label: string; offline: boolean; reason?: string }>('/ai-status'),

  setAiMode: (data: { offline: boolean }) =>
    request<{ mode: string; label: string; offline: boolean; reason?: string }>('/ai-mode', {
      method: 'POST',
      body: JSON.stringify(data),
    }),

  // Hindsight agent memory
  getMemoryStatus: () => request<MemoryStatus>('/memory/status'),

  toggleMemory: (enabled?: boolean) =>
    request<MemoryStatus>('/memory/toggle', {
      method: 'POST',
      body: JSON.stringify(typeof enabled === 'boolean' ? { enabled } : {}),
    }),

  recallMemories: (q: string) =>
    request<{ enabled: boolean; memories: RecalledMemory[] }>(`/memory/recall?q=${encodeURIComponent(q)}`),

  getRecentMemories: () =>
    request<{ enabled: boolean; entries: MemoryJournalEntry[]; status: MemoryStatus }>('/memory/recent'),

  getMemoryBrief: (target: string) =>
    request<{ available: boolean; text: string }>(`/memory/brief?target=${encodeURIComponent(target)}`),

  seedMemory: () =>
    request<{ total: number; stored: number; failed: number }>('/memory/seed', { method: 'POST' }),

  reportRemediationOutcome: (data: { vendor: string; controlId: string; hostname?: string | null; worked: boolean; notes?: string }) =>
    request<{ ok: boolean; stored: boolean }>('/remediation/outcome', {
      method: 'POST',
      body: JSON.stringify(data),
    }),

  // Auth
  login: (email: string, password?: string, role?: RoleType) =>
    request<{ token: string; user: User; permissions: string[] }>('/auth/login', {
      method: 'POST',
      body: JSON.stringify({ email, password, role }),
    }),

  register: (name: string, email: string, password?: string, role: RoleType = 'DEVELOPER', department?: string) =>
    request<{ token: string; user: User; permissions: string[] }>('/auth/register', {
      method: 'POST',
      body: JSON.stringify({ name, email, password, role, department }),
    }),

  switchRole: (role: RoleType) =>
    request<{ token: string; user: User; permissions: string[] }>('/auth/switch-role', {
      method: 'POST',
      body: JSON.stringify({ role }),
    }),

  getMe: () =>
    request<{ user: User; permissions: string[] }>('/auth/me'),

  forgotPassword: (email: string) =>
    request<{ message: string }>('/auth/forgot-password', {
      method: 'POST',
      body: JSON.stringify({ email }),
    }),

  // Dashboard
  getDashboardStats: () =>
    request<DashboardStats>('/dashboard/stats'),

  // APIs
  getApis: (params?: { environment?: string; authType?: string; search?: string }) => {
    const query = new URLSearchParams();
    if (params?.environment) query.set('environment', params.environment);
    if (params?.authType) query.set('authType', params.authType);
    if (params?.search) query.set('search', params.search);
    return request<ApiItem[]>(`/apis?${query.toString()}`);
  },

  getApi: (id: string) =>
    request<{ api: ApiItem; endpoints: ApiEndpoint[]; findings: SecurityFinding[]; activities: AuditLogEntry[] }>(`/apis/${id}`),

  createApi: (data: Partial<ApiItem> & { endpoints?: Partial<ApiEndpoint>[] }) =>
    request<ApiItem>('/apis', {
      method: 'POST',
      body: JSON.stringify(data),
    }),

  updateApi: (id: string, data: Partial<ApiItem>) =>
    request<ApiItem>(`/apis/${id}`, {
      method: 'PUT',
      body: JSON.stringify(data),
    }),

  deleteApi: (id: string) =>
    request<{ success: boolean; message: string }>(`/apis/${id}`, {
      method: 'DELETE',
    }),

  addEndpoint: (apiId: string, endpoint: Partial<ApiEndpoint>) =>
    request<ApiEndpoint>(`/apis/${apiId}/endpoints`, {
      method: 'POST',
      body: JSON.stringify(endpoint),
    }),

  deleteEndpoint: (apiId: string, endpointId: string) =>
    request<{ success: boolean; message: string }>(`/apis/${apiId}/endpoints/${endpointId}`, {
      method: 'DELETE',
    }),

  // Scans
  startScan: (apiId: string) =>
    request<{ scan: ScanRecord; findings: SecurityFinding[]; updatedApi: ApiItem }>(`/apis/${apiId}/scan`, {
      method: 'POST',
    }),

  getScans: () =>
    request<ScanRecord[]>('/scans'),

  analyzeSpec: (data: { spec: string; saveToInventory?: boolean; saveFindings?: boolean; environment?: string }) =>
    request<{
      parsed: {
        title: string;
        version: string;
        specVersion: string;
        baseUrl: string;
        allBaseUrls: string[];
        description: string;
        endpointsCount: number;
        methodsCount: number;
        securitySchemesCount: number;
        securitySchemes: any[];
        endpoints: any[];
      };
      findings: SecurityFinding[];
      score: number;
      summary: {
        critical: number;
        high: number;
        medium: number;
        low: number;
        total: number;
      };
      createdApi?: ApiItem;
    }>('/scanner/analyze-spec', {
      method: 'POST',
      body: JSON.stringify(data),
    }),

  // Findings
  getFindings: (params?: { severity?: string; apiId?: string; status?: string; category?: string; search?: string }) => {
    const query = new URLSearchParams();
    if (params?.severity) query.set('severity', params.severity);
    if (params?.apiId) query.set('apiId', params.apiId);
    if (params?.status) query.set('status', params.status);
    if (params?.category) query.set('category', params.category);
    if (params?.search) query.set('search', params.search);
    return request<SecurityFinding[]>(`/findings?${query.toString()}`);
  },

  getFinding: (id: string) =>
    request<{ finding: SecurityFinding; api: ApiItem }>(`/findings/${id}`),

  updateFindingStatus: (id: string, status: string, acceptedReason?: string) =>
    request<SecurityFinding>(`/findings/${id}/status`, {
      method: 'PUT',
      body: JSON.stringify({ status, acceptedReason }),
    }),

  // Zero Trust
  getZeroTrust: () =>
    request<ZeroTrustAssessmentResponse>('/zero-trust'),

  assessZeroTrust: () =>
    request<ZeroTrustAssessmentResponse>('/zero-trust/assess', {
      method: 'POST',
    }),

  // Compliance (CIS)
  getCompliance: () =>
    request<{
      score: number;
      controls: CISControl[];
      stats: {
        total: number;
        passed: number;
        failed: number;
        warning: number;
        notEvaluated: number;
        requiresReview: number;
      };
      framework: { name: string; version: string; description: string };
    }>('/compliance'),

  runComplianceAssessment: () =>
    request<{ score: number; controls: CISControl[] }>('/compliance/assess', {
      method: 'POST',
    }),

  updateControlStatus: (id: string, status: string, detectedConfig?: string) =>
    request<CISControl>(`/compliance/controls/${id}`, {
      method: 'PUT',
      body: JSON.stringify({ status, detectedConfig }),
    }),

  // AI Security & Prompt Sanitization
  analyzeApiSpec: (data: { name: string; baseUrl: string; authType: string; environment: string; specOrConfig: string }) =>
    request<{
      riskLevel: string;
      confidenceScore: number;
      securityAnalysis: string;
      riskExplanation: string;
      recommendedAction: string;
      requiresAnalystReview: boolean;
      identifiedVulnerabilities: Array<{ category: string; description: string; severity: string }>;
      evaluatedPillars: Record<string, string>;
      memoriesUsed?: string[];
      memoryCount?: number;
    }>('/ai/analyze', {
      method: 'POST',
      body: JSON.stringify(data),
    }),

  sanitizePrompt: (prompt: string) =>
    request<{
      originalPrompt: string;
      riskLevel: string;
      detectedPattern: string;
      reason: string;
      sanitizedPrompt: string;
      recommendedAction: string;
      defenseMechanismsApplied: string[];
      isBlocked: boolean;
      confidenceScore: number;
    }>('/ai/sanitize', {
      method: 'POST',
      body: JSON.stringify({ prompt }),
    }),

  // Knowledge Base
  getKnowledgeRules: () =>
    request<KnowledgeRule[]>('/knowledge-rules'),

  createKnowledgeRule: (rule: Partial<KnowledgeRule>) =>
    request<KnowledgeRule>('/knowledge-rules', {
      method: 'POST',
      body: JSON.stringify(rule),
    }),

  deleteKnowledgeRule: (id: string) =>
    request<{ success: boolean }>(`/knowledge-rules/${id}`, {
      method: 'DELETE',
    }),

  // Remediation
  getRemediationItems: () =>
    request<Array<{
      id: string;
      findingId: string;
      title: string;
      apiName: string;
      endpoint: string;
      severity: string;
      problem: string;
      whyItMatters: string;
      recommendedFix: string;
      implementationGuide: string;
      validationSteps: string;
      status: string;
    }>>('/remediation'),

  // Reports
  getReports: () =>
    request<ReportItem[]>('/reports'),

  createReport: (data: { title?: string; organization?: string }) =>
    request<ReportItem>('/reports', {
      method: 'POST',
      body: JSON.stringify(data),
    }),

  getReportDetail: (id: string) =>
    request<{
      report: ReportItem;
      apis: ApiItem[];
      findings: SecurityFinding[];
      cisControls: CISControl[];
      zeroTrustPillars: ZeroTrustPillar[];
    }>(`/reports/${id}`),

  // Audit Logs
  getAuditLogs: () =>
    request<AuditLogEntry[]>('/audit-logs'),

  verifyAuditChain: () =>
    request<{ isValid: boolean; brokenAtLogId?: string; totalChecked: number }>('/audit-logs/verify', {
      method: 'POST',
    }),

  // RBAC
  getRbacPermissions: () =>
    request<Record<RoleType, string[]>>('/rbac/permissions'),

  updateRbacPermissions: (role: RoleType, permissions: string[]) =>
    request<Record<RoleType, string[]>>('/rbac/permissions', {
      method: 'PUT',
      body: JSON.stringify({ role, permissions }),
    }),

  // Network Devices & Compliance Normalization
  getDevices: (params?: { search?: string; vendor?: string; status?: string }) => {
    const query = new URLSearchParams();
    if (params?.search) query.set('search', params.search);
    if (params?.vendor) query.set('vendor', params.vendor);
    if (params?.status) query.set('status', params.status);
    return request<NetworkDevice[]>(`/devices?${query.toString()}`);
  },

  getDeviceStats: () =>
    request<{
      total: number;
      compliant: number;
      warning: number;
      nonCompliant: number;
      avgScore: number;
      vendorBreakdown: Array<{ vendor: string; count: number }>;
    }>('/devices/stats'),

  getDevice: (id: string) =>
    request<NetworkDevice>(`/devices/${id}`),

  uploadDeviceConfigs: (files: Array<{ filename: string; content: string }>) =>
    request<{ message: string; devices: NetworkDevice[]; quarantined?: Array<{ filename: string; hits: Array<{ line: number; pattern: string }> }> }>('/devices/upload', {
      method: 'POST',
      body: JSON.stringify({ files }),
    }),

  renormalizeDevice: (id: string) =>
    request<NetworkDevice>(`/devices/${id}/renormalize`, {
      method: 'POST',
    }),

  deleteDevice: (id: string) =>
    request<{ message: string; id: string }>(`/devices/${id}`, {
      method: 'DELETE',
    }),

  loadSampleDevices: () =>
    request<{ message: string; devices: NetworkDevice[]; evaluationsCount: number }>('/devices/load-samples', {
      method: 'POST',
    }),

  getVendorCliRemediations: (data: {
    vendor: string;
    model?: string | null;
    osVersion?: string | null;
    hostname?: string | null;
    controls: Array<{
      controlId: string;
      title?: string;
      field: string;
      expectedValue: any;
      actualValue: any;
      remediation: string;
    }>;
  }) =>
    request<{
      vendor: string;
      offline?: boolean;
      memoryEnabled?: boolean;
      remediations: Array<{ controlId: string; field: string; cliCommands: string; source?: 'template' | 'ai-gemini'; guarded?: boolean; memoriesUsed?: string[]; memoryCount?: number }>;
    }>('/compliance/remediation-cli', {
      method: 'POST',
      body: JSON.stringify(data),
    }),

  // Report seals (HMAC-SHA256), verification and dry-run fix audit
  sealReport: (kind: string, label: string, payload: Record<string, any>) =>
    request<{ seal: string; sealedAt: string; algorithm: string; payload: Record<string, any> }>('/reports/seal', {
      method: 'POST',
      body: JSON.stringify({ kind, label, payload }),
    }),

  verifyReport: (payload: Record<string, any>, seal: string) =>
    request<{ authentic: boolean; verdict: 'AUTHENTIC' | 'TAMPERED'; algorithm: string; checkedAt: string }>('/reports/verify', {
      method: 'POST',
      body: JSON.stringify({ payload, seal }),
    }),

  logFixAudit: (data: { deviceId: string; hostname?: string | null; approvedCount: number; edits: Array<{ controlId: string }> }) =>
    request<{ ok: boolean }>('/reports/fix-audit', {
      method: 'POST',
      body: JSON.stringify(data),
    }),

  // Multi-Framework Compliance Engine
  getComplianceFrameworks: () =>
    request<SecurityFramework[]>('/compliance/frameworks'),

  getComplianceFramework: (id: string) =>
    request<SecurityFramework>(`/compliance/frameworks/${id}`),

  evaluateCompliance: (frameworkIds?: string[], deviceIds?: string[]) =>
    request<{ message: string; evaluations: DeviceFrameworkEvaluation[] }>('/compliance/evaluate', {
      method: 'POST',
      body: JSON.stringify({ frameworkIds, deviceIds }),
    }),

  getComplianceEvaluations: (params?: { deviceId?: string; frameworkId?: string }) => {
    const query = new URLSearchParams();
    if (params?.deviceId) query.set('deviceId', params.deviceId);
    if (params?.frameworkId) query.set('frameworkId', params.frameworkId);
    return request<DeviceFrameworkEvaluation[]>(`/compliance/evaluations?${query.toString()}`);
  },

  getComplianceSummary: () =>
    request<{
      totalDevices: number;
      totalEvaluations: number;
      avgScore: number;
      totalPassed: number;
      totalFailed: number;
      totalNotEvaluable: number;
      availableFrameworks: SecurityFramework[];
    }>('/compliance/summary'),

  // Training & Normalization Rule Learning
  getTrainingUnrecognizedLines: () =>
    request<{
      totalUnrecognized: number;
      vendorGroups: Array<{
        vendor: string;
        count: number;
        items: Array<{
          line: string;
          lineNumber: number;
          categoryHint?: string;
          deviceId: string;
          deviceHostname: string;
          filename: string;
        }>;
      }>;
    }>('/training/unrecognized-lines'),

  getLearnedRules: () =>
    request<LearnedRule[]>('/training/rules'),

  createLearnedRule: (rule: {
    name?: string;
    vendor: string;
    field: string;
    regex: string;
    extractionType?: 'capture_group' | 'presence_true' | 'presence_false' | 'static_value';
    extractionMode?: 'capture_group' | 'presence_true' | 'presence_false' | 'static_value';
    captureGroupIndex?: number;
    staticValue?: any;
    sampleLine?: string;
  }) =>
    request<LearnedRule>('/training/rules', {
      method: 'POST',
      body: JSON.stringify(rule),
    }),

  deleteLearnedRule: (id: string) =>
    request<{ success: boolean; id: string }>(`/training/rules/${id}`, {
      method: 'DELETE',
    }),

  reparseDevice: (deviceId: string) =>
    request<TrainingCoverageDiff>('/training/reparse-device', {
      method: 'POST',
      body: JSON.stringify({ deviceId }),
    }),

  // Extensibility: Framework Packs & Vendor Packs
  getFrameworkPacks: () =>
    request<SecurityFramework[]>('/packs/frameworks'),

  exportFrameworkPack: (id: string) =>
    request<SecurityFramework>(`/packs/frameworks/${id}/export`),

  importFrameworkPack: (data: any) =>
    request<{ success: boolean; message: string; frameworks: SecurityFramework[] }>('/packs/frameworks/import', {
      method: 'POST',
      body: JSON.stringify(data),
    }),

  deleteFrameworkPack: (id: string) =>
    request<{ success: boolean; message: string; id: string }>(`/packs/frameworks/${id}`, {
      method: 'DELETE',
    }),

  getVendorPacks: () =>
    request<VendorPack[]>('/packs/vendors'),

  exportVendorPack: (vendorOrId: string) =>
    request<VendorPack>(`/packs/vendors/${encodeURIComponent(vendorOrId)}/export`),

  importVendorPack: (data: any) =>
    request<{ success: boolean; message: string; packs: VendorPack[]; learnedRulesCount: number }>('/packs/vendors/import', {
      method: 'POST',
      body: JSON.stringify(data),
    }),

  deleteVendorPack: (id: string) =>
    request<{ success: boolean; message: string; id: string }>(`/packs/vendors/${id}`, {
      method: 'DELETE',
    }),
};
