export type RoleType = 'ADMIN' | 'SECURITY_ANALYST' | 'DEVELOPER';

export interface User {
  id: string;
  name: string;
  email: string;
  role: RoleType;
  department: string;
  avatarUrl?: string;
  createdAt: string;
}

export interface ApiEndpoint {
  id: string;
  apiId: string;
  method: 'GET' | 'POST' | 'PUT' | 'DELETE' | 'PATCH';
  path: string;
  authRequired: boolean;
  rateLimitEnabled: boolean;
  sensitivity: 'PUBLIC' | 'INTERNAL' | 'CONFIDENTIAL' | 'RESTRICTED';
  riskLevel: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  description: string;
}

export interface ApiItem {
  id: string;
  name: string;
  baseUrl: string;
  environment: 'Development' | 'Testing' | 'Staging' | 'Production';
  owner: string;
  authType: 'None' | 'JWT' | 'OAuth2' | 'API Key' | 'Basic Authentication' | 'Custom';
  description: string;
  riskScore: number;
  securityScore: number;
  lastScan: string | null;
  status: 'ACTIVE' | 'WARNING' | 'CRITICAL' | 'DEPRECATED';
  endpointsCount: number;
  openFindingsCount: number;
  isDemo?: boolean;
}

export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
export type FindingStatus = 'OPEN' | 'IN_PROGRESS' | 'RESOLVED' | 'ACCEPTED_RISK';

export interface SecurityFinding {
  id: string;
  findingId: string;
  title: string;
  apiId: string;
  apiName: string;
  endpoint: string;
  method: string;
  category: 'Access Control' | 'Authentication' | 'Rate Limiting' | 'Data Exposure' | 'CORS' | 'Headers' | 'Input Validation' | 'TLS/Crypto' | 'Configuration';
  severity: Severity;
  status: FindingStatus;
  description: string;
  evidence: string;
  impact: string;
  recommendation: string;
  implementationGuide: string;
  validationSteps: string;
  acceptedReason?: string;
  resolvedAt?: string;
  createdAt: string;
  updatedAt: string;
}

export interface ScanRecord {
  id: string;
  apiId: string;
  apiName: string;
  initiatedBy: string;
  status: 'QUEUED' | 'RUNNING' | 'COMPLETED' | 'FAILED';
  startedAt: string;
  completedAt?: string;
  findingsDiscovered: number;
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
  securityScoreResult: number;
  logs: string[];
}

export interface CISControl {
  id: string;
  controlId: string;
  title: string;
  category: string;
  description: string;
  expectedConfig: string;
  detectedConfig: string;
  severity: Severity;
  status: 'PASS' | 'FAIL' | 'WARNING' | 'NOT EVALUATED' | 'REQUIRES REVIEW';
  remediation: string;
  lastAudited: string;
}

export interface ZeroTrustCategoryAssessment {
  id: string;
  category:
    | 'Identity verification'
    | 'Authentication'
    | 'Authorization'
    | 'Least privilege'
    | 'RBAC'
    | 'Continuous verification'
    | 'Session security'
    | 'Token security'
    | 'API access control'
    | 'Audit logging';
  score: number;
  status: 'OPTIMAL' | 'ACCEPTABLE' | 'NEEDS_IMPROVEMENT' | 'CRITICAL';
  dataSource: 'LIVE_ASSESSMENT' | 'DEMO_BASELINE';
  evidence: string;
  reason: string;
  recommendedImprovement: string;
  metrics: {
    label: string;
    value: string | number;
  }[];
}

export interface ZeroTrustAssessmentResponse {
  overallScore: number;
  postureLevel: 'OPTIMAL' | 'ACCEPTABLE' | 'ELEVATED_RISK' | 'NON_COMPLIANT';
  assessedAt: string;
  categories: ZeroTrustCategoryAssessment[];
  pillars?: ZeroTrustPillar[];
  totalControlsAudited: number;
  compliantCount: number;
  warningCount: number;
  criticalCount: number;
  summaryReason: string;
  coveragePercent?: number;
  enforcedPolicies?: number;
  pendingVerifications?: number;
}

export interface ZeroTrustPillar {
  pillar: 'Identity' | 'Device' | 'Application' | 'Network' | 'Data' | 'Session';
  score: number;
  status: 'OPTIMAL' | 'ACCEPTABLE' | 'NEEDS_IMPROVEMENT' | 'NON_COMPLIANT';
  principles: {
    name: string;
    verified: boolean;
    description: string;
  }[];
}

export interface KnowledgeRule {
  id: string;
  pattern: string;
  category: string;
  securityParameter: string;
  expectedBehavior: string;
  severity: Severity;
  description: string;
  remediation: string;
  createdBy: string;
  createdAt: string;
}

export interface AuditLogEntry {
  id: string;
  timestamp: string;
  user: string;
  userEmail: string;
  role: RoleType;
  action: string;
  resource: string;
  details: string;
  ipAddress: string;
  previousHash: string;
  hash: string;
}

export interface ReportItem {
  id: string;
  seal?: string;
  sealedAt?: string;
  title: string;
  organization: string;
  generatedBy: string;
  createdAt: string;
  securityScore: number;
  zeroTrustScore: number;
  complianceScore: number;
  totalApis: number;
  findingsCount: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
  };
  summary: string;
}

export interface NetworkFleetStats {
  totalDevices: number;
  avgFleetCompliance: number;
  compliantDevices: number;
  warningDevices: number;
  nonCompliantDevices: number;
  unrecognizedLinesCount: number;
  learnedRulesCount: number;
  totalControlsEvaluated: number;
  passedControls: number;
  failedControls: number;
  vendorBreakdown: Array<{ vendor: string; count: number; avgScore: number; color?: string }>;
  frameworkSummaries: Array<{
    id: string;
    name: string;
    version: string;
    avgScore: number;
    passCount: number;
    failCount: number;
    notEvalCount: number;
  }>;
  topFailedControls: Array<{
    controlId: string;
    frameworkId: string;
    title: string;
    severity: string;
    failCount: number;
    remediationTemplate?: string;
  }>;
  recentDevices: Array<{
    id: string;
    hostname: string;
    vendor: string;
    model: string;
    osVersion: string;
    complianceScore: number;
    status: string;
    unrecognizedLinesCount: number;
  }>;
}

export interface DashboardStats {
  metrics: {
    totalDevices?: number;
    avgFleetCompliance?: number;
    compliantDevices?: number;
    warningDevices?: number;
    nonCompliantDevices?: number;
    unrecognizedLinesCount?: number;
    learnedRulesCount?: number;
    totalApis: number;
    activeApis: number;
    criticalVulnerabilities: number;
    highVulnerabilities: number;
    mediumVulnerabilities: number;
    lowVulnerabilities: number;
    complianceScore: number;
    zeroTrustScore: number;
    avgSecurityScore: number;
    totalSecurityEvents: number;
    passedControls: number;
    failedControls: number;
    warningControls: number;
    notEvaluatedControls: number;
  };
  fleet?: NetworkFleetStats;
  severityBreakdown: Array<{ severity: string; count: number; color: string }>;
  securityTrend: Array<{ period: string; score: number }>;
  envRiskDistribution: Array<{ env: string; count: number; avgRisk: number }>;
  eventsTimeline: Array<{ day: string; count: number }>;
  recentActivities: Array<{
    id: string;
    timestamp: string;
    api: string;
    event: string;
    severity: string;
    status: string;
    user: string;
    hash: string;
  }>;
}

export interface NormalizedField<T> {
  value: T;
  sourceLine?: string | null;
  lineNumber?: number | null;
  confidence: number;
  source?: 'rule' | 'gemini' | 'offline' | 'default';
}

export interface SecurityBaselineModel {
  ssh_version: NormalizedField<string | null>;
  telnet_enabled: NormalizedField<boolean>;
  http_server_enabled: NormalizedField<boolean>;
  https_enabled: NormalizedField<boolean>;
  password_encryption: NormalizedField<string | boolean>;
  min_password_length: NormalizedField<number | null>;
  aaa_enabled: NormalizedField<boolean>;
  logging_hosts: NormalizedField<string[]>;
  ntp_servers: NormalizedField<string[]>;
  snmp_version: NormalizedField<string | null>;
  snmp_community_default: NormalizedField<boolean>;
  banner_set: NormalizedField<boolean>;
  session_timeout: NormalizedField<number | null>;
  acl_count: NormalizedField<number>;
  tls_min_version: NormalizedField<string | null>;
  ssh_timeout?: NormalizedField<number | null>;
  ssh_retries?: NormalizedField<number | null>;
  cdp_lldp_disabled?: NormalizedField<boolean>;
  source_routing_disabled?: NormalizedField<boolean>;
  service_tcp_keepalives?: NormalizedField<boolean>;
}

export interface UnrecognizedLine {
  lineNumber: number;
  line: string;
  categoryHint?: string;
}

export interface NetworkDevice {
  id: string;
  quarantined?: boolean;
  injectionFindings?: Array<{ line: number; pattern: string; risk: string; excerpt: string }>;
  filename: string;
  rawConfig: string;
  detectedVendor: string;
  vendor?: string;
  vendorGuessMethod: 'regex' | 'gemini' | 'offline';
  vendorConfidence: number; // 0 - 100
  hostname: string | null;
  serialNumber: string | null;
  model: string | null;
  osVersion?: string | null;
  uploadTime: string;
  lineCount: number;
  byteSize: number;
  baselineModel: SecurityBaselineModel;
  unrecognizedLines: UnrecognizedLine[];
  overallComplianceScore: number;
  complianceScore?: number;
  status: 'ANALYZED' | 'WARNING' | 'COMPLIANT' | 'NON_COMPLIANT';
}

export interface FrameworkControl {
  id: string;
  title: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  field: string;
  operator: 'equals' | 'not_equals' | 'gte' | 'lte' | 'contains' | 'is_not_empty' | 'is_empty';
  expectedValue: any;
  remediation: string;
}

export interface SecurityFramework {
  id?: string;
  frameworkId: string;
  name: string;
  version: string;
  description: string;
  controlCount?: number;
  controls?: FrameworkControl[];
}

export interface ControlEvaluationResult {
  controlId: string;
  frameworkId: string;
  title: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  field: string;
  status: 'PASS' | 'FAIL' | 'NOT_EVALUABLE';
  expectedValue: any;
  actualValue: any;
  sourceLine?: string | null;
  lineNumber?: number | null;
  remediation: string;
  remediationTemplate?: string;
}

export interface DeviceFrameworkEvaluation {
  id: string;
  deviceId: string;
  deviceHostname: string;
  deviceVendor: string;
  frameworkId: string;
  frameworkName: string;
  frameworkVersion: string;
  evaluatedAt: string;
  complianceScore: number;
  totalControls: number;
  passedCount: number;
  failedCount: number;
  notEvaluableCount: number;
  controlResults: ControlEvaluationResult[];
  summary?: {
    totalControls: number;
    passCount: number;
    failCount: number;
    notEvaluableCount: number;
    score: number;
  };
  results?: ControlEvaluationResult[];
}

export interface LearnedRule {
  id: string;
  name: string;
  vendor: string;
  regex: string;
  field: string;
  extractionType: 'capture_group' | 'presence_true' | 'presence_false' | 'static_value';
  captureGroupIndex?: number;
  staticValue?: any;
  confidence?: number;
  sampleLine?: string;
  createdAt: string;
  createdBy: string;
}

export interface TrainingCoverageDiff {
  deviceId: string;
  deviceHostname: string;
  deviceVendor: string;
  before: {
    unrecognizedCount: number;
    complianceScore: number;
    unrecognizedLines: UnrecognizedLine[];
  };
  after: {
    unrecognizedCount: number;
    complianceScore: number;
    unrecognizedLines: UnrecognizedLine[];
  };
  remediatedLines: Array<{
    lineNumber: number;
    line: string;
    ruleName: string;
    targetField: string;
    extractedValue: any;
  }>;
}

export interface VendorPackRule {
  id?: string;
  name: string;
  field: string;
  regex: string;
  extractionType: 'capture_group' | 'presence_true' | 'presence_false' | 'static_value';
  captureGroupIndex?: number;
  staticValue?: any;
  sampleLine?: string;
  confidence?: number;
}

export interface VendorPack {
  vendorPackId: string;
  vendor: string;
  version: string;
  description: string;
  author?: string;
  updatedAt?: string;
  detectionSignatures?: Array<{ pattern: string; confidence?: number }>;
  rules: VendorPackRule[];
}

