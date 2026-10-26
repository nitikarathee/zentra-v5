import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import type {
  NetworkDevice,
  SecurityBaselineModel,
  UnrecognizedLine,
  NormalizedField,
  LearnedRule,
  DeviceFrameworkEvaluation,
  ControlEvaluationResult,
  SecurityFramework,
  TrainingCoverageDiff,
} from '../src/types/index.ts';

export type {
  NetworkDevice,
  SecurityBaselineModel,
  UnrecognizedLine,
  NormalizedField,
  LearnedRule,
  DeviceFrameworkEvaluation,
  ControlEvaluationResult,
  SecurityFramework,
  TrainingCoverageDiff,
};

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
  riskScore: number; // 0 - 100
  securityScore: number; // 0 - 100
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
  findingId: string; // e.g. ZEN-F-101
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

// Compute SHA-256 tamper-evident hash
export function calculateAuditHash(
  timestamp: string,
  user: string,
  action: string,
  resource: string,
  details: string,
  previousHash: string
): string {
  const payload = `${timestamp}|${user}|${action}|${resource}|${details}|${previousHash}`;
  return crypto.createHash('sha256').update(payload).digest('hex');
}

// Database In-Memory Store with Initial Realistic Cybersecurity Data
class ZentraDatabase {
  users: User[] = [
    {
      id: 'usr-admin-1',
      name: 'Alex Vance',
      email: 'admin@zentra.sec',
      role: 'ADMIN',
      department: 'Enterprise Security Architecture',
      createdAt: '2026-01-10T08:00:00Z',
    },
    {
      id: 'usr-analyst-1',
      name: 'Dr. Elena Rostova',
      email: 'analyst@zentra.sec',
      role: 'SECURITY_ANALYST',
      department: 'SOC & Threat Intelligence',
      createdAt: '2026-02-14T09:30:00Z',
    },
    {
      id: 'usr-dev-1',
      name: 'Marcus Chen',
      email: 'dev@zentra.sec',
      role: 'DEVELOPER',
      department: 'API Platform Engineering',
      createdAt: '2026-03-01T11:15:00Z',
    },
  ];

  rolesPermissions: Record<RoleType, string[]> = {
    ADMIN: [
      'api:create', 'api:edit', 'api:delete', 'api:scan',
      'finding:view', 'finding:status_update', 'finding:accept_risk',
      'compliance:view', 'compliance:assess', 'compliance:edit',
      'ai:analyze', 'ai:sanitize',
      'knowledge:view', 'knowledge:manage',
      'reports:view', 'reports:create', 'reports:export',
      'audit:view', 'audit:verify',
      'rbac:manage', 'settings:edit'
    ],
    SECURITY_ANALYST: [
      'api:view', 'api:scan',
      'finding:view', 'finding:status_update', 'finding:accept_risk',
      'compliance:view', 'compliance:assess',
      'ai:analyze', 'ai:sanitize',
      'knowledge:view', 'knowledge:manage',
      'reports:view', 'reports:create', 'reports:export',
      'audit:view',
      'remediation:view'
    ],
    DEVELOPER: [
      'api:view', 'api:create', 'api:edit', 'api:scan',
      'finding:view', 'finding:status_update',
      'compliance:view',
      'ai:sanitize',
      'knowledge:view',
      'remediation:view',
      'reports:view'
    ]
  };

  apis: ApiItem[] = [
    {
      id: 'api-1',
      name: 'Authentication & SSO Service',
      baseUrl: 'https://auth.internal.corp/v2',
      environment: 'Production',
      owner: 'SecOps Identity Team',
      authType: 'JWT',
      description: 'Core OAuth2/OIDC identity provider issuing access tokens, refresh tokens, and mTLS session tickets.',
      riskScore: 68,
      securityScore: 82,
      lastScan: '2026-09-23T14:30:00Z',
      status: 'WARNING',
      endpointsCount: 14,
      openFindingsCount: 2,
      isDemo: true,
    },
    {
      id: 'api-2',
      name: 'Payment Gateway API',
      baseUrl: 'https://pay.gateway.internal/api/v1',
      environment: 'Production',
      owner: 'Fintech Core Platform',
      authType: 'OAuth2',
      description: 'Cardholder transaction processing, recurring billing subscriptions, and PCI-DSS tokenized settlement.',
      riskScore: 84,
      securityScore: 71,
      lastScan: '2026-09-24T04:15:00Z',
      status: 'CRITICAL',
      endpointsCount: 22,
      openFindingsCount: 3,
      isDemo: true,
    },
    {
      id: 'api-3',
      name: 'User Management API',
      baseUrl: 'https://users.api.cluster.local/v1',
      environment: 'Production',
      owner: 'Core Backend Engineering',
      authType: 'JWT',
      description: 'Directory services, profile modification, organization hierarchies, and role assignments.',
      riskScore: 74,
      securityScore: 76,
      lastScan: '2026-09-22T18:00:00Z',
      status: 'CRITICAL',
      endpointsCount: 18,
      openFindingsCount: 2,
      isDemo: true,
    },
    {
      id: 'api-4',
      name: 'Order Fulfillment API',
      baseUrl: 'https://orders-staging.service.internal/v3',
      environment: 'Staging',
      owner: 'Supply Chain Engineering',
      authType: 'API Key',
      description: 'Logistics processing, warehouse dispatch orders, and inventory allocation management.',
      riskScore: 42,
      securityScore: 88,
      lastScan: '2026-09-21T09:40:00Z',
      status: 'ACTIVE',
      endpointsCount: 16,
      openFindingsCount: 1,
      isDemo: true,
    },
    {
      id: 'api-5',
      name: 'Notification & Webhook Dispatcher',
      baseUrl: 'https://notify-dev.mesh.internal/api',
      environment: 'Development',
      owner: 'DevOps Communications',
      authType: 'Basic Authentication',
      description: 'Outbound webhook dispatches, SMS notifications, and system broadcast event routing.',
      riskScore: 79,
      securityScore: 64,
      lastScan: '2026-09-20T11:20:00Z',
      status: 'WARNING',
      endpointsCount: 9,
      openFindingsCount: 3,
      isDemo: true,
    },
  ];

  endpoints: ApiEndpoint[] = [
    {
      id: 'ep-1',
      apiId: 'api-3',
      method: 'GET',
      path: '/api/users/{id}',
      authRequired: true,
      rateLimitEnabled: false,
      sensitivity: 'RESTRICTED',
      riskLevel: 'CRITICAL',
      description: 'Fetch user profile record and account metadata by user ID'
    },
    {
      id: 'ep-2',
      apiId: 'api-3',
      method: 'PUT',
      path: '/api/users/{id}/roles',
      authRequired: true,
      rateLimitEnabled: true,
      sensitivity: 'RESTRICTED',
      riskLevel: 'HIGH',
      description: 'Assign authorization roles and scopes to a target user'
    },
    {
      id: 'ep-3',
      apiId: 'api-1',
      method: 'POST',
      path: '/v2/token',
      authRequired: true,
      rateLimitEnabled: false,
      sensitivity: 'CONFIDENTIAL',
      riskLevel: 'HIGH',
      description: 'Exchange authorization grant for signed JWT access and refresh token'
    },
    {
      id: 'ep-4',
      apiId: 'api-2',
      method: 'POST',
      path: '/api/v1/charges',
      authRequired: true,
      rateLimitEnabled: true,
      sensitivity: 'RESTRICTED',
      riskLevel: 'CRITICAL',
      description: 'Initiate payment card transaction capture against merchant ledger'
    },
    {
      id: 'ep-5',
      apiId: 'api-2',
      method: 'GET',
      path: '/api/v1/customers/{id}/cards',
      authRequired: true,
      rateLimitEnabled: false,
      sensitivity: 'RESTRICTED',
      riskLevel: 'HIGH',
      description: 'Retrieve stored card tokens and masked customer payment methods'
    },
    {
      id: 'ep-6',
      apiId: 'api-5',
      method: 'POST',
      path: '/api/webhooks/broadcast',
      authRequired: false,
      rateLimitEnabled: false,
      sensitivity: 'INTERNAL',
      riskLevel: 'CRITICAL',
      description: 'Trigger unauthenticated broadcast dispatch to external registered endpoints'
    }
  ];

  findings: SecurityFinding[] = [
    {
      id: 'fnd-1',
      findingId: 'ZEN-F-1001',
      title: 'Broken Object Level Authorization (BOLA / IDOR)',
      apiId: 'api-3',
      apiName: 'User Management API',
      endpoint: '/api/users/{id}',
      method: 'GET',
      category: 'Access Control',
      severity: 'CRITICAL',
      status: 'OPEN',
      description: 'The endpoint returns customer account records based on the user-supplied route parameter `{id}` without validating whether the caller owns or has explicit delegation for the requested object.',
      evidence: 'GET /api/users/usr_9984 returned HTTP 200 with complete PII and identity claims when requested using Bearer token belonging to caller usr_1042.',
      impact: 'Horizontal privilege escalation allowing authenticated attackers to enumerate and scrape entire user registries, exposing contact information, security questions, and corporate role mappings.',
      recommendation: 'Enforce strict Zero-Trust object authorization at the controller or service layer. Verify `token.sub === req.params.id` or validate administrative delegation role prior to querying database.',
      implementationGuide: 'Configure an API policy filter or middleware `validateResourceOwnership({ param: "id", allowRoles: ["sec_admin"] })` immediately prior to handler execution.',
      validationSteps: 'Issue request using token A for entity B and verify HTTP 403 Forbidden is returned with audit event dispatched to SIEM.',
      createdAt: '2026-09-22T18:05:00Z',
      updatedAt: '2026-09-22T18:05:00Z',
    },
    {
      id: 'fnd-2',
      findingId: 'ZEN-F-1002',
      title: 'Excessive JWT Token Lifetime & Weak Algorithm Support',
      apiId: 'api-1',
      apiName: 'Authentication & SSO Service',
      endpoint: '/v2/token',
      method: 'POST',
      category: 'Authentication',
      severity: 'HIGH',
      status: 'OPEN',
      description: 'Access tokens are minted with an expiration (`exp`) timestamp exceeding 72 hours, and the token verification routine permits the deprecated `HS256` symmetric signing mode alongside asymmetric keys.',
      evidence: 'Decoded JWT header indicates `{"alg":"HS256"}` accepted; payload claims include `exp: 1774358400` (+259,200s window) with no cryptographic refresh rotation binding.',
      impact: 'If a token is intercepted via logs, proxies, or client-side storage, an adversary retains persistent unrevoked API access for days without triggering re-authentication.',
      recommendation: 'Enforce asymmetric RS256/ES256 or EdDSA signatures only. Constrain short-lived access tokens to 15 minutes max, coupled with strict single-use refresh token rotation.',
      implementationGuide: 'Set `jwt.sign(payload, privateKey, { algorithm: "ES256", expiresIn: "15m" })`. Reject any token carrying `"alg": "none"` or `"alg": "HS256"` at API Gateway.',
      validationSteps: 'Inspect token headers to confirm ES256 signature; submit expired or altered token and confirm HTTP 401 Unauthorized.',
      createdAt: '2026-09-23T14:35:00Z',
      updatedAt: '2026-09-23T14:35:00Z',
    },
    {
      id: 'fnd-3',
      findingId: 'ZEN-F-1003',
      title: 'Missing Rate Limiting on Payment Ingestion Endpoint',
      apiId: 'api-2',
      apiName: 'Payment Gateway API',
      endpoint: '/api/v1/charges',
      method: 'POST',
      category: 'Rate Limiting',
      severity: 'HIGH',
      status: 'IN_PROGRESS',
      description: 'The payment transaction processing endpoint does not enforce rate throttling or burst protection per client IP or authenticated organization ID.',
      evidence: 'Automated scan baseline generated 120 consecutive payment authorization POST requests within a 3.2-second window without receiving HTTP 429 Too Many Requests.',
      impact: 'Vulnerability to card-testing attacks (card cracking / BIN attacks), payment gateway denial of service, and rapid resource exhaustion incurring merchant transaction penalty fees.',
      recommendation: 'Implement distributed token bucket or sliding-window rate limiting on all financial mutation routes (e.g. max 10 requests per minute per merchant key, 5 per IP).',
      implementationGuide: 'Deploy Redis-backed rate limiter: `rateLimiter({ windowMs: 60 * 1000, max: 10, keyGenerator: (req) => req.user?.orgId || req.ip })`.',
      validationSteps: 'Send 11 rapid requests in 10 seconds; verify 11th request returns 429 with `Retry-After` header and security event logged.',
      createdAt: '2026-09-24T04:20:00Z',
      updatedAt: '2026-09-24T05:00:00Z',
    },
    {
      id: 'fnd-4',
      findingId: 'ZEN-F-1004',
      title: 'Sensitive PII & Cardholder Data Exposure in Response',
      apiId: 'api-2',
      apiName: 'Payment Gateway API',
      endpoint: '/api/v1/customers/{id}/cards',
      method: 'GET',
      category: 'Data Exposure',
      severity: 'CRITICAL',
      status: 'OPEN',
      description: 'Endpoint response model serializes unmasked cardholder billing addresses and unencrypted bank routing identifiers in cleartext JSON.',
      evidence: 'Response payload contains fields `"full_billing_address"`, `"bank_routing_unmasked"`, and plaintext card expiration year without tokenized masking.',
      impact: 'Severe non-compliance with PCI-DSS Requirement 3.3 and 3.4; unauthorized callers or compromised frontend caches expose sensitive consumer financial data.',
      recommendation: 'Apply response data transfer object (DTO) filtering to mask or omit non-essential fields prior to serialization.',
      implementationGuide: 'Filter outgoing models with strict schema projection: return only `last4`, `brand`, and `tokenized_id`. Strip raw banking details.',
      validationSteps: 'Query endpoint and verify response payload contains only PCI-compliant masked fields and no raw routing numbers.',
      createdAt: '2026-09-24T04:22:00Z',
      updatedAt: '2026-09-24T04:22:00Z',
    },
    {
      id: 'fnd-5',
      findingId: 'ZEN-F-1005',
      title: 'Permissive Wildcard CORS Configuration on Internal API',
      apiId: 'api-5',
      apiName: 'Notification & Webhook Dispatcher',
      endpoint: '/api/webhooks/broadcast',
      method: 'POST',
      category: 'CORS',
      severity: 'MEDIUM',
      status: 'OPEN',
      description: 'The server returns `Access-Control-Allow-Origin: *` in conjunction with `Access-Control-Allow-Credentials: true` on an endpoint handling internal messaging broadcasts.',
      evidence: 'CORS preflight OPTIONS request returned header `Access-Control-Allow-Origin: *` while accepting session cookies.',
      impact: 'Malicious external websites visited by an authenticated developer can forge cross-origin requests to trigger arbitrary webhook dispatch alerts.',
      recommendation: 'Restrict `Access-Control-Allow-Origin` to an explicitly defined whitelist of trusted corporate origins and reject wildcard asterisks with credentials.',
      implementationGuide: 'Configure CORS middleware: `cors({ origin: ["https://console.internal.corp"], credentials: true })`.',
      validationSteps: 'Send OPTIONS request with header `Origin: https://evil-site.com`; verify server responds without allow header or returns 403.',
      createdAt: '2026-09-20T11:25:00Z',
      updatedAt: '2026-09-20T11:25:00Z',
    },
    {
      id: 'fnd-6',
      findingId: 'ZEN-F-1006',
      title: 'Missing Mandatory Security Headers (HSTS, CSP, X-Frame)',
      apiId: 'api-5',
      apiName: 'Notification & Webhook Dispatcher',
      endpoint: '/*',
      method: 'ALL',
      category: 'Headers',
      severity: 'LOW',
      status: 'RESOLVED',
      description: 'API responses do not include defense-in-depth headers such as Strict-Transport-Security, X-Content-Type-Options, or Content-Security-Policy.',
      evidence: 'Response headers missing `Strict-Transport-Security: max-age=31536000; includeSubDomains` and `X-Content-Type-Options: nosniff`.',
      impact: 'Increases susceptibility to protocol downgrade attacks, MIME-type confusion exploitation, and clickjacking overlays.',
      recommendation: 'Implement standard security headers via reverse proxy or Helmet middleware across all API routes.',
      implementationGuide: 'Mount `helmet()` or configure ingress controller to inject HSTS (max-age=63072000), `nosniff`, and `deny` frame options.',
      validationSteps: 'Perform curl check and verify all required headers are present on all status codes (2xx, 4xx, 5xx).',
      resolvedAt: '2026-09-21T10:00:00Z',
      createdAt: '2026-09-20T11:26:00Z',
      updatedAt: '2026-09-21T10:00:00Z',
    },
  ];

  cisControls: CISControl[] = [
    {
      id: 'cis-1-1',
      controlId: 'CIS 1.1',
      title: 'Enforce Strong TLS (1.2+ / 1.3) & Forward Secrecy',
      category: 'Network & Transport Security',
      description: 'Ensure all external and internal API ingress gateways strictly reject TLS 1.0/1.1, SSLv3, and insecure cipher suites, mandating TLS 1.3 with Perfect Forward Secrecy (PFS).',
      expectedConfig: 'MinTLSVersion: TLSv1.3; Ciphers: ECDHE-ECDSA-AES256-GCM-SHA384, TLS_AES_256_GCM_SHA384',
      detectedConfig: 'TLS 1.2 and 1.3 enabled; legacy CBC ciphers disabled; PFS active.',
      severity: 'CRITICAL',
      status: 'PASS',
      remediation: 'Maintain modern cipher configurations in ingress gateway or load balancer certificates.',
      lastAudited: '2026-09-24T05:30:00Z'
    },
    {
      id: 'cis-1-2',
      controlId: 'CIS 1.2',
      title: 'Strict Authentication for All Non-Public Endpoints',
      category: 'Authentication',
      description: 'All API routes must default to closed/deny unless explicitly tagged with an authorized public route annotation. Insecure default-open routes are strictly prohibited.',
      expectedConfig: 'DefaultPolicy: Deny; AuthRequired: True on 100% of internal/restricted routes.',
      detectedConfig: 'Endpoint /api/webhooks/broadcast on Notification API permits unauthenticated POST.',
      severity: 'CRITICAL',
      status: 'FAIL',
      remediation: 'Apply Zero-Trust gateway interceptor requiring valid JWT or mTLS identity before routing to backend.',
      lastAudited: '2026-09-24T05:30:00Z'
    },
    {
      id: 'cis-1-3',
      controlId: 'CIS 1.3',
      title: 'JSON Web Token Expiration and Signature Validation',
      category: 'Authentication',
      description: 'Tokens must be signed with robust cryptographic algorithms (RS256/ES256), have a maximum lifespan of 15 minutes, and be validated against issuer, audience, and revocation registries.',
      expectedConfig: 'MaxTokenLifetime: <= 15m; SupportedAlgs: ES256, RS256; RevocationCheck: Enabled.',
      detectedConfig: 'Auth API issues 72h tokens; HS256 symmetric signature mode is permitted.',
      severity: 'HIGH',
      status: 'FAIL',
      remediation: 'Configure OAuth token service to cap access token expiration at 900 seconds and enforce ES256.',
      lastAudited: '2026-09-24T05:30:00Z'
    },
    {
      id: 'cis-2-1',
      controlId: 'CIS 2.1',
      title: 'Implement Role-Based Access Control and Principle of Least Privilege',
      category: 'Authorization & RBAC',
      description: 'API controllers must verify caller roles and granular resource scopes. Administrative endpoints must enforce separation of duties.',
      expectedConfig: 'RBAC: Enabled; Granular scopes enforced per route; DefaultLeastPrivilege: True.',
      detectedConfig: 'User Management API allows caller to query other user objects (BOLA detected).',
      severity: 'HIGH',
      status: 'FAIL',
      remediation: 'Introduce resource ownership checks and granular permission claim verification in API handlers.',
      lastAudited: '2026-09-24T05:30:00Z'
    },
    {
      id: 'cis-2-2',
      controlId: 'CIS 2.2',
      title: 'Administrative Endpoint Isolation & Multi-Factor Verification',
      category: 'Authorization & RBAC',
      description: 'Endpoints capable of altering security policies or user roles must require elevated authorization context and step-up MFA challenge.',
      expectedConfig: 'AdminRoutes: Subnet-isolated or requires MFA claim `amr: ["mfa"]`.',
      detectedConfig: 'Admin role assignment endpoint `/roles` requires Admin JWT, but lacks step-up MFA claim check.',
      severity: 'MEDIUM',
      status: 'WARNING',
      remediation: 'Inject step-up auth policy requirement for privileged administrative mutations.',
      lastAudited: '2026-09-24T05:30:00Z'
    },
    {
      id: 'cis-3-1',
      controlId: 'CIS 3.1',
      title: 'Cryptographic Protection for Sensitive Data in Transit & Rest',
      category: 'Data Protection',
      description: 'All sensitive payloads, API credentials, and database fields containing financial or personal data must utilize AES-256-GCM or equivalent authenticated encryption.',
      expectedConfig: 'DataInTransit: TLS 1.3; StorageEncryption: AES-256-GCM; KeyRotation: 90 days.',
      detectedConfig: 'Database volume encryption enabled; transit TLS verified.',
      severity: 'HIGH',
      status: 'PASS',
      remediation: 'Continue automated cryptographic key rotation every 90 days via KMS.',
      lastAudited: '2026-09-24T05:30:00Z'
    },
    {
      id: 'cis-3-2',
      controlId: 'CIS 3.2',
      title: 'Masking & Filtering of PII and Secrets in API Responses',
      category: 'Data Protection',
      description: 'API responses must omit unnecessary fields and mask sensitive personal or financial indicators before returning to caller.',
      expectedConfig: 'ResponseFiltering: Enabled; PII_Masking: Enforced on cards and identity numbers.',
      detectedConfig: 'Payment Gateway API exposes unmasked billing address and routing identifiers.',
      severity: 'CRITICAL',
      status: 'FAIL',
      remediation: 'Apply projection filtering and mask credit card accounts to last 4 digits.',
      lastAudited: '2026-09-24T05:30:00Z'
    },
    {
      id: 'cis-4-1',
      controlId: 'CIS 4.1',
      title: 'Request Throttling & Rate Limiting per Client ID / IP',
      category: 'Resilience & API Abuse',
      description: 'Enforce rate limiting on all ingress endpoints to prevent brute-force attacks, credential stuffing, card cracking, and denial of service.',
      expectedConfig: 'RateLimiting: Enabled globally; Tiered limits per auth status; BurstProtection: True.',
      detectedConfig: 'Missing rate limiting on Payment Gateway `/charges` endpoint.',
      severity: 'HIGH',
      status: 'FAIL',
      remediation: 'Implement token bucket rate limiter at API gateway enforcing 10 req/min for charge endpoints.',
      lastAudited: '2026-09-24T05:30:00Z'
    },
    {
      id: 'cis-4-2',
      controlId: 'CIS 4.2',
      title: 'Strict Content-Type and Payload Validation to Prevent Injection',
      category: 'Input Validation',
      description: 'Reject unexpected MIME types, enforce JSON schema validation on all incoming request bodies, and strip unknown parameters to prevent mass assignment.',
      expectedConfig: 'SchemaValidation: Strict; DisallowUnknownFields: True; ContentType: Explicit.',
      detectedConfig: 'JSON schema validation active on 4 out of 5 registered APIs.',
      severity: 'MEDIUM',
      status: 'PASS',
      remediation: 'Ensure OpenAPI schema validation filters are mounted on all development services.',
      lastAudited: '2026-09-24T05:30:00Z'
    },
    {
      id: 'cis-5-1',
      controlId: 'CIS 5.1',
      title: 'Immutable Centralized Audit Logging with Cryptographic Integrity',
      category: 'Logging & Auditing',
      description: 'All security-relevant actions, authentication attempts, and authorization failures must be recorded in an immutable ledger with SHA-256 chain verification.',
      expectedConfig: 'AuditLogging: Centralized; TamperEvident: SHA-256 Chained; Retention: >= 365 days.',
      detectedConfig: 'ZENTRA SHA-256 tamper-evident cryptographic log chaining active with 100% hash verification.',
      severity: 'CRITICAL',
      status: 'PASS',
      remediation: 'Verify continuous forward-link integrity and periodically archive immutable block snapshots.',
      lastAudited: '2026-09-24T05:30:00Z'
    },
    {
      id: 'cis-5-2',
      controlId: 'CIS 5.2',
      title: 'Automated Anomaly Detection & Security Alerting',
      category: 'Logging & Auditing',
      description: 'Near-real-time correlation of authentication spikes, authorization failures, and token anomaly events dispatched to security operations.',
      expectedConfig: 'AnomalyDetection: Real-time; AlertLatency: < 60s; SIEMIntegration: Active.',
      detectedConfig: 'Real-time telemetry event stream operational with automated threshold notifications.',
      severity: 'HIGH',
      status: 'PASS',
      remediation: 'Tune alert thresholds quarterly based on traffic baseline growth.',
      lastAudited: '2026-09-24T05:30:00Z'
    },
  ];

  zeroTrustPillars: ZeroTrustPillar[] = [
    {
      pillar: 'Identity',
      score: 88,
      status: 'ACCEPTABLE',
      principles: [
        { name: 'Strong Multi-Factor Authentication', verified: true, description: 'Phishing-resistant WebAuthn/FIDO2 enforced for administrative roles' },
        { name: 'Continuous Identity Verification', verified: true, description: 'Re-evaluates identity risk on every sensitive API transaction' },
        { name: 'Zero Shared Service Accounts', verified: false, description: 'Two legacy batch workers still use shared static API keys' },
      ]
    },
    {
      pillar: 'Device',
      score: 82,
      status: 'ACCEPTABLE',
      principles: [
        { name: 'Endpoint Posture Assessment', verified: true, description: 'Device certificates checked before granting VPN/Gateway access' },
        { name: 'Encrypted Local Storage', verified: true, description: 'Full-disk encryption and MDM compliance verified on all caller clients' },
        { name: 'Automated Device Isolation', verified: false, description: 'Real-time revocation upon malware detection in progress' },
      ]
    },
    {
      pillar: 'Application',
      score: 74,
      status: 'NEEDS_IMPROVEMENT',
      principles: [
        { name: 'Granular API Authorization (BOLA/IDOR Protection)', verified: false, description: 'User Management API requires object-level policy enforcement' },
        { name: 'Strict Schema & Input Sanitization', verified: true, description: 'Incoming payloads validated against compiled OpenAPI schemas' },
        { name: 'Automated Vulnerability Scanning', verified: true, description: 'Continuous dynamic and static API testing integrated into CI/CD' },
      ]
    },
    {
      pillar: 'Network',
      score: 91,
      status: 'OPTIMAL',
      principles: [
        { name: 'Microsegmentation & mTLS Mesh', verified: true, description: 'Service-to-service communication encrypted with mutual TLS certificates' },
        { name: 'No Implicit Perimeter Trust', verified: true, description: 'Internal VPC treated identically to untrusted internet traffic' },
        { name: 'Ingress Web Application Firewall', verified: true, description: 'DDoS mitigation and Layer 7 protocol filtering active' },
      ]
    },
    {
      pillar: 'Data',
      score: 79,
      status: 'NEEDS_IMPROVEMENT',
      principles: [
        { name: 'Data Classification & Labeling', verified: true, description: 'Endpoints classified by data sensitivity (Restricted, Confidential, Public)' },
        { name: 'PII & Financial Masking in Responses', verified: false, description: 'Payment API exposes unmasked cardholder routing details' },
        { name: 'End-to-End Field-Level Encryption', verified: true, description: 'Sensitive columns encrypted with AES-256 before storage' },
      ]
    },
    {
      pillar: 'Session',
      score: 86,
      status: 'ACCEPTABLE',
      principles: [
        { name: 'Short-Lived Ephemeral Tokens', verified: false, description: 'Auth service issues 72h tokens; target policy is <= 15 minutes' },
        { name: 'Cryptographic Token Binding', verified: true, description: 'Tokens tied to client TLS thumbprint where supported' },
        { name: 'Instant Revocation Capability', verified: true, description: 'Centralized Redis revocation blocklist checked on critical transactions' },
      ]
    },
  ];

  knowledgeRules: KnowledgeRule[] = [
    {
      id: 'kr-1',
      pattern: 'admin=true',
      category: 'Authorization',
      securityParameter: 'privileged_access',
      expectedBehavior: 'Administrative privileges must be explicitly authorized via signed JWT role claims, never trusted from query parameters or client body.',
      severity: 'CRITICAL',
      description: 'Detects client requests attempting to assert administrative status via URL parameters or JSON payload fields.',
      remediation: 'Ignore client-supplied `admin` or `role` parameters; compute authorization strictly from validated server-side claims.',
      createdBy: 'Alex Vance (Admin)',
      createdAt: '2026-02-15T10:00:00Z',
    },
    {
      id: 'kr-2',
      pattern: 'password_in_url',
      category: 'Authentication',
      securityParameter: 'credential_leakage',
      expectedBehavior: 'Passwords and secrets must never be transmitted via GET query parameters or URL path fragments.',
      severity: 'HIGH',
      description: 'Prevents credentials from persisting in browser histories, web server access logs, and proxy traces.',
      remediation: 'Transmit credentials exclusively inside encrypted POST request bodies using HTTPS.',
      createdBy: 'Elena Rostova (Analyst)',
      createdAt: '2026-03-01T14:20:00Z',
    },
    {
      id: 'kr-3',
      pattern: 'allow_origin=*',
      category: 'CORS',
      securityParameter: 'cors_policy',
      expectedBehavior: 'Wildcard CORS headers must not be combined with authenticated credentials or internal sensitive APIs.',
      severity: 'MEDIUM',
      description: 'Flags overly permissive cross-origin resource sharing policies that risk cross-site data theft.',
      remediation: 'Specify strict origin whitelists: `Access-Control-Allow-Origin: https://trusted.app.corp`.',
      createdBy: 'Alex Vance (Admin)',
      createdAt: '2026-03-10T16:45:00Z',
    },
  ];

  auditLogs: AuditLogEntry[] = [];
  scans: ScanRecord[] = [];
  reports: ReportItem[] = [];
  devices: NetworkDevice[] = [];
  learnedRules: LearnedRule[] = [];
  frameworkEvaluations: DeviceFrameworkEvaluation[] = [];

  constructor() {
    this.seedInitialAuditLogs();
    this.seedInitialReports();
    this.seedInitialDevices();
    this.seedInitialLearnedRules();
    this.load();
  }

  seedInitialLearnedRules() {
    this.learnedRules = [
      {
        id: 'rule-lr-101',
        name: 'Fortinet HTTP Daemon Disable',
        vendor: 'Fortinet FortiOS',
        regex: 'set\\s+admin-http\\s+(enable|disable)',
        field: 'http_server_enabled',
        extractionType: 'capture_group',
        captureGroupIndex: 1,
        confidence: 0.99,
        sampleLine: 'set admin-http disable',
        createdAt: '2026-10-23T20:00:00.000Z',
        createdBy: 'Alex Vance (Admin)',
      },
      {
        id: 'rule-lr-102',
        name: 'Fortinet Admin Idle Timeout Extractor',
        vendor: 'Fortinet FortiOS',
        regex: 'set\\s+admintimeout\\s+(\\d+)',
        field: 'session_timeout',
        extractionType: 'capture_group',
        captureGroupIndex: 1,
        confidence: 0.99,
        sampleLine: 'set admintimeout 10',
        createdAt: '2026-10-23T20:05:00.000Z',
        createdBy: 'Alex Vance (Admin)',
      },
      {
        id: 'rule-lr-103',
        name: 'Arista TerminAttr Daemon Identification',
        vendor: 'Arista EOS',
        regex: 'daemon\\s+TerminAttr',
        field: 'logging_hosts',
        extractionType: 'presence_true',
        confidence: 0.95,
        sampleLine: 'daemon TerminAttr',
        createdAt: '2026-10-23T20:10:00.000Z',
        createdBy: 'Alex Vance (Admin)',
      },
      {
        id: 'rule-lr-104',
        name: 'Cisco Service TCP Keepalives Out',
        vendor: 'Cisco IOS-XE / IOS',
        regex: 'service\\s+tcp-keepalives-out',
        field: 'service_tcp_keepalives',
        extractionType: 'presence_true',
        confidence: 0.99,
        sampleLine: 'service tcp-keepalives-out',
        createdAt: '2026-10-23T20:15:00.000Z',
        createdBy: 'Alex Vance (Admin)',
      },
    ];
  }

  seedInitialDevices() {
    const ciscoConfig = `!
version 17.6
service timestamps debug datetime msec
service timestamps log datetime msec
service password-encryption
service tcp-keepalives-in
service tcp-keepalives-out
!
hostname CORE-SW01-SFO
!
boot-start-marker
boot-end-marker
!
! Chassis Serial Number: FOC2438L01B
! Model Number: Catalyst 9300-48P
!
security passwords min-length 12
enable secret 9 $9$vD8M$yJm3P89312.44
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
snmp-server user secadmin SECURE_V3 v3 auth sha MyAuthKey priv aes 256 MyPrivKey
!
banner motd ^C
=====================================================
AUTHORIZED ACCESS ONLY. ALL SESSIONS ARE MONITORED.
=====================================================
^C
!
ip access-list extended MGMT-ACL
 permit tcp 10.0.0.0 0.255.255.255 any eq 22
 deny   ip any any log
!
line con 0
 exec-timeout 5 0
line vty 0 4
 access-class MGMT-ACL in
 exec-timeout 10 0
 transport input ssh
line vty 5 15
 exec-timeout 10 0
 transport input ssh
!
end`;

    const juniperConfig = `## Last-changed: 2026-03-12 14:22:10 UTC
version 21.4R3.15;
system {
    host-name SRX345-EDGE-NYC;
    time-zone UTC;
    chassis serial-number JN1249A873F;
    root-authentication {
        encrypted-password "$6$jXy8Z...$v9zZ";
    }
    login {
        message "RESTRICTED NETWORK ASSET - DISCONNECT IMMEDIATELY IF UNAUTHORIZED";
        idle-timeout 10;
        password {
            format sha-512;
            minimum-password-length 14;
        }
    }
    services {
        ssh {
            protocol-version v2;
            connection-limit 10;
            rate-limit 5;
        }
        web-management {
            https {
                port 443;
                tls-version tlsv1.2;
            }
        }
    }
    syslog {
        host 192.168.10.25 {
            any notice;
        }
    }
    ntp {
        server 192.168.10.1;
    }
}
snmp {
    community telemetry-ro-sec {
        authorization read-only;
    }
}
firewall {
    family inet {
        filter EDGE-FILTER {
            term ALLOW-SSH {
                from {
                    source-address 10.200.0.0/16;
                    protocol tcp;
                    destination-port 22;
                }
                then accept;
            }
            term DROP-ALL {
                then {
                    count dropped-packets;
                    reject;
                }
            }
        }
    }
}`;

    const aristaConfig = `! device: LEAF02-DC1 (DCS-7050CX3-32S, EOS-4.28.1F)
!
transceiver qsfp default-mode 4x10G
!
hostname LEAF02-DC1
!
spanning-tree mode mstp
!
no service telnet
!
enable secret sha512 $6$rounds=50000$Arista$Z...
username admin privilege 15 role network-admin secret sha512 $6$rounds=50000$Admin$X...
!
management ssh
   protocol 2
   idle-timeout 15
!
management api http-commands
   no shutdown
   protocol https
!
logging host 10.50.0.10
ntp server 10.50.0.1
!
ip access-list CONTROL-PLANE
   10 permit tcp 10.0.0.0/8 any eq ssh
   20 deny ip any any log
!
banner motd
Authorized access only. Violators will be prosecuted.
EOF
!
end`;

    const legacyCiscoConfig = `Current configuration : 1582 bytes
!
version 12.2
no service password-encryption
!
hostname ACCESS-SW04-BLDG2
!
enable password cisco123
!
ip http server
no ip http secure-server
!
snmp-server community public RO
snmp-server community private RW
!
line con 0
 password cisco
line vty 0 4
 password cisco
 transport input all
line vty 5 15
 password cisco
 transport input telnet
!
end`;

    this.devices = [
      {
        id: 'dev-001',
        filename: 'core-sw01-sfo.cfg',
        rawConfig: ciscoConfig,
        detectedVendor: 'Cisco IOS-XE / IOS',
        vendorGuessMethod: 'regex',
        vendorConfidence: 96,
        hostname: 'CORE-SW01-SFO',
        serialNumber: 'FOC2438L01B',
        model: 'Catalyst 9300-48P',
        uploadTime: '2026-10-23T18:30:00.000Z',
        lineCount: ciscoConfig.split('\\n').length,
        byteSize: Buffer.byteLength(ciscoConfig),
        overallComplianceScore: 100,
        status: 'COMPLIANT',
        unrecognizedLines: [],
        baselineModel: {
          ssh_version: { value: '2', sourceLine: 'ip ssh version 2', lineNumber: 27, confidence: 0.98, source: 'rule' },
          telnet_enabled: { value: false, sourceLine: 'transport input ssh', lineNumber: 52, confidence: 0.96, source: 'rule' },
          http_server_enabled: { value: false, sourceLine: 'no ip http server', lineNumber: 24, confidence: 0.98, source: 'rule' },
          https_enabled: { value: true, sourceLine: 'ip http secure-server', lineNumber: 25, confidence: 0.98, source: 'rule' },
          password_encryption: { value: 'Type 9 (Scrypt / Strongest)', sourceLine: 'enable secret 9 $9$vD8M$yJm3P89312.44', lineNumber: 17, confidence: 0.99, source: 'rule' },
          min_password_length: { value: 12, sourceLine: 'security passwords min-length 12', lineNumber: 16, confidence: 0.98, source: 'rule' },
          aaa_enabled: { value: true, sourceLine: 'aaa new-model', lineNumber: 19, confidence: 0.99, source: 'rule' },
          logging_hosts: { value: ['10.100.1.50', '10.100.1.51'], sourceLine: 'logging host 10.100.1.50', lineNumber: 30, confidence: 0.95, source: 'rule' },
          ntp_servers: { value: ['10.100.2.1', '10.100.2.2'], sourceLine: 'ntp server 10.100.2.1', lineNumber: 32, confidence: 0.95, source: 'rule' },
          snmp_version: { value: 'v3 (Encrypted USM)', sourceLine: 'snmp-server group SECURE_V3 v3 priv', lineNumber: 35, confidence: 0.98, source: 'rule' },
          snmp_community_default: { value: false, confidence: 0.95, source: 'rule' },
          banner_set: { value: true, sourceLine: 'banner motd ^C', lineNumber: 38, confidence: 0.96, source: 'rule' },
          session_timeout: { value: 10, sourceLine: 'exec-timeout 10 0', lineNumber: 50, confidence: 0.96, source: 'rule' },
          acl_count: { value: 1, sourceLine: 'ip access-list extended MGMT-ACL', lineNumber: 44, confidence: 0.95, source: 'rule' },
          tls_min_version: { value: 'TLS 1.2', sourceLine: 'ip http secure-active-session-tls-version TLSv1.2', lineNumber: 26, confidence: 0.95, source: 'rule' },
          ssh_timeout: { value: 60, sourceLine: 'ip ssh time-out 60', lineNumber: 28, confidence: 0.95, source: 'rule' },
          ssh_retries: { value: 3, sourceLine: 'ip ssh authentication-retries 3', lineNumber: 29, confidence: 0.95, source: 'rule' },
          cdp_lldp_disabled: { value: false, confidence: 0.5, source: 'default' },
          source_routing_disabled: { value: true, sourceLine: 'no ip source-route', lineNumber: 23, confidence: 0.95, source: 'rule' },
          service_tcp_keepalives: { value: true, sourceLine: 'service tcp-keepalives-in', lineNumber: 6, confidence: 0.95, source: 'rule' },
        },
      },
      {
        id: 'dev-002',
        filename: 'srx345-edge-nyc.conf',
        rawConfig: juniperConfig,
        detectedVendor: 'Juniper JunOS',
        vendorGuessMethod: 'regex',
        vendorConfidence: 97,
        hostname: 'SRX345-EDGE-NYC',
        serialNumber: 'JN1249A873F',
        model: 'SRX345-SYS-JB',
        uploadTime: '2026-10-23T19:15:00.000Z',
        lineCount: juniperConfig.split('\\n').length,
        byteSize: Buffer.byteLength(juniperConfig),
        overallComplianceScore: 100,
        status: 'COMPLIANT',
        unrecognizedLines: [],
        baselineModel: {
          ssh_version: { value: '2', sourceLine: 'protocol-version v2;', lineNumber: 22, confidence: 0.98, source: 'rule' },
          telnet_enabled: { value: false, confidence: 0.92, source: 'rule' },
          http_server_enabled: { value: false, confidence: 0.95, source: 'rule' },
          https_enabled: { value: true, sourceLine: 'https { port 443; tls-version tlsv1.2; }', lineNumber: 27, confidence: 0.98, source: 'rule' },
          password_encryption: { value: 'SHA-512 (Strong)', sourceLine: 'format sha-512;', lineNumber: 14, confidence: 0.99, source: 'rule' },
          min_password_length: { value: 14, sourceLine: 'minimum-password-length 14;', lineNumber: 15, confidence: 0.98, source: 'rule' },
          aaa_enabled: { value: true, sourceLine: 'root-authentication / system login classes', lineNumber: 7, confidence: 0.90, source: 'rule' },
          logging_hosts: { value: ['192.168.10.25'], sourceLine: 'host 192.168.10.25', lineNumber: 35, confidence: 0.95, source: 'rule' },
          ntp_servers: { value: ['192.168.10.1'], sourceLine: 'server 192.168.10.1;', lineNumber: 40, confidence: 0.95, source: 'rule' },
          snmp_version: { value: 'v2c', sourceLine: 'community telemetry-ro-sec', lineNumber: 44, confidence: 0.90, source: 'rule' },
          snmp_community_default: { value: false, confidence: 0.95, source: 'rule' },
          banner_set: { value: true, sourceLine: 'message "RESTRICTED NETWORK ASSET...";', lineNumber: 11, confidence: 0.96, source: 'rule' },
          session_timeout: { value: 10, sourceLine: 'idle-timeout 10;', lineNumber: 12, confidence: 0.92, source: 'rule' },
          acl_count: { value: 1, sourceLine: 'filter EDGE-FILTER', lineNumber: 50, confidence: 0.95, source: 'rule' },
          tls_min_version: { value: 'TLS 1.2', sourceLine: 'tls-version tlsv1.2;', lineNumber: 29, confidence: 0.95, source: 'rule' },
        },
      },
      {
        id: 'dev-003',
        filename: 'arista-leaf02-dc1.eos',
        rawConfig: aristaConfig,
        detectedVendor: 'Arista EOS',
        vendorGuessMethod: 'regex',
        vendorConfidence: 96,
        hostname: 'LEAF02-DC1',
        serialNumber: 'JPE19450321',
        model: 'DCS-7050CX3-32S',
        uploadTime: '2026-10-23T20:00:00.000Z',
        lineCount: aristaConfig.split('\\n').length,
        byteSize: Buffer.byteLength(aristaConfig),
        overallComplianceScore: 95,
        status: 'COMPLIANT',
        unrecognizedLines: [
          { lineNumber: 3, line: 'transceiver qsfp default-mode 4x10G', categoryHint: 'Hardware Interface Setting' },
          { lineNumber: 7, line: 'spanning-tree mode mstp', categoryHint: 'Layer 2 Protocol' },
        ],
        baselineModel: {
          ssh_version: { value: '2', sourceLine: 'protocol 2', lineNumber: 17, confidence: 0.95, source: 'rule' },
          telnet_enabled: { value: false, sourceLine: 'no service telnet', lineNumber: 9, confidence: 0.96, source: 'rule' },
          http_server_enabled: { value: false, confidence: 0.90, source: 'rule' },
          https_enabled: { value: true, sourceLine: 'protocol https', lineNumber: 22, confidence: 0.98, source: 'rule' },
          password_encryption: { value: 'SHA-512 (Strong)', sourceLine: 'enable secret sha512 $6$rounds=50000$...', lineNumber: 11, confidence: 0.99, source: 'rule' },
          min_password_length: { value: null, confidence: 0.1, source: 'default' },
          aaa_enabled: { value: true, sourceLine: 'role network-admin secret sha512', lineNumber: 12, confidence: 0.90, source: 'rule' },
          logging_hosts: { value: ['10.50.0.10'], sourceLine: 'logging host 10.50.0.10', lineNumber: 24, confidence: 0.95, source: 'rule' },
          ntp_servers: { value: ['10.50.0.1'], sourceLine: 'ntp server 10.50.0.1', lineNumber: 25, confidence: 0.95, source: 'rule' },
          snmp_version: { value: null, confidence: 0.1, source: 'default' },
          snmp_community_default: { value: false, confidence: 0.95, source: 'rule' },
          banner_set: { value: true, sourceLine: 'banner motd', lineNumber: 31, confidence: 0.96, source: 'rule' },
          session_timeout: { value: 15, sourceLine: 'idle-timeout 15', lineNumber: 18, confidence: 0.92, source: 'rule' },
          acl_count: { value: 1, sourceLine: 'ip access-list CONTROL-PLANE', lineNumber: 27, confidence: 0.95, source: 'rule' },
          tls_min_version: { value: 'TLS 1.2', confidence: 0.85, source: 'rule' },
        },
      },
      {
        id: 'dev-004',
        filename: 'legacy-access-sw04.txt',
        rawConfig: legacyCiscoConfig,
        detectedVendor: 'Cisco IOS (Legacy)',
        vendorGuessMethod: 'regex',
        vendorConfidence: 88,
        hostname: 'ACCESS-SW04-BLDG2',
        serialNumber: 'FCZ1144Z0Y8',
        model: 'Catalyst 2960-24',
        uploadTime: '2026-10-23T20:30:00.000Z',
        lineCount: legacyCiscoConfig.split('\\n').length,
        byteSize: Buffer.byteLength(legacyCiscoConfig),
        overallComplianceScore: 15,
        status: 'NON_COMPLIANT',
        unrecognizedLines: [
          { lineNumber: 1, line: 'Current configuration : 1582 bytes', categoryHint: 'IOS Header' },
        ],
        baselineModel: {
          ssh_version: { value: null, confidence: 0.1, source: 'default' },
          telnet_enabled: { value: true, sourceLine: 'transport input all / transport input telnet', lineNumber: 19, confidence: 0.98, source: 'rule' },
          http_server_enabled: { value: true, sourceLine: 'ip http server', lineNumber: 9, confidence: 0.98, source: 'rule' },
          https_enabled: { value: false, sourceLine: 'no ip http secure-server', lineNumber: 10, confidence: 0.98, source: 'rule' },
          password_encryption: { value: 'Cleartext / Type 0 (Unencrypted Insecure)', sourceLine: 'no service password-encryption / enable password cisco123', lineNumber: 4, confidence: 0.95, source: 'rule' },
          min_password_length: { value: null, confidence: 0.1, source: 'default' },
          aaa_enabled: { value: false, confidence: 0.95, source: 'rule' },
          logging_hosts: { value: [], confidence: 0.2, source: 'default' },
          ntp_servers: { value: [], confidence: 0.2, source: 'default' },
          snmp_version: { value: 'v2c (Cleartext Community)', sourceLine: 'snmp-server community public RO', lineNumber: 12, confidence: 0.92, source: 'rule' },
          snmp_community_default: { value: true, sourceLine: 'snmp-server community public RO / private RW', lineNumber: 12, confidence: 0.99, source: 'rule' },
          banner_set: { value: false, confidence: 0.2, source: 'default' },
          session_timeout: { value: null, confidence: 0.1, source: 'default' },
          acl_count: { value: 0, confidence: 0.5, source: 'default' },
          tls_min_version: { value: null, confidence: 0.1, source: 'default' },
        },
      },
    ];
  }

  private seedInitialAuditLogs() {
    const genesisHash = '0000000000000000000000000000000000000000000000000000000000000000';
    let prev = genesisHash;

    const initialEntries = [
      {
        timestamp: '2026-09-24T03:00:00Z',
        user: 'Alex Vance',
        userEmail: 'admin@zentra.sec',
        role: 'ADMIN' as RoleType,
        action: 'SYSTEM_BOOTSTRAP',
        resource: 'ZENTRA Core Security Engine',
        details: 'Initialized Zero-Trust policy engine with CIS API Benchmark v1.2 ruleset.',
        ipAddress: '10.240.0.1',
      },
      {
        timestamp: '2026-09-24T04:00:00Z',
        user: 'Elena Rostova',
        userEmail: 'analyst@zentra.sec',
        role: 'SECURITY_ANALYST' as RoleType,
        action: 'API_SCAN_COMPLETED',
        resource: 'Payment Gateway API',
        details: 'Completed scheduled compliance assessment. Discovered 3 findings (1 Critical, 1 High, 1 Medium).',
        ipAddress: '192.168.10.45',
      },
      {
        timestamp: '2026-09-24T05:10:00Z',
        user: 'Alex Vance',
        userEmail: 'admin@zentra.sec',
        role: 'ADMIN' as RoleType,
        action: 'KNOWLEDGE_RULE_CREATED',
        resource: 'Knowledge Rule KR-3',
        details: 'Added pattern matching for permissive wildcard CORS headers.',
        ipAddress: '10.240.0.1',
      },
      {
        timestamp: '2026-09-24T05:45:00Z',
        user: 'Marcus Chen',
        userEmail: 'dev@zentra.sec',
        role: 'DEVELOPER' as RoleType,
        action: 'FINDING_STATUS_UPDATE',
        resource: 'ZEN-F-1003 (Missing Rate Limiting)',
        details: 'Updated status from OPEN to IN_PROGRESS. Assigned to sprint queue for Redis rate limiter deployment.',
        ipAddress: '192.168.10.92',
      },
    ];

    for (const item of initialEntries) {
      const hash = calculateAuditHash(
        item.timestamp,
        item.user,
        item.action,
        item.resource,
        item.details,
        prev
      );
      this.auditLogs.push({
        id: `log-${this.auditLogs.length + 1}`,
        ...item,
        previousHash: prev,
        hash,
      });
      prev = hash;
    }
  }

  private seedInitialReports() {
    this.reports.push({
      id: 'rep-1',
      title: 'Q3 Enterprise API Zero-Trust & CIS Security Assessment',
      organization: 'Fintech & Cloud Services Global Corp',
      generatedBy: 'Dr. Elena Rostova',
      createdAt: '2026-09-23T18:00:00Z',
      securityScore: 78,
      zeroTrustScore: 84,
      complianceScore: 72,
      totalApis: 5,
      findingsCount: {
        critical: 2,
        high: 2,
        medium: 1,
        low: 1,
        info: 0,
      },
      summary: 'Executive assessment across 5 core enterprise APIs. Priority remediation required for Broken Object Level Authorization on User API and unmasked PII exposure on Payment Gateway.'
    });
  }

  // Record a new audit log with SHA-256 chain
  addAuditLog(entry: {
    user: string;
    userEmail: string;
    role: RoleType;
    action: string;
    resource: string;
    details: string;
    ipAddress?: string;
  }): AuditLogEntry {
    const timestamp = new Date().toISOString();
    const previousHash = this.auditLogs.length > 0 
      ? this.auditLogs[this.auditLogs.length - 1].hash 
      : '0000000000000000000000000000000000000000000000000000000000000000';
    
    const hash = calculateAuditHash(
      timestamp,
      entry.user,
      entry.action,
      entry.resource,
      entry.details,
      previousHash
    );

    const newLog: AuditLogEntry = {
      id: `log-${this.auditLogs.length + 1}`,
      timestamp,
      user: entry.user,
      userEmail: entry.userEmail,
      role: entry.role,
      action: entry.action,
      resource: entry.resource,
      details: entry.details,
      ipAddress: entry.ipAddress || '127.0.0.1',
      previousHash,
      hash,
    };

    this.auditLogs.push(newLog);
    this.persist();
    return newLog;
  }

  // Persistence methods
  persist(): void {
    try {
      const dataDir = path.resolve(process.cwd(), 'data');
      if (!fs.existsSync(dataDir)) {
        fs.mkdirSync(dataDir, { recursive: true });
      }
      const filePath = path.join(dataDir, 'zentra-db.json');
      const payload = {
        users: this.users,
        rolesPermissions: this.rolesPermissions,
        apis: this.apis,
        endpoints: this.endpoints,
        findings: this.findings,
        scans: this.scans,
        cisControls: this.cisControls,
        zeroTrustPillars: this.zeroTrustPillars,
        knowledgeRules: this.knowledgeRules,
        auditLogs: this.auditLogs,
        reports: this.reports,
        devices: this.devices,
        learnedRules: this.learnedRules,
        frameworkEvaluations: this.frameworkEvaluations,
      };
      fs.writeFileSync(filePath, JSON.stringify(payload, null, 2), 'utf-8');
    } catch (err) {
      console.warn('[ZENTRA-DB] Persistence write error:', err);
    }
  }

  load(): void {
    try {
      const filePath = path.resolve(process.cwd(), 'data', 'zentra-db.json');
      if (fs.existsSync(filePath)) {
        const raw = fs.readFileSync(filePath, 'utf-8');
        const parsed = JSON.parse(raw);
        if (Array.isArray(parsed.users) && parsed.users.length > 0) this.users = parsed.users;
        if (parsed.rolesPermissions) this.rolesPermissions = parsed.rolesPermissions;
        if (Array.isArray(parsed.apis) && parsed.apis.length > 0) this.apis = parsed.apis;
        if (Array.isArray(parsed.endpoints) && parsed.endpoints.length > 0) this.endpoints = parsed.endpoints;
        if (Array.isArray(parsed.findings)) this.findings = parsed.findings;
        if (Array.isArray(parsed.scans)) this.scans = parsed.scans;
        if (Array.isArray(parsed.cisControls) && parsed.cisControls.length > 0) this.cisControls = parsed.cisControls;
        if (Array.isArray(parsed.zeroTrustPillars) && parsed.zeroTrustPillars.length > 0) this.zeroTrustPillars = parsed.zeroTrustPillars;
        if (Array.isArray(parsed.knowledgeRules)) this.knowledgeRules = parsed.knowledgeRules;
        if (Array.isArray(parsed.auditLogs) && parsed.auditLogs.length > 0) this.auditLogs = parsed.auditLogs;
        if (Array.isArray(parsed.reports)) this.reports = parsed.reports;
        if (Array.isArray(parsed.devices) && parsed.devices.length > 0) {
          this.devices = parsed.devices;
        } else if (!this.devices || this.devices.length === 0) {
          this.seedInitialDevices();
        }
        if (Array.isArray(parsed.learnedRules) && parsed.learnedRules.length > 0) {
          this.learnedRules = parsed.learnedRules;
        } else if (!this.learnedRules || this.learnedRules.length === 0) {
          this.seedInitialLearnedRules();
        }
        if (Array.isArray(parsed.frameworkEvaluations)) {
          this.frameworkEvaluations = parsed.frameworkEvaluations;
        }
        console.log('[ZENTRA-DB] Hydrated state from data/zentra-db.json');
      } else {
        this.persist();
      }
    } catch (err) {
      console.warn('[ZENTRA-DB] Persistence read error, using in-memory state:', err);
    }
  }


  // Verify the entire SHA-256 chain integrity
  verifyAuditIntegrity(): { isValid: boolean; brokenAtLogId?: string; totalChecked: number } {
    let prev = '0000000000000000000000000000000000000000000000000000000000000000';
    for (const log of this.auditLogs) {
      if (log.previousHash !== prev) {
        return { isValid: false, brokenAtLogId: log.id, totalChecked: this.auditLogs.length };
      }
      const recalculated = calculateAuditHash(
        log.timestamp,
        log.user,
        log.action,
        log.resource,
        log.details,
        prev
      );
      if (recalculated !== log.hash) {
        return { isValid: false, brokenAtLogId: log.id, totalChecked: this.auditLogs.length };
      }
      prev = log.hash;
    }
    return { isValid: true, totalChecked: this.auditLogs.length };
  }

  // Calculate overall dynamic metrics
  getDashboardStats() {
    const totalApis = this.apis.length;
    const activeApis = this.apis.filter(a => a.status === 'ACTIVE' || a.status === 'WARNING' || a.status === 'CRITICAL').length;
    const openFindings = this.findings.filter(f => f.status === 'OPEN' || f.status === 'IN_PROGRESS');
    const criticalVulnerabilities = openFindings.filter(f => f.severity === 'CRITICAL').length;
    const highVulnerabilities = openFindings.filter(f => f.severity === 'HIGH').length;
    const mediumVulnerabilities = openFindings.filter(f => f.severity === 'MEDIUM').length;
    const lowVulnerabilities = openFindings.filter(f => f.severity === 'LOW').length;

    // Calculate CIS Compliance Score
    const evaluatedControls = this.cisControls.filter(c => c.status !== 'NOT EVALUATED');
    const passedControls = this.cisControls.filter(c => c.status === 'PASS').length;
    const complianceScore = evaluatedControls.length > 0 
      ? Math.round((passedControls / evaluatedControls.length) * 100) 
      : 0;

    // Calculate Zero-Trust Score
    const zeroTrustScore = Math.round(
      this.zeroTrustPillars.reduce((acc, p) => acc + p.score, 0) / this.zeroTrustPillars.length
    );

    // Calculate Average API Security Score
    const avgSecurityScore = this.apis.length > 0
      ? Math.round(this.apis.reduce((acc, a) => acc + a.securityScore, 0) / this.apis.length)
      : 0;

    return {
      totalApis,
      activeApis,
      criticalVulnerabilities,
      highVulnerabilities,
      mediumVulnerabilities,
      lowVulnerabilities,
      complianceScore,
      zeroTrustScore,
      avgSecurityScore,
      totalSecurityEvents: this.auditLogs.length,
      passedControls,
      failedControls: this.cisControls.filter(c => c.status === 'FAIL').length,
      warningControls: this.cisControls.filter(c => c.status === 'WARNING').length,
      notEvaluatedControls: this.cisControls.filter(c => c.status === 'NOT EVALUATED').length,
    };
  }
}

export const db = new ZentraDatabase();
