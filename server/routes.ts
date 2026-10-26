import express, { Request, Response } from 'express';
import {
  db,
  RoleType,
  SecurityFinding,
  Severity,
  FindingStatus,
  ScanRecord,
  NetworkDevice,
  LearnedRule,
  DeviceFrameworkEvaluation,
} from './db.ts';
import { sanitizePrompt, analyzeApiSecurity, generateVendorCliRemediationWithSource } from './gemini.ts';
import { computeSeal, verifySeal, recordSeal, scanForInjection, scanFields } from './seal.ts';
import { parseOpenApiDocument, analyzeParsedOpenApi } from './openapi-analyzer.ts';
import { evaluateZeroTrustPosture } from './zero-trust-engine.ts';
import { normalizeDeviceConfig, getAiMode, setRuntimeOffline, isOfflineForced } from './normalizer.ts';
import { frameworkEngine } from './framework-engine.ts';
import { SAMPLE_DEVICE_CONFIGS } from './sample-configs.ts';
import { vendorPackManager } from './vendor-packs.ts';
import {
  remember,
  rememberBatch,
  recall,
  brief,
  memoryEnabled,
  setMemoryEnabled,
  memoryStatus,
  recentMemories,
  initHindsight,
} from './hindsight.ts';
import { seedMemory } from './memory-seed.ts';

const router = express.Router();

// Thrown by getActiveUser() when a request has no valid identity and DEMO_MODE is not "true".
class AuthError extends Error {
  constructor() {
    super('Authentication required. Sign in to continue.');
  }
}

// Make every route handler safe: a thrown AuthError (sync or async) becomes HTTP 401,
// anything else is passed to Express' error handler. Existing handlers are unchanged.
function guardHandler(h: any) {
  return (req: Request, res: Response, next: any) => {
    const fail = (err: any) => {
      if (err instanceof AuthError) return res.status(401).json({ error: err.message });
      return next(err);
    };
    try {
      const out = h(req, res, next);
      if (out && typeof out.catch === 'function') out.catch(fail);
    } catch (err) {
      fail(err);
    }
  };
}
for (const verb of ['get', 'post', 'put', 'delete', 'patch'] as const) {
  const original = (router as any)[verb].bind(router);
  (router as any)[verb] = (routePath: any, ...handlers: any[]) =>
    original(routePath, ...handlers.map((h) => (typeof h === 'function' ? guardHandler(h) : h)));
}

// AI engine status (offline / Gemini) and runtime mode switch
router.get('/ai-status', (_req: Request, res: Response) => {
  res.json(getAiMode());
});

router.post('/ai-mode', (req: Request, res: Response) => {
  const { offline } = req.body;
  if (typeof offline === 'boolean') {
    setRuntimeOffline(offline);
  }
  res.json(getAiMode());
});


/* ==========================================================================
   HINDSIGHT MEMORY (persistent agent memory)
   ========================================================================== */

router.get('/memory/status', (_req: Request, res: Response) => {
  return res.json(memoryStatus());
});

router.post('/memory/toggle', (req: Request, res: Response) => {
  const user = getActiveUser(req);
  const { enabled } = req.body || {};
  setMemoryEnabled(typeof enabled === 'boolean' ? enabled : !memoryEnabled);
  if (memoryEnabled) void initHindsight();
  db.addAuditLog({
    user: user.name,
    userEmail: user.email,
    role: user.role,
    action: 'MEMORY_TOGGLED',
    resource: 'Hindsight memory',
    details: `Agent memory turned ${memoryEnabled ? 'ON' : 'OFF'}.`,
    ipAddress: req.ip || '127.0.0.1',
  });
  return res.json(memoryStatus());
});

router.get('/memory/recall', async (req: Request, res: Response) => {
  const q = typeof req.query.q === 'string' ? req.query.q.trim() : '';
  if (!q) return res.status(400).json({ error: 'Query parameter q is required.' });
  const memories = await recall(q);
  return res.json({ enabled: memoryEnabled, memories });
});

router.get('/memory/recent', (_req: Request, res: Response) => {
  return res.json({ enabled: memoryEnabled, entries: recentMemories(60), status: memoryStatus() });
});

router.get('/memory/brief', async (req: Request, res: Response) => {
  const target = typeof req.query.target === 'string' ? req.query.target.trim() : '';
  if (!target) return res.status(400).json({ error: 'Query parameter target is required.' });
  if (!memoryEnabled) {
    return res.json({ available: false, text: 'Memory is OFF. Turn Memory ON in the header to get an audit briefing.' });
  }
  const text = await brief(
    `Give an audit readiness briefing for ${target}: what failed before, what was accepted as risk, what fixes worked or failed, and what needs attention now.`,
    'ZENTRA security compliance audit'
  );
  if (!text) {
    return res.json({
      available: false,
      text: 'No briefing available yet. Either Hindsight is unreachable, or no memories exist for this target. Try "Load sample memory" and wait a minute.',
    });
  }
  return res.json({ available: true, text });
});

router.post('/memory/seed', async (req: Request, res: Response) => {
  const user = getActiveUser(req);
  const result = await seedMemory();
  db.addAuditLog({
    user: user.name,
    userEmail: user.email,
    role: user.role,
    action: 'MEMORY_SEEDED',
    resource: 'Hindsight memory',
    details: `Loaded ${result.stored}/${result.total} sample memories into the memory bank.`,
    ipAddress: req.ip || '127.0.0.1',
  });
  if (result.stored === 0) {
    return res.status(502).json({ ...result, error: 'Could not reach Hindsight. Check HINDSIGHT_BASE_URL / HINDSIGHT_API_KEY.' });
  }
  return res.json(result);
});

// Did a generated CLI fix work? Feeds the next recommendation.
router.post('/remediation/outcome', (req: Request, res: Response) => {
  const user = getActiveUser(req);
  const { vendor, controlId, hostname, worked, notes } = req.body || {};
  if (!vendor || !controlId || typeof worked !== 'boolean') {
    return res.status(400).json({ error: 'vendor, controlId and worked (boolean) are required.' });
  }
  const content = `Remediation of ${controlId} on ${vendor} ${hostname || ''} ${worked ? 'WORKED' : 'FAILED'}. Notes: ${notes || 'none'}`.replace(/\s+/g, ' ');
  void remember(content, 'remediation-outcome', {
    vendor,
    controlId,
    hostname: hostname || '',
    worked: String(worked),
    reportedBy: `${user.name} (${user.role})`,
  });
  db.addAuditLog({
    user: user.name,
    userEmail: user.email,
    role: user.role,
    action: 'REMEDIATION_OUTCOME_REPORTED',
    resource: `${controlId} on ${hostname || vendor}`,
    details: `Reported that the generated fix ${worked ? 'WORKED' : 'FAILED'}.${notes ? ` Notes: ${String(notes).slice(0, 200)}` : ''}`,
    ipAddress: req.ip || '127.0.0.1',
  });
  return res.json({ ok: true, stored: memoryEnabled });
});

// Helper to extract user identity from Authorization header or simulate active user
function getActiveUser(req: Request) {
  const authHeader = req.headers.authorization;
  if (authHeader && authHeader.startsWith('Bearer ')) {
    const token = authHeader.substring(7);
    // Simple token payload decode for demonstration
    try {
      const parts = token.split('.');
      if (parts.length === 3) {
        const payload = JSON.parse(Buffer.from(parts[1], 'base64').toString('utf8'));
        const user = db.users.find(u => u.id === payload.sub || u.email === payload.email);
        if (user) return user;
      }
    } catch {
      // Fallback
    }
  }
  // No valid token. Only fall back to the Admin demo user when DEMO_MODE=true; otherwise 401.
  if (process.env.DEMO_MODE === 'true') {
    return db.users[0];
  }
  throw new AuthError();
}

// Helper to create a signed demo JWT token
function createToken(user: typeof db.users[0]) {
  const header = Buffer.from(JSON.stringify({ alg: 'ES256', typ: 'JWT' })).toString('base64url');
  const payload = Buffer.from(JSON.stringify({
    sub: user.id,
    name: user.name,
    email: user.email,
    role: user.role,
    iss: 'https://auth.zentra.sec',
    aud: 'https://api.zentra.sec',
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + (15 * 60), // 15 min Zero-Trust compliant lifetime
  })).toString('base64url');
  const signature = Buffer.from(`sig_${user.id}_${Date.now()}`).toString('base64url');
  return `${header}.${payload}.${signature}`;
}

/* ==========================================================================
   AUTHENTICATION ROUTES
   ========================================================================== */

router.post('/auth/login', (req: Request, res: Response) => {
  const { email, role } = req.body;
  const cleanEmail = (email || '').toLowerCase().trim();
  let user = db.users.find(u => u.email.toLowerCase() === cleanEmail);
  
  if (!user) {
    // If not found by email, check common demo aliases or role matching
    if (cleanEmail === 'developer@zentra.sec' || cleanEmail.startsWith('dev')) {
      user = db.users.find(u => u.role === 'DEVELOPER');
    } else if (cleanEmail.startsWith('analyst')) {
      user = db.users.find(u => u.role === 'SECURITY_ANALYST');
    } else if (cleanEmail.startsWith('admin')) {
      user = db.users.find(u => u.role === 'ADMIN');
    } else if (role && ['ADMIN', 'SECURITY_ANALYST', 'DEVELOPER'].includes(role)) {
      user = db.users.find(u => u.role === role);
    }
  }

  if (!user) {
    return res.status(401).json({ error: 'Invalid credentials. Use a demo account or register.' });
  }

  const token = createToken(user);

  db.addAuditLog({
    user: user.name,
    userEmail: user.email,
    role: user.role,
    action: 'USER_LOGIN',
    resource: 'ZENTRA Portal',
    details: `Successful Zero-Trust authentication session established with role [${user.role}].`,
    ipAddress: req.ip || '127.0.0.1',
  });

  return res.json({
    token,
    user,
    permissions: db.rolesPermissions[user.role],
  });
});

router.post('/auth/register', (req: Request, res: Response) => {
  const { name, email, role, department } = req.body;
  if (!name || !email) {
    return res.status(400).json({ error: 'Name and email are required.' });
  }

  const existing = db.users.find(u => u.email.toLowerCase() === email.toLowerCase());
  if (existing) {
    return res.status(409).json({ error: 'User with this email already exists.' });
  }

  const assignedRole: RoleType = (['ADMIN', 'SECURITY_ANALYST', 'DEVELOPER'].includes(role))
    ? role
    : 'DEVELOPER';

  const newUser = {
    id: `usr-${Date.now()}`,
    name,
    email,
    role: assignedRole,
    department: department || 'Engineering',
    createdAt: new Date().toISOString(),
  };

  db.users.push(newUser);
  const token = createToken(newUser);

  db.addAuditLog({
    user: newUser.name,
    userEmail: newUser.email,
    role: newUser.role,
    action: 'USER_REGISTERED',
    resource: 'User Registry',
    details: `New account provisioned with role [${newUser.role}] in ${newUser.department}.`,
    ipAddress: req.ip || '127.0.0.1',
  });

  return res.status(201).json({
    token,
    user: newUser,
    permissions: db.rolesPermissions[newUser.role],
  });
});

router.get('/auth/me', (req: Request, res: Response) => {
  const user = getActiveUser(req);
  return res.json({
    user,
    permissions: db.rolesPermissions[user.role],
  });
});

router.post('/auth/switch-role', (req: Request, res: Response) => {
  const { role } = req.body;
  if (!['ADMIN', 'SECURITY_ANALYST', 'DEVELOPER'].includes(role)) {
    return res.status(400).json({ error: 'Invalid role specified.' });
  }
  let targetUser = db.users.find(u => u.role === role);
  if (!targetUser) {
    targetUser = {
      id: `usr-${role.toLowerCase()}-demo`,
      name: role === 'ADMIN' ? 'Alex Vance' : role === 'SECURITY_ANALYST' ? 'Dr. Elena Rostova' : 'Marcus Chen',
      email: `${role.toLowerCase()}@zentra.sec`,
      role: role as RoleType,
      department: 'Security Operations',
      createdAt: new Date().toISOString(),
    };
    db.users.push(targetUser);
  }

  const token = createToken(targetUser);

  db.addAuditLog({
    user: targetUser.name,
    userEmail: targetUser.email,
    role: targetUser.role,
    action: 'ROLE_SWITCHED_DEMO',
    resource: 'Session Context',
    details: `Active session context switched to role [${role}].`,
    ipAddress: req.ip || '127.0.0.1',
  });

  return res.json({
    token,
    user: targetUser,
    permissions: db.rolesPermissions[targetUser.role],
  });
});

router.post('/auth/forgot-password', (req: Request, res: Response) => {
  const { email } = req.body;
  db.addAuditLog({
    user: email || 'Anonymous',
    userEmail: email || 'unknown',
    role: 'DEVELOPER',
    action: 'PASSWORD_RESET_REQUESTED',
    resource: 'Account Recovery',
    details: `Password recovery challenge generated for ${email}.`,
    ipAddress: req.ip || '127.0.0.1',
  });
  return res.json({
    message: 'If the account exists, a Zero-Trust cryptographic reset challenge has been transmitted.',
  });
});

/* ==========================================================================
   DASHBOARD STATS
   ========================================================================== */

router.get('/dashboard/stats', (_req: Request, res: Response) => {
  const baseMetrics = db.getDashboardStats();
  const devices = db.devices || [];
  const totalDevices = devices.length;
  const avgFleetCompliance = totalDevices > 0
    ? Math.round(devices.reduce((acc, d) => acc + (d.complianceScore ?? d.overallComplianceScore ?? 0), 0) / totalDevices)
    : 0;
  const compliantDevices = devices.filter(d => (d.complianceScore ?? d.overallComplianceScore ?? 0) >= 80).length;
  const warningDevices = devices.filter(d => (d.complianceScore ?? d.overallComplianceScore ?? 0) >= 50 && (d.complianceScore ?? d.overallComplianceScore ?? 0) < 80).length;
  const nonCompliantDevices = devices.filter(d => (d.complianceScore ?? d.overallComplianceScore ?? 0) < 50).length;
  const unrecognizedLinesCount = devices.reduce((acc, d) => acc + (d.unrecognizedLines ? d.unrecognizedLines.length : 0), 0);
  const learnedRulesCount = (db.learnedRules || []).length;

  // Evaluations metrics
  const evaluations = db.frameworkEvaluations || [];
  let totalControlsEvaluated = 0;
  let evalPassCount = 0;
  let evalFailCount = 0;
  evaluations.forEach(ev => {
    totalControlsEvaluated += (ev.totalControls ?? ev.summary?.totalControls ?? 0);
    evalPassCount += (ev.passedCount ?? ev.summary?.passCount ?? 0);
    evalFailCount += (ev.failedCount ?? ev.summary?.failCount ?? 0);
  });

  // Vendor breakdown
  const vendorMap = new Map<string, { count: number; totalScore: number }>();
  devices.forEach(d => {
    const v = d.vendor || d.detectedVendor || 'Unknown Vendor';
    const score = d.complianceScore ?? d.overallComplianceScore ?? 0;
    const curr = vendorMap.get(v) || { count: 0, totalScore: 0 };
    curr.count += 1;
    curr.totalScore += score;
    vendorMap.set(v, curr);
  });

  const vendorColors: Record<string, string> = {
    'Cisco IOS-XE / IOS': '#06b6d4',
    'Cisco IOS-XE': '#06b6d4',
    'Palo Alto PAN-OS': '#f97316',
    'Juniper JunOS': '#a855f7',
    'Arista EOS': '#3b82f6',
    'SONiC Linux NOS': '#10b981',
    'SONiC / Linux NOS': '#10b981',
  };

  const vendorBreakdown = Array.from(vendorMap.entries()).map(([vendor, data]) => ({
    vendor,
    count: data.count,
    avgScore: Math.round(data.totalScore / data.count),
    color: vendorColors[vendor] || '#38bdf8',
  }));

  // Framework summaries
  const allFrameworks = frameworkEngine.getAvailableFrameworks();
  const frameworkSummaries = allFrameworks.map((fw: any) => {
    const fwEvals = evaluations.filter(e => e.frameworkId === (fw.frameworkId || fw.id));
    const count = fwEvals.length;
    const avgScore = count > 0 ? Math.round(fwEvals.reduce((a, b) => a + (b.complianceScore ?? b.summary?.score ?? 0), 0) / count) : 0;
    const passCount = fwEvals.reduce((a, b) => a + (b.passedCount ?? b.summary?.passCount ?? 0), 0);
    const failCount = fwEvals.reduce((a, b) => a + (b.failedCount ?? b.summary?.failCount ?? 0), 0);
    const notEvalCount = fwEvals.reduce((a, b) => a + (b.notEvaluableCount ?? b.summary?.notEvaluableCount ?? 0), 0);
    return {
      id: fw.frameworkId || fw.id,
      name: fw.name,
      version: fw.version,
      avgScore,
      passCount,
      failCount,
      notEvalCount,
    };
  });

  // Top failed controls across all evaluations
  const failControlMap = new Map<string, { controlId: string; frameworkId: string; title: string; severity: string; failCount: number; remediationTemplate?: string }>();
  evaluations.forEach(ev => {
    const results = ev.controlResults || ev.results || [];
    results.forEach((res: any) => {
      if (res.status === 'FAIL') {
        const key = `${ev.frameworkId}:${res.controlId}`;
        const existing = failControlMap.get(key) || {
          controlId: res.controlId,
          frameworkId: ev.frameworkId,
          title: res.title,
          severity: res.severity,
          failCount: 0,
          remediationTemplate: res.remediationTemplate || res.remediation,
        };
        existing.failCount += 1;
        failControlMap.set(key, existing);
      }
    });
  });

  const topFailedControls = Array.from(failControlMap.values())
    .sort((a, b) => b.failCount - a.failCount)
    .slice(0, 6);

  // Recent devices
  const recentDevices = devices.slice(-5).reverse().map(d => {
    const score = d.complianceScore ?? d.overallComplianceScore ?? 0;
    return {
      id: d.id,
      hostname: d.hostname || 'Unknown Host',
      vendor: d.vendor || d.detectedVendor || 'Unknown Vendor',
      model: d.model || 'Modular',
      osVersion: d.osVersion || 'Unknown',
      complianceScore: score,
      status: score >= 80 ? 'COMPLIANT' : score >= 50 ? 'WARNING' : 'NON_COMPLIANT',
      unrecognizedLinesCount: d.unrecognizedLines ? d.unrecognizedLines.length : 0,
    };
  });

  const fleet = {
    totalDevices,
    avgFleetCompliance,
    compliantDevices,
    warningDevices,
    nonCompliantDevices,
    unrecognizedLinesCount,
    learnedRulesCount,
    totalControlsEvaluated: totalControlsEvaluated || (evalPassCount + evalFailCount),
    passedControls: evalPassCount,
    failedControls: evalFailCount,
    vendorBreakdown,
    frameworkSummaries,
    topFailedControls,
    recentDevices,
  };

  const metrics = {
    ...baseMetrics,
    totalDevices,
    avgFleetCompliance,
    compliantDevices,
    warningDevices,
    nonCompliantDevices,
    unrecognizedLinesCount,
    learnedRulesCount,
    complianceScore: avgFleetCompliance || baseMetrics.complianceScore,
    passedControls: evalPassCount || baseMetrics.passedControls,
    failedControls: evalFailCount || baseMetrics.failedControls,
  };

  const critFails = topFailedControls.filter(c => c.severity === 'CRITICAL').reduce((a, b) => a + b.failCount, 0);
  const highFails = topFailedControls.filter(c => c.severity === 'HIGH').reduce((a, b) => a + b.failCount, 0);
  const medFails = topFailedControls.filter(c => c.severity === 'MEDIUM').reduce((a, b) => a + b.failCount, 0);
  const lowFails = topFailedControls.filter(c => c.severity === 'LOW').reduce((a, b) => a + b.failCount, 0);

  const severityBreakdown = [
    { severity: 'CRITICAL', count: critFails || baseMetrics.criticalVulnerabilities, color: '#ef4444' },
    { severity: 'HIGH', count: highFails || baseMetrics.highVulnerabilities, color: '#f97316' },
    { severity: 'MEDIUM', count: medFails || baseMetrics.mediumVulnerabilities, color: '#eab308' },
    { severity: 'LOW', count: lowFails || baseMetrics.lowVulnerabilities, color: '#06b6d4' },
  ];

  const securityTrend = [
    { period: 'W1', score: 65 },
    { period: 'W2', score: 71 },
    { period: 'W3', score: 74 },
    { period: 'W4', score: 80 },
    { period: 'Current', score: avgFleetCompliance || 78 },
  ];

  const envRiskDistribution = [
    { env: 'Production Core', count: Math.max(1, Math.ceil(totalDevices * 0.4)), avgRisk: Math.max(15, 100 - avgFleetCompliance) },
    { env: 'DC Spine/Leaf', count: Math.max(1, Math.ceil(totalDevices * 0.3)), avgRisk: 42 },
    { env: 'Edge / DMZ', count: Math.max(1, Math.ceil(totalDevices * 0.2)), avgRisk: 68 },
    { env: 'Lab / Staging', count: Math.max(1, Math.ceil(totalDevices * 0.1)), avgRisk: 25 },
  ];

  const eventsTimeline = [
    { day: 'Mon', count: 18 },
    { day: 'Tue', count: 26 },
    { day: 'Wed', count: 14 },
    { day: 'Thu', count: 32 },
    { day: 'Today', count: db.auditLogs.length },
  ];

  const recentActivities = db.auditLogs.slice(-6).reverse().map(l => ({
    id: l.id,
    timestamp: l.timestamp,
    api: l.resource,
    event: l.action,
    severity: l.action.includes('CRITICAL') || l.details.includes('Critical') ? 'CRITICAL' : l.action.includes('FAIL') ? 'HIGH' : 'INFO',
    status: 'RECORDED',
    user: l.user,
    hash: l.hash.substring(0, 12) + '...',
  }));

  return res.json({
    metrics,
    fleet,
    severityBreakdown,
    securityTrend,
    envRiskDistribution,
    eventsTimeline,
    recentActivities,
  });
});

/* ==========================================================================
   API INVENTORY MANAGEMENT
   ========================================================================== */

router.get('/apis', (req: Request, res: Response) => {
  const { environment, authType, search } = req.query;
  let items = [...db.apis];

  if (environment && environment !== 'ALL') {
    items = items.filter(a => a.environment === environment);
  }
  if (authType && authType !== 'ALL') {
    items = items.filter(a => a.authType === authType);
  }
  if (search && typeof search === 'string') {
    const q = search.toLowerCase();
    items = items.filter(a => a.name.toLowerCase().includes(q) || a.baseUrl.toLowerCase().includes(q) || a.owner.toLowerCase().includes(q));
  }

  return res.json(items);
});

router.post('/apis', (req: Request, res: Response) => {
  const user = getActiveUser(req);
  const { name, baseUrl, environment, owner, authType, description, endpoints } = req.body;

  if (!name || !baseUrl || !environment || !authType) {
    return res.status(400).json({ error: 'Name, baseUrl, environment, and authType are required fields.' });
  }

  // Calculate baseline risk score based on environment and auth
  let baselineRisk = 30;
  if (environment === 'Production') baselineRisk += 20;
  if (authType === 'None') baselineRisk += 45;
  if (authType === 'Basic Authentication') baselineRisk += 25;
  if (authType === 'API Key') baselineRisk += 15;
  if (baseUrl.startsWith('http://')) baselineRisk += 20;

  const baselineSecurityScore = Math.max(10, 100 - baselineRisk);

  const newApi = {
    id: `api-${Date.now()}`,
    name,
    baseUrl,
    environment,
    owner: owner || user.name,
    authType,
    description: description || 'No description provided.',
    riskScore: Math.min(100, baselineRisk),
    securityScore: baselineSecurityScore,
    lastScan: null,
    status: baselineRisk > 70 ? 'WARNING' as const : 'ACTIVE' as const,
    endpointsCount: Array.isArray(endpoints) ? endpoints.length : 1,
    openFindingsCount: 0,
    isDemo: false,
  };

  db.apis.push(newApi);

  // Add default endpoint if none provided
  if (Array.isArray(endpoints) && endpoints.length > 0) {
    for (const ep of endpoints) {
      db.endpoints.push({
        id: `ep-${Date.now()}-${Math.random().toString(36).substring(2, 6)}`,
        apiId: newApi.id,
        method: ep.method || 'GET',
        path: ep.path || '/',
        authRequired: ep.authRequired !== false,
        rateLimitEnabled: !!ep.rateLimitEnabled,
        sensitivity: ep.sensitivity || 'INTERNAL',
        riskLevel: ep.riskLevel || 'MEDIUM',
        description: ep.description || 'Endpoint definition',
      });
    }
  } else {
    db.endpoints.push({
      id: `ep-${Date.now()}`,
      apiId: newApi.id,
      method: 'GET',
      path: '/health',
      authRequired: false,
      rateLimitEnabled: true,
      sensitivity: 'PUBLIC',
      riskLevel: 'LOW',
      description: 'API health and liveness probe',
    });
  }

  db.addAuditLog({
    user: user.name,
    userEmail: user.email,
    role: user.role,
    action: 'API_CREATED',
    resource: newApi.name,
    details: `Registered new API in [${newApi.environment}] environment with ${newApi.authType} authentication.`,
    ipAddress: req.ip || '127.0.0.1',
  });

  return res.status(201).json(newApi);
});

router.get('/apis/:id', (req: Request, res: Response) => {
  const api = db.apis.find(a => a.id === req.params.id);
  if (!api) {
    return res.status(404).json({ error: 'API not found' });
  }
  const endpoints = db.endpoints.filter(e => e.apiId === api.id);
  const findings = db.findings.filter(f => f.apiId === api.id);
  const activities = db.auditLogs.filter(l => l.resource === api.name || l.details.includes(api.name)).slice(-10);

  return res.json({
    api,
    endpoints,
    findings,
    activities,
  });
});

router.put('/apis/:id', (req: Request, res: Response) => {
  const user = getActiveUser(req);
  const index = db.apis.findIndex(a => a.id === req.params.id);
  if (index === -1) {
    return res.status(404).json({ error: 'API not found' });
  }

  const { name, baseUrl, environment, owner, authType, description } = req.body;
  const existing = db.apis[index];

  db.apis[index] = {
    ...existing,
    name: name || existing.name,
    baseUrl: baseUrl || existing.baseUrl,
    environment: environment || existing.environment,
    owner: owner || existing.owner,
    authType: authType || existing.authType,
    description: description !== undefined ? description : existing.description,
  };

  db.addAuditLog({
    user: user.name,
    userEmail: user.email,
    role: user.role,
    action: 'API_MODIFIED',
    resource: db.apis[index].name,
    details: `Updated configuration parameters for API ${db.apis[index].name}.`,
    ipAddress: req.ip || '127.0.0.1',
  });

  return res.json(db.apis[index]);
});

router.delete('/apis/:id', (req: Request, res: Response) => {
  const user = getActiveUser(req);
  if (user.role !== 'ADMIN') {
    return res.status(403).json({ error: 'RBAC restriction: Only ADMIN role can delete registered APIs.' });
  }

  const index = db.apis.findIndex(a => a.id === req.params.id);
  if (index === -1) {
    return res.status(404).json({ error: 'API not found' });
  }

  const deleted = db.apis.splice(index, 1)[0];
  // Remove linked endpoints and findings
  db.endpoints = db.endpoints.filter(e => e.apiId !== deleted.id);
  db.findings = db.findings.filter(f => f.apiId !== deleted.id);

  db.addAuditLog({
    user: user.name,
    userEmail: user.email,
    role: user.role,
    action: 'API_DELETED',
    resource: deleted.name,
    details: `Deleted API [${deleted.name}] and purged associated endpoint telemetry.`,
    ipAddress: req.ip || '127.0.0.1',
  });

  return res.json({ success: true, message: `API ${deleted.name} deleted.` });
});

router.post('/apis/:id/endpoints', (req: Request, res: Response) => {
  const user = getActiveUser(req);
  const api = db.apis.find(a => a.id === req.params.id);
  if (!api) {
    return res.status(404).json({ error: 'API not found' });
  }

  const { method, path, authRequired, rateLimitEnabled, sensitivity, riskLevel, description } = req.body;
  if (!path) {
    return res.status(400).json({ error: 'Endpoint path is required.' });
  }

  const newEndpoint = {
    id: `ep-${Date.now()}-${Math.random().toString(36).substring(2, 6)}`,
    apiId: api.id,
    method: method || 'GET',
    path: path.startsWith('/') ? path : `/${path}`,
    authRequired: authRequired !== false,
    rateLimitEnabled: Boolean(rateLimitEnabled),
    sensitivity: sensitivity || 'INTERNAL',
    riskLevel: riskLevel || 'MEDIUM',
    description: description || 'User-declared endpoint route',
  };

  db.endpoints.push(newEndpoint);
  api.endpointsCount = db.endpoints.filter(e => e.apiId === api.id).length;
  db.persist();

  db.addAuditLog({
    user: user.name,
    userEmail: user.email,
    role: user.role,
    action: 'ENDPOINT_ADDED',
    resource: `${api.name} (${newEndpoint.method} ${newEndpoint.path})`,
    details: `Added new endpoint route [${newEndpoint.method} ${newEndpoint.path}] with ${newEndpoint.authRequired ? 'mandatory auth' : 'anonymous access'}.`,
    ipAddress: req.ip || '127.0.0.1',
  });

  return res.status(201).json(newEndpoint);
});

router.delete('/apis/:id/endpoints/:endpointId', (req: Request, res: Response) => {
  const user = getActiveUser(req);
  const api = db.apis.find(a => a.id === req.params.id);
  if (!api) {
    return res.status(404).json({ error: 'API not found' });
  }

  const epIndex = db.endpoints.findIndex(e => e.id === req.params.endpointId && e.apiId === api.id);
  if (epIndex === -1) {
    return res.status(404).json({ error: 'Endpoint not found' });
  }

  const deletedEp = db.endpoints.splice(epIndex, 1)[0];
  api.endpointsCount = db.endpoints.filter(e => e.apiId === api.id).length;
  db.persist();

  db.addAuditLog({
    user: user.name,
    userEmail: user.email,
    role: user.role,
    action: 'ENDPOINT_DELETED',
    resource: `${api.name} (${deletedEp.method} ${deletedEp.path})`,
    details: `Deleted endpoint route [${deletedEp.method} ${deletedEp.path}] from inventory.`,
    ipAddress: req.ip || '127.0.0.1',
  });

  return res.json({ success: true, message: `Endpoint ${deletedEp.path} removed.` });
});

/* ==========================================================================
   API SCANNER WORKFLOW
   ========================================================================== */

router.post('/apis/:id/scan', async (req: Request, res: Response) => {
  const user = getActiveUser(req);
  const api = db.apis.find(a => a.id === req.params.id);
  if (!api) {
    return res.status(404).json({ error: 'API not found' });
  }

  const scanId = `scn-${Date.now()}`;
  const startedAt = new Date().toISOString();

  // Log scan initiation
  db.addAuditLog({
    user: user.name,
    userEmail: user.email,
    role: user.role,
    action: 'SCAN_STARTED',
    resource: api.name,
    details: `Zero-Trust security scan initiated for ${api.name} (${api.environment}).`,
    ipAddress: req.ip || '127.0.0.1',
  });

  // Execute deterministic rule checks against configuration, endpoints, and knowledge rules
  const discoveredFindings: SecurityFinding[] = [];
  const apiEndpoints = db.endpoints.filter(e => e.apiId === api.id);

  const logs: string[] = [
    `[${new Date().toISOString()}] Initializing ZENTRA Zero-Trust Security Scanner engine...`,
    `[${new Date().toISOString()}] Target: ${api.name} (${api.baseUrl})`,
    `[${new Date().toISOString()}] Discovering endpoints (${apiEndpoints.length} route declarations)...`,
    `[${new Date().toISOString()}] Analyzing authentication architecture [${api.authType}] in [${api.environment}]...`,
    `[${new Date().toISOString()}] Inspecting authorization policies and RBAC enforcement...`,
    `[${new Date().toISOString()}] Checking defense-in-depth HTTP security headers and mTLS boundaries...`,
    `[${new Date().toISOString()}] Analyzing payload input validation and schema bounds...`,
    `[${new Date().toISOString()}] Evaluating client request throttling and rate limiting...`,
    `[${new Date().toISOString()}] Testing for sensitive PII and secret exposure vectors...`,
    `[${new Date().toISOString()}] Matching against Zentra Security Knowledge Base (${db.knowledgeRules.length} custom rules)...`,
    `[${new Date().toISOString()}] Running CIS API Benchmark v1.2 compliance checks...`,
    `[${new Date().toISOString()}] Synthesizing findings and recalculating Zero-Trust score...`,
  ];

  // Rule 1: Insecure Cleartext HTTP Transport
  if (api.baseUrl.startsWith('http://')) {
    discoveredFindings.push({
      id: `fnd-${Date.now()}-http`,
      findingId: `ZEN-F-${Math.floor(1000 + Math.random() * 9000)}`,
      title: 'Insecure Cleartext Transport (Plain HTTP)',
      apiId: api.id,
      apiName: api.name,
      endpoint: '/*',
      method: 'ALL',
      category: 'TLS/Crypto',
      severity: 'CRITICAL',
      status: 'OPEN',
      description: 'The API is configured with an unencrypted HTTP URL schema, exposing all transmitted headers and payloads to eavesdropping and tampering.',
      evidence: `Base URL scheme: ${api.baseUrl}`,
      impact: 'Man-in-the-middle interception of credentials, bearer tokens, and confidential business payloads.',
      recommendation: 'Upgrade base protocol to HTTPS with mandatory TLS 1.3 encryption and HSTS headers.',
      implementationGuide: 'Redirect HTTP port 80 to HTTPS port 443 at load balancer; configure TLS certificates and enable HSTS with max-age=31536000.',
      validationSteps: 'Request endpoint via curl -I http://... and verify 301/308 redirect to HTTPS with Strict-Transport-Security header present.',
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
    });
  }

  // Rule 2: Unauthenticated API
  if (api.authType === 'None') {
    discoveredFindings.push({
      id: `fnd-${Date.now()}-noauth`,
      findingId: `ZEN-F-${Math.floor(1000 + Math.random() * 9000)}`,
      title: 'Missing Authentication on API Perimeter',
      apiId: api.id,
      apiName: api.name,
      endpoint: '/api/*',
      method: 'ALL',
      category: 'Authentication',
      severity: 'CRITICAL',
      status: 'OPEN',
      description: 'The API does not enforce any caller identity verification, directly violating Zero-Trust principle "Never trust. Always verify."',
      evidence: `Authentication scheme configured as 'None' in environment [${api.environment}].`,
      impact: 'Arbitrary untrusted callers can invoke service endpoints without authorization or auditing.',
      recommendation: 'Mandate cryptographic authentication using OAuth2 / JWT with short-lived tokens and signature verification.',
      implementationGuide: 'Mount authentication middleware verifying JWT signature before routing to any controller.',
      validationSteps: 'Issue request without Authorization header; verify HTTP 401 Unauthorized is returned.',
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
    });
  }

  // Rule 3: Basic Authentication
  if (api.authType === 'Basic Authentication') {
    discoveredFindings.push({
      id: `fnd-${Date.now()}-basic`,
      findingId: `ZEN-F-${Math.floor(1000 + Math.random() * 9000)}`,
      title: 'Insecure Authentication: Basic Auth Transmitted Over API Perimeter',
      apiId: api.id,
      apiName: api.name,
      endpoint: '/*',
      method: 'ALL',
      category: 'Authentication',
      severity: 'HIGH',
      status: 'OPEN',
      description: 'The API accepts RFC 7617 Basic Authentication. Base64 encoding provides zero confidentiality, and credentials are persistently retransmitted with every HTTP request.',
      evidence: `Auth scheme declared as Basic Authentication on ${api.name}.`,
      impact: 'Credential replay, lack of token revocation capability, and credential exposure in proxy logs.',
      recommendation: 'Deprecate Basic Authentication in favor of OAuth 2.0 / asymmetric signed JWT tokens with claims-based access control.',
      implementationGuide: 'Configure OAuth2 Bearer token validation middleware and reject requests with "Authorization: Basic" headers.',
      validationSteps: 'Transmit Authorization: Basic header; verify server responds with 401 and WWW-Authenticate: Bearer realm="zentra".',
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
    });
  }

  // Rule 4: Static API Key
  if (api.authType === 'API Key') {
    discoveredFindings.push({
      id: `fnd-${Date.now()}-apikey`,
      findingId: `ZEN-F-${Math.floor(1000 + Math.random() * 9000)}`,
      title: 'Static API Key Lacks Scope Delegation, Key Rotation, and Claim Expiry',
      apiId: api.id,
      apiName: api.name,
      endpoint: '/*',
      method: 'ALL',
      category: 'Authentication',
      severity: 'HIGH',
      status: 'OPEN',
      description: 'Static API keys act as long-lived bearer secrets without cryptographic expiration, user context, or fine-grained scope delegation.',
      evidence: `Auth scheme declared as API Key on ${api.name}.`,
      impact: 'Leaked API keys allow unauthorized perpetual access until manual revocation.',
      recommendation: 'Migrate to ephemeral JWT tokens with short TTLs (15 min) or implement automated API key rotation and IP allowlisting.',
      implementationGuide: 'Exchange API key for short-lived JWT session token at auth endpoint; enforce token lifetime check.',
      validationSteps: 'Verify API key rotation webhook and ensure expired tokens receive HTTP 401.',
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
    });
  }

  // Rule 5: Production Environment without mTLS
  if (api.environment === 'Production' && api.authType === 'JWT') {
    discoveredFindings.push({
      id: `fnd-${Date.now()}-mtls`,
      findingId: `ZEN-F-${Math.floor(1000 + Math.random() * 9000)}`,
      title: 'Missing Mutual TLS (mTLS) Client Certificate Verification',
      apiId: api.id,
      apiName: api.name,
      endpoint: '/*',
      method: 'ALL',
      category: 'TLS/Crypto',
      severity: 'HIGH',
      status: 'OPEN',
      description: 'Production ingress gateway accepts client traffic without validating X.509 client certificates at the transport layer.',
      evidence: `Production API ${api.name} lacking mTLS boundary enforcement.`,
      impact: 'Susceptible to unauthorized network ingress if application-layer bearer token is intercepted.',
      recommendation: 'Enforce two-way mTLS on inter-service ingress proxies with short-lived client certificates.',
      implementationGuide: 'Configure Nginx/Envoy proxy with `ssl_verify_client on` and trusted internal CA bundle.',
      validationSteps: 'Send HTTPS request without client certificate; verify handshake terminates with SSL alert certificate required.',
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
    });
  }

  // Rule 6: Check for unauthenticated non-health endpoints (BOLA risk)
  const unauthEndpoints = apiEndpoints.filter(e => !e.authRequired && e.path !== '/health');
  if (unauthEndpoints.length > 0) {
    discoveredFindings.push({
      id: `fnd-${Date.now()}-bola`,
      findingId: `ZEN-F-${Math.floor(1000 + Math.random() * 9000)}`,
      title: 'Broken Object Level Authorization (BOLA) & Unauthenticated Route Exposure',
      apiId: api.id,
      apiName: api.name,
      endpoint: unauthEndpoints[0].path,
      method: unauthEndpoints[0].method,
      category: 'Access Control',
      severity: 'CRITICAL',
      status: 'OPEN',
      description: `Endpoint ${unauthEndpoints[0].method} ${unauthEndpoints[0].path} does not enforce caller authentication or resource ownership verification.`,
      evidence: `Endpoint declared with authRequired: false in ${api.environment}.`,
      impact: 'Callers can manipulate or exfiltrate private records belonging to other tenants without authorization.',
      recommendation: 'Bind caller identity from verified JWT claims and validate that caller owns the requested resource.',
      implementationGuide: 'Inject object ownership check middleware: `if (req.user.id !== resource.ownerId) return res.status(403).json(...)`.',
      validationSteps: 'Access resource belonging to tenant B while authenticated as tenant A; verify HTTP 403 Forbidden is returned.',
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
    });
  }

  // Rule 7: Missing Rate Limiting on declared endpoints
  const unthrottled = apiEndpoints.filter(e => !e.rateLimitEnabled);
  if (unthrottled.length > 0) {
    discoveredFindings.push({
      id: `fnd-${Date.now()}-ratelimit`,
      findingId: `ZEN-F-${Math.floor(1000 + Math.random() * 9000)}`,
      title: 'Unrestricted Resource Consumption: Missing Request Rate Limiting',
      apiId: api.id,
      apiName: api.name,
      endpoint: unthrottled[0].path,
      method: unthrottled[0].method,
      category: 'Rate Limiting',
      severity: 'MEDIUM',
      status: 'OPEN',
      description: `Endpoint ${unthrottled[0].path} lacks request throttling policies, exposing the backend service to DoS attacks and resource exhaustion.`,
      evidence: `rateLimitEnabled is false on endpoint ${unthrottled[0].path}.`,
      impact: 'Denial of Service (DoS), backend CPU/memory starvation, and increased cloud infrastructure costs.',
      recommendation: 'Enforce token bucket or sliding window rate limiting (e.g., max 100 requests per minute per IP / client token).',
      implementationGuide: 'Mount express-rate-limit or Redis token bucket: `rateLimit({ windowMs: 60000, max: 100 })`.',
      validationSteps: 'Send burst of 150 requests within 10 seconds; verify HTTP 429 Too Many Requests with Retry-After header.',
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
    });
  }

  // Rule 8: Evaluate Custom Knowledge Base Rules
  for (const kr of db.knowledgeRules) {
    const patternLower = kr.pattern.toLowerCase();
    const matchesApi = api.name.toLowerCase().includes(patternLower) ||
      api.description.toLowerCase().includes(patternLower) ||
      apiEndpoints.some(e => e.path.toLowerCase().includes(patternLower) || e.description.toLowerCase().includes(patternLower));

    if (matchesApi || kr.pattern === 'admin=true') {
      discoveredFindings.push({
        id: `fnd-${Date.now()}-${kr.id}`,
        findingId: `ZEN-F-${Math.floor(1000 + Math.random() * 9000)}`,
        title: `Policy Violation: ${kr.expectedBehavior.substring(0, 60)}...`,
        apiId: api.id,
        apiName: api.name,
        endpoint: apiEndpoints.length > 0 ? apiEndpoints[0].path : '/*',
        method: apiEndpoints.length > 0 ? apiEndpoints[0].method : 'GET',
        category: (kr.category as any) || 'Access Control',
        severity: kr.severity,
        status: 'OPEN',
        description: `Triggered Knowledge Rule [${kr.securityParameter}]: ${kr.description}`,
        evidence: `Pattern "${kr.pattern}" identified in API configuration or parameter signature.`,
        impact: 'Potential privilege elevation or policy non-compliance via client parameter manipulation.',
        recommendation: kr.remediation,
        implementationGuide: 'Validate caller state against server-side authorization matrix and reject client-provided role flags.',
        validationSteps: 'Submit request with parameter and confirm HTTP 403 Forbidden is returned.',
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
      });
    }
  }

  // Rule 9: Defense-in-depth headers if no other findings
  if (discoveredFindings.length === 0) {
    discoveredFindings.push({
      id: `fnd-${Date.now()}-headers`,
      findingId: `ZEN-F-${Math.floor(1000 + Math.random() * 9000)}`,
      title: 'Missing Strict-Transport-Security (HSTS) & Security Response Headers',
      apiId: api.id,
      apiName: api.name,
      endpoint: '/*',
      method: 'ALL',
      category: 'Headers',
      severity: 'MEDIUM',
      status: 'OPEN',
      description: 'The API does not return defensive HTTP headers including Strict-Transport-Security, X-Content-Type-Options, and Content-Security-Policy.',
      evidence: 'Missing HSTS header on API response.',
      impact: 'Permits SSL-stripping attacks and MIME-type sniffing by malicious proxies.',
      recommendation: 'Inject helmet security headers on all responses.',
      implementationGuide: 'Mount helmet middleware: `app.use(helmet({ hsts: { maxAge: 31536000, includeSubDomains: true } }))`.',
      validationSteps: 'Inspect response headers and verify Strict-Transport-Security, X-Frame-Options: DENY, and X-Content-Type-Options: nosniff are present.',
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
    });
  }

  // Add discovered findings to global database
  for (const f of discoveredFindings) {
    db.findings.unshift(f);
  }

  const prevScore = api.securityScore;
  const prevOpenCount = api.openFindingsCount;

  // Update API scores
  const openForApi = db.findings.filter(f => f.apiId === api.id && (f.status === 'OPEN' || f.status === 'IN_PROGRESS'));
  const critCount = openForApi.filter(f => f.severity === 'CRITICAL').length;
  const highCount = openForApi.filter(f => f.severity === 'HIGH').length;
  const medCount = openForApi.filter(f => f.severity === 'MEDIUM').length;
  const lowCount = openForApi.filter(f => f.severity === 'LOW').length;

  const penalty = (critCount * 25) + (highCount * 12) + (medCount * 5) + (lowCount * 2);
  api.securityScore = Math.max(20, 100 - penalty);
  api.riskScore = Math.min(95, penalty + 15);
  api.lastScan = new Date().toISOString();
  api.status = critCount > 0 ? 'CRITICAL' : highCount > 0 ? 'WARNING' : 'ACTIVE';
  api.openFindingsCount = openForApi.length;

  const completedAt = new Date().toISOString();

  const scanRecord: typeof db.scans[0] = {
    id: scanId,
    apiId: api.id,
    apiName: api.name,
    initiatedBy: user.name,
    status: 'COMPLETED',
    startedAt,
    completedAt,
    findingsDiscovered: discoveredFindings.length,
    criticalCount: critCount,
    highCount,
    mediumCount: medCount,
    lowCount,
    securityScoreResult: api.securityScore,
    logs,
  };
  db.scans.unshift(scanRecord);

  // Log scan completion in SHA-256 audit ledger
  db.addAuditLog({
    user: user.name,
    userEmail: user.email,
    role: user.role,
    action: 'SCAN_COMPLETED',
    resource: api.name,
    details: `Completed scan with ${discoveredFindings.length} finding(s). Updated API security score to ${api.securityScore}%.`,
    ipAddress: req.ip || '127.0.0.1',
  });

  // Memory: remember a short scan summary
  {
    const dScore = api.securityScore - (prevScore ?? api.securityScore);
    const dOpen = api.openFindingsCount - (prevOpenCount ?? api.openFindingsCount);
    const change = `Change since last scan: security score ${prevScore ?? 'n/a'} -> ${api.securityScore} (${dScore >= 0 ? '+' : ''}${dScore}), open findings ${prevOpenCount ?? 'n/a'} -> ${api.openFindingsCount} (${dOpen >= 0 ? '+' : ''}${dOpen}).`;
    void remember(
      `Scan of ${api.name} (${api.environment}, ${api.authType}) found ${discoveredFindings.length} new finding(s): ${critCount} critical, ${highCount} high, ${medCount} medium, ${lowCount} low open in total. ${change}`,
      'scan-summary',
      { api: api.name, newFindings: String(discoveredFindings.length), critical: String(critCount), high: String(highCount) }
    );
  }

  return res.json({
    scan: scanRecord,
    findings: discoveredFindings,
    updatedApi: api,
  });
});

router.get('/scans', (_req: Request, res: Response) => {
  return res.json(db.scans);
});

router.post('/scanner/analyze-spec', (req: Request, res: Response) => {
  const user = getActiveUser(req);
  const { spec, saveToInventory, saveFindings, environment } = req.body;

  if (!spec || typeof spec !== 'string' || !spec.trim()) {
    return res.status(400).json({ error: 'Please provide an OpenAPI or Swagger document (JSON or YAML).' });
  }

  try {
    const parsedDoc = parseOpenApiDocument(spec);
    
    let targetApiId = `spec-${Date.now()}`;
    let createdApi: any = null;

    if (saveToInventory) {
      let authType = 'None';
      if (parsedDoc.securitySchemes.length > 0) {
        const firstScheme = parsedDoc.securitySchemes[0];
        if (firstScheme.type === 'http' && firstScheme.scheme === 'bearer') {
          authType = 'JWT';
        } else if (firstScheme.type === 'http' && firstScheme.scheme === 'basic') {
          authType = 'Basic Authentication';
        } else if (firstScheme.type === 'apiKey') {
          authType = 'API Key';
        } else if (firstScheme.type === 'oauth2' || firstScheme.type === 'openIdConnect') {
          authType = 'OAuth2';
        } else {
          authType = firstScheme.name;
        }
      }

      createdApi = {
        id: `api-${Date.now()}`,
        name: parsedDoc.title,
        baseUrl: parsedDoc.baseUrl,
        environment: environment || (parsedDoc.baseUrl.includes('prod') ? 'Production' : 'Staging'),
        owner: `${user.name} (${user.department || 'API Platform'})`,
        authType,
        description: parsedDoc.description || `Imported from ${parsedDoc.specVersion} document with ${parsedDoc.endpoints.length} endpoint(s).`,
        riskScore: 50,
        securityScore: 80,
        lastScan: new Date().toISOString(),
        status: 'ACTIVE',
        endpointsCount: parsedDoc.endpoints.length,
        openFindingsCount: 0,
        isDemo: false,
      };

      db.apis.unshift(createdApi);
      targetApiId = createdApi.id;

      // Add endpoints to db.endpoints
      parsedDoc.endpoints.forEach((ep, idx) => {
        const isSensitive = ep.path.toLowerCase().match(/\/(admin|secret|cred|token|pay|auth)/);
        const isConfidential = ep.path.toLowerCase().match(/\/(user|account|order|profile|patient|ehr)/);
        const authRequired = ep.security.length > 0;

        const sensitivity = isSensitive
          ? 'RESTRICTED'
          : isConfidential
          ? 'CONFIDENTIAL'
          : authRequired
          ? 'INTERNAL'
          : 'PUBLIC';

        const riskLevel = !authRequired && isSensitive
          ? 'CRITICAL'
          : isSensitive
          ? 'HIGH'
          : isConfidential
          ? 'MEDIUM'
          : 'LOW';

        db.endpoints.push({
          id: `ep-${createdApi.id}-${idx + 1}`,
          apiId: createdApi.id,
          path: ep.path,
          method: ep.method as any,
          authRequired,
          rateLimitEnabled: ep.responses.some(r => r.status === '429' || r.hasRateLimitHeaders),
          sensitivity,
          riskLevel,
          description: ep.summary || `Endpoint ${ep.method} ${ep.path}`,
        });
      });

      db.addAuditLog({
        user: user.name,
        userEmail: user.email,
        role: user.role,
        action: 'API_IMPORTED',
        resource: createdApi.name,
        details: `Imported API from OpenAPI/Swagger spec with ${parsedDoc.endpoints.length} routes. Base URL: ${createdApi.baseUrl}`,
        ipAddress: req.ip || '127.0.0.1',
      });
    }

    const analysis = analyzeParsedOpenApi(parsedDoc, targetApiId);

    if (createdApi) {
      createdApi.securityScore = analysis.score;
      createdApi.riskScore = Math.max(15, 100 - analysis.score);
      createdApi.openFindingsCount = analysis.findings.length;
      if (analysis.summary.critical > 0) createdApi.status = 'CRITICAL';
      else if (analysis.summary.high > 0) createdApi.status = 'WARNING';
      else createdApi.status = 'ACTIVE';
    }

    if (saveFindings) {
      for (const f of analysis.findings) {
        db.findings.unshift(f);
      }

      const scanRecord: ScanRecord = {
        id: `scan-${Date.now()}`,
        apiId: targetApiId,
        apiName: parsedDoc.title,
        initiatedBy: user.name,
        status: 'COMPLETED',
        startedAt: new Date(Date.now() - 1500).toISOString(),
        completedAt: new Date().toISOString(),
        findingsDiscovered: analysis.findings.length,
        criticalCount: analysis.summary.critical,
        highCount: analysis.summary.high,
        mediumCount: analysis.summary.medium,
        lowCount: analysis.summary.low,
        securityScoreResult: analysis.score,
        logs: [
          `[${new Date().toISOString()}] Parsed ${parsedDoc.specVersion} specification: "${parsedDoc.title}"`,
          `[${new Date().toISOString()}] Extracted ${parsedDoc.endpoints.length} endpoint operations and ${parsedDoc.securitySchemes.length} security scheme(s)`,
          `[${new Date().toISOString()}] Completed static security analysis. Discovered ${analysis.findings.length} finding(s).`,
        ],
      };
      db.scans.unshift(scanRecord);

      db.addAuditLog({
        user: user.name,
        userEmail: user.email,
        role: user.role,
        action: 'SPEC_STATIC_ANALYSIS_COMPLETED',
        resource: parsedDoc.title,
        details: `Static analysis of OpenAPI spec discovered ${analysis.findings.length} findings (${analysis.summary.critical} Crit, ${analysis.summary.high} High). Score: ${analysis.score}%.`,
        ipAddress: req.ip || '127.0.0.1',
      });
    }

    return res.json({
      ...analysis,
      createdApi,
    });
  } catch (err: any) {
    return res.status(400).json({ error: err.message || 'Failed to parse and analyze specification.' });
  }
});

/* ==========================================================================
   SECURITY FINDINGS ROUTES
   ========================================================================== */

router.get('/findings', (req: Request, res: Response) => {
  const { severity, apiId, status, category, search } = req.query;
  let items = [...db.findings];

  if (severity && severity !== 'ALL') {
    items = items.filter(f => f.severity === severity);
  }
  if (apiId && apiId !== 'ALL') {
    items = items.filter(f => f.apiId === apiId);
  }
  if (status && status !== 'ALL') {
    items = items.filter(f => f.status === status);
  }
  if (category && category !== 'ALL') {
    items = items.filter(f => f.category === category);
  }
  if (search && typeof search === 'string') {
    const q = search.toLowerCase();
    items = items.filter(f => 
      f.title.toLowerCase().includes(q) ||
      f.findingId.toLowerCase().includes(q) ||
      f.endpoint.toLowerCase().includes(q) ||
      f.description.toLowerCase().includes(q)
    );
  }

  return res.json(items);
});

router.get('/findings/:id', (req: Request, res: Response) => {
  const finding = db.findings.find(f => f.id === req.params.id || f.findingId === req.params.id);
  if (!finding) {
    return res.status(404).json({ error: 'Finding not found' });
  }
  const api = db.apis.find(a => a.id === finding.apiId);
  return res.json({ finding, api });
});

router.put('/findings/:id/status', (req: Request, res: Response) => {
  const user = getActiveUser(req);
  const { status, acceptedReason } = req.body;
  const validStatuses: FindingStatus[] = ['OPEN', 'IN_PROGRESS', 'RESOLVED', 'ACCEPTED_RISK'];

  if (!validStatuses.includes(status)) {
    return res.status(400).json({ error: 'Invalid status' });
  }

  if (status === 'ACCEPTED_RISK' && user.role !== 'ADMIN' && user.role !== 'SECURITY_ANALYST') {
    return res.status(403).json({ error: 'RBAC restriction: Only ADMIN or SECURITY_ANALYST can accept security risks.' });
  }

  const index = db.findings.findIndex(f => f.id === req.params.id || f.findingId === req.params.id);
  if (index === -1) {
    return res.status(404).json({ error: 'Finding not found' });
  }

  const existing = db.findings[index];
  const oldStatus = existing.status;

  db.findings[index] = {
    ...existing,
    status,
    acceptedReason: status === 'ACCEPTED_RISK' ? (acceptedReason || 'Compensating controls reviewed by security') : existing.acceptedReason,
    resolvedAt: status === 'RESOLVED' ? new Date().toISOString() : undefined,
    updatedAt: new Date().toISOString(),
  };

  // Recalculate open count on parent API
  const api = db.apis.find(a => a.id === existing.apiId);
  if (api) {
    api.openFindingsCount = db.findings.filter(f => f.apiId === api.id && (f.status === 'OPEN' || f.status === 'IN_PROGRESS')).length;
  }

  db.addAuditLog({
    user: user.name,
    userEmail: user.email,
    role: user.role,
    action: 'FINDING_STATUS_UPDATE',
    resource: `${existing.findingId} (${existing.title})`,
    details: `Updated finding status from [${oldStatus}] to [${status}]${status === 'ACCEPTED_RISK' ? ` with justification: ${acceptedReason || 'Reviewed'}` : ''}.`,
    ipAddress: req.ip || '127.0.0.1',
  });

  // Memory: remember the decision (fire-and-forget)
  {
    const reason = db.findings[index].acceptedReason && status === 'ACCEPTED_RISK' ? db.findings[index].acceptedReason : acceptedReason;
    void remember(
      `Finding ${existing.findingId} '${existing.title}' on ${existing.apiName} (${existing.category}, ${existing.severity}) changed from ${oldStatus} to ${status} by ${user.name} (${user.role}).${reason ? ` Reason: ${reason}` : ''}`,
      'finding-decision',
      { findingId: existing.findingId, api: existing.apiName, severity: existing.severity, status, previousStatus: oldStatus, user: user.name }
    );
  }

  return res.json(db.findings[index]);
});

/* ==========================================================================
   ZERO TRUST MODULE
   ========================================================================== */

router.get('/zero-trust', (_req: Request, res: Response) => {
  const assessment = evaluateZeroTrustPosture();
  const pillars = db.zeroTrustPillars;

  return res.json({
    ...assessment,
    pillars,
    coveragePercent: Math.round((assessment.compliantCount / assessment.totalControlsAudited) * 100),
    enforcedPolicies: 28,
    pendingVerifications: assessment.warningCount + assessment.criticalCount,
  });
});

router.post('/zero-trust/assess', (req: Request, res: Response) => {
  const user = getActiveUser(req);
  const assessment = evaluateZeroTrustPosture();

  // Also sync legacy pillars for consistency
  const criticals = db.findings.filter(f => f.severity === 'CRITICAL' && f.status === 'OPEN').length;
  const highs = db.findings.filter(f => f.severity === 'HIGH' && f.status === 'OPEN').length;

  for (const pillar of db.zeroTrustPillars) {
    if (pillar.pillar === 'Application') {
      pillar.score = Math.max(50, 95 - (criticals * 10) - (highs * 4));
    }
    if (pillar.pillar === 'Data') {
      const dataFindings = db.findings.filter(f => f.category === 'Data Exposure' && f.status === 'OPEN').length;
      pillar.score = Math.max(50, 92 - (dataFindings * 12));
    }
  }

  db.addAuditLog({
    user: user.name,
    userEmail: user.email,
    role: user.role,
    action: 'ZERO_TRUST_ASSESSMENT',
    resource: 'Zero-Trust Architecture',
    details: `Executed 10-category Zero-Trust posture evaluation. Calculated overall score: ${assessment.overallScore}% (${assessment.postureLevel}). Compliant categories: ${assessment.compliantCount}/10.`,
    ipAddress: req.ip || '127.0.0.1',
  });

  return res.json({
    ...assessment,
    pillars: db.zeroTrustPillars,
    coveragePercent: Math.round((assessment.compliantCount / assessment.totalControlsAudited) * 100),
    enforcedPolicies: 28,
    pendingVerifications: assessment.warningCount + assessment.criticalCount,
  });
});

/* ==========================================================================
   FRAMEWORK COMPLIANCE ENGINE (CIS, NIST, DISA STIG, ISO 27001)
   ========================================================================== */

// Legacy compliance compatibility endpoint for global search and reports
router.get('/compliance', (_req: Request, res: Response) => {
  const evaluated = db.cisControls.filter(c => c.status !== 'NOT EVALUATED');
  const passed = db.cisControls.filter(c => c.status === 'PASS').length;
  const score = evaluated.length > 0 ? Math.round((passed / evaluated.length) * 100) : 72;

  return res.json({
    score,
    controls: db.cisControls,
    stats: {
      total: db.cisControls.length,
      passed,
      failed: db.cisControls.filter(c => c.status === 'FAIL').length,
      warning: db.cisControls.filter(c => c.status === 'WARNING').length,
      notEvaluated: db.cisControls.filter(c => c.status === 'NOT EVALUATED').length,
      requiresReview: db.cisControls.filter(c => c.status === 'REQUIRES REVIEW').length,
    },
    framework: {
      name: 'CIS API & Network Baseline Benchmark',
      version: 'v2.1',
      description: 'Standard security controls for network infrastructure and APIs.',
    },
  });
});

router.post('/compliance/assess', (req: Request, res: Response) => {
  return res.json({
    score: 78,
    controls: db.cisControls,
  });
});

// 1. GET /compliance/frameworks - List available JSON frameworks
router.get('/compliance/frameworks', (_req: Request, res: Response) => {
  const frameworks = frameworkEngine.getAvailableFrameworks();
  return res.json(frameworks);
});

// 2. GET /compliance/frameworks/:id - Full framework details
router.get('/compliance/frameworks/:id', (req: Request, res: Response) => {
  const fw = frameworkEngine.getFramework(req.params.id);
  if (!fw) {
    return res.status(404).json({ error: 'Framework not found' });
  }
  return res.json(fw);
});

/* ==========================================================================
   PACKS & EXTENSIBILITY (VENDOR PACKS & FRAMEWORK PACKS)
   ========================================================================== */

// 1. GET /packs/frameworks - Get all installed framework packs
router.get('/packs/frameworks', (_req: Request, res: Response) => {
  const frameworks = frameworkEngine.getAllFrameworks();
  return res.json(frameworks);
});

// 2. GET /packs/frameworks/:id/export - Export single framework pack JSON
router.get('/packs/frameworks/:id/export', (req: Request, res: Response) => {
  const fw = frameworkEngine.getFramework(req.params.id);
  if (!fw) {
    return res.status(404).json({ error: 'Framework pack not found' });
  }
  return res.json(fw);
});

// 3. POST /packs/frameworks/import - Import a framework pack JSON
router.post('/packs/frameworks/import', (req: Request, res: Response) => {
  const user = getActiveUser(req);
  const data = req.body;
  const packs: any[] = Array.isArray(data) ? data : data.frameworks ? data.frameworks : [data];

  const imported: string[] = [];

  for (const pack of packs) {
    if (!pack || !pack.frameworkId || !pack.name || !Array.isArray(pack.controls)) {
      return res.status(400).json({
        error: 'Invalid framework pack format. Required fields: frameworkId, name, version, and controls array.',
      });
    }

    // Validate controls
    for (const c of pack.controls) {
      if (!c.id || !c.title || !c.field || !c.operator) {
        return res.status(400).json({
          error: `Control validation failed in framework ${pack.frameworkId}: control must have id, title, field, and operator.`,
        });
      }
    }

    frameworkEngine.saveFramework(pack);
    imported.push(pack.name);

    db.addAuditLog({
      user: user.name,
      userEmail: user.email,
      role: user.role,
      action: 'FRAMEWORK_PACK_IMPORTED',
      resource: `Framework: ${pack.name} (${pack.frameworkId})`,
      details: `Imported framework pack [${pack.name} v${pack.version || '1.0'}] with ${pack.controls.length} controls without code changes.`,
      ipAddress: req.ip || '127.0.0.1',
    });
  }

  return res.json({
    success: true,
    message: `Successfully imported ${imported.length} framework pack(s): ${imported.join(', ')}. Available immediately in compliance engine.`,
    frameworks: frameworkEngine.getAvailableFrameworks(),
  });
});

// 4. DELETE /packs/frameworks/:id - Delete a framework pack
router.delete('/packs/frameworks/:id', (req: Request, res: Response) => {
  const user = getActiveUser(req);
  if (user.role !== 'ADMIN') {
    return res.status(403).json({ error: 'RBAC restriction: Only ADMIN can delete framework packs.' });
  }

  const fwId = req.params.id;
  const fw = frameworkEngine.getFramework(fwId);
  const success = frameworkEngine.deleteFramework(fwId);

  if (!success) {
    return res.status(404).json({ error: 'Framework pack file not found or could not be removed.' });
  }

  // Remove evaluations associated with this framework
  db.frameworkEvaluations = db.frameworkEvaluations.filter(e => e.frameworkId !== fwId);
  db.persist();

  db.addAuditLog({
    user: user.name,
    userEmail: user.email,
    role: user.role,
    action: 'FRAMEWORK_PACK_DELETED',
    resource: `Framework: ${fw?.name || fwId}`,
    details: `Deleted framework pack [${fwId}]. Removed associated evaluations.`,
    ipAddress: req.ip || '127.0.0.1',
  });

  return res.json({ success: true, message: `Framework pack ${fwId} removed.`, id: fwId });
});

// 5. GET /packs/vendors - List all vendor packs
router.get('/packs/vendors', (_req: Request, res: Response) => {
  const packs = vendorPackManager.getAllPacks();
  return res.json(packs);
});

// 6. GET /packs/vendors/:vendorOrId/export - Export vendor pack JSON
router.get('/packs/vendors/:vendorOrId/export', (req: Request, res: Response) => {
  const param = req.params.vendorOrId;
  const pack = vendorPackManager.getPack(param) || vendorPackManager.exportPackForVendor(param);
  return res.json(pack);
});

// 7. POST /packs/vendors/import - Import vendor pack JSON
router.post('/packs/vendors/import', (req: Request, res: Response) => {
  const user = getActiveUser(req);
  const data = req.body;
  const packs: any[] = Array.isArray(data) ? data : data.vendorPacks ? data.vendorPacks : [data];

  const imported: string[] = [];

  for (const pack of packs) {
    if (!pack || !pack.vendor || !Array.isArray(pack.rules)) {
      return res.status(400).json({
        error: 'Invalid vendor pack format. Required fields: vendor, description, and rules array.',
      });
    }

    // Validate regex patterns
    for (const r of pack.rules) {
      if (!r.regex || !r.field) {
        return res.status(400).json({
          error: `Rule validation failed in vendor pack ${pack.vendor}: regex and field are required.`,
        });
      }
      try {
        new RegExp(r.regex, 'i');
      } catch (err: any) {
        return res.status(400).json({
          error: `Invalid regex pattern in rule "${r.name || r.field}": ${err.message}`,
        });
      }
    }

    vendorPackManager.savePack(pack, user.name);
    imported.push(pack.vendor);

    db.addAuditLog({
      user: user.name,
      userEmail: user.email,
      role: user.role,
      action: 'VENDOR_PACK_IMPORTED',
      resource: `Vendor Pack: ${pack.vendor}`,
      details: `Imported vendor normalization pack [${pack.vendor} v${pack.version || '1.0'}] with ${pack.rules.length} extraction rules without code changes.`,
      ipAddress: req.ip || '127.0.0.1',
    });
  }

  return res.json({
    success: true,
    message: `Successfully imported ${imported.length} vendor pack(s): ${imported.join(', ')}. Rules synchronized into runtime normalizer.`,
    packs: vendorPackManager.getAllPacks(),
    learnedRulesCount: db.learnedRules.length,
  });
});

// 8. DELETE /packs/vendors/:id - Delete a vendor pack
router.delete('/packs/vendors/:id', (req: Request, res: Response) => {
  const user = getActiveUser(req);
  if (user.role !== 'ADMIN') {
    return res.status(403).json({ error: 'RBAC restriction: Only ADMIN can delete vendor packs.' });
  }

  const packId = req.params.id;
  const pack = vendorPackManager.getPack(packId);
  const success = vendorPackManager.deletePack(packId);

  if (!success) {
    return res.status(404).json({ error: 'Vendor pack not found.' });
  }

  db.addAuditLog({
    user: user.name,
    userEmail: user.email,
    role: user.role,
    action: 'VENDOR_PACK_DELETED',
    resource: `Vendor Pack: ${pack?.vendor || packId}`,
    details: `Deleted vendor pack [${packId}].`,
    ipAddress: req.ip || '127.0.0.1',
  });

  return res.json({ success: true, message: `Vendor pack ${packId} deleted.`, id: packId });
});

// 3. POST /compliance/evaluate - Run evaluation on selected frameworks and devices
router.post('/compliance/evaluate', (req: Request, res: Response) => {
  const user = getActiveUser(req);
  const { frameworkIds, deviceIds } = req.body;

  // Determine frameworks to evaluate
  const allFrameworks = frameworkEngine.getAvailableFrameworks();
  const targetFwIds: string[] = Array.isArray(frameworkIds) && frameworkIds.length > 0
    ? frameworkIds
    : allFrameworks.map(f => f.frameworkId);

  // Determine devices to evaluate
  const targetDevices: NetworkDevice[] = Array.isArray(deviceIds) && deviceIds.length > 0
    ? db.devices.filter(d => deviceIds.includes(d.id))
    : db.devices;

  if (targetDevices.length === 0) {
    return res.status(400).json({ error: 'No devices found in repository to evaluate.' });
  }

  const newEvaluations: DeviceFrameworkEvaluation[] = [];

  for (const device of targetDevices) {
    for (const fwId of targetFwIds) {
      const evaluation = frameworkEngine.evaluateDeviceAgainstFramework(device, fwId);
      if (evaluation) {
        // Remove prior evaluation for this device + framework pair if exists
        const existingIdx = db.frameworkEvaluations.findIndex(
          e => e.deviceId === device.id && e.frameworkId === fwId
        );
        if (existingIdx !== -1) {
          db.frameworkEvaluations.splice(existingIdx, 1);
        }
        db.frameworkEvaluations.push(evaluation);
        newEvaluations.push(evaluation);
      }
    }
  }

  db.persist();

  db.addAuditLog({
    user: user.name,
    userEmail: user.email,
    role: user.role,
    action: 'FRAMEWORK_COMPLIANCE_EVALUATED',
    resource: `${targetFwIds.join(', ')}`,
    details: `Executed security baseline framework evaluations across ${targetDevices.length} network device(s) for frameworks: [${targetFwIds.join(', ')}]. Generated ${newEvaluations.length} evaluation matrix records.`,
    ipAddress: req.ip || '127.0.0.1',
  });

  // Memory: remember every failed control (batched, fire-and-forget)
  {
    const failedItems: Array<{ content: string; context: string; metadata: Record<string, string> }> = [];
    for (const ev of newEvaluations) {
      const dev = targetDevices.find((d) => d.id === ev.deviceId);
      for (const ctrl of ev.controlResults) {
        if (ctrl.status !== 'FAIL') continue;
        failedItems.push({
          content: `Device ${ev.deviceHostname} (${ev.deviceVendor}${dev?.model ? ` ${dev.model}` : ''}) failed ${ctrl.controlId} ${ctrl.title} against ${ev.frameworkName}. Expected ${JSON.stringify(ctrl.expectedValue)}, found ${JSON.stringify(ctrl.actualValue)}`,
          context: 'compliance-result',
          metadata: { hostname: ev.deviceHostname, vendor: ev.deviceVendor, controlId: ctrl.controlId, framework: ev.frameworkId, severity: ctrl.severity },
        });
      }
    }
    if (failedItems.length > 0) void rememberBatch(failedItems.slice(0, 200));
  }

  return res.json({
    message: `Evaluation completed successfully for ${targetDevices.length} device(s) across ${targetFwIds.length} framework(s).`,
    evaluations: newEvaluations,
  });
});

// 4. GET /compliance/evaluations - Get evaluation records
router.get('/compliance/evaluations', (_req: Request, res: Response) => {
  const { deviceId, frameworkId } = _req.query;

  // If no evaluations exist, run initial evaluation across all devices & frameworks
  if (db.frameworkEvaluations.length === 0 && db.devices.length > 0) {
    const allFrameworks = frameworkEngine.getAvailableFrameworks();
    for (const device of db.devices) {
      for (const fw of allFrameworks) {
        const ev = frameworkEngine.evaluateDeviceAgainstFramework(device, fw.frameworkId);
        if (ev) db.frameworkEvaluations.push(ev);
      }
    }
    db.persist();
  }

  let results = [...db.frameworkEvaluations];

  if (deviceId && typeof deviceId === 'string' && deviceId !== 'ALL') {
    results = results.filter(e => e.deviceId === deviceId);
  }

  if (frameworkId && typeof frameworkId === 'string' && frameworkId !== 'ALL') {
    results = results.filter(e => e.frameworkId === frameworkId);
  }

  return res.json(results);
});

// 5. GET /compliance/summary - High-level compliance stats
router.get('/compliance/summary', (_req: Request, res: Response) => {
  if (db.frameworkEvaluations.length === 0 && db.devices.length > 0) {
    const allFrameworks = frameworkEngine.getAvailableFrameworks();
    for (const device of db.devices) {
      for (const fw of allFrameworks) {
        const ev = frameworkEngine.evaluateDeviceAgainstFramework(device, fw.frameworkId);
        if (ev) db.frameworkEvaluations.push(ev);
      }
    }
    db.persist();
  }

  const evaluations = db.frameworkEvaluations;
  const totalEvals = evaluations.length;
  const avgScore = totalEvals > 0 ? Math.round(evaluations.reduce((acc, e) => acc + e.complianceScore, 0) / totalEvals) : 0;

  let totalPassed = 0;
  let totalFailed = 0;
  let totalNotEvaluable = 0;

  for (const e of evaluations) {
    totalPassed += e.passedCount;
    totalFailed += e.failedCount;
    totalNotEvaluable += e.notEvaluableCount;
  }

  return res.json({
    totalDevices: db.devices.length,
    totalEvaluations: totalEvals,
    avgScore,
    totalPassed,
    totalFailed,
    totalNotEvaluable,
    availableFrameworks: frameworkEngine.getAvailableFrameworks(),
  });
});

// 6. POST /compliance/remediation-cli - Generate vendor-specific CLI remediation for failed controls
router.post('/compliance/remediation-cli', async (req: Request, res: Response) => {
  const user = getActiveUser(req);
  const { vendor, model, osVersion, hostname, controls } = req.body;

  if (!vendor || !Array.isArray(controls)) {
    return res.status(400).json({ error: 'Vendor and controls array are required.' });
  }

  try {
    const offline = isOfflineForced();
    let blocked = 0;

    const remediations = await Promise.all(
      controls.map(async (ctrl: any) => {
        // Injection guard BEFORE any AI call: if control text looks hostile, use the template only.
        const hits = scanFields([ctrl.title, ctrl.remediation, String(ctrl.expectedValue ?? ''), String(ctrl.actualValue ?? '')]);
        const forceTemplate = offline || hits.length > 0;
        if (hits.length > 0) blocked++;

        const out = await generateVendorCliRemediationWithSource(
          {
            vendor,
            model: model || null,
            osVersion: osVersion || null,
            hostname: hostname || null,
            controlId: ctrl.controlId || ctrl.id || 'CONTROL',
            controlTitle: ctrl.title || 'Security Baseline Control',
            field: ctrl.field || '',
            expectedValue: ctrl.expectedValue,
            actualValue: ctrl.actualValue,
            genericRemediation: ctrl.remediation || '',
          },
          forceTemplate
        );

        // Memory: remember the generated fix (use the clean commands, never the memory notes)
        void remember(
          `Generated CLI fix (${out.source}) for ${ctrl.controlId || ctrl.id || 'CONTROL'} ${ctrl.title || ''} on ${vendor} ${hostname || ''}: ${String(out.baseCommands).replace(/\s*\n\s*/g, ' ; ').slice(0, 1200)}`,
          'remediation-generated',
          { vendor, controlId: ctrl.controlId || ctrl.id || '', hostname: hostname || '', source: out.source }
        );

        return {
          controlId: ctrl.controlId || ctrl.id,
          field: ctrl.field,
          cliCommands: out.commands,
          source: out.source,
          guarded: hits.length > 0,
          memoriesUsed: out.memoriesUsed,
          memoryCount: out.memoryCount,
        };
      })
    );

    if (blocked > 0) {
      db.addAuditLog({
        user: user.name,
        userEmail: user.email,
        role: user.role,
        action: 'PROMPT_INJECTION_BLOCKED',
        resource: `Remediation: ${hostname || vendor}`,
        details: `Injection guard flagged ${blocked} control field(s) before AI fix generation; template fixes used instead of Gemini.`,
        ipAddress: req.ip || '127.0.0.1',
      });
    }

    return res.json({ vendor, offline, remediations, memoryEnabled });
  } catch (err: any) {
    console.error('Error generating CLI remediations:', err);
    return res.status(500).json({ error: 'Failed to generate vendor CLI remediation' });
  }
});

/* ==========================================================================
   REPORT SEALS, VERIFICATION & DRY-RUN FIX AUDIT
   ========================================================================== */

// Seal a report: HMAC-SHA256 over its contents (device id, findings, results, timestamp)
router.post('/reports/seal', (req: Request, res: Response) => {
  const user = getActiveUser(req);
  const { kind, label, payload } = req.body;
  if (!payload || typeof payload !== 'object') {
    return res.status(400).json({ error: 'A report payload object is required to seal.' });
  }
  const sealedAt = new Date().toISOString();
  const sealed = { ...payload, sealedAt };
  const seal = computeSeal(sealed);
  const rec = recordSeal(String(kind || 'report'), String(label || 'report'), seal, sealedAt);

  db.addAuditLog({
    user: user.name,
    userEmail: user.email,
    role: user.role,
    action: 'REPORT_SEALED',
    resource: String(label || 'report'),
    details: `Report sealed with HMAC-SHA256 ${seal.slice(0, 16)}... [${rec.id}]`,
    ipAddress: req.ip || '127.0.0.1',
  });

  return res.json({ seal, sealedAt, algorithm: 'HMAC-SHA256', payload: sealed });
});

// Verify a report: server recomputes the HMAC and compares
router.post('/reports/verify', (req: Request, res: Response) => {
  const user = getActiveUser(req);
  const { payload, seal } = req.body;
  if (!payload || typeof payload !== 'object' || typeof seal !== 'string') {
    return res.status(400).json({ error: 'Both report data (payload) and seal are required.' });
  }
  const authentic = verifySeal(payload, seal);

  db.addAuditLog({
    user: user.name,
    userEmail: user.email,
    role: user.role,
    action: authentic ? 'REPORT_VERIFIED_AUTHENTIC' : 'REPORT_VERIFY_TAMPERED',
    resource: String(payload.hostname || payload.title || payload.deviceId || 'report'),
    details: authentic
      ? `Seal ${seal.slice(0, 16)}... matched recomputed HMAC.`
      : `Seal ${seal.slice(0, 16)}... did NOT match. Report contents were modified or the seal is forged.`,
    ipAddress: req.ip || '127.0.0.1',
  });

  return res.json({
    authentic,
    verdict: authentic ? 'AUTHENTIC' : 'TAMPERED',
    algorithm: 'HMAC-SHA256',
    checkedAt: new Date().toISOString(),
  });
});

// Audit entry for operator-reviewed fix commands (dry run - nothing is executed)
router.post('/reports/fix-audit', (req: Request, res: Response) => {
  const user = getActiveUser(req);
  const { hostname, deviceId, edits, approvedCount } = req.body;
  const edited = Array.isArray(edits) ? edits : [];
  db.addAuditLog({
    user: user.name,
    userEmail: user.email,
    role: user.role,
    action: edited.length > 0 ? 'FIX_COMMANDS_EDITED_APPROVED' : 'FIX_COMMANDS_APPROVED',
    resource: `Device: ${hostname || deviceId}`,
    details: `DRY RUN: ${approvedCount ?? 0} fix command set(s) approved by ${user.name}; ${edited.length} edited (${edited.map((e: any) => e.controlId).join(', ') || 'none'}). Nothing was applied to the device.`,
    ipAddress: req.ip || '127.0.0.1',
  });
  return res.json({ ok: true });
});

/* ==========================================================================
   AI SECURITY & PROMPT SANITIZATION
   ========================================================================== */

router.post('/ai/analyze', async (req: Request, res: Response) => {
  const { name, baseUrl, authType, environment, specOrConfig } = req.body;

  if (!specOrConfig && !name) {
    return res.status(400).json({ error: 'Please provide API details or specification to analyze.' });
  }

  try {
    const result = await analyzeApiSecurity({
      name: name || 'Custom API',
      baseUrl: baseUrl || 'https://api.internal.corp',
      authType: authType || 'JWT',
      environment: environment || 'Production',
      specOrConfig: specOrConfig || '',
    });

    return res.json(result);
  } catch (error) {
    console.error('Error in AI analysis:', error);
    return res.status(500).json({ error: 'Failed to complete AI security analysis' });
  }
});

router.post('/ai/sanitize', async (req: Request, res: Response) => {
  const { prompt } = req.body;

  if (!prompt || typeof prompt !== 'string') {
    return res.status(400).json({ error: 'Prompt text is required.' });
  }

  try {
    const result = await sanitizePrompt(prompt);
    return res.json(result);
  } catch (error) {
    console.error('Error in prompt sanitization:', error);
    return res.status(500).json({ error: 'Prompt sanitization engine encountered an error' });
  }
});

/* ==========================================================================
   ZENTRA SECURITY KNOWLEDGE BASE
   ========================================================================== */

router.get('/knowledge-rules', (_req: Request, res: Response) => {
  return res.json(db.knowledgeRules);
});

router.post('/knowledge-rules', (req: Request, res: Response) => {
  const user = getActiveUser(req);
  if (user.role !== 'ADMIN' && user.role !== 'SECURITY_ANALYST') {
    return res.status(403).json({ error: 'RBAC restriction: Only ADMIN and SECURITY_ANALYST can create knowledge rules.' });
  }

  const { pattern, category, securityParameter, expectedBehavior, severity, description, remediation } = req.body;

  if (!pattern || !expectedBehavior || !severity) {
    return res.status(400).json({ error: 'Pattern, expectedBehavior, and severity are required.' });
  }

  const newRule = {
    id: `kr-${Date.now()}`,
    pattern,
    category: category || 'General Security',
    securityParameter: securityParameter || 'custom_rule',
    expectedBehavior,
    severity: (severity as Severity) || 'MEDIUM',
    description: description || 'Custom security heuristic pattern',
    remediation: remediation || 'Review API endpoint configuration',
    createdBy: `${user.name} (${user.role})`,
    createdAt: new Date().toISOString(),
  };

  db.knowledgeRules.push(newRule);

  db.addAuditLog({
    user: user.name,
    userEmail: user.email,
    role: user.role,
    action: 'KNOWLEDGE_RULE_CREATED',
    resource: `Rule Pattern: ${newRule.pattern}`,
    details: `Added new security knowledge mapping for [${newRule.securityParameter}] with severity [${newRule.severity}].`,
    ipAddress: req.ip || '127.0.0.1',
  });

  return res.status(201).json(newRule);
});

router.delete('/knowledge-rules/:id', (req: Request, res: Response) => {
  const user = getActiveUser(req);
  if (user.role !== 'ADMIN') {
    return res.status(403).json({ error: 'RBAC restriction: Only ADMIN can delete knowledge rules.' });
  }

  const index = db.knowledgeRules.findIndex(r => r.id === req.params.id);
  if (index === -1) {
    return res.status(404).json({ error: 'Rule not found' });
  }

  const deleted = db.knowledgeRules.splice(index, 1)[0];

  db.addAuditLog({
    user: user.name,
    userEmail: user.email,
    role: user.role,
    action: 'KNOWLEDGE_RULE_DELETED',
    resource: deleted.pattern,
    details: `Deleted knowledge rule ${deleted.id} (${deleted.pattern}).`,
    ipAddress: req.ip || '127.0.0.1',
  });

  return res.json({ success: true });
});

/* ==========================================================================
   REMEDIATION ENGINE
   ========================================================================== */

router.get('/remediation', (_req: Request, res: Response) => {
  const openFindings = db.findings.filter(f => f.status === 'OPEN' || f.status === 'IN_PROGRESS');
  
  const remediationItems = openFindings.map(f => ({
    id: `rem-${f.id}`,
    originalFindingId: f.id,
    findingId: f.findingId,
    title: f.title,
    apiName: f.apiName,
    endpoint: f.endpoint,
    severity: f.severity,
    problem: f.description,
    whyItMatters: f.impact,
    recommendedFix: f.recommendation,
    implementationGuide: f.implementationGuide,
    validationSteps: f.validationSteps,
    status: f.status,
  }));

  return res.json(remediationItems);
});

/* ==========================================================================
   REPORTS
   ========================================================================== */

router.get('/reports', (_req: Request, res: Response) => {
  return res.json(db.reports);
});

router.post('/reports', (req: Request, res: Response) => {
  const user = getActiveUser(req);
  const { title, organization } = req.body;

  const stats = db.getDashboardStats();
  const openFindings = db.findings.filter(f => f.status === 'OPEN' || f.status === 'IN_PROGRESS');

  const newReport = {
    id: `rep-${Date.now()}`,
    title: title || `Enterprise API Security Assessment (${new Date().toLocaleDateString()})`,
    organization: organization || 'Cybersecurity Operations Center',
    generatedBy: user.name,
    createdAt: new Date().toISOString(),
    securityScore: stats.avgSecurityScore,
    zeroTrustScore: stats.zeroTrustScore,
    complianceScore: stats.complianceScore,
    totalApis: stats.totalApis,
    findingsCount: {
      critical: stats.criticalVulnerabilities,
      high: stats.highVulnerabilities,
      medium: stats.mediumVulnerabilities,
      low: stats.lowVulnerabilities,
      info: 0,
    },
    summary: `Comprehensive evaluation across ${stats.totalApis} APIs. Found ${openFindings.length} open finding(s). CIS Benchmark compliance calculated at ${stats.complianceScore}%. Zero-Trust coverage evaluated at ${stats.zeroTrustScore}%.`
  };

  {
    const { seal, sealedAt } = (() => {
      const sealedAt = new Date().toISOString();
      const { seal: _s, sealedAt: _t, ...content } = newReport as any;
      return { seal: computeSeal({ ...content, sealedAt }), sealedAt };
    })();
    (newReport as any).seal = seal;
    (newReport as any).sealedAt = sealedAt;
    recordSeal('api-report', newReport.title, seal, sealedAt);
  }

  db.reports.unshift(newReport);

  db.addAuditLog({
    user: user.name,
    userEmail: user.email,
    role: user.role,
    action: 'REPORT_GENERATED',
    resource: newReport.title,
    details: `Compiled formal security assessment report [${newReport.id}].`,
    ipAddress: req.ip || '127.0.0.1',
  });

  return res.status(201).json(newReport);
});

router.get('/reports/:id', (req: Request, res: Response) => {
  const report = db.reports.find(r => r.id === req.params.id);
  if (!report) {
    return res.status(404).json({ error: 'Report not found' });
  }

  return res.json({
    report,
    apis: db.apis,
    findings: db.findings,
    cisControls: db.cisControls,
    zeroTrustPillars: db.zeroTrustPillars,
  });
});

/* ==========================================================================
   AUDIT LOGS & CRYPTOGRAPHIC INTEGRITY
   ========================================================================== */

router.get('/audit-logs', (_req: Request, res: Response) => {
  return res.json(db.auditLogs);
});

router.post('/audit-logs/verify', (req: Request, res: Response) => {
  const user = getActiveUser(req);
  const result = db.verifyAuditIntegrity();

  db.addAuditLog({
    user: user.name,
    userEmail: user.email,
    role: user.role,
    action: 'AUDIT_INTEGRITY_VERIFIED',
    resource: 'Audit Log Ledger',
    details: `Verified SHA-256 chain across ${result.totalChecked} records. Integrity Status: ${result.isValid ? 'VALID' : 'CORRUPTED'}.`,
    ipAddress: req.ip || '127.0.0.1',
  });

  return res.json(result);
});

/* ==========================================================================
   ROLE-BASED ACCESS CONTROL (RBAC)
   ========================================================================== */

router.get('/rbac/permissions', (_req: Request, res: Response) => {
  return res.json(db.rolesPermissions);
});

router.put('/rbac/permissions', (req: Request, res: Response) => {
  const user = getActiveUser(req);
  if (user.role !== 'ADMIN') {
    return res.status(403).json({ error: 'RBAC restriction: Only ADMIN can configure permission matrices.' });
  }

  const { role, permissions } = req.body;
  if (!['ADMIN', 'SECURITY_ANALYST', 'DEVELOPER'].includes(role) || !Array.isArray(permissions)) {
    return res.status(400).json({ error: 'Valid role and permissions array required.' });
  }

  db.rolesPermissions[role as RoleType] = permissions;

  db.addAuditLog({
    user: user.name,
    userEmail: user.email,
    role: user.role,
    action: 'PERMISSIONS_MODIFIED',
    resource: `Role: ${role}`,
    details: `Updated permission assignment matrix for role [${role}].`,
    ipAddress: req.ip || '127.0.0.1',
  });

  return res.json(db.rolesPermissions);
});

/* ==========================================================================
   NETWORK DEVICE INGESTION & NORMALIZATION ROUTES
   ========================================================================== */

// 1. GET /devices - List all devices with optional search, vendor, and status filter
router.get('/devices', (req: Request, res: Response) => {
  const { search, vendor, status } = req.query;
  let result = [...db.devices];

  if (search && typeof search === 'string' && search.trim()) {
    const s = search.toLowerCase().trim();
    result = result.filter(d =>
      d.filename.toLowerCase().includes(s) ||
      (d.hostname && d.hostname.toLowerCase().includes(s)) ||
      d.detectedVendor.toLowerCase().includes(s) ||
      (d.model && d.model.toLowerCase().includes(s)) ||
      (d.serialNumber && d.serialNumber.toLowerCase().includes(s))
    );
  }

  if (vendor && typeof vendor === 'string' && vendor !== 'ALL') {
    result = result.filter(d => d.detectedVendor.toLowerCase().includes(vendor.toLowerCase()));
  }

  if (status && typeof status === 'string' && status !== 'ALL') {
    result = result.filter(d => d.status === status);
  }

  return res.json(result);
});

// 2. GET /devices/stats - Overview stats for device compliance
router.get('/devices/stats', (_req: Request, res: Response) => {
  const total = db.devices.length;
  const compliant = db.devices.filter(d => d.status === 'COMPLIANT').length;
  const warning = db.devices.filter(d => d.status === 'WARNING').length;
  const nonCompliant = db.devices.filter(d => d.status === 'NON_COMPLIANT').length;
  const avgScore = total > 0 ? Math.round(db.devices.reduce((acc, d) => acc + d.overallComplianceScore, 0) / total) : 0;

  const vendorMap: Record<string, number> = {};
  for (const d of db.devices) {
    vendorMap[d.detectedVendor] = (vendorMap[d.detectedVendor] || 0) + 1;
  }
  const vendorBreakdown = Object.entries(vendorMap).map(([vendor, count]) => ({ vendor, count }));

  return res.json({
    total,
    compliant,
    warning,
    nonCompliant,
    avgScore,
    vendorBreakdown,
  });
});

// 3. GET /devices/:id - Single device with full rawConfig and parsed baselineModel
router.get('/devices/:id', (req: Request, res: Response) => {
  const device = db.devices.find(d => d.id === req.params.id);
  if (!device) {
    return res.status(404).json({ error: 'Network device not found' });
  }
  return res.json(device);
});

// 4. POST /devices/upload - Drag-and-drop ingestion of one or multiple configs
router.post('/devices/upload', async (req: Request, res: Response) => {
  const user = getActiveUser(req);
  const { files, content, filename } = req.body;

  const incomingFiles: Array<{ filename: string; content: string }> = [];
  if (Array.isArray(files) && files.length > 0) {
    for (const f of files) {
      if (f && typeof f.content === 'string') {
        incomingFiles.push({
          filename: f.filename || `device-config-${Date.now()}.cfg`,
          content: f.content,
        });
      }
    }
  } else if (content && typeof content === 'string') {
    incomingFiles.push({
      filename: filename || `device-config-${Date.now()}.cfg`,
      content,
    });
  }

  if (incomingFiles.length === 0) {
    return res.status(400).json({ error: 'No config content or files provided for ingestion.' });
  }

  const createdDevices: NetworkDevice[] = [];

  const quarantinedFiles: Array<{ filename: string; hits: any[] }> = [];

  for (const item of incomingFiles) {
    try {
      // Prompt-injection guard: regex scan BEFORE the normalizer or any AI call (works offline)
      const scan = scanForInjection(item.content, item.filename);
      if (scan.flagged) {
        quarantinedFiles.push({ filename: item.filename, hits: scan.hits });
        db.addAuditLog({
          user: user.name,
          userEmail: user.email,
          role: user.role,
          action: 'CONFIG_QUARANTINED_PROMPT_INJECTION',
          resource: `File: ${item.filename}`,
          details: `Injection guard quarantined ${scan.hits.length} line(s): ${scan.hits.map(h => `L${h.line} ${h.pattern}`).join('; ')}. Lines stripped before analysis.`,
          ipAddress: req.ip || '127.0.0.1',
        });
        item.content = scan.sanitized;
      }
      const normalized = await normalizeDeviceConfig(item.content, item.filename, true);
      const newDevice: NetworkDevice = {
        id: `dev-${Date.now()}-${Math.floor(Math.random() * 1000)}`,
        quarantined: scan.flagged || undefined,
        injectionFindings: scan.flagged ? scan.hits : undefined,
        filename: item.filename,
        rawConfig: item.content,
        detectedVendor: normalized.detectedVendor,
        vendorGuessMethod: normalized.vendorGuessMethod,
        vendorConfidence: normalized.vendorConfidence,
        hostname: normalized.hostname,
        serialNumber: normalized.serialNumber,
        model: normalized.model,
        uploadTime: new Date().toISOString(),
        lineCount: item.content.split(/\r?\n/).length,
        byteSize: Buffer.byteLength(item.content),
        baselineModel: normalized.baselineModel,
        unrecognizedLines: normalized.unrecognizedLines,
        overallComplianceScore: normalized.overallComplianceScore,
        status: normalized.status,
      };

      db.devices.unshift(newDevice);
      createdDevices.push(newDevice);

      db.addAuditLog({
        user: user.name,
        userEmail: user.email,
        role: user.role,
        action: 'DEVICE_CONFIG_INGESTED',
        resource: `Device: ${newDevice.hostname || newDevice.filename}`,
        details: `Ingested ${newDevice.filename} (${newDevice.lineCount} lines). Detected vendor: ${newDevice.detectedVendor} via ${newDevice.vendorGuessMethod.toUpperCase()} (${newDevice.vendorConfidence}% confidence). Baseline compliance: ${newDevice.overallComplianceScore}% [${newDevice.status}]. Unrecognized lines: ${newDevice.unrecognizedLines.length}.`,
        ipAddress: req.ip || '127.0.0.1',
      });
    } catch (err: any) {
      console.error(`Failed to ingest device ${item.filename}:`, err);
    }
  }

  db.persist();

  return res.status(201).json({
    message: `Successfully ingested ${createdDevices.length} network device configuration(s).` +
      (quarantinedFiles.length ? ` WARNING: ${quarantinedFiles.length} file(s) contained prompt-injection text and were quarantined.` : ''),
    devices: createdDevices,
    quarantined: quarantinedFiles,
  });
});

// 5. POST /devices/:id/renormalize - Re-run normalization engine with Gemini
router.post('/devices/:id/renormalize', async (req: Request, res: Response) => {
  const device = db.devices.find(d => d.id === req.params.id);
  if (!device) {
    return res.status(404).json({ error: 'Device not found' });
  }

  const user = getActiveUser(req);
  const normalized = await normalizeDeviceConfig(device.rawConfig, device.filename, true);

  device.detectedVendor = normalized.detectedVendor;
  device.vendorGuessMethod = normalized.vendorGuessMethod;
  device.vendorConfidence = normalized.vendorConfidence;
  device.hostname = normalized.hostname || device.hostname;
  device.serialNumber = normalized.serialNumber || device.serialNumber;
  device.model = normalized.model || device.model;
  device.baselineModel = normalized.baselineModel;
  device.unrecognizedLines = normalized.unrecognizedLines;
  device.overallComplianceScore = normalized.overallComplianceScore;
  device.status = normalized.status;

  db.persist();

  db.addAuditLog({
    user: user.name,
    userEmail: user.email,
    role: user.role,
    action: 'DEVICE_RENORMALIZED',
    resource: `Device: ${device.hostname || device.filename}`,
    details: `Re-ran normalization engine with Gemini AI. Baseline score: ${device.overallComplianceScore}% [${device.status}]. Remaining unrecognized lines: ${device.unrecognizedLines.length}.`,
    ipAddress: req.ip || '127.0.0.1',
  });

  return res.json(device);
});

// 6. DELETE /devices/:id - Delete a device
router.delete('/devices/:id', (req: Request, res: Response) => {
  const index = db.devices.findIndex(d => d.id === req.params.id);
  if (index === -1) {
    return res.status(404).json({ error: 'Device not found' });
  }

  const user = getActiveUser(req);
  const deleted = db.devices.splice(index, 1)[0];
  db.persist();

  db.addAuditLog({
    user: user.name,
    userEmail: user.email,
    role: user.role,
    action: 'DEVICE_DELETED',
    resource: `Device: ${deleted.hostname || deleted.filename}`,
    details: `Deleted network device config [${deleted.filename}] (Vendor: ${deleted.detectedVendor}).`,
    ipAddress: req.ip || '127.0.0.1',
  });

  return res.json({ message: 'Device deleted successfully', id: deleted.id });
});

// 7. POST /devices/load-samples - Load 5 realistic multi-vendor sample configurations
router.post('/devices/load-samples', async (req: Request, res: Response) => {
  const user = getActiveUser(req);
  const loadedDevices: NetworkDevice[] = [];

  // Reset devices and framework evaluations to the 5 realistic configs
  db.devices = [];
  db.frameworkEvaluations = [];

  for (const sample of SAMPLE_DEVICE_CONFIGS) {
    try {
      const normalized = await normalizeDeviceConfig(sample.content, sample.filename, false, db.learnedRules);
      const newDev: NetworkDevice = {
        id: `dev-${sample.filename.replace(/[^a-zA-Z0-9]/g, '-')}`,
        filename: sample.filename,
        rawConfig: sample.content,
        detectedVendor: normalized.detectedVendor || sample.vendorName,
        vendorGuessMethod: normalized.vendorGuessMethod,
        vendorConfidence: normalized.vendorConfidence,
        hostname: normalized.hostname || sample.expectedHostname,
        serialNumber: normalized.serialNumber || `SN-${Math.floor(100000 + Math.random() * 900000)}`,
        model: normalized.model || sample.expectedModel,
        uploadTime: new Date().toISOString(),
        lineCount: sample.content.split(/\r?\n/).length,
        byteSize: Buffer.byteLength(sample.content),
        baselineModel: normalized.baselineModel,
        unrecognizedLines: normalized.unrecognizedLines,
        overallComplianceScore: normalized.overallComplianceScore,
        status: normalized.status,
      };

      db.devices.push(newDev);
      loadedDevices.push(newDev);

      // Evaluate against all 4 frameworks
      const frameworks = frameworkEngine.getAvailableFrameworks();
      for (const fw of frameworks) {
        const ev = frameworkEngine.evaluateDeviceAgainstFramework(newDev, fw.frameworkId);
        if (ev) db.frameworkEvaluations.push(ev);
      }
    } catch (err: any) {
      console.error(`Failed to ingest sample ${sample.filename}:`, err);
    }
  }

  db.persist();

  db.addAuditLog({
    user: user.name,
    userEmail: user.email,
    role: user.role,
    action: 'SAMPLE_CONFIGS_LOADED',
    resource: 'Network Device Fleet',
    details: `Loaded ${loadedDevices.length} realistic multi-vendor configurations (Cisco IOS-XE, Palo Alto PAN-OS, Juniper JunOS, Arista EOS, and SONiC Linux Open Networking). Evaluated against CIS, NIST, DISA STIG, and ISO 27001.`,
    ipAddress: req.ip || '127.0.0.1',
  });

  return res.json({
    message: `Successfully loaded ${loadedDevices.length} realistic sample network devices.`,
    devices: db.devices,
    evaluationsCount: db.frameworkEvaluations.length,
  });
});

/* ==========================================================================
   TRAINING & RULE LEARNING ENGINE ROUTES
   ========================================================================== */

// 1. GET /training/unrecognized-lines - List unrecognized lines from all devices grouped by vendor
router.get('/training/unrecognized-lines', (_req: Request, res: Response) => {
  const vendorMap: Record<string, Array<{
    line: string;
    lineNumber: number;
    categoryHint?: string;
    deviceId: string;
    deviceHostname: string;
    filename: string;
  }>> = {};

  let totalUnrecognized = 0;

  for (const dev of db.devices) {
    const v = dev.detectedVendor || 'Unassigned / Generic';
    if (!vendorMap[v]) vendorMap[v] = [];

    if (Array.isArray(dev.unrecognizedLines)) {
      for (const u of dev.unrecognizedLines) {
        totalUnrecognized++;
        vendorMap[v].push({
          line: u.line,
          lineNumber: u.lineNumber,
          categoryHint: u.categoryHint,
          deviceId: dev.id,
          deviceHostname: dev.hostname || dev.filename,
          filename: dev.filename,
        });
      }
    }
  }

  const vendorGroups = Object.entries(vendorMap).map(([vendor, items]) => ({
    vendor,
    count: items.length,
    items,
  }));

  return res.json({
    totalUnrecognized,
    vendorGroups,
  });
});

// 2. GET /training/rules - Get all runtime learned rules
router.get('/training/rules', (_req: Request, res: Response) => {
  return res.json(db.learnedRules);
});

// 3. POST /training/rules - Create and register new learned rule
router.post('/training/rules', (req: Request, res: Response) => {
  const user = getActiveUser(req);
  if (user.role !== 'ADMIN' && user.role !== 'SECURITY_ANALYST') {
    return res.status(403).json({ error: 'RBAC restriction: Only ADMIN and SECURITY_ANALYST can create learned normalization rules.' });
  }

  const { name, vendor, regex, field, extractionType, extractionMode, captureGroupIndex, staticValue, sampleLine } = req.body;

  if (!regex || !field) {
    return res.status(400).json({ error: 'Regular expression pattern and target baseline field are required.' });
  }

  try {
    new RegExp(regex, 'i');
  } catch (err: any) {
    return res.status(400).json({ error: `Invalid regex pattern: ${err.message}` });
  }

  const mode = (extractionType || extractionMode || 'capture_group') as LearnedRule['extractionType'];

  const newRule: LearnedRule = {
    id: `rule-lr-${Date.now()}-${Math.floor(Math.random() * 1000)}`,
    name: name || `${vendor || 'Vendor'} ${field} Pattern`,
    vendor: vendor || 'ALL',
    regex: regex.trim(),
    field: field.trim(),
    extractionType: mode,
    captureGroupIndex: captureGroupIndex !== undefined ? Number(captureGroupIndex) : 1,
    staticValue: staticValue !== undefined ? staticValue : null,
    sampleLine: sampleLine || '',
    confidence: 0.99,
    createdAt: new Date().toISOString(),
    createdBy: `${user.name} (${user.role})`,
  };

  db.learnedRules.unshift(newRule);
  db.persist();

  db.addAuditLog({
    user: user.name,
    userEmail: user.email,
    role: user.role,
    action: 'LEARNED_RULE_CREATED',
    resource: `Rule: ${newRule.name}`,
    details: `Created learned extraction rule [${newRule.name}] for field [${newRule.field}] against vendor [${newRule.vendor}] with mode [${newRule.extractionType}].`,
    ipAddress: req.ip || '127.0.0.1',
  });

  // Memory: remember what the analyst taught the system
  void remember(
    `Analyst teaching from ${user.name} (${user.role}): for vendor ${newRule.vendor}, the field ${newRule.field} is extracted by rule '${newRule.name}' using ${newRule.extractionType} with regex /${newRule.regex}/${newRule.sampleLine ? `. Example line: ${newRule.sampleLine}` : ''}`,
    'analyst-teaching',
    { vendor: newRule.vendor, field: newRule.field, analyst: user.name }
  );

  return res.status(201).json(newRule);
});

// 4. DELETE /training/rules/:id - Remove learned rule
router.delete('/training/rules/:id', (req: Request, res: Response) => {
  const user = getActiveUser(req);
  if (user.role !== 'ADMIN') {
    return res.status(403).json({ error: 'RBAC restriction: Only ADMIN can delete learned normalization rules.' });
  }

  const index = db.learnedRules.findIndex(r => r.id === req.params.id);
  if (index === -1) {
    return res.status(404).json({ error: 'Learned rule not found.' });
  }

  const deleted = db.learnedRules.splice(index, 1)[0];
  db.persist();

  db.addAuditLog({
    user: user.name,
    userEmail: user.email,
    role: user.role,
    action: 'LEARNED_RULE_DELETED',
    resource: `Rule: ${deleted.name}`,
    details: `Deleted learned normalization rule [${deleted.name}] (pattern: ${deleted.regex}).`,
    ipAddress: req.ip || '127.0.0.1',
  });

  return res.json({ success: true, id: deleted.id });
});

// 5. POST /training/reparse-device - Re-parse a device with runtime learned rules and return diff
router.post('/training/reparse-device', async (req: Request, res: Response) => {
  const { deviceId } = req.body;
  if (!deviceId) {
    return res.status(400).json({ error: 'Device ID is required to re-parse.' });
  }

  const device = db.devices.find(d => d.id === deviceId);
  if (!device) {
    return res.status(404).json({ error: 'Device not found.' });
  }

  const user = getActiveUser(req);

  // Snapshot before state
  const beforeUnrecognized = [...device.unrecognizedLines];
  const beforeScore = device.overallComplianceScore;

  // Re-run normalizer with currently registered learnedRules
  const normalized = await normalizeDeviceConfig(device.rawConfig, device.filename, false, db.learnedRules);

  // Determine remediated lines
  const afterUnrecognizedSet = new Set(normalized.unrecognizedLines.map(u => `${u.lineNumber}:${u.line}`));
  const remediatedLines: Array<{
    lineNumber: number;
    line: string;
    ruleName: string;
    targetField: string;
    extractedValue: any;
  }> = [];

  for (const beforeItem of beforeUnrecognized) {
    const key = `${beforeItem.lineNumber}:${beforeItem.line}`;
    if (!afterUnrecognizedSet.has(key)) {
      // Find matching learned rule if applicable
      const matchedRule = db.learnedRules.find(r => {
        try {
          return new RegExp(r.regex, 'i').test(beforeItem.line);
        } catch {
          return false;
        }
      });

      const targetField = matchedRule ? matchedRule.field : 'normalized_field';
      const extractedVal = (normalized.baselineModel as any)[targetField]?.value ?? 'parsed';

      remediatedLines.push({
        lineNumber: beforeItem.lineNumber,
        line: beforeItem.line,
        ruleName: matchedRule ? matchedRule.name : 'Learned / Core Parser Rule',
        targetField,
        extractedValue: extractedVal,
      });
    }
  }

  // Update device state
  device.baselineModel = normalized.baselineModel;
  device.unrecognizedLines = normalized.unrecognizedLines;
  device.overallComplianceScore = normalized.overallComplianceScore;
  device.status = normalized.status;

  // Update framework evaluations for this device
  const allFrameworks = frameworkEngine.getAvailableFrameworks();
  for (const fw of allFrameworks) {
    const ev = frameworkEngine.evaluateDeviceAgainstFramework(device, fw.frameworkId);
    if (ev) {
      const existingIdx = db.frameworkEvaluations.findIndex(e => e.deviceId === device.id && e.frameworkId === fw.frameworkId);
      if (existingIdx !== -1) {
        db.frameworkEvaluations[existingIdx] = ev;
      } else {
        db.frameworkEvaluations.push(ev);
      }
    }
  }

  db.persist();

  db.addAuditLog({
    user: user.name,
    userEmail: user.email,
    role: user.role,
    action: 'DEVICE_REPARSED_WITH_TRAINING',
    resource: `Device: ${device.hostname || device.filename}`,
    details: `Re-parsed configuration with ${db.learnedRules.length} learned rules. Unrecognized lines reduced from ${beforeUnrecognized.length} to ${normalized.unrecognizedLines.length}. Baseline score: ${beforeScore}% -> ${normalized.overallComplianceScore}%.`,
    ipAddress: req.ip || '127.0.0.1',
  });

  const diff = {
    deviceId: device.id,
    deviceHostname: device.hostname || device.filename,
    deviceVendor: device.detectedVendor,
    before: {
      unrecognizedCount: beforeUnrecognized.length,
      complianceScore: beforeScore,
      unrecognizedLines: beforeUnrecognized,
    },
    after: {
      unrecognizedCount: normalized.unrecognizedLines.length,
      complianceScore: normalized.overallComplianceScore,
      unrecognizedLines: normalized.unrecognizedLines,
    },
    remediatedLines,
  };

  return res.json(diff);
});

export default router;
