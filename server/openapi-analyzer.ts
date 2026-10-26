import YAML from 'yaml';
import type { SecurityFinding, Severity } from './db.ts';

export interface ParsedEndpointInfo {
  path: string;
  method: string;
  summary?: string;
  operationId?: string;
  security: string[];
  parametersCount: number;
  hasRequestBody: boolean;
  requestBodyTypes: string[];
  parameters: {
    name: string;
    in: string;
    required: boolean;
    type?: string;
    hasConstraints: boolean;
    constraints?: string[];
  }[];
  responses: {
    status: string;
    description?: string;
    hasSchema: boolean;
    hasRateLimitHeaders: boolean;
  }[];
}

export interface ParsedSecuritySchemeInfo {
  name: string;
  type: string;
  scheme?: string;
  in?: string;
  bearerFormat?: string;
  flows?: string[];
  scopes?: string[];
}

export interface ParsedOpenApiDocument {
  specVersion: string; // e.g. "3.0.0", "3.1.0", "2.0"
  title: string;
  version: string;
  description?: string;
  baseUrl: string;
  allBaseUrls: string[];
  globalSecurity: string[];
  securitySchemes: ParsedSecuritySchemeInfo[];
  endpoints: ParsedEndpointInfo[];
  rawObject: any;
}

export interface SpecAnalysisResult {
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
    securitySchemes: ParsedSecuritySchemeInfo[];
    endpoints: ParsedEndpointInfo[];
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
}

/**
 * Parses user-provided OpenAPI or Swagger documents in JSON or YAML format.
 */
export function parseOpenApiDocument(rawText: string): ParsedOpenApiDocument {
  if (!rawText || typeof rawText !== 'string' || !rawText.trim()) {
    throw new Error('Specification document is empty.');
  }

  let doc: any;

  // Try JSON first, fallback to YAML
  const trimmed = rawText.trim();
  if (trimmed.startsWith('{')) {
    try {
      doc = JSON.parse(trimmed);
    } catch (jsonErr: any) {
      try {
        doc = YAML.parse(trimmed);
      } catch (yamlErr: any) {
        throw new Error(`Failed to parse specification: ${jsonErr.message || yamlErr.message}`);
      }
    }
  } else {
    try {
      doc = YAML.parse(trimmed);
    } catch (yamlErr: any) {
      try {
        doc = JSON.parse(trimmed);
      } catch (jsonErr: any) {
        throw new Error(`Failed to parse specification as YAML or JSON: ${yamlErr.message}`);
      }
    }
  }

  if (!doc || typeof doc !== 'object') {
    throw new Error('Parsed document is not a valid JSON/YAML object.');
  }

  const isOpenApi3 = Boolean(doc.openapi);
  const isSwagger2 = Boolean(doc.swagger);

  if (!isOpenApi3 && !isSwagger2) {
    throw new Error('Document does not appear to be an OpenAPI 3.x (missing "openapi") or Swagger 2.0 (missing "swagger") document.');
  }

  const specVersion = doc.openapi || doc.swagger || 'Unknown';
  const title = doc.info?.title || 'Untitled API Specification';
  const version = doc.info?.version || '1.0.0';
  const description = doc.info?.description || '';

  // Extract Base URLs
  const allBaseUrls: string[] = [];
  if (isOpenApi3 && Array.isArray(doc.servers) && doc.servers.length > 0) {
    for (const s of doc.servers) {
      if (s?.url) allBaseUrls.push(String(s.url));
    }
  } else if (isSwagger2) {
    const host = doc.host || 'localhost';
    const basePath = doc.basePath || '';
    const schemes = Array.isArray(doc.schemes) && doc.schemes.length > 0 ? doc.schemes : ['https'];
    for (const scheme of schemes) {
      allBaseUrls.push(`${scheme}://${host}${basePath}`);
    }
  }

  const baseUrl = allBaseUrls.length > 0 ? allBaseUrls[0] : 'https://api.internal.local';

  // Global Security
  const globalSecurity: string[] = [];
  if (Array.isArray(doc.security)) {
    for (const secItem of doc.security) {
      if (secItem && typeof secItem === 'object') {
        globalSecurity.push(...Object.keys(secItem));
      }
    }
  }

  // Security Schemes
  const securitySchemes: ParsedSecuritySchemeInfo[] = [];
  if (isOpenApi3 && doc.components?.securitySchemes) {
    for (const [name, schemeObj] of Object.entries<any>(doc.components.securitySchemes)) {
      if (!schemeObj) continue;
      const flows = schemeObj.flows ? Object.keys(schemeObj.flows) : undefined;
      const scopes: string[] = [];
      if (schemeObj.flows) {
        for (const flow of Object.values<any>(schemeObj.flows)) {
          if (flow?.scopes) {
            scopes.push(...Object.keys(flow.scopes));
          }
        }
      }
      securitySchemes.push({
        name,
        type: schemeObj.type || 'unknown',
        scheme: schemeObj.scheme,
        in: schemeObj.in,
        bearerFormat: schemeObj.bearerFormat,
        flows,
        scopes: scopes.length > 0 ? Array.from(new Set(scopes)) : undefined,
      });
    }
  } else if (isSwagger2 && doc.securityDefinitions) {
    for (const [name, schemeObj] of Object.entries<any>(doc.securityDefinitions)) {
      if (!schemeObj) continue;
      const scopes = schemeObj.scopes ? Object.keys(schemeObj.scopes) : undefined;
      securitySchemes.push({
        name,
        type: schemeObj.type || 'unknown',
        in: schemeObj.in,
        flows: schemeObj.flow ? [schemeObj.flow] : undefined,
        scopes,
      });
    }
  }

  // Endpoints & Operations
  const endpoints: ParsedEndpointInfo[] = [];
  const httpMethods = ['get', 'post', 'put', 'delete', 'patch', 'options', 'head'];

  if (doc.paths && typeof doc.paths === 'object') {
    for (const [pathStr, pathItem] of Object.entries<any>(doc.paths)) {
      if (!pathItem || typeof pathItem !== 'object') continue;

      const pathLevelParams = Array.isArray(pathItem.parameters) ? pathItem.parameters : [];

      for (const method of httpMethods) {
        const op = pathItem[method];
        if (!op || typeof op !== 'object') continue;

        // Collect parameters (path-level + operation-level)
        const opLevelParams = Array.isArray(op.parameters) ? op.parameters : [];
        const mergedParams = [...pathLevelParams, ...opLevelParams];

        const parsedParams = mergedParams.map((p: any) => {
          const constraints: string[] = [];
          const schema = p.schema || p;

          if (schema.pattern) constraints.push(`pattern: ${schema.pattern}`);
          if (schema.minLength !== undefined) constraints.push(`minLength: ${schema.minLength}`);
          if (schema.maxLength !== undefined) constraints.push(`maxLength: ${schema.maxLength}`);
          if (schema.minimum !== undefined) constraints.push(`min: ${schema.minimum}`);
          if (schema.maximum !== undefined) constraints.push(`max: ${schema.maximum}`);
          if (Array.isArray(schema.enum)) constraints.push(`enum: [${schema.enum.join(', ')}]`);
          if (schema.maxItems !== undefined) constraints.push(`maxItems: ${schema.maxItems}`);

          return {
            name: p.name || 'unnamed',
            in: p.in || 'query',
            required: Boolean(p.required),
            type: schema.type || (schema.schema ? schema.schema.type : undefined),
            hasConstraints: constraints.length > 0,
            constraints: constraints.length > 0 ? constraints : undefined,
          };
        });

        // Request Body
        let hasRequestBody = false;
        const requestBodyTypes: string[] = [];

        if (isOpenApi3 && op.requestBody?.content) {
          hasRequestBody = true;
          requestBodyTypes.push(...Object.keys(op.requestBody.content));
        } else if (isSwagger2) {
          const bodyParam = mergedParams.find((p: any) => p.in === 'body');
          if (bodyParam) {
            hasRequestBody = true;
            if (Array.isArray(doc.consumes)) {
              requestBodyTypes.push(...doc.consumes);
            } else if (Array.isArray(op.consumes)) {
              requestBodyTypes.push(...op.consumes);
            } else {
              requestBodyTypes.push('application/json');
            }
          }
        }

        // Operation Security
        let opSecurity: string[] = [];
        if (Array.isArray(op.security)) {
          for (const s of op.security) {
            if (s && typeof s === 'object') {
              opSecurity.push(...Object.keys(s));
            }
          }
        } else {
          // Inherits global
          opSecurity = [...globalSecurity];
        }

        // Responses
        const responses: {
          status: string;
          description?: string;
          hasSchema: boolean;
          hasRateLimitHeaders: boolean;
        }[] = [];

        if (op.responses && typeof op.responses === 'object') {
          for (const [code, respObj] of Object.entries<any>(op.responses)) {
            if (!respObj) continue;
            const hasSchema = Boolean(
              respObj.schema ||
              respObj.content?.['application/json']?.schema ||
              respObj.content && Object.keys(respObj.content).length > 0
            );

            const headers = respObj.headers ? Object.keys(respObj.headers).map(h => h.toLowerCase()) : [];
            const hasRateLimitHeaders = headers.some(h =>
              h.includes('ratelimit') || h.includes('retry-after') || h.includes('rate-limit')
            );

            responses.push({
              status: code,
              description: respObj.description,
              hasSchema,
              hasRateLimitHeaders,
            });
          }
        }

        endpoints.push({
          path: pathStr,
          method: method.toUpperCase(),
          summary: op.summary,
          operationId: op.operationId,
          security: opSecurity,
          parametersCount: parsedParams.length,
          hasRequestBody,
          requestBodyTypes,
          parameters: parsedParams,
          responses,
        });
      }
    }
  }

  return {
    specVersion,
    title,
    version,
    description,
    baseUrl,
    allBaseUrls,
    globalSecurity,
    securitySchemes,
    endpoints,
    rawObject: doc,
  };
}

/**
 * Performs static security analysis on the parsed OpenAPI document.
 * Strictly adheres to evidence in the document; does NOT claim a vulnerability if evidence is lacking.
 */
export function analyzeParsedOpenApi(parsed: ParsedOpenApiDocument, apiTargetId?: string): SpecAnalysisResult {
  const findings: SecurityFinding[] = [];
  const doc = parsed.rawObject;
  const targetId = apiTargetId || `spec-${Date.now()}`;
  const apiName = parsed.title || 'Imported API Spec';

  const now = new Date().toISOString();

  // Helper to add finding
  const addFinding = (params: {
    title: string;
    endpoint: string;
    method: string;
    category: SecurityFinding['category'];
    severity: Severity;
    description: string;
    evidence: string;
    impact: string;
    recommendation: string;
    implementationGuide: string;
    validationSteps: string;
  }) => {
    findings.push({
      id: `fnd-spec-${findings.length + 1}-${Date.now().toString(36)}`,
      findingId: `ZEN-F-${Math.floor(2000 + Math.random() * 8000)}`,
      title: params.title,
      apiId: targetId,
      apiName,
      endpoint: params.endpoint,
      method: params.method,
      category: params.category,
      severity: params.severity,
      status: 'OPEN',
      description: params.description,
      evidence: params.evidence,
      impact: params.impact,
      recommendation: params.recommendation,
      implementationGuide: params.implementationGuide,
      validationSteps: params.validationSteps,
      createdAt: now,
      updatedAt: now,
    });
  };

  // =========================================================================
  // 1. Insecure HTTP URLs
  // =========================================================================
  const insecureUrls = parsed.allBaseUrls.filter(u => u.startsWith('http://'));
  if (insecureUrls.length > 0) {
    addFinding({
      title: 'Insecure Cleartext Transport (Plain HTTP Server URL)',
      endpoint: '/*',
      method: 'ALL',
      category: 'TLS/Crypto',
      severity: 'CRITICAL',
      description: 'The OpenAPI specification explicitly defines one or more base server URLs using unencrypted plain HTTP transport.',
      evidence: `Insecure server URL(s) detected in specification: ${insecureUrls.join(', ')}`,
      impact: 'All traffic sent to this server is transmitted in cleartext, exposing authentication headers, tokens, and payloads to network eavesdropping and tampering.',
      recommendation: 'Update server definitions in the specification to use HTTPS with TLS 1.3 encryption.',
      implementationGuide: 'In OpenAPI specification, update servers:\nservers:\n  - url: "https://api.yourdomain.com/v1"\n    description: "Production encrypted gateway"',
      validationSteps: 'Verify all servers entries start with "https://" and verify load balancer terminates TLS with valid certificates.',
    });
  }

  // =========================================================================
  // 2. Weak TLS Configuration when represented in the specification
  // =========================================================================
  // Check if specification contains explicit TLS version configuration in custom extensions
  const tlsConfigStr = JSON.stringify({
    tls: doc['x-tls'] || doc['x-tls-version'] || doc['x-ssl'] || doc['x-security']?.tls,
    servers: doc.servers,
  }).toLowerCase();

  if (
    tlsConfigStr.includes('tls 1.0') ||
    tlsConfigStr.includes('tlsv1.0') ||
    tlsConfigStr.includes('tls 1.1') ||
    tlsConfigStr.includes('tlsv1.1') ||
    tlsConfigStr.includes('sslv3')
  ) {
    addFinding({
      title: 'Weak Transport Layer Security (TLS 1.0/1.1 or SSLv3) Represented',
      endpoint: '/*',
      method: 'ALL',
      category: 'TLS/Crypto',
      severity: 'HIGH',
      description: 'The specification or security metadata explicitly declares support for deprecated and vulnerable cryptographic protocols (TLS 1.0, TLS 1.1, or SSLv3).',
      evidence: `Found deprecated protocol declaration in specification security metadata: ${tlsConfigStr.substring(0, 140)}...`,
      impact: 'Vulnerable to BEAST, POODLE, and downgrade cipher attacks. Modern browsers and security standards (PCI-DSS 4.0, NIST SP 800-52) mandate TLS 1.2 minimum and prefer TLS 1.3.',
      recommendation: 'Configure TLS minimum protocol version to TLS 1.2 or TLS 1.3 and disable legacy ciphers.',
      implementationGuide: 'In API Gateway/Nginx configuration:\nssl_protocols TLSv1.2 TLSv1.3;\nssl_ciphers HIGH:!aNULL:!MD5;',
      validationSteps: 'Run testssl.sh or SSL Labs scanner against domain to verify TLS 1.0 and 1.1 handshakes are rejected.',
    });
  }

  // =========================================================================
  // 3. Missing Security Schemes
  // =========================================================================
  if (parsed.securitySchemes.length === 0) {
    addFinding({
      title: 'Missing Security Schemes in Specification',
      endpoint: '/*',
      method: 'ALL',
      category: 'Authentication',
      severity: 'HIGH',
      description: 'The API specification defines zero security schemes in components.securitySchemes (OpenAPI 3) or securityDefinitions (Swagger 2).',
      evidence: 'No security schemes or authentication mechanisms are defined in components.securitySchemes or securityDefinitions.',
      impact: 'Without declared security schemes, API clients and automated enforcement gateways have no authentication contracts, risking completely unauthenticated exposure.',
      recommendation: 'Define standard authentication schemes such as OAuth 2.0 (JWT bearer) or OpenID Connect in components.securitySchemes.',
      implementationGuide: 'components:\n  securitySchemes:\n    BearerAuth:\n      type: http\n      scheme: bearer\n      bearerFormat: JWT',
      validationSteps: 'Verify specification components.securitySchemes includes valid bearer, oauth2, or apiKey schemes.',
    });
  }

  // =========================================================================
  // 4. Weak Authentication Schemes Defined
  // =========================================================================
  for (const scheme of parsed.securitySchemes) {
    // Basic Auth
    if (scheme.type === 'http' && scheme.scheme === 'basic') {
      addFinding({
        title: `Weak Authentication Scheme: HTTP Basic Auth Defined (${scheme.name})`,
        endpoint: '/*',
        method: 'ALL',
        category: 'Authentication',
        severity: 'HIGH',
        description: `Security scheme "${scheme.name}" specifies HTTP Basic Authentication. RFC 7617 Basic Auth transmits credentials using Base64 encoding with every HTTP request.`,
        evidence: `components.securitySchemes.${scheme.name}: { type: "http", scheme: "basic" }`,
        impact: 'Base64 offers no encryption or replay protection. Basic auth lacks token revocation, claims validation, and granular role delegation.',
        recommendation: 'Migrate from Basic Authentication to OAuth 2.0 with short-lived JWT bearer tokens or API key signatures.',
        implementationGuide: `${scheme.name}:\n  type: http\n  scheme: bearer\n  bearerFormat: JWT`,
        validationSteps: 'Ensure all API routes authenticate via signed Bearer JWTs instead of "Authorization: Basic" headers.',
      });
    }

    // API Key in Query Parameter
    if (scheme.type === 'apiKey' && scheme.in === 'query') {
      addFinding({
        title: `Insecure API Key Location: Query Parameter (${scheme.name})`,
        endpoint: '/*',
        method: 'ALL',
        category: 'Authentication',
        severity: 'HIGH',
        description: `Security scheme "${scheme.name}" transmits the API key as a URL query parameter (in: "query").`,
        evidence: `components.securitySchemes.${scheme.name}: { type: "apiKey", in: "query" }`,
        impact: 'Query strings are routinely logged in cleartext by intermediate reverse proxies, load balancer access logs, browser history, and HTTP Referer headers.',
        recommendation: 'Transmit API keys in standard HTTP headers (e.g., in: "header", name: "X-API-Key" or "Authorization").',
        implementationGuide: `${scheme.name}:\n  type: apiKey\n  in: header\n  name: X-API-Key`,
        validationSteps: 'Verify API rejects query parameter keys and only accepts authentication via request headers.',
      });
    }

    // OAuth2 Implicit Flow
    if (scheme.flows?.includes('implicit')) {
      addFinding({
        title: `Deprecated & Insecure OAuth2 Implicit Grant Flow (${scheme.name})`,
        endpoint: '/*',
        method: 'ALL',
        category: 'Authentication',
        severity: 'HIGH',
        description: `Security scheme "${scheme.name}" defines the OAuth2 Implicit grant flow, which is deprecated in OAuth 2.0 Security Best Current Practice and OAuth 2.1.`,
        evidence: `components.securitySchemes.${scheme.name}.flows.implicit is declared.`,
        impact: 'Access tokens are returned directly in the URL redirect fragment, vulnerable to token leakage via browser history, open redirects, and Referer headers.',
        recommendation: 'Replace Implicit flow with Authorization Code flow with Proof Key for Code Exchange (PKCE).',
        implementationGuide: 'flows:\n  authorizationCode:\n    authorizationUrl: https://auth.domain.com/oauth/authorize\n    tokenUrl: https://auth.domain.com/oauth/token',
        validationSteps: 'Verify OAuth2 authorization flow requires PKCE code_challenge and code_verifier parameters.',
      });
    }
  }

  // =========================================================================
  // 5. Missing Authentication on Specific Operations
  // =========================================================================
  const publicExceptions = ['/health', '/ping', '/status', '/metrics', '/docs', '/swagger', '/openapi'];

  for (const ep of parsed.endpoints) {
    const isPublicException = publicExceptions.some(p => ep.path.toLowerCase().includes(p));
    const pathItem = doc.paths?.[ep.path];
    const op = pathItem?.[ep.method.toLowerCase()];

    // Explicitly unauthenticated: op.security is [] (empty array)
    const explicitlyUnsecured = Array.isArray(op?.security) && op.security.length === 0;

    // Or no global security AND no op security
    const completelyUnsecured = parsed.globalSecurity.length === 0 && (!op?.security || op.security.length === 0);

    if ((explicitlyUnsecured || completelyUnsecured) && !isPublicException) {
      const isMutation = ['POST', 'PUT', 'DELETE', 'PATCH'].includes(ep.method);
      const isSensitivePath = ep.path.toLowerCase().match(/\/(user|admin|account|order|pay|setting|secret|credential|token|config|auth)/);

      if (isMutation || isSensitivePath) {
        addFinding({
          title: `Missing Authentication: Unprotected Operation (${ep.method} ${ep.path})`,
          endpoint: ep.path,
          method: ep.method,
          category: 'Authentication',
          severity: isMutation ? 'CRITICAL' : 'HIGH',
          description: `The operation ${ep.method} ${ep.path} specifies no authentication requirements (${explicitlyUnsecured ? 'explicitly security: []' : 'no global or operation security'}).`,
          evidence: `Operation ${ep.method} ${ep.path}: ${explicitlyUnsecured ? 'security: []' : 'missing security declaration while global security is unset.'}`,
          impact: 'Any anonymous remote caller can invoke this endpoint to mutate state or access sensitive resources without identity verification.',
          recommendation: 'Enforce authentication security requirements globally or on this operation.',
          implementationGuide: `paths:\n  ${ep.path}:\n    ${ep.method.toLowerCase()}:\n      security:\n        - BearerAuth: []`,
          validationSteps: 'Submit unauthenticated request to this endpoint and verify server responds with HTTP 401 Unauthorized.',
        });
      }
    }
  }

  // =========================================================================
  // 6. Missing Authorization Information (RBAC Scopes)
  // =========================================================================
  for (const ep of parsed.endpoints) {
    const pathItem = doc.paths?.[ep.path];
    const op = pathItem?.[ep.method.toLowerCase()];

    if (Array.isArray(op?.security)) {
      for (const secRequirement of op.security) {
        for (const [schemeName, scopes] of Object.entries<any>(secRequirement)) {
          const schemeDef = parsed.securitySchemes.find(s => s.name === schemeName);
          const isOauthOrOidc = schemeDef?.type === 'oauth2' || schemeDef?.type === 'openIdConnect';

          // If scheme is OAuth2/OIDC, but scopes array is empty on privileged endpoints
          if (isOauthOrOidc && Array.isArray(scopes) && scopes.length === 0) {
            const isPrivileged = ['POST', 'PUT', 'DELETE', 'PATCH'].includes(ep.method) ||
              ep.path.toLowerCase().includes('/admin') ||
              ep.path.toLowerCase().includes('/roles') ||
              ep.path.toLowerCase().includes('/users');

            if (isPrivileged) {
              addFinding({
                title: `Missing Scope Authorization Constraints (${ep.method} ${ep.path})`,
                endpoint: ep.path,
                method: ep.method,
                category: 'Access Control',
                severity: 'HIGH',
                description: `Operation ${ep.method} ${ep.path} requires OAuth2 scheme "${schemeName}" but specifies an empty required scopes array ([]).`,
                evidence: `security: [{ "${schemeName}": [] }] on privileged endpoint ${ep.method} ${ep.path}`,
                impact: 'Any caller with a valid OAuth token—regardless of granted scopes or client permissions—can execute this privileged operation, violating Principle of Least Privilege.',
                recommendation: `Declare granular OAuth2 scopes (e.g., "${ep.path.split('/')[1] || 'resource'}:write") to restrict invocation to authorized roles.`,
                implementationGuide: `security:\n  - ${schemeName}:\n      - "${ep.path.replace(/\//g, '_').replace(/^_/, '')}:write"`,
                validationSteps: 'Attempt invocation with access token lacking the specific required scope; verify HTTP 403 Forbidden.',
              });
            }
          }
        }
      }
    }
  }

  // =========================================================================
  // 7. Missing Rate-Limit Configuration
  // =========================================================================
  const rateLimitExtensions = doc['x-rate-limit'] || doc['x-throttling'];
  let specHasAnyRateLimiting = Boolean(rateLimitExtensions);

  for (const ep of parsed.endpoints) {
    if (ep.responses.some(r => r.status === '429' || r.hasRateLimitHeaders)) {
      specHasAnyRateLimiting = true;
      break;
    }
  }

  if (!specHasAnyRateLimiting) {
    const publicMutationEndpoints = parsed.endpoints.filter(e =>
      ['POST', 'PUT', 'DELETE'].includes(e.method) &&
      (e.path.toLowerCase().includes('login') ||
       e.path.toLowerCase().includes('auth') ||
       e.path.toLowerCase().includes('token') ||
       e.path.toLowerCase().includes('search') ||
       e.path.toLowerCase().includes('register') ||
       e.path.toLowerCase().includes('pay'))
    );

    const targetEp = publicMutationEndpoints.length > 0 ? publicMutationEndpoints[0] : parsed.endpoints[0];

    if (targetEp) {
      addFinding({
        title: 'Missing Rate-Limiting & Throttling Configuration in Specification',
        endpoint: targetEp.path,
        method: targetEp.method,
        category: 'Rate Limiting',
        severity: 'MEDIUM',
        description: 'The specification provides no evidence of request rate limiting or throttling policies: no 429 response declarations, Retry-After headers, or throttling extensions.',
        evidence: `No HTTP 429 response code or rate-limiting headers (X-RateLimit-*, Retry-After) defined across operations, including high-risk endpoint ${targetEp.method} ${targetEp.path}.`,
        impact: 'Exposes API to denial of service (DoS), credential stuffing, and brute force enumeration without throttling defenses.',
        recommendation: 'Document HTTP 429 responses with standard RateLimit headers and enforce ingress rate limiting.',
        implementationGuide: 'responses:\n  "429":\n    description: "Rate limit exceeded"\n    headers:\n      Retry-After:\n        schema:\n          type: integer\n        description: "Seconds until quota reset"',
        validationSteps: 'Send high-frequency requests exceeding quota; verify HTTP 429 status code with Retry-After header.',
      });
    }
  }

  // =========================================================================
  // 8. Excessive Data Exposure
  // =========================================================================
  const sensitiveFieldNames = [
    'password', 'password_hash', 'passwd', 'secret', 'client_secret',
    'private_key', 'ssn', 'social_security', 'credit_card', 'cvv', 'cvc'
  ];

  for (const ep of parsed.endpoints) {
    const pathItem = doc.paths?.[ep.path];
    const op = pathItem?.[ep.method.toLowerCase()];
    const successResp = op?.responses?.['200'] || op?.responses?.['201'];

    if (successResp) {
      const respSchema = successResp.schema || successResp.content?.['application/json']?.schema;
      if (respSchema) {
        const checkSchemaProps = (schemaObj: any, currentPath = '') => {
          if (!schemaObj || typeof schemaObj !== 'object') return;

          if (schemaObj.properties && typeof schemaObj.properties === 'object') {
            for (const [propName, propDef] of Object.entries<any>(schemaObj.properties)) {
              const fullPropName = currentPath ? `${currentPath}.${propName}` : propName;
              const lower = propName.toLowerCase();

              if (sensitiveFieldNames.some(s => lower === s || lower.endsWith(`_${s}`))) {
                addFinding({
                  title: `Excessive Data Exposure: Sensitive Property in Response (${ep.method} ${ep.path})`,
                  endpoint: ep.path,
                  method: ep.method,
                  category: 'Data Exposure',
                  severity: 'HIGH',
                  description: `The 200/201 response schema for ${ep.method} ${ep.path} explicitly defines the sensitive property "${fullPropName}".`,
                  evidence: `Response schema property detected: "${fullPropName}" in endpoint ${ep.method} ${ep.path}`,
                  impact: 'Returning credentials, password hashes, or confidential PII in API responses risks unauthorized credential exposure and privacy regulation violations.',
                  recommendation: 'Remove sensitive properties from response models and apply data transfer object (DTO) projections.',
                  implementationGuide: 'Filter entity before serialization:\nconst { password, ...safeUser } = userRecord;\nres.json(safeUser);',
                  validationSteps: 'Invoke endpoint and verify response payload does not contain sensitive attributes.',
                });
              }

              if (propDef?.properties) {
                checkSchemaProps(propDef, fullPropName);
              }
            }
          }

          if (schemaObj.items) {
            checkSchemaProps(schemaObj.items, currentPath);
          }
        };

        checkSchemaProps(respSchema);
      }
    }
  }

  // =========================================================================
  // 9. Missing Input Constraints
  // =========================================================================
  for (const ep of parsed.endpoints) {
    // Check parameters lacking bounds
    for (const param of ep.parameters) {
      if (!param.hasConstraints && (param.type === 'string' || param.type === 'integer' || param.type === 'number')) {
        // Skip common ID/UUID if it's clear
        const isCommonSafe = param.name === 'id' && param.in === 'path';
        if (!isCommonSafe) {
          addFinding({
            title: `Missing Input Constraints on Parameter "${param.name}" (${ep.method} ${ep.path})`,
            endpoint: ep.path,
            method: ep.method,
            category: 'Input Validation',
            severity: 'MEDIUM',
            description: `Parameter "${param.name}" (in: ${param.in}, type: ${param.type}) has no defined constraints (missing maxLength, pattern, minimum, maximum, or enum).`,
            evidence: `Parameter definition: { name: "${param.name}", in: "${param.in}", type: "${param.type}" } has zero constraint keywords.`,
            impact: 'Lack of input validation bounds permits buffer exhaustion, oversized string injection, and unexpected data formats.',
            recommendation: `Add validation bounds such as maxLength, pattern regex, or numeric range constraints to parameter "${param.name}".`,
            implementationGuide: `parameters:\n  - name: ${param.name}\n    in: ${param.in}\n    schema:\n      type: ${param.type}\n      maxLength: 100\n      pattern: "^[a-zA-Z0-9_-]+$"`,
            validationSteps: 'Submit an oversized string (e.g. 5,000 characters) or malformed value and verify input validation rejects it with HTTP 400.',
          });
          break; // Avoid spamming multiple identical findings per endpoint
        }
      }
    }

    // Check request bodies with unconstrained objects
    const pathItem = doc.paths?.[ep.path];
    const op = pathItem?.[ep.method.toLowerCase()];
    const reqBodySchema = op?.requestBody?.content?.['application/json']?.schema;
    if (reqBodySchema?.type === 'object' && reqBodySchema?.additionalProperties === true && !reqBodySchema?.properties) {
      addFinding({
        title: `Unconstrained Request Body Schema (Open Object) (${ep.method} ${ep.path})`,
        endpoint: ep.path,
        method: ep.method,
        category: 'Input Validation',
        severity: 'MEDIUM',
        description: `Request body for ${ep.method} ${ep.path} defines a generic open object (additionalProperties: true with no property validation).`,
        evidence: `requestBody schema: type: object, additionalProperties: true, properties: undefined`,
        impact: 'Permits mass assignment, prototype pollution, and arbitrary parameter injection into backend persistence layers.',
        recommendation: 'Define explicit property schemas and set additionalProperties: false to enforce strict payload contracts.',
        implementationGuide: 'requestBody:\n  content:\n    application/json:\n      schema:\n        type: object\n        additionalProperties: false\n        properties:\n          name:\n            type: string',
        validationSteps: 'Send payload with undeclared fields; verify validation middleware rejects unexpected attributes with HTTP 400 or 422.',
      });
    }
  }

  // =========================================================================
  // 10. Unsafe CORS Configuration when represented
  // =========================================================================
  const corsExtension = doc['x-cors'] || doc['x-cors-config'];
  const docStr = JSON.stringify(doc).toLowerCase();

  if (corsExtension) {
    const corsStr = JSON.stringify(corsExtension).toLowerCase();
    if (corsStr.includes('"*"') || corsStr.includes("'*'")) {
      addFinding({
        title: 'Unsafe Wildcard CORS Configuration Represented in Specification',
        endpoint: '/*',
        method: 'ALL',
        category: 'CORS',
        severity: 'HIGH',
        description: 'The API specification explicitly configures wildcard Access-Control-Allow-Origin ("*") in its CORS metadata.',
        evidence: `Found wildcard CORS declaration in specification extension: ${JSON.stringify(corsExtension)}`,
        impact: 'Permits any arbitrary external third-party domain in a browser environment to issue cross-origin requests to this API.',
        recommendation: 'Restrict allowed origins to trusted explicit domain names and never combine wildcard origins with credentials.',
        implementationGuide: 'x-cors:\n  allowOrigin:\n    - "https://app.yourdomain.com"\n  allowCredentials: true',
        validationSteps: 'Inspect HTTP OPTIONS preflight responses and verify Access-Control-Allow-Origin reflects only validated whitelisted origins.',
      });
    }
  }

  // Calculate score and summary
  const critical = findings.filter(f => f.severity === 'CRITICAL').length;
  const high = findings.filter(f => f.severity === 'HIGH').length;
  const medium = findings.filter(f => f.severity === 'MEDIUM').length;
  const low = findings.filter(f => f.severity === 'LOW').length;
  const total = findings.length;

  const score = Math.max(10, Math.min(100, Math.round(100 - (critical * 18) - (high * 9) - (medium * 4) - (low * 1))));

  return {
    parsed: {
      title: parsed.title,
      version: parsed.version,
      specVersion: parsed.specVersion,
      baseUrl: parsed.baseUrl,
      allBaseUrls: parsed.allBaseUrls,
      description: parsed.description || '',
      endpointsCount: parsed.endpoints.length,
      methodsCount: parsed.endpoints.length,
      securitySchemesCount: parsed.securitySchemes.length,
      securitySchemes: parsed.securitySchemes,
      endpoints: parsed.endpoints,
    },
    findings,
    score,
    summary: {
      critical,
      high,
      medium,
      low,
      total,
    },
  };
}
