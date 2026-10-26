import fs from 'fs';
import path from 'path';
import { NetworkDevice, SecurityBaselineModel } from '../src/types/index.ts';

export interface FrameworkControl {
  id: string;
  title: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  field: keyof SecurityBaselineModel | string;
  operator: 'equals' | 'not_equals' | 'gte' | 'lte' | 'contains' | 'is_not_empty' | 'is_empty';
  expectedValue: any;
  remediation: string;
}

export interface SecurityFramework {
  frameworkId: string;
  name: string;
  version: string;
  description: string;
  controls: FrameworkControl[];
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
  complianceScore: number; // 0 - 100
  totalControls: number;
  passedCount: number;
  failedCount: number;
  notEvaluableCount: number;
  controlResults: ControlEvaluationResult[];
}

export class FrameworkEngine {
  private frameworks: Map<string, SecurityFramework> = new Map();

  constructor() {
    this.loadFrameworks();
  }

  // Load JSON data files dynamically from data/frameworks
  public loadFrameworks(): void {
    const dir = path.resolve(process.cwd(), 'data', 'frameworks');
    if (!fs.existsSync(dir)) {
      console.warn('[FRAMEWORK-ENGINE] Frameworks dir not found, creating:', dir);
      fs.mkdirSync(dir, { recursive: true });
      return;
    }

    this.frameworks.clear();
    const files = fs.readdirSync(dir).filter(f => f.endsWith('.json'));
    for (const file of files) {
      try {
        const fullPath = path.join(dir, file);
        const raw = fs.readFileSync(fullPath, 'utf-8');
        const parsed = JSON.parse(raw) as SecurityFramework;
        if (parsed.frameworkId && Array.isArray(parsed.controls)) {
          this.frameworks.set(parsed.frameworkId, parsed);
        }
      } catch (err) {
        console.error(`[FRAMEWORK-ENGINE] Error reading framework file ${file}:`, err);
      }
    }
    console.log(`[FRAMEWORK-ENGINE] Loaded ${this.frameworks.size} frameworks from data/frameworks.`);
  }

  public getAvailableFrameworks(): Array<{
    frameworkId: string;
    name: string;
    version: string;
    description: string;
    controlCount: number;
  }> {
    this.loadFrameworks(); // reload to pick up any changes
    const list: Array<any> = [];
    for (const fw of this.frameworks.values()) {
      list.push({
        frameworkId: fw.frameworkId,
        name: fw.name,
        version: fw.version,
        description: fw.description,
        controlCount: fw.controls.length,
      });
    }
    return list;
  }

  public getAllFrameworks(): SecurityFramework[] {
    this.loadFrameworks();
    return Array.from(this.frameworks.values());
  }

  public getFramework(frameworkId: string): SecurityFramework | undefined {
    return this.frameworks.get(frameworkId);
  }

  public saveFramework(fw: SecurityFramework): void {
    const dir = path.resolve(process.cwd(), 'data', 'frameworks');
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }
    const cleanId = (fw.frameworkId || 'custom-fw').toLowerCase().replace(/[^a-z0-9_-]/g, '-');
    const filename = `${cleanId}.json`;
    const filePath = path.join(dir, filename);
    fs.writeFileSync(filePath, JSON.stringify(fw, null, 2), 'utf-8');
    this.loadFrameworks();
  }

  public deleteFramework(frameworkId: string): boolean {
    const dir = path.resolve(process.cwd(), 'data', 'frameworks');
    if (!fs.existsSync(dir)) return false;
    const files = fs.readdirSync(dir).filter(f => f.endsWith('.json'));
    for (const file of files) {
      try {
        const fullPath = path.join(dir, file);
        const raw = fs.readFileSync(fullPath, 'utf-8');
        const parsed = JSON.parse(raw);
        if (parsed.frameworkId === frameworkId) {
          fs.unlinkSync(fullPath);
          this.loadFrameworks();
          return true;
        }
      } catch {
        // ignore
      }
    }
    return false;
  }

  // Evaluate a specific control against a device's baseline model
  public evaluateControl(
    control: FrameworkControl,
    device: NetworkDevice,
    frameworkId: string
  ): ControlEvaluationResult {
    const fieldObj = (device.baselineModel as any)[control.field];
    const vendor = device.detectedVendor || 'Network Device';
    const remediation = control.remediation.replace(/\{vendor\}/g, vendor);

    // If field object missing or value is null/undefined
    if (!fieldObj || fieldObj.value === null || fieldObj.value === undefined) {
      return {
        controlId: control.id,
        frameworkId,
        title: control.title,
        severity: control.severity,
        field: String(control.field),
        status: 'NOT_EVALUABLE',
        expectedValue: control.expectedValue,
        actualValue: 'Not Detected / Unconfigured',
        sourceLine: null,
        lineNumber: null,
        remediation,
      };
    }

    const val = fieldObj.value;
    let passed = false;

    switch (control.operator) {
      case 'equals':
        passed = val === control.expectedValue;
        break;
      case 'not_equals':
        passed = val !== control.expectedValue;
        break;
      case 'gte':
        passed = typeof val === 'number' && val >= Number(control.expectedValue);
        break;
      case 'lte':
        passed = typeof val === 'number' && val <= Number(control.expectedValue);
        break;
      case 'contains':
        passed = String(val).toLowerCase().includes(String(control.expectedValue).toLowerCase());
        break;
      case 'is_not_empty':
        passed = Array.isArray(val) ? val.length > 0 : Boolean(val);
        break;
      case 'is_empty':
        passed = Array.isArray(val) ? val.length === 0 : !val;
        break;
      default:
        passed = false;
    }

    return {
      controlId: control.id,
      frameworkId,
      title: control.title,
      severity: control.severity,
      field: String(control.field),
      status: passed ? 'PASS' : 'FAIL',
      expectedValue: control.expectedValue,
      actualValue: Array.isArray(val) ? val.join(', ') : val,
      sourceLine: fieldObj.sourceLine || null,
      lineNumber: fieldObj.lineNumber || null,
      remediation,
    };
  }

  // Evaluate a device against a framework
  public evaluateDeviceAgainstFramework(
    device: NetworkDevice,
    frameworkId: string
  ): DeviceFrameworkEvaluation | null {
    const fw = this.frameworks.get(frameworkId);
    if (!fw) return null;

    const controlResults: ControlEvaluationResult[] = [];
    let passedCount = 0;
    let failedCount = 0;
    let notEvaluableCount = 0;

    for (const ctrl of fw.controls) {
      const res = this.evaluateControl(ctrl, device, frameworkId);
      controlResults.push(res);
      if (res.status === 'PASS') passedCount++;
      else if (res.status === 'FAIL') failedCount++;
      else notEvaluableCount++;
    }

    const evaluable = passedCount + failedCount;
    const complianceScore = evaluable > 0 ? Math.round((passedCount / evaluable) * 100) : 0;

    return {
      id: `eval-${device.id}-${frameworkId}-${Date.now()}`,
      deviceId: device.id,
      deviceHostname: device.hostname || device.filename,
      deviceVendor: device.detectedVendor,
      frameworkId: fw.frameworkId,
      frameworkName: fw.name,
      frameworkVersion: fw.version,
      evaluatedAt: new Date().toISOString(),
      complianceScore,
      totalControls: fw.controls.length,
      passedCount,
      failedCount,
      notEvaluableCount,
      controlResults,
    };
  }
}

export const frameworkEngine = new FrameworkEngine();
