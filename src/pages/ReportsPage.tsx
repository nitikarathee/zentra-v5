import React, { useState, useEffect, useMemo } from 'react';
import {
  FileText,
  Download,
  Printer,
  Archive,
  Server,
  ShieldCheck,
  ShieldAlert,
  CheckCircle2,
  XCircle,
  HelpCircle,
  RotateCw,
  Search,
  Filter,
  Eye,
  Terminal,
  ExternalLink,
  Layers,
  ChevronRight,
  Sparkles,
  Cpu,
  Plus,
  KeyRound,
  Activity,
  FileSpreadsheet,
  PackageCheck,
} from 'lucide-react';
import jsPDF from 'jspdf';
import JSZip from 'jszip';
import { Card } from '../components/common/Card';
import { Modal } from '../components/common/Modal';
import { SeverityBadge, StatusBadge } from '../components/common/Badge';
import {
  NetworkDevice,
  DeviceFrameworkEvaluation,
  SecurityFramework,
  ControlEvaluationResult,
  ReportItem,
  ApiItem,
  SecurityFinding,
  CISControl,
  ZeroTrustPillar,
} from '../types';
import { MemoryBadge } from '../components/memory/MemoryBadge';
import { FixOutcomeButtons } from '../components/memory/FixOutcomeButtons';
import { apiService } from '../services/api';
import { useToast } from '../context/ToastContext';
import { useAuth } from '../context/AuthContext';

export function ReportsPage({ onSelectFinding }: { onSelectFinding?: (id: string) => void }) {
  // Mode Tab: API Reports ("the old one") vs Fleet Baseline Reports
  const [activeReportTab, setActiveReportTab] = useState<'api' | 'fleet'>('api');

  // Network fleet state
  const [devices, setDevices] = useState<NetworkDevice[]>([]);
  const [evaluations, setEvaluations] = useState<DeviceFrameworkEvaluation[]>([]);
  const [frameworks, setFrameworks] = useState<SecurityFramework[]>([]);

  // API assessment state ("the old one")
  const [apiReports, setApiReports] = useState<ReportItem[]>([]);
  const [apis, setApis] = useState<ApiItem[]>([]);
  const [findings, setFindings] = useState<SecurityFinding[]>([]);
  const [cisControls, setCisControls] = useState<CISControl[]>([]);
  const [isCreateModalOpen, setIsCreateModalOpen] = useState(false);
  const [newTitle, setNewTitle] = useState('');
  const [newOrg, setNewOrg] = useState('');
  const [isSubmittingReport, setIsSubmittingReport] = useState(false);
  const [generatingApiPdfIds, setGeneratingApiPdfIds] = useState<Record<string, boolean>>({});
  const [generatingApiZipIds, setGeneratingApiZipIds] = useState<Record<string, boolean>>({});
  const [selectedApiReport, setSelectedApiReport] = useState<ReportItem | null>(null);

  const [loading, setLoading] = useState(true);

  // Per-device generating state
  const [generatingIds, setGeneratingIds] = useState<Record<string, boolean>>({});

  // Bulk ZIP export state
  const [isBulkExporting, setIsBulkExporting] = useState(false);
  const [bulkProgress, setBulkProgress] = useState<{ current: number; total: number; hostname: string } | null>(null);

  // Preview Modal
  const [previewDevice, setPreviewDevice] = useState<NetworkDevice | null>(null);
  const [previewRemediations, setPreviewRemediations] = useState<Array<{ controlId: string; field: string; cliCommands: string; source?: 'template' | 'ai-gemini'; memoriesUsed?: string[]; memoryCount?: number }>>([]);
  // Dry-run fix drafts, keyed `${deviceId}::${controlId}`. Nothing is ever executed on a device.
  const [fixDrafts, setFixDrafts] = useState<Record<string, { original: string; text: string; approved: boolean; editing: boolean }>>({});
  const [loadingPreview, setLoadingPreview] = useState(false);

  // Filters
  const [search, setSearch] = useState('');
  const [vendorFilter, setVendorFilter] = useState('ALL');

  const { showToast } = useToast();
  const { user } = useAuth();

  const loadData = async () => {
    try {
      setLoading(true);
      const [devList, evalList, fwList, repList, apiList, findList, comp] = await Promise.all([
        apiService.getDevices().catch(() => []),
        apiService.getComplianceEvaluations().catch(() => []),
        apiService.getComplianceFrameworks().catch(() => []),
        apiService.getReports().catch(() => []),
        apiService.getApis().catch(() => []),
        apiService.getFindings().catch(() => []),
        apiService.getCompliance().catch(() => ({ controls: [] as CISControl[] })),
      ]);
      setDevices(devList || []);
      setEvaluations(evalList || []);
      setFrameworks(fwList || []);
      setApiReports(repList || []);
      setApis(apiList || []);
      setFindings(findList || []);
      setCisControls(comp?.controls || []);
    } catch (err: any) {
      showToast('Error Loading Audit Data', err.message, 'error');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  const handleLoadSampleDevices = async () => {
    try {
      setLoading(true);
      const res = await apiService.loadSampleDevices();
      setDevices(res.devices);
      const freshEvals = await apiService.getComplianceEvaluations();
      setEvaluations(freshEvals);
      showToast('Sample Fleet Loaded', res.message, 'success');
    } catch (err: any) {
      showToast('Failed to load sample fleet', err.message, 'error');
    } finally {
      setLoading(false);
    }
  };

  // Helper to compile a PDF for a device
  const buildDevicePdf = async (device: NetworkDevice): Promise<{ doc: jsPDF; filename: string; sealFile: { name: string; content: string } | null; seal: string | null }> => {
    // 1. Gather all framework evaluations for this device
    let devEvals = evaluations.filter((e) => e.deviceId === device.id);
    if (devEvals.length === 0) {
      const evalRes = await apiService.evaluateCompliance(undefined, [device.id]);
      devEvals = evalRes.evaluations;
    }

    // 2. Extract failed controls
    const failedControls: ControlEvaluationResult[] = [];
    devEvals.forEach((ev) => {
      ev.controlResults.forEach((ctrl) => {
        if (ctrl.status === 'FAIL') {
          // Avoid duplicate control ID across frameworks if identical
          if (!failedControls.some((fc) => fc.controlId === ctrl.controlId)) {
            failedControls.push(ctrl);
          }
        }
      });
    });

    // 3. Request Gemini to adapt vendor-specific CLI remediation
    let cliRemediations: Array<{ controlId: string; field: string; cliCommands: string; source?: 'template' | 'ai-gemini' }> = [];
    try {
      if (failedControls.length > 0) {
        const res = await apiService.getVendorCliRemediations({
          vendor: device.detectedVendor,
          model: device.model,
          hostname: device.hostname,
          controls: failedControls.map((fc) => ({
            controlId: fc.controlId,
            title: fc.title,
            field: fc.field,
            expectedValue: fc.expectedValue,
            actualValue: fc.actualValue,
            remediation: fc.remediation,
          })),
        });
        cliRemediations = res.remediations;
      }
    } catch (err) {
      console.warn('CLI remediation generation fallback:', err);
    }

    // 4. Create jsPDF document
    const doc = new jsPDF({
      orientation: 'portrait',
      unit: 'mm',
      format: 'a4',
    });

    const pageWidth = doc.internal.pageSize.getWidth();
    const pageHeight = doc.internal.pageSize.getHeight();
    const margin = 14;
    let y = margin;
    const usedFixes: Array<{ controlId: string; commands: string; source: string; edited: boolean }> = [];

    // Helper: Add new page if content exceeds height
    const checkPageBreak = (neededHeight: number) => {
      if (y + neededHeight > pageHeight - 18) {
        doc.addPage();
        y = margin + 8;
        renderPageHeaderSmall();
      }
    };

    // Small running header on subsequent pages
    const renderPageHeaderSmall = () => {
      doc.setFillColor(15, 23, 42); // slate-900
      doc.rect(0, 0, pageWidth, 12, 'F');
      doc.setTextColor(6, 182, 212); // cyan-500
      doc.setFontSize(8);
      doc.setFont('helvetica', 'bold');
      doc.text(`ZENTRA COMPLIANCE REPORT: ${device.hostname || device.filename}`, margin, 8);
      doc.setTextColor(148, 163, 184); // slate-400
      doc.text(`Vendor: ${device.detectedVendor}`, pageWidth - margin - 50, 8);
      y = 18;
    };

    // Header Banner
    doc.setFillColor(15, 23, 42); // slate-900
    doc.rect(0, 0, pageWidth, 36, 'F');

    doc.setTextColor(6, 182, 212); // cyan-400
    doc.setFontSize(18);
    doc.setFont('helvetica', 'bold');
    doc.text('ZENTRA NETWORK SECURITY AUDIT REPORT', margin, 14);

    doc.setTextColor(226, 232, 240); // slate-200
    doc.setFontSize(9);
    doc.setFont('helvetica', 'normal');
    doc.text('Device Security Baseline & Multi-Framework Configuration Compliance Certificate', margin, 21);

    doc.setTextColor(148, 163, 184); // slate-400
    doc.setFontSize(8);
    doc.text(`Generated: ${new Date().toUTCString()}  |  Engine: ZENTRA Compliance Kernel v3.0`, margin, 28);

    y = 44;

    // Device Identification Card
    doc.setFillColor(248, 250, 252); // slate-50
    doc.setDrawColor(203, 213, 225); // slate-300
    doc.roundedRect(margin, y, pageWidth - margin * 2, 38, 2, 2, 'FD');

    doc.setTextColor(15, 23, 42); // slate-900
    doc.setFontSize(12);
    doc.setFont('helvetica', 'bold');
    doc.text('Device Identification & Hardware Inventory', margin + 4, y + 7);

    doc.setFontSize(9);
    doc.setFont('helvetica', 'normal');
    doc.setTextColor(51, 65, 85);

    // Left Column
    doc.setFont('helvetica', 'bold');
    doc.text('Hostname:', margin + 4, y + 16);
    doc.setFont('helvetica', 'normal');
    doc.text(device.hostname || 'Unassigned / Not Detected', margin + 28, y + 16);

    doc.setFont('helvetica', 'bold');
    doc.text('Vendor / OS:', margin + 4, y + 23);
    doc.setFont('helvetica', 'normal');
    doc.text(`${device.detectedVendor} (${device.vendorGuessMethod.toUpperCase()} ${device.vendorConfidence}%)`, margin + 28, y + 23);

    doc.setFont('helvetica', 'bold');
    doc.text('Model:', margin + 4, y + 30);
    doc.setFont('helvetica', 'normal');
    doc.text(device.model || 'General Network Appliance', margin + 28, y + 30);

    // Right Column
    doc.setFont('helvetica', 'bold');
    doc.text('Serial Number:', margin + 105, y + 16);
    doc.setFont('helvetica', 'normal');
    doc.text(device.serialNumber || 'SN-UNKNOWN', margin + 132, y + 16);

    doc.setFont('helvetica', 'bold');
    doc.text('Config File:', margin + 105, y + 23);
    doc.setFont('helvetica', 'normal');
    doc.text(`${device.filename} (${device.lineCount} lines, ${Math.round(device.byteSize / 1024)} KB)`, margin + 132, y + 23);

    doc.setFont('helvetica', 'bold');
    doc.text('Ingested At:', margin + 105, y + 30);
    doc.setFont('helvetica', 'normal');
    doc.text(new Date(device.uploadTime).toLocaleDateString(), margin + 132, y + 30);

    y += 44;

    // Executive Scorecard Card
    const score = device.overallComplianceScore;
    const scoreColor = score >= 80 ? [16, 185, 129] : score >= 60 ? [245, 158, 11] : [239, 68, 68];

    doc.setFillColor(241, 245, 249); // slate-100
    doc.setDrawColor(203, 213, 225);
    doc.roundedRect(margin, y, pageWidth - margin * 2, 28, 2, 2, 'FD');

    doc.setFontSize(10);
    doc.setFont('helvetica', 'bold');
    doc.setTextColor(15, 23, 42);
    doc.text('Security Baseline Compliance Scorecard', margin + 4, y + 7);

    // Score Circle / Pill
    doc.setFillColor(scoreColor[0], scoreColor[1], scoreColor[2]);
    doc.roundedRect(margin + 4, y + 11, 28, 12, 1.5, 1.5, 'F');
    doc.setTextColor(255, 255, 255);
    doc.setFontSize(11);
    doc.setFont('helvetica', 'bold');
    doc.text(`${score}%`, margin + 11, y + 19.5);

    doc.setFontSize(8);
    doc.setFont('helvetica', 'normal');
    doc.setTextColor(71, 85, 105);

    // Compute passed, failed, not-evaluable
    let totalP = 0;
    let totalF = 0;
    let totalN = 0;
    devEvals.forEach((ev) => {
      totalP += ev.passedCount;
      totalF += ev.failedCount;
      totalN += ev.notEvaluableCount;
    });

    doc.setFont('helvetica', 'bold');
    doc.text('Overall Status:', margin + 38, y + 15);
    doc.setFont('helvetica', 'normal');
    doc.text(device.status, margin + 63, y + 15);

    doc.setFont('helvetica', 'bold');
    doc.text('Passed Controls:', margin + 38, y + 21);
    doc.setFont('helvetica', 'normal');
    doc.text(`${totalP} controls`, margin + 63, y + 21);

    doc.setFont('helvetica', 'bold');
    doc.text('Failed Controls:', margin + 105, y + 15);
    doc.setFont('helvetica', 'normal');
    doc.text(`${totalF} controls`, margin + 132, y + 15);

    doc.setFont('helvetica', 'bold');
    doc.text('Frameworks Evaluated:', margin + 105, y + 21);
    doc.setFont('helvetica', 'normal');
    doc.text(`${devEvals.length} Standards (CIS, NIST, STIG, ISO)`, margin + 138, y + 21);

    y += 34;

    // Framework Summary Table
    checkPageBreak(30);
    doc.setFontSize(11);
    doc.setFont('helvetica', 'bold');
    doc.setTextColor(15, 23, 42);
    doc.text('Compliance Breakdown by Security Framework', margin, y);
    y += 4;

    // Framework Table Header
    doc.setFillColor(30, 41, 59); // slate-800
    doc.rect(margin, y, pageWidth - margin * 2, 7, 'F');
    doc.setTextColor(255, 255, 255);
    doc.setFontSize(8);
    doc.setFont('helvetica', 'bold');
    doc.text('Framework Name', margin + 3, y + 5);
    doc.text('Version', margin + 60, y + 5);
    doc.text('Score', margin + 95, y + 5);
    doc.text('Passed', margin + 115, y + 5);
    doc.text('Failed', margin + 135, y + 5);
    doc.text('Not Evaluable', margin + 155, y + 5);
    y += 7;

    doc.setFont('helvetica', 'normal');
    devEvals.forEach((ev, idx) => {
      checkPageBreak(8);
      doc.setFillColor(idx % 2 === 0 ? 255 : 248, idx % 2 === 0 ? 255 : 250, idx % 2 === 0 ? 255 : 252);
      doc.rect(margin, y, pageWidth - margin * 2, 6, 'F');
      doc.setTextColor(30, 41, 59);
      doc.setFontSize(8);
      doc.text(ev.frameworkName, margin + 3, y + 4.2);
      doc.text(ev.frameworkVersion, margin + 60, y + 4.2);
      doc.text(`${ev.complianceScore}%`, margin + 95, y + 4.2);
      doc.text(String(ev.passedCount), margin + 115, y + 4.2);
      doc.text(String(ev.failedCount), margin + 135, y + 4.2);
      doc.text(String(ev.notEvaluableCount), margin + 155, y + 4.2);
      y += 6;
    });

    y += 8;

    // Detailed Pass / Fail Evaluation Controls Table
    checkPageBreak(35);
    doc.setFontSize(11);
    doc.setFont('helvetica', 'bold');
    doc.setTextColor(15, 23, 42);
    doc.text('Detailed Security Controls Matrix', margin, y);
    y += 4;

    // Controls Table Header
    doc.setFillColor(30, 41, 59);
    doc.rect(margin, y, pageWidth - margin * 2, 7, 'F');
    doc.setTextColor(255, 255, 255);
    doc.setFontSize(8);
    doc.setFont('helvetica', 'bold');
    doc.text('Control ID & Title', margin + 3, y + 5);
    doc.text('Framework', margin + 65, y + 5);
    doc.text('Severity', margin + 95, y + 5);
    doc.text('Expected Value', margin + 120, y + 5);
    doc.text('Status', margin + 155, y + 5);
    y += 7;

    // Render controls across all frameworks
    devEvals.forEach((ev) => {
      ev.controlResults.forEach((ctrl, idx) => {
        checkPageBreak(8);
        doc.setFillColor(idx % 2 === 0 ? 255 : 248, idx % 2 === 0 ? 255 : 250, idx % 2 === 0 ? 255 : 252);
        doc.rect(margin, y, pageWidth - margin * 2, 6.5, 'F');

        doc.setFontSize(7.5);
        doc.setFont('helvetica', 'bold');
        doc.setTextColor(15, 23, 42);
        const titleShort = `${ctrl.controlId}: ${ctrl.title}`.substring(0, 36);
        doc.text(titleShort, margin + 3, y + 4.5);

        doc.setFont('helvetica', 'normal');
        doc.setTextColor(71, 85, 105);
        doc.text(ev.frameworkName.substring(0, 16), margin + 65, y + 4.5);

        // Severity
        doc.setFont('helvetica', 'bold');
        if (ctrl.severity === 'CRITICAL') doc.setTextColor(225, 29, 72);
        else if (ctrl.severity === 'HIGH') doc.setTextColor(234, 88, 12);
        else if (ctrl.severity === 'MEDIUM') doc.setTextColor(202, 138, 4);
        else doc.setTextColor(71, 85, 105);
        doc.text(ctrl.severity, margin + 95, y + 4.5);

        // Expected
        doc.setFont('helvetica', 'normal');
        doc.setTextColor(71, 85, 105);
        doc.text(String(ctrl.expectedValue).substring(0, 16), margin + 120, y + 4.5);

        // Status
        if (ctrl.status === 'PASS') {
          doc.setTextColor(16, 185, 129);
          doc.setFont('helvetica', 'bold');
          doc.text('PASS', margin + 155, y + 4.5);
        } else if (ctrl.status === 'FAIL') {
          doc.setTextColor(239, 68, 68);
          doc.setFont('helvetica', 'bold');
          doc.text('FAIL', margin + 155, y + 4.5);
        } else {
          doc.setTextColor(245, 158, 11);
          doc.setFont('helvetica', 'bold');
          doc.text('N/A', margin + 155, y + 4.5);
        }

        y += 6.5;
      });
    });

    y += 10;

    // Step-by-Step Vendor CLI Remediation Section
    checkPageBreak(40);
    doc.setFontSize(12);
    doc.setFont('helvetica', 'bold');
    doc.setTextColor(15, 23, 42);
    doc.text(`Step-by-Step CLI Remediation (${device.detectedVendor} Syntax)`, margin, y);
    y += 4;

    doc.setFontSize(8);
    doc.setFont('helvetica', 'normal');
    doc.setTextColor(100, 116, 139);
    doc.text('Exact terminal CLI statements to fix identified non-compliant security controls on this device.', margin, y);
    y += 6;

    if (failedControls.length === 0) {
      doc.setFillColor(240, 253, 244); // emerald-50
      doc.setDrawColor(187, 247, 208);
      doc.roundedRect(margin, y, pageWidth - margin * 2, 16, 1.5, 1.5, 'FD');
      doc.setTextColor(21, 128, 61);
      doc.setFontSize(9);
      doc.setFont('helvetica', 'bold');
      doc.text('All controls compliant! No CLI remediation required for this network device.', margin + 4, y + 9);
      y += 20;
    } else {
      failedControls.forEach((ctrl, i) => {
        checkPageBreak(36);

        // Find matching tailored CLI command
        const remObj = cliRemediations.find((r) => r.controlId === ctrl.controlId);
        const generatedText = remObj?.cliCommands || ctrl.remediation.replace(/\{vendor\}/g, device.detectedVendor);
        const draft = fixDrafts[`${device.id}::${ctrl.controlId}`];
        const useDraft = !!draft && (draft.approved || draft.text !== draft.original);
        const cliText = useDraft ? draft.text : generatedText;
        const srcLabel = remObj?.source === 'ai-gemini' ? 'AI-generated (Gemini)' : 'Template';
        const fixLabel = `${srcLabel}${useDraft && draft.text !== draft.original ? ' + operator edited' : useDraft ? ' + approved' : ''}`;
        usedFixes.push({ controlId: ctrl.controlId, commands: cliText, source: remObj?.source === 'ai-gemini' ? 'ai-gemini' : 'template', edited: useDraft && draft.text !== draft.original });

        // Card container
        doc.setFillColor(254, 242, 242); // rose-50
        doc.setDrawColor(254, 202, 202); // rose-200
        doc.roundedRect(margin, y, pageWidth - margin * 2, 8, 1, 1, 'FD');

        doc.setFontSize(8.5);
        doc.setFont('helvetica', 'bold');
        doc.setTextColor(159, 18, 57);
        doc.text(`[FAIL - ${ctrl.severity}] Control ${ctrl.controlId}: ${ctrl.title}`, margin + 3, y + 5.5);
        doc.setFont('helvetica', 'normal');
        doc.setFontSize(6.5);
        doc.text(fixLabel, pageWidth - margin - 3, y + 5.5, { align: 'right' });
        y += 9;

        // Command code block box
        const lines = doc.splitTextToSize(cliText, pageWidth - margin * 2 - 8);
        const boxHeight = Math.max(14, lines.length * 3.5 + 4);
        checkPageBreak(boxHeight + 4);

        doc.setFillColor(15, 23, 42); // slate-900 (terminal box)
        doc.setDrawColor(51, 65, 85);
        doc.roundedRect(margin, y, pageWidth - margin * 2, boxHeight, 1, 1, 'F');

        doc.setTextColor(6, 182, 212); // cyan-400 font
        doc.setFont('courier', 'normal');
        doc.setFontSize(7.5);
        doc.text(lines, margin + 4, y + 4.5);

        y += boxHeight + 4;
      });
    }

    // 5. Seal: HMAC-SHA256 over the report contents (computed on the server)
    let sealFile: { name: string; content: string } | null = null;
    let sealInfo: { seal: string; sealedAt: string } | null = null;
    try {
      const allResults = devEvals.flatMap((ev) =>
        ev.controlResults.map((c) => ({ framework: c.frameworkId, controlId: c.controlId, status: c.status, severity: c.severity }))
      );
      const sealRes = await apiService.sealReport('device', device.hostname || device.filename, {
        deviceId: device.id,
        hostname: device.hostname || null,
        serialNumber: device.serialNumber || null,
        vendor: device.detectedVendor,
        model: device.model || null,
        complianceScore: device.overallComplianceScore,
        status: device.status,
        generatedAt: new Date().toISOString(),
        generatedBy: user?.name || 'Security Lead',
        results: allResults,
        findings: failedControls.map((c) => ({ controlId: c.controlId, severity: c.severity, field: c.field, actualValue: String(c.actualValue ?? '') })),
        fixes: usedFixes,
      });
      sealInfo = { seal: sealRes.seal, sealedAt: sealRes.sealedAt };
      sealFile = {
        name: `${(device.hostname || device.filename).replace(/[^a-zA-Z0-9_-]/g, '_')}.seal.json`,
        content: JSON.stringify({ seal: sealRes.seal, algorithm: sealRes.algorithm, payload: sealRes.payload }, null, 2),
      };
    } catch (err) {
      console.warn('Report seal unavailable:', err);
    }

    checkPageBreak(40);
    y += 4;
    doc.setDrawColor(6, 182, 212);
    doc.setFillColor(240, 253, 250);
    doc.roundedRect(margin, y, pageWidth - margin * 2, 32, 1.5, 1.5, 'FD');
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(9);
    doc.setTextColor(15, 118, 110);
    doc.text('ZENTRA REPORT SEAL (HMAC-SHA256)', margin + 4, y + 6);
    doc.setFont('courier', 'normal');
    doc.setFontSize(7.5);
    doc.setTextColor(15, 23, 42);
    if (sealInfo) {
      doc.text(sealInfo.seal.slice(0, 32), margin + 4, y + 13);
      doc.text(sealInfo.seal.slice(32), margin + 4, y + 18);
      doc.setFont('helvetica', 'normal');
      doc.setFontSize(7.5);
      doc.text(`Sealed: ${new Date(sealInfo.sealedAt).toLocaleString()}  |  Keyed hash: any edit to this report breaks the seal.`, margin + 4, y + 24);
      doc.text('Verify in ZENTRA > Verify Report using the .seal.json file and this hash.', margin + 4, y + 29);
    } else {
      doc.setFont('helvetica', 'normal');
      doc.text('Seal unavailable (server not reachable when this report was generated).', margin + 4, y + 14);
    }
    y += 36;

    // Add page numbers and footers across all pages
    const totalPages = doc.getNumberOfPages();
    for (let p = 1; p <= totalPages; p++) {
      doc.setPage(p);
      doc.setDrawColor(226, 232, 240);
      doc.line(margin, pageHeight - 12, pageWidth - margin, pageHeight - 12);
      doc.setFont('helvetica', 'normal');
      doc.setFontSize(7.5);
      doc.setTextColor(148, 163, 184);
      doc.text(`ZENTRA Network Security Compliance Audit | ${device.hostname || device.filename}`, margin, pageHeight - 7);
      doc.text(`Page ${p} of ${totalPages}`, pageWidth - margin - 20, pageHeight - 7);
    }

    const cleanName = (device.hostname || device.filename).replace(/[^a-zA-Z0-9_-]/g, '_');
    return { doc, filename: `${cleanName}-compliance-report.pdf`, sealFile, seal: sealInfo?.seal || null };
  };

  // Export single device PDF
  const handleExportSinglePdf = async (device: NetworkDevice) => {
    try {
      setGeneratingIds((prev) => ({ ...prev, [device.id]: true }));
      const { doc, filename, sealFile } = await buildDevicePdf(device);
      doc.save(filename);
      if (sealFile) {
        const blob = new Blob([sealFile.content], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = sealFile.name;
        a.click();
        URL.revokeObjectURL(url);
      }
      showToast('PDF Export Complete', `Downloaded audit report for ${device.hostname || device.filename}.`, 'success');
    } catch (err: any) {
      showToast('PDF Export Error', err.message, 'error');
    } finally {
      setGeneratingIds((prev) => ({ ...prev, [device.id]: false }));
    }
  };

  // Export All as ZIP
  const handleExportAllZip = async () => {
    if (devices.length === 0) {
      showToast('No Devices Available', 'Ingest devices or load sample configs first.', 'error');
      return;
    }

    try {
      setIsBulkExporting(true);
      const zip = new JSZip();
      const fleetSeals: Record<string, string | null> = {};

      for (let i = 0; i < devices.length; i++) {
        const device = devices[i];
        setBulkProgress({
          current: i + 1,
          total: devices.length,
          hostname: device.hostname || device.filename,
        });

        const { doc, filename, sealFile, seal } = await buildDevicePdf(device);
        const pdfArrayBuffer = doc.output('arraybuffer');
        zip.file(filename, pdfArrayBuffer);
        if (sealFile) zip.file(sealFile.name, sealFile.content);
        fleetSeals[device.id] = seal;
      }

      // Add a fleet-wide manifest
      const manifest = {
        generatedAt: new Date().toISOString(),
        totalDevices: devices.length,
        devices: devices.map((d) => ({
          hostname: d.hostname,
          vendor: d.detectedVendor,
          model: d.model,
          complianceScore: d.overallComplianceScore,
          status: d.status,
          filename: d.filename,
          serialNumber: d.serialNumber || null,
          reportSeal: fleetSeals[d.id] || null,
        })),
        sealAlgorithm: 'HMAC-SHA256 (verify each device in ZENTRA > Verify Report)',
        engine: 'ZENTRA Vendor-Agnostic Network Configuration Compliance Platform',
      };
      zip.file('audit-manifest.json', JSON.stringify(manifest, null, 2));

      setBulkProgress({
        current: devices.length,
        total: devices.length,
        hostname: 'Packaging ZIP Archive...',
      });

      const zipBlob = await zip.generateAsync({ type: 'blob' });
      const url = URL.createObjectURL(zipBlob);
      const link = document.createElement('a');
      link.href = url;
      link.download = `zentra-fleet-compliance-reports-${new Date().toISOString().split('T')[0]}.zip`;
      link.click();
      URL.revokeObjectURL(url);

      showToast(
        'Bulk ZIP Export Complete',
        `Successfully packaged ${devices.length} per-device compliance reports into ZIP.`,
        'success'
      );
    } catch (err: any) {
      showToast('ZIP Export Error', err.message, 'error');
    } finally {
      setIsBulkExporting(false);
      setBulkProgress(null);
    }
  };

  // Helper to compile API Security Assessment PDF ("the old one")
  const buildApiAssessmentPdf = (
    report: ReportItem,
    apisList: ApiItem[],
    findingsList: SecurityFinding[],
    cisList: CISControl[]
  ): jsPDF => {
    const doc = new jsPDF({ orientation: 'portrait', unit: 'mm', format: 'a4' });
    const pageWidth = doc.internal.pageSize.getWidth();
    const pageHeight = doc.internal.pageSize.getHeight();
    const margin = 14;
    let y = margin;

    const checkPageBreak = (neededHeight: number) => {
      if (y + neededHeight > pageHeight - 18) {
        doc.addPage();
        y = margin + 8;
        doc.setFillColor(15, 23, 42);
        doc.rect(0, 0, pageWidth, 12, 'F');
        doc.setTextColor(6, 182, 212);
        doc.setFontSize(8);
        doc.setFont('helvetica', 'bold');
        doc.text(`ZENTRA API SECURITY AUDIT: ${report.title}`, margin, 8);
        doc.setTextColor(148, 163, 184);
        doc.text(`Org: ${report.organization}`, pageWidth - margin - 50, 8);
        y = 18;
      }
    };

    // Header banner
    doc.setFillColor(15, 23, 42);
    doc.rect(0, 0, pageWidth, 36, 'F');
    doc.setTextColor(6, 182, 212);
    doc.setFontSize(18);
    doc.setFont('helvetica', 'bold');
    doc.text('ZENTRA ENTERPRISE API SECURITY AUDIT', margin, 14);

    doc.setTextColor(226, 232, 240);
    doc.setFontSize(9);
    doc.setFont('helvetica', 'normal');
    doc.text(`${report.title} — ${report.organization}`, margin, 21);

    doc.setTextColor(148, 163, 184);
    doc.setFontSize(8);
    doc.text(`Audited: ${new Date(report.createdAt).toUTCString()}  |  Auditor: ${report.generatedBy}  |  Kernel v3.2`, margin, 28);
    y = 44;

    // Scorecard Box
    doc.setFillColor(248, 250, 252);
    doc.setDrawColor(203, 213, 225);
    doc.roundedRect(margin, y, pageWidth - margin * 2, 34, 2, 2, 'FD');

    doc.setFontSize(11);
    doc.setFont('helvetica', 'bold');
    doc.setTextColor(15, 23, 42);
    doc.text('Executive Scorecard & Zero-Trust Verification', margin + 4, y + 7);

    doc.setFontSize(9);
    doc.setFont('helvetica', 'normal');
    doc.setTextColor(51, 65, 85);
    doc.text(`Overall Security Score: ${report.securityScore}%`, margin + 4, y + 15);
    doc.text(`Zero-Trust Coverage: ${report.zeroTrustScore}%`, margin + 4, y + 22);
    doc.text(`CIS Benchmark Compliance: ${report.complianceScore}%`, margin + 4, y + 29);

    doc.text(`Monitored APIs: ${report.totalApis}`, margin + 75, y + 15);
    doc.text(`Critical Vulnerabilities: ${report.findingsCount.critical}`, margin + 75, y + 22);
    doc.text(`High Vulnerabilities: ${report.findingsCount.high}`, margin + 75, y + 29);

    doc.text(`Medium Vulnerabilities: ${report.findingsCount.medium}`, margin + 135, y + 15);
    doc.text(`Low / Info Findings: ${report.findingsCount.low + report.findingsCount.info}`, margin + 135, y + 22);
    doc.text(`Status: ${report.findingsCount.critical === 0 ? 'COMPLIANT' : 'ACTION REQUIRED'}`, margin + 135, y + 29);
    y += 40;

    // Executive Summary text
    checkPageBreak(25);
    doc.setFontSize(11);
    doc.setFont('helvetica', 'bold');
    doc.setTextColor(15, 23, 42);
    doc.text('Executive Evaluation Summary', margin, y);
    y += 5;
    doc.setFontSize(8.5);
    doc.setFont('helvetica', 'normal');
    doc.setTextColor(71, 85, 105);
    const summaryLines = doc.splitTextToSize(report.summary, pageWidth - margin * 2);
    doc.text(summaryLines, margin, y);
    y += summaryLines.length * 4.5 + 8;

    // Findings Matrix
    checkPageBreak(30);
    doc.setFontSize(11);
    doc.setFont('helvetica', 'bold');
    doc.setTextColor(15, 23, 42);
    doc.text('Active Security Findings & OWASP Vulnerabilities', margin, y);
    y += 5;

    doc.setFillColor(30, 41, 59);
    doc.rect(margin, y, pageWidth - margin * 2, 7, 'F');
    doc.setTextColor(255, 255, 255);
    doc.setFontSize(8);
    doc.setFont('helvetica', 'bold');
    doc.text('Finding ID', margin + 3, y + 5);
    doc.text('Title / Category', margin + 32, y + 5);
    doc.text('API / Endpoint', margin + 95, y + 5);
    doc.text('Severity', margin + 145, y + 5);
    doc.text('Status', margin + 165, y + 5);
    y += 7;

    doc.setFont('helvetica', 'normal');
    findingsList.slice(0, 15).forEach((f, idx) => {
      checkPageBreak(8);
      doc.setFillColor(idx % 2 === 0 ? 255 : 248, idx % 2 === 0 ? 255 : 250, idx % 2 === 0 ? 255 : 252);
      doc.rect(margin, y, pageWidth - margin * 2, 6, 'F');
      doc.setTextColor(30, 41, 59);
      doc.setFontSize(7.5);
      doc.text(f.findingId || f.id.slice(0, 10), margin + 3, y + 4.2);
      doc.text((f.title || '').slice(0, 35), margin + 32, y + 4.2);
      doc.text(`${f.apiName} ${f.endpoint}`.slice(0, 32), margin + 95, y + 4.2);
      doc.setFont('helvetica', 'bold');
      if (f.severity === 'CRITICAL') doc.setTextColor(220, 38, 38);
      else if (f.severity === 'HIGH') doc.setTextColor(234, 88, 12);
      else if (f.severity === 'MEDIUM') doc.setTextColor(202, 138, 4);
      else doc.setTextColor(71, 85, 105);
      doc.text(f.severity, margin + 145, y + 4.2);
      doc.setFont('helvetica', 'normal');
      doc.setTextColor(30, 41, 59);
      doc.text(f.status, margin + 165, y + 4.2);
      y += 6;
    });

    const totalPages = doc.getNumberOfPages();
    for (let p = 1; p <= totalPages; p++) {
      doc.setPage(p);
      doc.setDrawColor(226, 232, 240);
      doc.line(margin, pageHeight - 12, pageWidth - margin, pageHeight - 12);
      doc.setFont('helvetica', 'normal');
      doc.setFontSize(7.5);
      doc.setTextColor(148, 163, 184);
      doc.text(`ZENTRA Zero-Trust Security Audit | ${report.title}`, margin, pageHeight - 7);
      doc.text(`Page ${p} of ${totalPages}`, pageWidth - margin - 20, pageHeight - 7);
    }

    return doc;
  };

  // Helper to compile CSV from findings
  const buildFindingsCsv = (fList: SecurityFinding[]): string => {
    const headers = ['Finding ID', 'Title', 'API Name', 'Endpoint', 'Method', 'Category', 'Severity', 'Status', 'Description', 'Recommendation', 'Impact'];
    const rows = fList.map((f) => [
      `"${(f.findingId || f.id).replace(/"/g, '""')}"`,
      `"${(f.title || '').replace(/"/g, '""')}"`,
      `"${(f.apiName || '').replace(/"/g, '""')}"`,
      `"${(f.endpoint || '').replace(/"/g, '""')}"`,
      `"${(f.method || '').replace(/"/g, '""')}"`,
      `"${(f.category || '').replace(/"/g, '""')}"`,
      `"${f.severity}"`,
      `"${f.status}"`,
      `"${(f.description || '').replace(/"/g, '""')}"`,
      `"${(f.recommendation || '').replace(/"/g, '""')}"`,
      `"${(f.impact || '').replace(/"/g, '""')}"`,
    ]);
    return [headers.join(','), ...rows.map((r) => r.join(','))].join('\n');
  };

  // Create new API Assessment Report
  const handleCreateApiReport = async (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    try {
      setIsSubmittingReport(true);
      const created = await apiService.createReport({
        title: newTitle || undefined,
        organization: newOrg || undefined,
      });
      setApiReports((prev) => [created, ...prev]);
      setIsCreateModalOpen(false);
      setNewTitle('');
      setNewOrg('');
      showToast('Report Generated', `Compiled formal security assessment: ${created.title}`, 'success');
    } catch (err: any) {
      showToast('Report Creation Error', err.message, 'error');
    } finally {
      setIsSubmittingReport(false);
    }
  };

  // Export Single API Report PDF
  const handleExportApiReportPdf = async (report: ReportItem) => {
    try {
      setGeneratingApiPdfIds((prev) => ({ ...prev, [report.id]: true }));
      const [detail, allFindings, allApis, compliance] = await Promise.all([
        apiService.getReportDetail(report.id).catch(() => null),
        apiService.getFindings(),
        apiService.getApis(),
        apiService.getCompliance(),
      ]);
      const fList = detail?.findings || allFindings;
      const aList = detail?.apis || allApis;
      const cList = detail?.cisControls || compliance.controls;

      const doc = buildApiAssessmentPdf(report, aList, fList, cList);
      const cleanTitle = (report.title || 'report').replace(/[^a-zA-Z0-9_-]/g, '_');
      doc.save(`${cleanTitle}.pdf`);
      showToast('PDF Exported', `Downloaded PDF for ${report.title}`, 'success');
    } catch (err: any) {
      showToast('PDF Export Error', err.message, 'error');
    } finally {
      setGeneratingApiPdfIds((prev) => ({ ...prev, [report.id]: false }));
    }
  };

  // Export Single API Report as full ZIP package
  const handleExportApiReportZip = async (report: ReportItem) => {
    try {
      setGeneratingApiZipIds((prev) => ({ ...prev, [report.id]: true }));
      const [detail, allFindings, allApis, compliance, zeroTrust] = await Promise.all([
        apiService.getReportDetail(report.id).catch(() => null),
        apiService.getFindings(),
        apiService.getApis(),
        apiService.getCompliance(),
        apiService.getZeroTrust().catch(() => null),
      ]);
      const fList = detail?.findings || allFindings;
      const aList = detail?.apis || allApis;
      const cList = detail?.cisControls || compliance.controls;

      const zip = new JSZip();

      // 1. Executive PDF
      const doc = buildApiAssessmentPdf(report, aList, fList, cList);
      const pdfArrayBuffer = doc.output('arraybuffer');
      const cleanTitle = (report.title || 'report').replace(/[^a-zA-Z0-9_-]/g, '_');
      zip.file(`${cleanTitle}-Executive-Audit-Report.pdf`, pdfArrayBuffer);

      // 2. CSV findings
      zip.file('owasp-api-findings.csv', buildFindingsCsv(fList));

      // 3. Raw datasets
      zip.file('owasp-api-findings.json', JSON.stringify(fList, null, 2));
      zip.file('api-inventory.json', JSON.stringify(aList, null, 2));
      zip.file('cis-controls-evaluation.json', JSON.stringify(cList, null, 2));
      if (zeroTrust) {
        zip.file('zero-trust-assessment.json', JSON.stringify(zeroTrust, null, 2));
      }

      // 4. Manifest (with real HMAC-SHA256 seal)
      const apiSealRes = await apiService.sealReport('api-report', report.title, {
        reportId: report.id,
        title: report.title,
        organization: report.organization,
        auditor: report.generatedBy,
        scores: { securityScore: report.securityScore, zeroTrustScore: report.zeroTrustScore, complianceScore: report.complianceScore },
        findingsSummary: report.findingsCount,
        totalFindings: fList.length,
        totalApis: aList.length,
        reportCreatedAt: report.createdAt,
      });
      zip.file('report.seal.json', JSON.stringify({ seal: apiSealRes.seal, algorithm: apiSealRes.algorithm, payload: apiSealRes.payload }, null, 2));
      const manifest = {
        packageType: 'ZENTRA Enterprise Zero-Trust API Security Assessment Archive',
        reportId: report.id,
        title: report.title,
        organization: report.organization,
        auditor: report.generatedBy,
        generatedAt: new Date().toISOString(),
        scores: {
          securityScore: report.securityScore,
          zeroTrustScore: report.zeroTrustScore,
          complianceScore: report.complianceScore,
        },
        findingsSummary: report.findingsCount,
        files: [
          `${cleanTitle}-Executive-Audit-Report.pdf`,
          'owasp-api-findings.csv',
          'owasp-api-findings.json',
          'api-inventory.json',
          'cis-controls-evaluation.json',
          'zero-trust-assessment.json',
        ],
        cryptographicProof: { algorithm: 'HMAC-SHA256', seal: apiSealRes.seal, sealedAt: apiSealRes.sealedAt },
      };
      zip.file('audit-manifest.json', JSON.stringify(manifest, null, 2));

      const zipBlob = await zip.generateAsync({ type: 'blob' });
      const url = URL.createObjectURL(zipBlob);
      const link = document.createElement('a');
      link.href = url;
      link.download = `zentra-api-security-${cleanTitle}.zip`;
      link.click();
      URL.revokeObjectURL(url);

      showToast('ZIP Package Exported', `Generated full ZIP archive for ${report.title}`, 'success');
    } catch (err: any) {
      showToast('ZIP Export Error', err.message, 'error');
    } finally {
      setGeneratingApiZipIds((prev) => ({ ...prev, [report.id]: false }));
    }
  };

  // Export All API Reports into bulk ZIP archive
  const handleExportAllApiReportsZip = async () => {
    if (apiReports.length === 0) {
      showToast('No Reports Available', 'Generate an assessment report first.', 'warning');
      return;
    }

    try {
      setIsBulkExporting(true);
      const zip = new JSZip();

      const [allFindings, allApis, compliance, zeroTrust] = await Promise.all([
        apiService.getFindings(),
        apiService.getApis(),
        apiService.getCompliance(),
        apiService.getZeroTrust().catch(() => null),
      ]);

      for (let i = 0; i < apiReports.length; i++) {
        const rep = apiReports[i];
        setBulkProgress({
          current: i + 1,
          total: apiReports.length,
          hostname: rep.title,
        });

        const doc = buildApiAssessmentPdf(rep, allApis, allFindings, compliance.controls);
        const pdfBuf = doc.output('arraybuffer');
        const cleanName = (rep.title || `report-${i + 1}`).replace(/[^a-zA-Z0-9_-]/g, '_');
        zip.file(`reports/${cleanName}.pdf`, pdfBuf);
      }

      zip.file('owasp-api-findings.csv', buildFindingsCsv(allFindings));
      zip.file('owasp-api-findings.json', JSON.stringify(allFindings, null, 2));
      zip.file('api-inventory.json', JSON.stringify(allApis, null, 2));
      zip.file('cis-controls.json', JSON.stringify(compliance.controls, null, 2));
      if (zeroTrust) {
        zip.file('zero-trust-assessment.json', JSON.stringify(zeroTrust, null, 2));
      }

      const manifest = {
        generatedAt: new Date().toISOString(),
        totalReports: apiReports.length,
        reports: apiReports.map((r) => ({
          id: r.id,
          title: r.title,
          org: r.organization,
          securityScore: r.securityScore,
          zeroTrustScore: r.zeroTrustScore,
        })),
        engine: 'ZENTRA Enterprise Zero-Trust API Security Engine',
      };
      zip.file('audit-manifest.json', JSON.stringify(manifest, null, 2));

      setBulkProgress({
        current: apiReports.length,
        total: apiReports.length,
        hostname: 'Packaging ZIP Archive...',
      });

      const zipBlob = await zip.generateAsync({ type: 'blob' });
      const url = URL.createObjectURL(zipBlob);
      const link = document.createElement('a');
      link.href = url;
      link.download = `zentra-api-security-reports-${new Date().toISOString().split('T')[0]}.zip`;
      link.click();
      URL.revokeObjectURL(url);

      showToast('Bulk API ZIP Complete', `Packaged ${apiReports.length} API security reports into ZIP.`, 'success');
    } catch (err: any) {
      showToast('ZIP Export Error', err.message, 'error');
    } finally {
      setIsBulkExporting(false);
      setBulkProgress(null);
    }
  };

  // Export Unified Master Enterprise Compliance Bundle (.zip)
  const handleExportMasterBundleZip = async () => {
    try {
      setIsBulkExporting(true);
      const zip = new JSZip();

      // 1. Pack network fleet reports
      setBulkProgress({ current: 1, total: 3, hostname: 'Generating Network Fleet Reports...' });
      const fleetFolder = zip.folder('network-fleet');
      for (let i = 0; i < devices.length; i++) {
        const d = devices[i];
        const { doc, filename, sealFile } = await buildDevicePdf(d);
        fleetFolder?.file(filename, doc.output('arraybuffer'));
        if (sealFile) fleetFolder?.file(sealFile.name, sealFile.content);
      }

      // 2. Pack API security reports
      setBulkProgress({ current: 2, total: 3, hostname: 'Generating API Security Audits...' });
      const [allFindings, allApis, compliance, zeroTrust] = await Promise.all([
        apiService.getFindings().catch(() => []),
        apiService.getApis().catch(() => []),
        apiService.getCompliance().catch(() => ({ controls: [] as CISControl[] })),
        apiService.getZeroTrust().catch(() => null),
      ]);

      const apiFolder = zip.folder('api-security');
      if (apiReports.length > 0) {
        const primaryRep = apiReports[0];
        const doc = buildApiAssessmentPdf(primaryRep, allApis, allFindings, compliance.controls);
        apiFolder?.file('Executive-API-Security-Audit.pdf', doc.output('arraybuffer'));
      }
      apiFolder?.file('owasp-api-findings.csv', buildFindingsCsv(allFindings));
      apiFolder?.file('owasp-api-findings.json', JSON.stringify(allFindings, null, 2));
      apiFolder?.file('api-inventory.json', JSON.stringify(allApis, null, 2));
      apiFolder?.file('cis-controls-evaluation.json', JSON.stringify(compliance.controls, null, 2));
      if (zeroTrust) {
        apiFolder?.file('zero-trust-assessment.json', JSON.stringify(zeroTrust, null, 2));
      }

      // 3. Master Manifest
      setBulkProgress({ current: 3, total: 3, hostname: 'Packaging Master Enterprise ZIP...' });
      const masterBody = {
        bundle: 'ZENTRA Complete Enterprise Security & Compliance Bundle',
        timestamp: new Date().toISOString(),
        auditor: user?.name || 'Security Lead',
        networkFleet: {
          totalDevices: devices.length,
          devices: devices.map((d) => ({
            hostname: d.hostname,
            vendor: d.detectedVendor,
            complianceScore: d.overallComplianceScore,
          })),
        },
        apiSecurity: {
          totalApis: allApis.length,
          totalFindings: allFindings.length,
          criticalCount: allFindings.filter((f) => f.severity === 'CRITICAL').length,
          cisControlsCount: compliance.controls.length,
        },
      };
      const masterSealRes = await apiService.sealReport('master-bundle', 'Master Compliance Bundle', masterBody);
      const masterManifest = {
        ...masterBody,
        signature: { algorithm: masterSealRes.algorithm, seal: masterSealRes.seal, sealedAt: masterSealRes.sealedAt },
      };
      zip.file('MASTER-COMPLIANCE-MANIFEST.json', JSON.stringify(masterManifest, null, 2));
      zip.file('MASTER.seal.json', JSON.stringify({ seal: masterSealRes.seal, algorithm: masterSealRes.algorithm, payload: masterSealRes.payload }, null, 2));

      const blob = await zip.generateAsync({ type: 'blob' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `zentra-complete-enterprise-audit-package-${new Date().toISOString().split('T')[0]}.zip`;
      a.click();
      URL.revokeObjectURL(url);

      showToast(
        'Master Bundle Exported',
        'Successfully generated master ZIP containing all API security audits and network fleet reports.',
        'success'
      );
    } catch (err: any) {
      showToast('Master Export Error', err.message, 'error');
    } finally {
      setIsBulkExporting(false);
      setBulkProgress(null);
    }
  };

  // Preview Modal
  const handleOpenPreview = async (device: NetworkDevice) => {
    setPreviewDevice(device);
    setLoadingPreview(true);

    try {
      // Find failed controls
      const devEvals = evaluations.filter((e) => e.deviceId === device.id);
      const failedControls: ControlEvaluationResult[] = [];
      devEvals.forEach((ev) => {
        ev.controlResults.forEach((c) => {
          if (c.status === 'FAIL' && !failedControls.some((fc) => fc.controlId === c.controlId)) {
            failedControls.push(c);
          }
        });
      });

      if (failedControls.length > 0) {
        const res = await apiService.getVendorCliRemediations({
          vendor: device.detectedVendor,
          model: device.model,
          hostname: device.hostname,
          controls: failedControls.map((fc) => ({
            controlId: fc.controlId,
            title: fc.title,
            field: fc.field,
            expectedValue: fc.expectedValue,
            actualValue: fc.actualValue,
            remediation: fc.remediation,
          })),
        });
        setPreviewRemediations(res.remediations);
        setFixDrafts((prev) => {
          const next = { ...prev };
          res.remediations.forEach((r) => {
            const key = `${device.id}::${r.controlId}`;
            if (!next[key]) next[key] = { original: r.cliCommands, text: r.cliCommands, approved: false, editing: false };
          });
          return next;
        });
      } else {
        setPreviewRemediations([]);
      }
    } catch (err: any) {
      console.warn('Preview error:', err);
    } finally {
      setLoadingPreview(false);
    }
  };

  const updateDraft = (key: string, patch: Partial<{ text: string; approved: boolean; editing: boolean }>) =>
    setFixDrafts((prev) => ({ ...prev, [key]: { ...prev[key], ...patch } }));

  const handleApproveFix = async (device: NetworkDevice, controlId: string) => {
    const key = `${device.id}::${controlId}`;
    const d = fixDrafts[key];
    if (!d) return;
    updateDraft(key, { approved: true, editing: false });
    try {
      await apiService.logFixAudit({
        deviceId: device.id,
        hostname: device.hostname,
        approvedCount: 1,
        edits: d.text !== d.original ? [{ controlId }] : [],
      });
    } catch (err) {
      console.warn('Fix audit log failed:', err);
    }
  };

  // Filtered devices list
  const filteredDevices = useMemo(() => {
    return devices.filter((d) => {
      if (vendorFilter !== 'ALL' && !d.detectedVendor.toLowerCase().includes(vendorFilter.toLowerCase())) {
        return false;
      }
      if (search.trim()) {
        const q = search.toLowerCase().trim();
        const matchesHost = d.hostname?.toLowerCase().includes(q);
        const matchesFile = d.filename.toLowerCase().includes(q);
        const matchesVendor = d.detectedVendor.toLowerCase().includes(q);
        const matchesModel = d.model?.toLowerCase().includes(q);
        if (!matchesHost && !matchesFile && !matchesVendor && !matchesModel) return false;
      }
      return true;
    });
  }, [devices, vendorFilter, search]);

  const uniqueVendors = useMemo(() => {
    return Array.from(new Set(devices.map((d) => d.detectedVendor)));
  }, [devices]);

  return (
    <div className="space-y-6 text-left">
      {/* Page Header */}
      <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4 p-5 rounded-xl border border-slate-800 bg-slate-900/50 backdrop-blur-md">
        <div>
          <div className="flex items-center space-x-2">
            <h1 className="text-2xl font-bold text-white tracking-tight flex items-center gap-2">
              <FileText className="w-6 h-6 text-cyan-400" />
              Security Audit & Compliance Reports
            </h1>
            <span className="px-2.5 py-0.5 rounded-full text-xs font-semibold bg-cyan-500/10 text-cyan-400 border border-cyan-500/30">
              Bulk ZIP Packages Enabled
            </span>
          </div>
          <p className="text-sm text-slate-400 mt-1">
            Generate and package formal security assessment certificates, multi-framework compliance audits, and SIEM-ready finding datasets into downloadable ZIP archives.
          </p>
        </div>

        <div className="flex items-center gap-2.5 flex-wrap">
          {/* Master Bundle Export (Combines both API + Fleet reports) */}
          <button
            onClick={handleExportMasterBundleZip}
            disabled={isBulkExporting}
            className="px-3.5 py-2 text-xs font-semibold bg-gradient-to-r from-purple-600 to-indigo-600 hover:from-purple-500 hover:to-indigo-500 text-white rounded-lg flex items-center gap-2 shadow-lg shadow-purple-900/30 transition-all disabled:opacity-50 cursor-pointer"
            title="Package all API assessments and Network Fleet PDF certificates into one comprehensive master ZIP archive"
          >
            <PackageCheck className="w-4 h-4 text-purple-200" />
            <span>Master Enterprise Bundle (.zip)</span>
          </button>

          {activeReportTab === 'api' ? (
            <>
              <button
                onClick={() => setIsCreateModalOpen(true)}
                className="px-3.5 py-2 text-xs font-semibold bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 rounded-lg flex items-center gap-1.5 transition-colors cursor-pointer"
              >
                <Plus className="w-3.5 h-3.5 text-cyan-400" />
                <span>New API Assessment</span>
              </button>

              <button
                onClick={handleExportAllApiReportsZip}
                disabled={isBulkExporting || apiReports.length === 0}
                className="px-4 py-2 text-xs font-semibold bg-cyan-600 hover:bg-cyan-500 text-white rounded-lg flex items-center gap-2 shadow-lg shadow-cyan-900/30 transition-all disabled:opacity-50 cursor-pointer"
              >
                <Archive className="w-4 h-4" />
                <span>{isBulkExporting ? 'Packaging ZIP...' : `Export All API Reports (.zip)`}</span>
              </button>
            </>
          ) : (
            <>
              <button
                onClick={handleLoadSampleDevices}
                className="px-3.5 py-2 text-xs font-semibold bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 rounded-lg flex items-center gap-1.5 transition-colors cursor-pointer"
              >
                <Sparkles className="w-3.5 h-3.5 text-amber-400" />
                <span>Load Sample Fleet (5 Vendors)</span>
              </button>

              <button
                onClick={handleExportAllZip}
                disabled={isBulkExporting || devices.length === 0}
                className="px-4 py-2 text-xs font-semibold bg-cyan-600 hover:bg-cyan-500 text-white rounded-lg flex items-center gap-2 shadow-lg shadow-cyan-900/30 transition-all disabled:opacity-50 cursor-pointer"
              >
                <Archive className="w-4 h-4" />
                <span>{isBulkExporting ? 'Packaging ZIP...' : `Export All Fleet as ZIP (${devices.length})`}</span>
              </button>
            </>
          )}
        </div>
      </div>

      {/* Mode Navigation Tabs */}
      <div className="flex items-center gap-2 border-b border-slate-800 pb-2">
        <button
          onClick={() => setActiveReportTab('api')}
          className={`flex items-center gap-2 px-4 py-2 rounded-lg text-xs font-semibold transition cursor-pointer ${
            activeReportTab === 'api'
              ? 'bg-cyan-500/20 text-cyan-200 border border-cyan-500/40 shadow-sm'
              : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900'
          }`}
        >
          <Server className="w-4 h-4 text-cyan-400" />
          <span>API & Zero-Trust Security Assessments</span>
          <span className="text-[10px] font-mono bg-cyan-950/80 border border-cyan-500/30 text-cyan-300 px-1.5 py-0.5 rounded">
            {apiReports.length} Reports | ZIP Package
          </span>
        </button>

        <button
          onClick={() => setActiveReportTab('fleet')}
          className={`flex items-center gap-2 px-4 py-2 rounded-lg text-xs font-semibold transition cursor-pointer ${
            activeReportTab === 'fleet'
              ? 'bg-cyan-500/20 text-cyan-200 border border-cyan-500/40 shadow-sm'
              : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900'
          }`}
        >
          <Cpu className="w-4 h-4 text-cyan-400" />
          <span>Network Device Baseline Audits</span>
          <span className="text-[10px] font-mono bg-slate-800 border border-slate-700 text-slate-300 px-1.5 py-0.5 rounded">
            {devices.length} Devices | ZIP Bulk Export
          </span>
        </button>
      </div>

      {/* Progress Overlay for Bulk ZIP Export */}
      {isBulkExporting && bulkProgress && (
        <Card className="p-4 bg-cyan-950/40 border-cyan-800 animate-pulse">
          <div className="flex items-center justify-between text-xs text-cyan-300 font-mono mb-2">
            <span className="flex items-center gap-2">
              <RotateCw className="w-4 h-4 animate-spin text-cyan-400" />
              Generating & Packaging: {bulkProgress.hostname} ({bulkProgress.current} of {bulkProgress.total})
            </span>
            <span>{Math.round((bulkProgress.current / bulkProgress.total) * 100)}%</span>
          </div>
          <div className="w-full bg-slate-900 h-2 rounded-full overflow-hidden">
            <div
              className="bg-cyan-500 h-full transition-all duration-300"
              style={{ width: `${(bulkProgress.current / bulkProgress.total) * 100}%` }}
            />
          </div>
        </Card>
      )}

      {/* TAB 1: API & ZERO-TRUST ASSESSMENT REPORTS ("THE OLD ONE" + ZIP PACKAGE) */}
      {activeReportTab === 'api' && (
        <div className="space-y-6">
          {/* Quick Metrics */}
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
            <Card className="p-4 bg-slate-900/60 border-slate-800">
              <div className="text-xs text-slate-400 font-medium">Assessment Reports</div>
              <div className="text-2xl font-bold font-mono text-cyan-400 mt-1">{apiReports.length}</div>
              <div className="text-[11px] text-slate-500 mt-0.5">Formal executive certificates</div>
            </Card>

            <Card className="p-4 bg-slate-900/60 border-slate-800">
              <div className="text-xs text-slate-400 font-medium">Monitored APIs & Services</div>
              <div className="text-2xl font-bold font-mono text-emerald-400 mt-1">{apis.length}</div>
              <div className="text-[11px] text-slate-500 mt-0.5">Endpoints & gateways scanned</div>
            </Card>

            <Card className="p-4 bg-slate-900/60 border-slate-800">
              <div className="text-xs text-slate-400 font-medium">CIS API Benchmark Controls</div>
              <div className="text-2xl font-bold font-mono text-blue-400 mt-1">{cisControls.length}</div>
              <div className="text-[11px] text-slate-500 mt-0.5">Security baseline checks</div>
            </Card>

            <Card className="p-4 bg-slate-900/60 border-slate-800">
              <div className="text-xs text-slate-400 font-medium">Active Security Findings</div>
              <div className="text-2xl font-bold font-mono text-rose-400 mt-1">{findings.length}</div>
              <div className="text-[11px] text-slate-500 mt-0.5">
                {findings.filter((f) => f.severity === 'CRITICAL').length} Critical /{' '}
                {findings.filter((f) => f.severity === 'HIGH').length} High
              </div>
            </Card>
          </div>

          {/* API Reports List */}
          {loading ? (
            <div className="py-20 text-center">
              <div className="w-8 h-8 border-2 border-cyan-500 border-t-transparent rounded-full animate-spin mx-auto mb-3" />
              <p className="text-xs font-mono text-cyan-400">LOADING API SECURITY AUDITS...</p>
            </div>
          ) : apiReports.length === 0 ? (
            <Card className="p-12 text-center bg-slate-900/60 border-slate-800">
              <Server className="w-12 h-12 text-slate-600 mx-auto mb-3" />
              <h3 className="text-base font-medium text-slate-300">No Assessment Reports Yet</h3>
              <p className="text-xs text-slate-500 max-w-md mx-auto mt-1 mb-4">
                Compile your first formal API Security Assessment report. It includes Zero-Trust verification scores, CIS benchmark compliance, and downloadable ZIP bundles with raw JSON and CSV exports.
              </p>
              <button
                onClick={() => setIsCreateModalOpen(true)}
                className="px-4 py-2 text-xs font-semibold bg-cyan-600 hover:bg-cyan-500 text-white rounded-lg inline-flex items-center gap-2 cursor-pointer"
              >
                <Plus className="w-3.5 h-3.5" />
                Generate Assessment Report
              </button>
            </Card>
          ) : (
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
              {apiReports.map((rep) => {
                const isPdfGen = !!generatingApiPdfIds[rep.id];
                const isZipGen = !!generatingApiZipIds[rep.id];
                const scoreColor =
                  rep.securityScore >= 80
                    ? 'text-emerald-400 bg-emerald-950/60 border-emerald-500/30'
                    : rep.securityScore >= 60
                    ? 'text-amber-400 bg-amber-950/60 border-amber-500/30'
                    : 'text-rose-400 bg-rose-950/60 border-rose-500/30';

                return (
                  <Card
                    key={rep.id}
                    className="bg-slate-900/90 border-slate-800 hover:border-slate-700 transition p-5 flex flex-col justify-between"
                  >
                    <div>
                      {/* Top title and score */}
                      <div className="flex items-start justify-between gap-3 mb-3">
                        <div>
                          <span className="text-[10px] font-mono uppercase tracking-wider text-slate-500">
                            {rep.organization || 'Enterprise Cyber Command'}
                          </span>
                          <h3 className="text-base font-bold text-slate-100 mt-0.5 line-clamp-1">
                            {rep.title}
                          </h3>
                          <div className="flex items-center gap-2 text-xs text-slate-400 mt-1">
                            <span>Auditor: {rep.generatedBy}</span>
                            <span>•</span>
                            <span>{new Date(rep.createdAt).toLocaleDateString()}</span>
                          </div>
                        </div>

                        <div className={`px-3 py-1.5 rounded-lg border font-mono text-center shrink-0 ${scoreColor}`}>
                          <div className="text-lg font-bold leading-none">{rep.securityScore}%</div>
                          <div className="text-[9px] uppercase tracking-wider opacity-80 mt-0.5">Score</div>
                        </div>
                      </div>

                      {/* Summary pill matrix */}
                      <div className="grid grid-cols-3 gap-2 py-3 my-2 border-y border-slate-800/80 text-center">
                        <div className="p-2 rounded bg-slate-950/60 border border-slate-800">
                          <div className="text-[10px] font-mono text-slate-400">Zero-Trust</div>
                          <div className="text-sm font-mono font-bold text-cyan-300 mt-0.5">{rep.zeroTrustScore}%</div>
                        </div>
                        <div className="p-2 rounded bg-slate-950/60 border border-slate-800">
                          <div className="text-[10px] font-mono text-slate-400">CIS Benchmark</div>
                          <div className="text-sm font-mono font-bold text-emerald-300 mt-0.5">{rep.complianceScore}%</div>
                        </div>
                        <div className="p-2 rounded bg-slate-950/60 border border-slate-800">
                          <div className="text-[10px] font-mono text-slate-400">Target APIs</div>
                          <div className="text-sm font-mono font-bold text-slate-200 mt-0.5">{rep.totalApis}</div>
                        </div>
                      </div>

                      {/* Findings count breakdown */}
                      <div className="flex items-center gap-1.5 flex-wrap my-3 text-[11px] font-mono">
                        <span className="px-2 py-0.5 rounded bg-rose-950/60 border border-rose-800/60 text-rose-300 font-bold">
                          {rep.findingsCount?.critical ?? 0} Critical
                        </span>
                        <span className="px-2 py-0.5 rounded bg-orange-950/60 border border-orange-800/60 text-orange-300">
                          {rep.findingsCount?.high ?? 0} High
                        </span>
                        <span className="px-2 py-0.5 rounded bg-amber-950/60 border border-amber-800/60 text-amber-300">
                          {rep.findingsCount?.medium ?? 0} Medium
                        </span>
                        <span className="px-2 py-0.5 rounded bg-slate-800 border border-slate-700 text-slate-300">
                          {rep.findingsCount?.low ?? 0} Low
                        </span>
                      </div>

                      <p className="text-xs text-slate-400 line-clamp-2 mt-2 leading-relaxed">
                        {rep.summary}
                      </p>
                    </div>

                    {/* Action buttons */}
                    <div className="flex items-center gap-2 pt-4 mt-4 border-t border-slate-800/80">
                      <button
                        onClick={() => handleExportApiReportPdf(rep)}
                        disabled={isPdfGen}
                        className="flex-1 py-2 px-2.5 rounded-lg border border-slate-700 bg-slate-800/80 hover:bg-slate-700 text-slate-200 text-xs font-semibold flex items-center justify-center gap-1.5 transition disabled:opacity-50 cursor-pointer"
                        title="Download single-page executive assessment PDF"
                      >
                        {isPdfGen ? (
                          <RotateCw className="w-3.5 h-3.5 animate-spin text-cyan-400" />
                        ) : (
                          <Download className="w-3.5 h-3.5 text-cyan-400" />
                        )}
                        <span>{isPdfGen ? 'Building PDF...' : 'Download PDF'}</span>
                      </button>

                      {/* The prominent ZIP export button! */}
                      <button
                        onClick={() => handleExportApiReportZip(rep)}
                        disabled={isZipGen}
                        className="flex-1 py-2 px-2.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-semibold flex items-center justify-center gap-1.5 transition shadow-lg shadow-cyan-900/20 disabled:opacity-50 cursor-pointer"
                        title="Export complete ZIP archive with PDF, findings CSV, JSON datasets, and audit manifest"
                      >
                        {isZipGen ? (
                          <RotateCw className="w-3.5 h-3.5 animate-spin text-white" />
                        ) : (
                          <Archive className="w-3.5 h-3.5 text-cyan-200" />
                        )}
                        <span>{isZipGen ? 'Packaging ZIP...' : 'Export Package (.zip)'}</span>
                      </button>

                      <button
                        onClick={() => setSelectedApiReport(rep)}
                        className="p-2 rounded-lg border border-slate-800 bg-slate-950/60 hover:bg-slate-800 text-slate-400 hover:text-slate-200 transition cursor-pointer"
                        title="Inspect full audit summary modal"
                      >
                        <Eye className="w-4 h-4" />
                      </button>
                    </div>
                  </Card>
                );
              })}
            </div>
          )}
        </div>
      )}

      {/* TAB 2: NETWORK FLEET BASELINE AUDITS */}
      {activeReportTab === 'fleet' && (
        <div className="space-y-6">
          {/* Filter and Search Bar */}
          <Card className="p-4 bg-slate-900/60 border-slate-800">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
              <div className="flex items-center gap-3">
                <div className="relative">
                  <Search className="w-3.5 h-3.5 absolute left-2.5 top-1/2 -translate-y-1/2 text-slate-400" />
                  <input
                    type="text"
                    placeholder="Search by hostname, model, or filename..."
                    value={search}
                    onChange={(e) => setSearch(e.target.value)}
                    className="bg-slate-950 border border-slate-800 text-slate-200 text-xs rounded-lg pl-8 pr-3 py-1.5 focus:outline-none focus:border-cyan-500 w-64 placeholder:text-slate-600"
                  />
                </div>

                <select
                  value={vendorFilter}
                  onChange={(e) => setVendorFilter(e.target.value)}
                  className="bg-slate-950 border border-slate-800 text-slate-300 text-xs rounded-lg px-3 py-1.5 focus:outline-none focus:border-cyan-500"
                >
                  <option value="ALL">All Vendors ({uniqueVendors.length})</option>
                  {uniqueVendors.map((v) => (
                    <option key={v} value={v}>
                      {v}
                    </option>
                  ))}
                </select>
              </div>

              <div className="text-xs text-slate-400">
                Showing <span className="text-slate-200 font-mono font-bold">{filteredDevices.length}</span> of{' '}
                <span className="text-slate-200 font-mono">{devices.length}</span> devices ready for PDF / ZIP export
              </div>
            </div>
          </Card>

      {/* Devices Grid for Report Generation */}
      {loading ? (
        <div className="py-20 text-center">
          <div className="w-8 h-8 border-2 border-cyan-500 border-t-transparent rounded-full animate-spin mx-auto mb-3" />
          <p className="text-xs font-mono text-cyan-400">LOADING DEVICE REPOSITORY...</p>
        </div>
      ) : filteredDevices.length === 0 ? (
        <Card className="p-12 text-center bg-slate-900/60 border-slate-800">
          <Server className="w-12 h-12 text-slate-600 mx-auto mb-3" />
          <h3 className="text-base font-medium text-slate-300">No Network Devices Found</h3>
          <p className="text-xs text-slate-500 max-w-md mx-auto mt-1 mb-4">
            Upload configuration files or load the 5 realistic multi-vendor sample configurations to generate per-device audit PDFs.
          </p>
          <button
            onClick={handleLoadSampleDevices}
            className="px-4 py-2 text-xs font-semibold bg-cyan-600 hover:bg-cyan-500 text-white rounded-lg inline-flex items-center gap-2"
          >
            <Sparkles className="w-3.5 h-3.5" />
            Load Sample Fleet Now
          </button>
        </Card>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {filteredDevices.map((dev) => {
            const isGenerating = !!generatingIds[dev.id];
            const devEvals = evaluations.filter((e) => e.deviceId === dev.id);
            let failedCount = 0;
            devEvals.forEach((e) => {
              failedCount += e.failedCount;
            });

            return (
              <Card
                key={dev.id}
                className="bg-slate-900/90 border-slate-800 hover:border-slate-700 transition-all p-5 flex flex-col justify-between"
              >
                <div>
                  <div className="flex items-start justify-between gap-2 mb-2">
                    <div>
                      <div className="flex items-center gap-2">
                        <Server className="w-4 h-4 text-cyan-400" />
                        <h3 className="font-bold text-slate-100 text-sm tracking-tight truncate max-w-[180px]">
                          {dev.hostname || dev.filename}
                        </h3>
                      </div>
                      <div className="text-[11px] text-slate-400 mt-0.5">
                        {dev.filename}
                      </div>
                    </div>

                    <span
                      className={`text-sm font-extrabold font-mono px-2 py-0.5 rounded ${
                        dev.overallComplianceScore >= 80
                          ? 'bg-emerald-950 text-emerald-400 border border-emerald-800'
                          : dev.overallComplianceScore >= 60
                          ? 'bg-amber-950 text-amber-400 border border-amber-800'
                          : 'bg-rose-950 text-rose-400 border border-rose-800'
                      }`}
                    >
                      {dev.overallComplianceScore}%
                    </span>
                  </div>

                  {/* Metadata Chips */}
                  <div className="space-y-1.5 my-3 pt-2 border-t border-slate-800/60 text-xs">
                    <div className="flex items-center justify-between">
                      <span className="text-slate-500">Vendor / OS:</span>
                      <span className="text-slate-200 font-medium truncate max-w-[160px]">
                        {dev.detectedVendor}
                      </span>
                    </div>

                    <div className="flex items-center justify-between">
                      <span className="text-slate-500">Hardware Model:</span>
                      <span className="text-slate-300 font-mono text-[11px] truncate max-w-[160px]">
                        {dev.model || 'Enterprise Switch'}
                      </span>
                    </div>

                    <div className="flex items-center justify-between">
                      <span className="text-slate-500">Serial Number:</span>
                      <span className="text-slate-400 font-mono text-[11px]">
                        {dev.serialNumber || 'SN-UNKNOWN'}
                      </span>
                    </div>

                    <div className="flex items-center justify-between">
                      <span className="text-slate-500">Non-Compliant Gaps:</span>
                      <span className={`font-mono text-xs font-bold ${failedCount > 0 ? 'text-rose-400' : 'text-emerald-400'}`}>
                        {failedCount} failed controls
                      </span>
                    </div>
                  </div>

                  {/* Mini Framework Matrix */}
                  <div className="grid grid-cols-4 gap-1 py-2 text-center text-[10px] font-mono bg-slate-950 rounded border border-slate-800/80 mb-4">
                    {['cis', 'nist', 'disa-stig', 'iso-27001'].map((fwId) => {
                      const ev = devEvals.find((e) => e.frameworkId === fwId);
                      const sc = ev ? ev.complianceScore : dev.overallComplianceScore;
                      return (
                        <div key={fwId} className="p-1">
                          <div className="text-slate-500 uppercase">{fwId.split('-')[0]}</div>
                          <div className={`font-bold mt-0.5 ${sc >= 80 ? 'text-emerald-400' : sc >= 60 ? 'text-amber-400' : 'text-rose-400'}`}>
                            {sc}%
                          </div>
                        </div>
                      );
                    })}
                  </div>
                </div>

                {/* Actions */}
                <div className="flex items-center gap-2 pt-2 border-t border-slate-800">
                  <button
                    onClick={() => handleOpenPreview(dev)}
                    className="flex-1 py-1.5 px-2 text-xs font-medium text-slate-300 hover:text-white bg-slate-800/80 hover:bg-slate-700/80 border border-slate-700 rounded-lg flex items-center justify-center gap-1 transition-colors"
                  >
                    <Eye className="w-3.5 h-3.5 text-slate-400" />
                    Preview
                  </button>

                  <button
                    onClick={() => handleExportSinglePdf(dev)}
                    disabled={isGenerating}
                    className="flex-1 py-1.5 px-2 text-xs font-semibold text-cyan-300 bg-cyan-950/60 hover:bg-cyan-900/60 border border-cyan-800 rounded-lg flex items-center justify-center gap-1.5 transition-colors disabled:opacity-50"
                  >
                    <Download className={`w-3.5 h-3.5 ${isGenerating ? 'animate-spin' : ''}`} />
                    {isGenerating ? 'Generating...' : 'Export PDF'}
                  </button>
                </div>
              </Card>
            );
          })}
        </div>
      )}
        </div>
      )}

      {/* CREATE API ASSESSMENT REPORT MODAL ("THE OLD ONE") */}
      {isCreateModalOpen && (
        <Modal
          isOpen={isCreateModalOpen}
          onClose={() => setIsCreateModalOpen(false)}
          title="Generate Formal API Security Assessment"
          maxWidth="lg"
        >
          <form onSubmit={handleCreateApiReport} className="space-y-4">
            <p className="text-xs text-slate-400">
              This initiates a formal multi-domain security evaluation across active API endpoints, CIS API benchmark controls, OWASP vulnerabilities, and Zero-Trust pillars.
            </p>

            <div>
              <label className="block text-xs font-semibold text-slate-300 mb-1">
                Assessment Title
              </label>
              <input
                type="text"
                placeholder="e.g. Enterprise Production API Security Assessment"
                value={newTitle}
                onChange={(e) => setNewTitle(e.target.value)}
                className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs text-slate-100 placeholder:text-slate-600 focus:outline-none focus:border-cyan-500"
              />
            </div>

            <div>
              <label className="block text-xs font-semibold text-slate-300 mb-1">
                Organization / Division
              </label>
              <input
                type="text"
                placeholder="e.g. Cybersecurity Operations Center"
                value={newOrg}
                onChange={(e) => setNewOrg(e.target.value)}
                className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs text-slate-100 placeholder:text-slate-600 focus:outline-none focus:border-cyan-500"
              />
            </div>

            <div className="p-3 bg-slate-950/80 rounded-lg border border-slate-800/80 text-xs text-slate-400 space-y-1">
              <div className="flex items-center justify-between text-[11px]">
                <span className="text-slate-500">Auditor Identity:</span>
                <span className="text-cyan-300 font-mono">{user?.name} ({user?.role})</span>
              </div>
              <div className="flex items-center justify-between text-[11px]">
                <span className="text-slate-500">Target APIs:</span>
                <span className="text-slate-200 font-mono">{apis.length} Active Services</span>
              </div>
              <div className="flex items-center justify-between text-[11px]">
                <span className="text-slate-500">ZIP Export Included:</span>
                <span className="text-emerald-400 font-mono font-bold">YES (PDF + CSV + JSON)</span>
              </div>
            </div>

            <div className="flex items-center justify-end gap-3 pt-3 border-t border-slate-800">
              <button
                type="button"
                onClick={() => setIsCreateModalOpen(false)}
                className="px-4 py-2 text-xs text-slate-400 hover:text-slate-200 transition"
              >
                Cancel
              </button>
              <button
                type="submit"
                disabled={isSubmittingReport}
                className="px-4 py-2 text-xs font-semibold bg-cyan-600 hover:bg-cyan-500 text-white rounded-lg flex items-center gap-1.5 shadow-lg shadow-cyan-900/30 transition disabled:opacity-50"
              >
                {isSubmittingReport ? (
                  <RotateCw className="w-3.5 h-3.5 animate-spin" />
                ) : (
                  <Plus className="w-3.5 h-3.5" />
                )}
                <span>{isSubmittingReport ? 'Compiling...' : 'Generate & Certify Report'}</span>
              </button>
            </div>
          </form>
        </Modal>
      )}

      {/* VIEW API REPORT DETAIL MODAL */}
      {selectedApiReport && (
        <Modal
          isOpen={!!selectedApiReport}
          onClose={() => setSelectedApiReport(null)}
          title={`Executive Assessment: ${selectedApiReport.title}`}
          maxWidth="2xl"
        >
          <div className="space-y-4">
            <div className="p-4 bg-slate-950 rounded-xl border border-slate-800 grid grid-cols-3 gap-3 text-center">
              <div className="p-2 rounded bg-slate-900 border border-slate-800">
                <span className="text-[10px] font-mono text-slate-400 block uppercase">Security Score</span>
                <span className="text-lg font-bold font-mono text-emerald-400">{selectedApiReport.securityScore}%</span>
              </div>
              <div className="p-2 rounded bg-slate-900 border border-slate-800">
                <span className="text-[10px] font-mono text-slate-400 block uppercase">Zero-Trust Posture</span>
                <span className="text-lg font-bold font-mono text-cyan-400">{selectedApiReport.zeroTrustScore}%</span>
              </div>
              <div className="p-2 rounded bg-slate-900 border border-slate-800">
                <span className="text-[10px] font-mono text-slate-400 block uppercase">CIS Benchmark</span>
                <span className="text-lg font-bold font-mono text-blue-400">{selectedApiReport.complianceScore}%</span>
              </div>
            </div>

            <div className="space-y-2 text-xs text-slate-300">
              <div className="text-slate-400 font-semibold uppercase text-[11px] tracking-wider">Executive Summary</div>
              <div className="p-3 bg-slate-950 rounded-lg border border-slate-800 text-slate-300 leading-relaxed font-mono text-xs">
                {selectedApiReport.summary}
              </div>
            </div>

            <div className="flex items-center justify-between text-xs text-slate-400 p-3 bg-slate-950/60 rounded-lg border border-slate-800/60">
              <div>
                <span>Audited: </span>
                <span className="text-slate-200 font-mono">{new Date(selectedApiReport.createdAt).toLocaleString()}</span>
              </div>
              <div>
                <span>Auditor: </span>
                <span className="text-cyan-300 font-mono">{selectedApiReport.generatedBy}</span>
              </div>
            </div>

            <div className="flex items-center justify-end gap-3 pt-3 border-t border-slate-800">
              <button
                type="button"
                onClick={() => setSelectedApiReport(null)}
                className="px-4 py-2 text-xs font-medium text-slate-400 hover:text-slate-200"
              >
                Close
              </button>
              <button
                type="button"
                onClick={() => {
                  handleExportApiReportPdf(selectedApiReport);
                }}
                className="px-4 py-2 text-xs font-semibold bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 rounded-lg flex items-center gap-1.5"
              >
                <Download className="w-3.5 h-3.5 text-cyan-400" />
                <span>PDF Summary</span>
              </button>
              <button
                type="button"
                onClick={() => {
                  handleExportApiReportZip(selectedApiReport);
                }}
                className="px-4 py-2 text-xs font-semibold bg-cyan-600 hover:bg-cyan-500 text-white rounded-lg flex items-center gap-1.5 shadow-lg shadow-cyan-900/30"
              >
                <Archive className="w-3.5 h-3.5" />
                <span>Export ZIP Package</span>
              </button>
            </div>
          </div>
        </Modal>
      )}

      {/* Preview Modal for Device Scorecard & CLI */}
      {previewDevice && (
        <Modal
          isOpen={!!previewDevice}
          onClose={() => setPreviewDevice(null)}
          title={`Audit Certificate Preview: ${previewDevice.hostname || previewDevice.filename}`}
          maxWidth="3xl"
        >
          <div className="space-y-4">
            <div className="p-4 bg-slate-950 rounded-xl border border-slate-800 grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs">
              <div>
                <span className="text-slate-500 block">Vendor</span>
                <span className="font-semibold text-slate-200">{previewDevice.detectedVendor}</span>
              </div>
              <div>
                <span className="text-slate-500 block">Model</span>
                <span className="font-mono text-cyan-300">{previewDevice.model || 'Standard'}</span>
              </div>
              <div>
                <span className="text-slate-500 block">Serial Number</span>
                <span className="font-mono text-slate-300">{previewDevice.serialNumber || 'SN-UNKNOWN'}</span>
              </div>
              <div>
                <span className="text-slate-500 block">Compliance Score</span>
                <span className="font-mono font-bold text-base text-emerald-400">{previewDevice.overallComplianceScore}%</span>
              </div>
            </div>

            {/* CLI Remediations Section */}
            <div>
              <h4 className="text-xs font-semibold text-slate-300 uppercase tracking-wider mb-2 flex items-center gap-2">
                <Terminal className="w-4 h-4 text-cyan-400" />
                Tailored CLI Remediation Commands ({previewDevice.detectedVendor} Syntax)
              </h4>
              <div className="mb-2 px-3 py-1.5 rounded border border-amber-500/40 bg-amber-950/30 text-[11px] font-mono font-bold text-amber-300">
                DRY RUN – nothing is applied to the device. Commands are only generated; edited/approved versions go into the exported PDF and ZIP.
              </div>

              {loadingPreview ? (
                <div className="py-8 text-center text-xs text-slate-400 flex items-center justify-center gap-2">
                  <RotateCw className="w-4 h-4 animate-spin text-cyan-400" />
                  Generating vendor-syntax fix commands...
                </div>
              ) : previewRemediations.length === 0 ? (
                <div className="p-4 bg-emerald-950/20 border border-emerald-800/40 rounded-lg text-xs text-emerald-400 flex items-center gap-2">
                  <CheckCircle2 className="w-4 h-4" />
                  Device is 100% compliant across tested controls. No remediation necessary.
                </div>
              ) : (
                <div className="space-y-3 max-h-80 overflow-y-auto pr-1">
                  {previewRemediations.map((rem) => {
                    const key = `${previewDevice.id}::${rem.controlId}`;
                    const d = fixDrafts[key] || { original: rem.cliCommands, text: rem.cliCommands, approved: false, editing: false };
                    const modified = d.text !== d.original;
                    return (
                      <div key={rem.controlId} className="p-3 bg-slate-950 border border-slate-800 rounded-lg text-xs space-y-1.5">
                        <div className="flex items-center justify-between text-[11px] gap-2">
                          <span className="font-mono font-bold text-rose-400">{rem.controlId}</span>
                          <span className="flex items-center gap-1.5">
                            <span className={`px-1.5 py-0.5 rounded border text-[10px] font-mono ${rem.source === 'ai-gemini' ? 'border-purple-500/40 bg-purple-950/40 text-purple-300' : 'border-emerald-500/40 bg-emerald-950/40 text-emerald-300'}`}>
                              {rem.source === 'ai-gemini' ? 'AI-generated (Gemini)' : 'Template'}
                            </span>
                            <MemoryBadge memories={rem.memoriesUsed} subtitle={`Used for ${rem.controlId} on ${previewDevice.hostname || previewDevice.detectedVendor}`} />
                            {d.approved && <span className="px-1.5 py-0.5 rounded border border-cyan-500/40 bg-cyan-950/40 text-cyan-300 text-[10px] font-mono">{modified ? 'Approved (edited)' : 'Approved'}</span>}
                          </span>
                        </div>
                        <textarea
                          value={d.text}
                          readOnly={!d.editing}
                          onChange={(e) => updateDraft(key, { text: e.target.value, approved: false })}
                          rows={Math.min(10, Math.max(3, d.text.split('\n').length))}
                          spellCheck={false}
                          className={`w-full p-2.5 bg-slate-900 text-cyan-300 font-mono text-[11px] rounded border whitespace-pre focus:outline-none ${d.editing ? 'border-amber-500/60' : 'border-slate-800'}`}
                        />
                        <div className="flex items-center gap-2 text-[11px]">
                          <button type="button" onClick={() => updateDraft(key, { editing: true, approved: false })} className="px-2 py-1 rounded border border-slate-700 text-slate-300 hover:bg-slate-800">Edit</button>
                          <button type="button" onClick={() => updateDraft(key, { text: d.original, approved: false, editing: false })} disabled={!modified && !d.approved} className="px-2 py-1 rounded border border-slate-700 text-slate-300 hover:bg-slate-800 disabled:opacity-40">Reset to original</button>
                          <button type="button" onClick={() => handleApproveFix(previewDevice, rem.controlId)} disabled={d.approved} className="px-2 py-1 rounded bg-emerald-600 hover:bg-emerald-500 text-white disabled:opacity-50">Approve</button>
                        </div>
                        <div className="flex flex-wrap items-center gap-2 pt-1.5 mt-1 border-t border-slate-800/80 text-[11px]">
                          <FixOutcomeButtons vendor={previewDevice.detectedVendor} controlId={rem.controlId} hostname={previewDevice.hostname} />
                        </div>
                      </div>
                    );
                  })}
                </div>
              )}
            </div>

            <div className="flex items-center justify-end gap-3 pt-3 border-t border-slate-800">
              <button
                type="button"
                onClick={() => setPreviewDevice(null)}
                className="px-4 py-2 text-xs font-medium text-slate-400 hover:text-slate-200"
              >
                Close Preview
              </button>
              <button
                type="button"
                onClick={() => {
                  handleExportSinglePdf(previewDevice);
                  setPreviewDevice(null);
                }}
                className="px-4 py-2 text-xs font-semibold bg-cyan-600 hover:bg-cyan-500 text-white rounded-lg flex items-center gap-1.5"
              >
                <Download className="w-3.5 h-3.5" />
                Download PDF Certificate
              </button>
            </div>
          </div>
        </Modal>
      )}
    </div>
  );
}
