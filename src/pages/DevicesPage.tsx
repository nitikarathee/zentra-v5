import React, { useState, useEffect, useRef } from 'react';
import {
  UploadCloud,
  FileText,
  Search,
  Filter,
  Trash2,
  Eye,
  CheckCircle2,
  AlertTriangle,
  XCircle,
  Plus,
  RefreshCw,
  Cpu,
  Layers,
  ArrowRight,
  ShieldCheck,
  Sparkles,
  Terminal,
  Copy,
  Check,
  X,
  FileCode,
  Archive,
  Download,
} from 'lucide-react';
import JSZip from 'jszip';
import { NetworkDevice } from '../types';
import { apiService } from '../services/api';
import { useToast } from '../context/ToastContext';
import { DeviceDetailPage } from './DeviceDetailPage';

export function DevicesPage() {
  const { showToast } = useToast();
  const [devices, setDevices] = useState<NetworkDevice[]>([]);
  const [stats, setStats] = useState<{
    total: number;
    compliant: number;
    warning: number;
    nonCompliant: number;
    avgScore: number;
    vendorBreakdown: Array<{ vendor: string; count: number }>;
  } | null>(null);

  const [isLoading, setIsLoading] = useState(true);
  const [isUploading, setIsUploading] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');
  const [vendorFilter, setVendorFilter] = useState('ALL');
  const [statusFilter, setStatusFilter] = useState('ALL');

  // Selected device for full detail page
  const [selectedDevice, setSelectedDevice] = useState<NetworkDevice | null>(null);

  // Quick View Raw Modal
  const [rawModalDevice, setRawModalDevice] = useState<NetworkDevice | null>(null);
  const [rawModalSearch, setRawModalSearch] = useState('');
  const [copiedRaw, setCopiedRaw] = useState(false);

  // Paste Config Modal
  const [isPasteModalOpen, setIsPasteModalOpen] = useState(false);
  const [pasteFilename, setPasteFilename] = useState('');
  const [pasteContent, setPasteContent] = useState('');

  // Drag and Drop state
  const [isDragging, setIsDragging] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const loadDevices = async () => {
    try {
      setIsLoading(true);
      const [deviceList, statData] = await Promise.all([
        apiService.getDevices({
          search: searchQuery || undefined,
          vendor: vendorFilter !== 'ALL' ? vendorFilter : undefined,
          status: statusFilter !== 'ALL' ? statusFilter : undefined,
        }),
        apiService.getDeviceStats(),
      ]);
      setDevices(deviceList);
      setStats(statData);
    } catch (err: any) {
      showToast(
        'Error Loading Devices',
        err.message || 'Failed to fetch network device configs',
        'error'
      );
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    loadDevices();
  }, [searchQuery, vendorFilter, statusFilter]);

  // Handle files ingestion with ZIP unpack support
  const processFiles = async (files: FileList | File[]) => {
    if (!files || files.length === 0) return;

    setIsUploading(true);
    showToast(
      'Ingesting Configurations',
      `Parsing and normalizing ${files.length} payload(s)...`,
      'info'
    );

    const filePayloads: Array<{ filename: string; content: string }> = [];

    for (let i = 0; i < files.length; i++) {
      const file = files[i];
      const isZip = file.name.toLowerCase().endsWith('.zip') || file.type.includes('zip');

      if (isZip) {
        try {
          const zip = await JSZip.loadAsync(file);
          let extracted = 0;
          for (const [relativePath, zipEntry] of Object.entries(zip.files)) {
            if (!zipEntry.dir) {
              if (relativePath.includes('__MACOSX') || relativePath.startsWith('.')) continue;
              const text = await zipEntry.async('text');
              if (text && text.trim()) {
                const baseName = relativePath.split('/').pop() || relativePath;
                filePayloads.push({
                  filename: baseName,
                  content: text,
                });
                extracted++;
              }
            }
          }
          showToast('ZIP Archive Extracted', `Unpacked ${extracted} config file(s) from ${file.name}.`, 'info');
        } catch (err: any) {
          console.error(`ZIP unpack error for ${file.name}:`, err);
          showToast('ZIP Unpack Error', `Failed to read ${file.name}: ${err.message}`, 'error');
        }
      } else {
        try {
          const text = await file.text();
          if (text.trim()) {
            filePayloads.push({
              filename: file.name,
              content: text,
            });
          }
        } catch (err) {
          console.error(`Error reading ${file.name}:`, err);
        }
      }
    }

    if (filePayloads.length === 0) {
      showToast(
        'Upload Failed',
        'No readable text config content found in selected files or ZIP archives.',
        'error'
      );
      setIsUploading(false);
      return;
    }

    try {
      const res = await apiService.uploadDeviceConfigs(filePayloads);
      showToast(
        res.quarantined && res.quarantined.length ? 'Prompt Injection Quarantined' : 'Ingestion Success',
        res.message || `Ingested ${res.devices.length} network device(s).`,
        res.quarantined && res.quarantined.length ? 'error' : 'success'
      );
      await loadDevices();
    } catch (err: any) {
      showToast(
        'Ingestion Error',
        err.message || 'Failed to process config files',
        'error'
      );
    } finally {
      setIsUploading(false);
    }
  };

  // Export all current configurations into a ZIP archive
  const handleExportConfigsZip = async () => {
    if (devices.length === 0) {
      showToast('No Configs Available', 'No device configurations to export.', 'warning');
      return;
    }
    try {
      const zip = new JSZip();
      devices.forEach((d) => {
        const cleanName = (d.hostname || d.filename || d.id).replace(/[^a-zA-Z0-9_-]/g, '_');
        const content = d.rawConfig || `# ZENTRA Stored Configuration for ${d.hostname || d.filename}\n# Vendor: ${d.detectedVendor}\n# Model: ${d.model}\n`;
        zip.file(`${cleanName}.cfg`, content);
      });

      const manifest = {
        archive: 'ZENTRA Network Device Fleet Configurations Backup',
        exportedAt: new Date().toISOString(),
        totalConfigs: devices.length,
        devices: devices.map((d) => ({
          id: d.id,
          hostname: d.hostname,
          vendor: d.detectedVendor,
          model: d.model,
          complianceScore: d.overallComplianceScore,
          filename: d.filename,
        })),
      };
      zip.file('fleet-manifest.json', JSON.stringify(manifest, null, 2));

      const blob = await zip.generateAsync({ type: 'blob' });
      const url = URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.download = `zentra-fleet-configs-${new Date().toISOString().split('T')[0]}.zip`;
      link.click();
      URL.revokeObjectURL(url);

      showToast('Configs Exported', `Packaged ${devices.length} network configs into ZIP archive.`, 'success');
    } catch (err: any) {
      showToast('Export Error', err.message, 'error');
    }
  };

  // Drag and Drop handlers
  const handleDragOver = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(true);
  };

  const handleDragLeave = () => {
    setIsDragging(false);
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(false);
    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      processFiles(e.dataTransfer.files);
    }
  };

  // Delete device
  const handleDeleteDevice = async (id: string, name: string) => {
    if (!confirm(`Are you sure you want to delete config "${name}"?`)) return;

    try {
      await apiService.deleteDevice(id);
      showToast(
        'Device Deleted',
        `Removed "${name}" from compliance repository.`,
        'info'
      );
      if (selectedDevice?.id === id) {
        setSelectedDevice(null);
      }
      loadDevices();
    } catch (err: any) {
      showToast(
        'Delete Failed',
        err.message || 'Could not delete device',
        'error'
      );
    }
  };

  // Handle paste modal submission
  const handlePasteSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!pasteContent.trim()) {
      showToast('Validation', 'Config content cannot be empty', 'error');
      return;
    }

    const filename = pasteFilename.trim() || `device-pasted-${Date.now()}.cfg`;
    setIsUploading(true);
    setIsPasteModalOpen(false);

    try {
      const res = await apiService.uploadDeviceConfigs([{ filename, content: pasteContent }]);
      showToast(
        res.quarantined && res.quarantined.length ? 'Prompt Injection Quarantined' : 'Device Ingested',
        res.message,
        res.quarantined && res.quarantined.length ? 'error' : 'success'
      );
      setPasteFilename('');
      setPasteContent('');
      await loadDevices();
    } catch (err: any) {
      showToast(
        'Ingestion Failed',
        err.message || 'Could not ingest pasted config',
        'error'
      );
    } finally {
      setIsUploading(false);
    }
  };

  const handleLoadFiveSamples = async () => {
    try {
      setIsUploading(true);
      const res = await apiService.loadSampleDevices();
      showToast('Sample Fleet Loaded', res.message || 'Loaded 5 realistic sample configs across Cisco, Palo Alto, Juniper, Arista, and SONiC.', 'success');
      await loadDevices();
    } catch (err: any) {
      showToast('Error Loading Samples', err.message, 'error');
    } finally {
      setIsUploading(false);
    }
  };

  // Quick seed samples
  const handleLoadSample = (sampleType: 'cisco' | 'juniper' | 'fortigate') => {
    if (sampleType === 'fortigate') {
      const fortinetConfig = `config system global
    set hostname "FGT-CORP-EDGE"
    set admintimeout 10
    set admin-sport 8443
    set admin-https enable
    set admin-http disable
    set strong-crypto enable
end
config system interface
    edit "wan1"
        set mode static
        set ip 198.51.100.2 255.255.255.0
        set allowaccess ping https ssh
    next
end
config log syslogd setting
    set status enable
    set server "10.0.100.20"
end
config system ntp
    set server-mode enable
    set ntpserver "10.0.100.1"
end
config firewall policy
    edit 1
        set name "CORP-OUTBOUND-SECURE"
        set srcintf "internal"
        set dstintf "wan1"
        set action accept
        set schedule "always"
        set service "HTTPS" "SSH"
        set logtraffic all
    next
end`;
      processFiles([new File([fortinetConfig], 'fortigate-corp-edge.conf', { type: 'text/plain' })]);
    } else if (sampleType === 'cisco') {
      const ciscoSample = `!
version 17.3
hostname DIST-SW02-DENVER
!
security passwords min-length 14
enable secret 9 $9$a89f...
service password-encryption
service tcp-keepalives-in
!
no ip http server
ip http secure-server
ip ssh version 2
ip ssh time-out 60
ip ssh authentication-retries 3
!
logging host 172.16.50.10
ntp server 172.16.1.1
!
line vty 0 4
 transport input ssh
 exec-timeout 10 0
!
end`;
      processFiles([new File([ciscoSample], 'dist-sw02-denver.cfg', { type: 'text/plain' })]);
    } else {
      const juniperSample = `## Last-changed: 2026-04-10
system {
    host-name QFX5100-SPINE-01;
    services {
        ssh {
            protocol-version v2;
        }
        web-management {
            https;
        }
    }
    syslog {
        host 10.20.30.40;
    }
    ntp {
        server 10.20.30.1;
    }
}`;
      processFiles([new File([juniperSample], 'qfx5100-spine01.conf', { type: 'text/plain' })]);
    }
  };

  // If a device is currently selected for detail inspection
  if (selectedDevice) {
    return (
      <DeviceDetailPage
        device={selectedDevice}
        onBack={() => {
          setSelectedDevice(null);
          loadDevices();
        }}
        onDeviceUpdated={(updated) => {
          setSelectedDevice(updated);
          setDevices((prev) => prev.map((d) => (d.id === updated.id ? updated : d)));
        }}
      />
    );
  }

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2 text-xs font-mono text-cyan-400">
            <Cpu className="w-3.5 h-3.5" />
            <span>VENDOR-AGNOSTIC NETWORK COMPLIANCE</span>
          </div>
          <h1 className="text-xl sm:text-2xl font-bold text-slate-100 mt-1">
            Network Device Configuration Repository
          </h1>
          <p className="text-xs text-slate-400 mt-0.5">
            Ingest, normalize, and audit router, switch, and firewall configs across Cisco, Juniper, Arista, Fortinet, and generic network OS.
          </p>
        </div>

        <div className="flex items-center gap-2.5 flex-wrap">
          <button
            onClick={handleLoadFiveSamples}
            disabled={isUploading}
            className="flex items-center gap-1.5 px-3 py-2 rounded-lg text-xs font-semibold bg-amber-500/10 border border-amber-500/30 text-amber-300 hover:bg-amber-500 hover:text-slate-950 transition disabled:opacity-50"
          >
            <Sparkles className="w-3.5 h-3.5 text-amber-400" />
            Load Sample Fleet (5 Vendors)
          </button>
          <button
            onClick={handleExportConfigsZip}
            disabled={devices.length === 0}
            className="flex items-center gap-1.5 px-3.5 py-2 rounded-lg text-xs font-semibold bg-indigo-500/10 border border-indigo-500/30 text-indigo-300 hover:bg-indigo-500 hover:text-white transition disabled:opacity-50 cursor-pointer"
            title="Download all stored network configurations packaged in a ZIP archive"
          >
            <Archive className="w-3.5 h-3.5 text-indigo-400" />
            <span>Export Fleet Configs (.zip)</span>
          </button>
          <button
            onClick={() => setIsPasteModalOpen(true)}
            className="flex items-center gap-2 px-3.5 py-2 rounded-lg text-xs font-medium bg-slate-900 border border-slate-800 text-slate-200 hover:text-white hover:border-slate-700 transition cursor-pointer"
          >
            <FileCode className="w-3.5 h-3.5 text-cyan-400" />
            Paste Config
          </button>
          <button
            onClick={() => fileInputRef.current?.click()}
            className="flex items-center gap-2 px-4 py-2 rounded-lg text-xs font-semibold bg-cyan-500 hover:bg-cyan-400 text-slate-950 shadow-lg shadow-cyan-500/20 transition cursor-pointer"
          >
            <Plus className="w-4 h-4" />
            Upload Config / ZIP
          </button>
          <input
            ref={fileInputRef}
            type="file"
            multiple
            accept=".cfg,.conf,.txt,.json,.ios,.eos,.zip,application/zip"
            className="hidden"
            onChange={(e) => {
              if (e.target.files) processFiles(e.target.files);
              e.target.value = '';
            }}
          />
        </div>
      </div>

      {/* Quick Stats Overview */}
      {stats && (
        <div className="grid grid-cols-2 sm:grid-cols-2 lg:grid-cols-5 gap-3.5">
          <div className="p-4 rounded-xl bg-slate-900/80 border border-slate-800/80">
            <div className="flex items-center justify-between text-slate-400 text-xs">
              <span>Total Devices</span>
              <Cpu className="w-4 h-4 text-cyan-400" />
            </div>
            <div className="mt-2 text-2xl font-bold text-slate-100">{stats.total}</div>
            <div className="mt-1 text-[11px] text-slate-400 font-mono">
              Avg score: <span className="text-cyan-400 font-semibold">{stats.avgScore}%</span>
            </div>
          </div>

          <div className="p-4 rounded-xl bg-slate-900/80 border border-slate-800/80">
            <div className="flex items-center justify-between text-slate-400 text-xs">
              <span>Compliant</span>
              <CheckCircle2 className="w-4 h-4 text-emerald-400" />
            </div>
            <div className="mt-2 text-2xl font-bold text-emerald-400">{stats.compliant}</div>
            <div className="mt-1 text-[11px] text-emerald-500 font-mono">
              Score ≥ 85% baseline
            </div>
          </div>

          <div className="p-4 rounded-xl bg-slate-900/80 border border-slate-800/80">
            <div className="flex items-center justify-between text-slate-400 text-xs">
              <span>Warning</span>
              <AlertTriangle className="w-4 h-4 text-amber-400" />
            </div>
            <div className="mt-2 text-2xl font-bold text-amber-400">{stats.warning}</div>
            <div className="mt-1 text-[11px] text-amber-500 font-mono">
              Score 60% – 84%
            </div>
          </div>

          <div className="p-4 rounded-xl bg-slate-900/80 border border-slate-800/80">
            <div className="flex items-center justify-between text-slate-400 text-xs">
              <span>Non-Compliant</span>
              <XCircle className="w-4 h-4 text-rose-400" />
            </div>
            <div className="mt-2 text-2xl font-bold text-rose-400">{stats.nonCompliant}</div>
            <div className="mt-1 text-[11px] text-rose-500 font-mono">
              Score &lt; 60% (Violations)
            </div>
          </div>

          <div className="p-4 rounded-xl bg-slate-900/80 border border-slate-800/80 col-span-2 sm:col-span-1">
            <div className="flex items-center justify-between text-slate-400 text-xs">
              <span>Vendors Detected</span>
              <Layers className="w-4 h-4 text-purple-400" />
            </div>
            <div className="mt-2 text-2xl font-bold text-purple-300">{stats.vendorBreakdown.length}</div>
            <div className="mt-1 text-[11px] text-slate-400 font-mono truncate">
              Multi-vendor normalized
            </div>
          </div>
        </div>
      )}

      {/* Drag & Drop Upload Zone */}
      <div
        onDragOver={handleDragOver}
        onDragLeave={handleDragLeave}
        onDrop={handleDrop}
        className={`relative rounded-2xl border-2 border-dashed p-8 transition-all flex flex-col items-center justify-center text-center cursor-pointer ${
          isDragging
            ? 'border-cyan-400 bg-cyan-950/30 scale-[1.005]'
            : 'border-slate-800/90 bg-slate-900/40 hover:border-slate-700 hover:bg-slate-900/60'
        }`}
        onClick={() => fileInputRef.current?.click()}
      >
        <div className="w-12 h-12 rounded-xl bg-cyan-500/10 border border-cyan-500/20 text-cyan-400 flex items-center justify-center mb-3">
          <UploadCloud className={`w-6 h-6 ${isUploading ? 'animate-bounce' : ''}`} />
        </div>

        <h3 className="text-sm font-semibold text-slate-200">
          Drag & Drop network device configuration files or .ZIP archives here
        </h3>
        <p className="text-xs text-slate-400 mt-1 max-w-md">
          Supports any vendor format (.cfg, .conf, .txt, .ios, .junos, .eos) as well as .zip archives. Archives are automatically extracted and batch-normalized.
        </p>

        <div className="mt-3 flex items-center gap-2 text-[11px] font-mono text-slate-400 flex-wrap justify-center">
          <span className="px-2 py-0.5 rounded bg-cyan-950/80 border border-cyan-500/40 text-cyan-300 font-bold">.ZIP Batch Extraction</span>
          <span className="px-2 py-0.5 rounded bg-slate-800 border border-slate-700">Cisco IOS / XE</span>
          <span className="px-2 py-0.5 rounded bg-slate-800 border border-slate-700">Juniper JunOS</span>
          <span className="px-2 py-0.5 rounded bg-slate-800 border border-slate-700">Arista EOS</span>
          <span className="px-2 py-0.5 rounded bg-slate-800 border border-slate-700">FortiOS</span>
        </div>

        {/* Quick Sample Ingestion shortcuts */}
        <div className="mt-4 pt-3 border-t border-slate-800/60 flex flex-wrap items-center justify-center gap-2 text-xs" onClick={(e) => e.stopPropagation()}>
          <span className="text-slate-400 text-[11px]">Quick test samples:</span>
          <button
            onClick={() => handleLoadSample('cisco')}
            className="px-2.5 py-1 rounded text-[11px] font-medium bg-slate-800 hover:bg-slate-700 text-cyan-300 border border-slate-700 transition"
          >
            + Sample Cisco Catalyst
          </button>
          <button
            onClick={() => handleLoadSample('juniper')}
            className="px-2.5 py-1 rounded text-[11px] font-medium bg-slate-800 hover:bg-slate-700 text-purple-300 border border-slate-700 transition"
          >
            + Sample Juniper SRX
          </button>
          <button
            onClick={() => handleLoadSample('fortigate')}
            className="px-2.5 py-1 rounded text-[11px] font-medium bg-slate-800 hover:bg-slate-700 text-amber-300 border border-slate-700 transition"
          >
            + Sample FortiGate Firewall
          </button>
        </div>
      </div>

      {/* Filters & Search Toolbar */}
      <div className="flex flex-col md:flex-row items-stretch md:items-center justify-between gap-3 bg-slate-900/60 p-3.5 rounded-xl border border-slate-800">
        <div className="relative flex-1">
          <Search className="w-4 h-4 absolute left-3 top-2.5 text-slate-500" />
          <input
            type="text"
            placeholder="Search by hostname, filename, model, vendor, or serial..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full bg-slate-950 border border-slate-800 rounded-lg pl-9 pr-3 py-1.5 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500"
          />
        </div>

        <div className="flex items-center gap-2">
          {/* Vendor Filter */}
          <select
            value={vendorFilter}
            onChange={(e) => setVendorFilter(e.target.value)}
            className="bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-xs text-slate-300 focus:outline-none focus:border-cyan-500"
          >
            <option value="ALL">All Vendors</option>
            <option value="Cisco">Cisco</option>
            <option value="Juniper">Juniper</option>
            <option value="Arista">Arista</option>
            <option value="Fortinet">Fortinet</option>
            <option value="Generic">Generic</option>
          </select>

          {/* Compliance Status Filter */}
          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            className="bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-xs text-slate-300 focus:outline-none focus:border-cyan-500"
          >
            <option value="ALL">All Statuses</option>
            <option value="COMPLIANT">Compliant (≥ 85%)</option>
            <option value="WARNING">Warning (60-84%)</option>
            <option value="NON_COMPLIANT">Non-Compliant (&lt; 60%)</option>
          </select>

          <button
            onClick={loadDevices}
            className="p-1.5 rounded-lg bg-slate-950 border border-slate-800 text-slate-400 hover:text-slate-100 transition"
            title="Refresh repository"
          >
            <RefreshCw className={`w-4 h-4 ${isLoading ? 'animate-spin' : ''}`} />
          </button>
        </div>
      </div>

      {/* Devices List Table */}
      <div className="rounded-xl border border-slate-800 bg-slate-950 overflow-hidden shadow-xl">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs text-slate-300">
            <thead className="bg-slate-900/90 text-[11px] uppercase font-mono tracking-wider text-slate-400 border-b border-slate-800">
              <tr>
                <th className="py-3.5 px-4 font-semibold">Device / Hostname</th>
                <th className="py-3.5 px-4 font-semibold">Vendor & OS Guess</th>
                <th className="py-3.5 px-4 font-semibold">Model / Serial</th>
                <th className="py-3.5 px-4 font-semibold">Baseline Compliance</th>
                <th className="py-3.5 px-4 font-semibold">Config Size</th>
                <th className="py-3.5 px-4 font-semibold">Ingestion Time</th>
                <th className="py-3.5 px-4 font-semibold text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/70">
              {devices.length === 0 ? (
                <tr>
                  <td colSpan={7} className="py-12 text-center text-slate-400">
                    <Cpu className="w-8 h-8 text-slate-600 mx-auto mb-2" />
                    <p className="font-semibold text-slate-300">No network devices found</p>
                    <p className="text-xs text-slate-500 mt-0.5">
                      Drag-and-drop a configuration file above or load a quick test sample.
                    </p>
                  </td>
                </tr>
              ) : (
                devices.map((device) => {
                  return (
                    <tr
                      key={device.id}
                      onClick={() => setSelectedDevice(device)}
                      className="hover:bg-slate-900/60 transition cursor-pointer group"
                    >
                      {/* Hostname & Filename */}
                      <td className="py-3.5 px-4">
                        <div className="font-semibold text-slate-100 flex items-center gap-2 group-hover:text-cyan-300 transition">
                          <Terminal className="w-3.5 h-3.5 text-cyan-400 shrink-0" />
                          <span className="truncate max-w-[200px]">{device.hostname || 'Unnamed Host'}</span>
                        </div>
                        <div className="text-[11px] font-mono text-slate-400 mt-0.5 truncate max-w-[200px]">
                          {device.filename}
                        </div>
                      </td>

                      {/* Vendor Guess Badge */}
                      <td className="py-3.5 px-4">
                        <div className="font-semibold text-slate-200">{device.detectedVendor}</div>
                        <div className="mt-1 flex items-center gap-1.5">
                          <span
                            className={`text-[9px] font-mono font-bold px-1.5 py-0.5 rounded uppercase tracking-wider ${
                              device.vendorGuessMethod === 'regex'
                                ? 'bg-blue-950 text-blue-300 border border-blue-500/30'
                                : device.vendorGuessMethod === 'offline'
                                ? 'bg-emerald-950 text-emerald-300 border border-emerald-500/30'
                                : 'bg-purple-950 text-purple-300 border border-purple-500/30'
                            }`}
                          >
                            {device.vendorGuessMethod}
                          </span>
                          <span className="text-[10px] text-slate-400 font-mono">
                            {device.vendorConfidence}% confidence
                          </span>
                        </div>
                      </td>

                      {/* Model & Serial */}
                      <td className="py-3.5 px-4 font-mono text-[11px]">
                        <div className="text-slate-200 font-medium truncate max-w-[160px]">
                          {device.model || 'Unknown Model'}
                        </div>
                        <div className="text-slate-400 truncate max-w-[160px]">
                          SN: {device.serialNumber || 'N/A'}
                        </div>
                      </td>

                      {/* Baseline Compliance Score */}
                      <td className="py-3.5 px-4">
                        <div className="flex items-center gap-2">
                          <span
                            className={`px-2 py-0.5 rounded text-[11px] font-bold font-mono ${
                              device.status === 'COMPLIANT'
                                ? 'bg-emerald-950 text-emerald-300 border border-emerald-500/30'
                                : device.status === 'WARNING'
                                ? 'bg-amber-950 text-amber-300 border border-amber-500/30'
                                : 'bg-rose-950 text-rose-300 border border-rose-500/30'
                            }`}
                          >
                            {device.overallComplianceScore}%
                          </span>
                          <span className="text-[11px] text-slate-400">
                            {device.status}
                          </span>
                        </div>
                        {device.unrecognizedLines.length > 0 && (
                          <div className="text-[10px] text-amber-400 font-mono mt-0.5">
                            {device.unrecognizedLines.length} unrecognized lines
                          </div>
                        )}
                      </td>

                      {/* Lines & File Size */}
                      <td className="py-3.5 px-4 font-mono text-[11px] text-slate-400">
                        <div>{device.lineCount} lines</div>
                        <div>{(device.byteSize / 1024).toFixed(1)} KB</div>
                      </td>

                      {/* Ingestion Time */}
                      <td className="py-3.5 px-4 text-[11px] text-slate-400 font-mono">
                        <div>{new Date(device.uploadTime).toLocaleDateString()}</div>
                        <div className="text-slate-500 text-[10px]">
                          {new Date(device.uploadTime).toLocaleTimeString()}
                        </div>
                      </td>

                      {/* Actions */}
                      <td className="py-3.5 px-4 text-right" onClick={(e) => e.stopPropagation()}>
                        <div className="flex items-center justify-end gap-1.5">
                          <button
                            onClick={() => setRawModalDevice(device)}
                            className="p-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 text-slate-400 hover:text-cyan-300 border border-slate-800 transition"
                            title="Quick View Raw Config"
                          >
                            <Eye className="w-3.5 h-3.5" />
                          </button>
                          <button
                            onClick={() => setSelectedDevice(device)}
                            className="p-1.5 rounded-lg bg-cyan-950/60 hover:bg-cyan-900/60 text-cyan-300 border border-cyan-800/40 transition"
                            title="Inspect Baseline Model & Unrecognized Lines"
                          >
                            <ArrowRight className="w-3.5 h-3.5" />
                          </button>
                          <button
                            onClick={() => handleDeleteDevice(device.id, device.hostname || device.filename)}
                            className="p-1.5 rounded-lg bg-slate-900 hover:bg-rose-950 text-slate-500 hover:text-rose-400 border border-slate-800 hover:border-rose-800/50 transition"
                            title="Delete device"
                          >
                            <Trash2 className="w-3.5 h-3.5" />
                          </button>
                        </div>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* QUICK VIEW RAW MODAL */}
      {rawModalDevice && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-sm animate-in fade-in duration-200">
          <div className="bg-slate-900 border border-slate-800 rounded-2xl w-full max-w-4xl max-h-[85vh] flex flex-col shadow-2xl overflow-hidden">
            <div className="p-4 border-b border-slate-800 flex items-center justify-between bg-slate-950/60">
              <div className="flex items-center gap-2">
                <Terminal className="w-4 h-4 text-cyan-400" />
                <div>
                  <h3 className="text-sm font-semibold text-slate-200">
                    Raw Config: {rawModalDevice.filename}
                  </h3>
                  <div className="text-[10px] font-mono text-slate-400">
                    {rawModalDevice.hostname} • {rawModalDevice.detectedVendor} • {rawModalDevice.lineCount} lines
                  </div>
                </div>
              </div>
              <div className="flex items-center gap-2">
                <button
                  onClick={() => {
                    navigator.clipboard.writeText(rawModalDevice.rawConfig);
                    setCopiedRaw(true);
                    setTimeout(() => setCopiedRaw(false), 2000);
                  }}
                  className="flex items-center gap-1 px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-xs text-slate-300 transition"
                >
                  {copiedRaw ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                  {copiedRaw ? 'Copied' : 'Copy'}
                </button>
                <button
                  onClick={() => {
                    const dev = rawModalDevice;
                    setRawModalDevice(null);
                    setSelectedDevice(dev);
                  }}
                  className="px-2.5 py-1 rounded bg-cyan-500 hover:bg-cyan-400 text-xs font-semibold text-slate-950 transition"
                >
                  Open Baseline Model
                </button>
                <button
                  onClick={() => setRawModalDevice(null)}
                  className="p-1 rounded text-slate-400 hover:text-slate-100 transition"
                >
                  <X className="w-4 h-4" />
                </button>
              </div>
            </div>

            {/* Search within raw */}
            <div className="p-2 border-b border-slate-800/80 bg-slate-950">
              <input
                type="text"
                placeholder="Filter lines..."
                value={rawModalSearch}
                onChange={(e) => setRawModalSearch(e.target.value)}
                className="w-full bg-slate-900 border border-slate-800 rounded px-3 py-1 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500"
              />
            </div>

            {/* Monospace content with line numbers */}
            <div className="flex-1 p-4 overflow-y-auto font-mono text-xs bg-slate-950 select-text">
              {rawModalDevice.rawConfig
                .split(/\r?\n/)
                .map((line, idx) => ({ line, num: idx + 1 }))
                .filter(({ line }) =>
                  rawModalSearch ? line.toLowerCase().includes(rawModalSearch.toLowerCase()) : true
                )
                .map(({ line, num }) => (
                  <div key={num} className="flex items-start hover:bg-slate-900/60 rounded px-1 group">
                    <span className="w-12 shrink-0 text-slate-600 select-none text-right pr-4 group-hover:text-cyan-500">
                      {num}
                    </span>
                    <span className="whitespace-pre-wrap break-all text-slate-300">
                      {line || ' '}
                    </span>
                  </div>
                ))}
            </div>
          </div>
        </div>
      )}

      {/* PASTE CONFIG MODAL */}
      {isPasteModalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-sm animate-in fade-in duration-200">
          <div className="bg-slate-900 border border-slate-800 rounded-2xl w-full max-w-2xl flex flex-col shadow-2xl overflow-hidden">
            <div className="p-4 border-b border-slate-800 flex items-center justify-between bg-slate-950/60">
              <div className="flex items-center gap-2">
                <FileCode className="w-4 h-4 text-cyan-400" />
                <h3 className="text-sm font-semibold text-slate-200">
                  Paste Raw Device Configuration
                </h3>
              </div>
              <button
                onClick={() => setIsPasteModalOpen(false)}
                className="p-1 rounded text-slate-400 hover:text-slate-100 transition"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <form onSubmit={handlePasteSubmit} className="p-4 space-y-4">
              <div>
                <label className="block text-xs font-medium text-slate-300 mb-1">
                  Filename / Label (optional)
                </label>
                <input
                  type="text"
                  placeholder="e.g. core-router01.cfg"
                  value={pasteFilename}
                  onChange={(e) => setPasteFilename(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500"
                />
              </div>

              <div>
                <label className="block text-xs font-medium text-slate-300 mb-1">
                  Configuration Text (any vendor)
                </label>
                <textarea
                  rows={14}
                  placeholder="Paste Cisco, Juniper, Arista, Fortinet, or any network config text here..."
                  value={pasteContent}
                  onChange={(e) => setPasteContent(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg p-3 font-mono text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500 resize-none"
                  required
                />
              </div>

              <div className="flex items-center justify-end gap-2 pt-2 border-t border-slate-800">
                <button
                  type="button"
                  onClick={() => setIsPasteModalOpen(false)}
                  className="px-4 py-2 rounded-lg text-xs font-medium bg-slate-800 text-slate-300 hover:bg-slate-700 transition"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={isUploading || !pasteContent.trim()}
                  className="px-4 py-2 rounded-lg text-xs font-semibold bg-cyan-500 hover:bg-cyan-400 text-slate-950 transition disabled:opacity-50"
                >
                  {isUploading ? 'Ingesting...' : 'Ingest & Normalize'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
