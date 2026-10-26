import React, { useState, useEffect } from 'react';
import {
  Brain,
  Plus,
  Trash2,
  Search,
  Shield,
  CheckCircle2,
  Sliders,
  Code,
  AlertTriangle,
} from 'lucide-react';
import { Card } from '../components/common/Card';
import { Modal } from '../components/common/Modal';
import { SeverityBadge } from '../components/common/Badge';
import { KnowledgeRule, Severity } from '../types';
import { apiService } from '../services/api';
import { useAuth } from '../context/AuthContext';
import { useToast } from '../context/ToastContext';

export function KnowledgeBasePage() {
  const [rules, setRules] = useState<KnowledgeRule[]>([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');
  const [isModalOpen, setIsModalOpen] = useState(false);

  // New Rule Form State
  const [formData, setFormData] = useState({
    pattern: '',
    category: 'Access Control',
    securityParameter: '',
    expectedBehavior: '',
    severity: 'HIGH' as Severity,
    description: '',
    remediation: '',
  });

  const { showToast } = useToast();
  const { hasPermission, role } = useAuth();

  const fetchRules = async () => {
    try {
      setLoading(true);
      const data = await apiService.getKnowledgeRules();
      setRules(data);
    } catch (err: any) {
      showToast('Failed to load knowledge rules', err.message, 'error');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchRules();
  }, []);

  const handleCreateRule = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!formData.pattern || !formData.expectedBehavior || !formData.securityParameter) {
      showToast('Validation Error', 'Pattern, Parameter, and Expected Behavior are required.', 'error');
      return;
    }

    try {
      const newRule = await apiService.createKnowledgeRule(formData);
      setRules([...rules, newRule]);
      setIsModalOpen(false);
      showToast('Knowledge Rule Added', `Added rule mapping for [${newRule.pattern}].`, 'success');
      setFormData({
        pattern: '',
        category: 'Access Control',
        securityParameter: '',
        expectedBehavior: '',
        severity: 'HIGH',
        description: '',
        remediation: '',
      });
    } catch (err: any) {
      showToast('Error adding rule', err.message, 'error');
    }
  };

  const handleDeleteRule = async (id: string) => {
    if (role !== 'ADMIN') {
      showToast('RBAC Restricted', 'Only ADMIN can delete knowledge rules.', 'warning');
      return;
    }
    try {
      await apiService.deleteKnowledgeRule(id);
      setRules((prev) => prev.filter((r) => r.id !== id));
      showToast('Rule Deleted', 'Knowledge mapping removed from scanner engine.', 'success');
    } catch (err: any) {
      showToast('Failed to delete rule', err.message, 'error');
    }
  };

  const filteredRules = rules.filter(
    (r) =>
      r.pattern.toLowerCase().includes(search.toLowerCase()) ||
      r.securityParameter.toLowerCase().includes(search.toLowerCase()) ||
      r.category.toLowerCase().includes(search.toLowerCase()) ||
      r.description.toLowerCase().includes(search.toLowerCase())
  );

  return (
    <div className="space-y-6 text-left">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-cyan-950 border border-cyan-500/40 text-cyan-300">
              CUSTOM RULE ENGINE
            </span>
            <span className="text-xs text-slate-400 font-mono">• Active Scanner Injection</span>
          </div>
          <h2 className="text-xl sm:text-2xl font-bold text-slate-100 tracking-tight mt-1">
            ZENTRA Security Knowledge Base
          </h2>
          <p className="text-xs sm:text-sm text-slate-400 mt-0.5">
            Define custom security heuristics, parameter patterns, and expected behaviors evaluated during automated scans.
          </p>
        </div>

        {hasPermission('knowledge:manage') && (
          <button
            onClick={() => setIsModalOpen(true)}
            className="flex items-center gap-2 px-4 py-2 rounded-lg bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white text-xs font-semibold shadow-lg shadow-cyan-900/30 transition cursor-pointer self-start sm:self-auto"
          >
            <Plus className="w-4 h-4" />
            <span>Add Knowledge Rule</span>
          </button>
        )}
      </div>

      {/* Filter */}
      <Card className="p-4">
        <div className="relative">
          <Search className="w-4 h-4 text-slate-400 absolute left-3 top-2.5" />
          <input
            type="text"
            placeholder="Search rules by pattern, parameter, category, or description..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="w-full pl-9 pr-3 py-1.5 rounded-lg border border-slate-800 bg-slate-950 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500"
          />
        </div>
      </Card>

      {/* Rules Cards */}
      {loading ? (
        <div className="py-12 text-center text-slate-400 text-xs font-mono">
          Loading knowledge base mappings...
        </div>
      ) : filteredRules.length === 0 ? (
        <div className="py-12 text-center text-slate-500 text-sm">
          No knowledge rules found matching search.
        </div>
      ) : (
        <div className="space-y-4">
          {filteredRules.map((rule) => (
            <Card
              key={rule.id}
              title={
                <div className="flex items-center gap-2 font-mono text-xs">
                  <span className="font-bold text-cyan-300">Pattern: "{rule.pattern}"</span>
                  <span className="text-slate-500">•</span>
                  <span className="text-slate-400">{rule.securityParameter}</span>
                </div>
              }
              action={
                <div className="flex items-center gap-2">
                  <SeverityBadge severity={rule.severity} size="sm" />
                  {role === 'ADMIN' && (
                    <button
                      onClick={() => handleDeleteRule(rule.id)}
                      className="p-1 rounded text-slate-400 hover:text-rose-400 hover:bg-slate-800 transition cursor-pointer"
                      title="Delete Rule"
                    >
                      <Trash2 className="w-3.5 h-3.5" />
                    </button>
                  )}
                </div>
              }
            >
              <div className="space-y-3 text-xs">
                <p className="text-slate-300">{rule.description}</p>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-3 font-mono text-[11px]">
                  <div className="p-2.5 rounded bg-slate-950 border border-slate-800">
                    <span className="text-slate-500 block uppercase text-[10px]">
                      Mandated Policy / Expected Behavior:
                    </span>
                    <span className="text-emerald-300 mt-0.5 block">{rule.expectedBehavior}</span>
                  </div>

                  <div className="p-2.5 rounded bg-slate-950 border border-slate-800">
                    <span className="text-slate-500 block uppercase text-[10px]">
                      Required Remediation:
                    </span>
                    <span className="text-cyan-300 mt-0.5 block font-sans">{rule.remediation}</span>
                  </div>
                </div>

                <div className="flex items-center justify-between pt-2 border-t border-slate-800/80 text-[10px] text-slate-500 font-mono">
                  <span>Author: {rule.createdBy}</span>
                  <span>Created: {new Date(rule.createdAt).toLocaleDateString()}</span>
                </div>
              </div>
            </Card>
          ))}
        </div>
      )}

      {/* Add Rule Modal */}
      <Modal
        isOpen={isModalOpen}
        onClose={() => setIsModalOpen(false)}
        title="Add Knowledge Base Rule Pattern"
        subtitle="This rule will immediately be evaluated against all active and future API scans"
        maxWidth="lg"
      >
        <form onSubmit={handleCreateRule} className="space-y-4 text-left text-xs">
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            <div>
              <label className="block font-semibold text-slate-300 mb-1">
                Target Parameter Pattern *
              </label>
              <input
                type="text"
                required
                placeholder="e.g. role=admin or is_internal=true"
                value={formData.pattern}
                onChange={(e) => setFormData({ ...formData, pattern: e.target.value })}
                className="w-full px-3 py-1.5 rounded-lg border border-slate-800 bg-slate-950 font-mono text-slate-200 focus:outline-none focus:border-cyan-500"
              />
            </div>

            <div>
              <label className="block font-semibold text-slate-300 mb-1">
                Security Parameter Key *
              </label>
              <input
                type="text"
                required
                placeholder="e.g. privilege_elevation_probe"
                value={formData.securityParameter}
                onChange={(e) => setFormData({ ...formData, securityParameter: e.target.value })}
                className="w-full px-3 py-1.5 rounded-lg border border-slate-800 bg-slate-950 font-mono text-slate-200 focus:outline-none focus:border-cyan-500"
              />
            </div>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            <div>
              <label className="block font-semibold text-slate-300 mb-1">Category</label>
              <select
                value={formData.category}
                onChange={(e) => setFormData({ ...formData, category: e.target.value })}
                className="w-full px-3 py-1.5 rounded-lg border border-slate-800 bg-slate-950 text-slate-200 focus:outline-none focus:border-cyan-500"
              >
                <option value="Access Control">Access Control</option>
                <option value="Authentication">Authentication</option>
                <option value="Rate Limiting">Rate Limiting</option>
                <option value="Data Exposure">Data Exposure</option>
                <option value="Input Validation">Input Validation</option>
              </select>
            </div>

            <div>
              <label className="block font-semibold text-slate-300 mb-1">Severity</label>
              <select
                value={formData.severity}
                onChange={(e) => setFormData({ ...formData, severity: e.target.value as any })}
                className="w-full px-3 py-1.5 rounded-lg border border-slate-800 bg-slate-950 text-slate-200 focus:outline-none focus:border-cyan-500"
              >
                <option value="CRITICAL">CRITICAL</option>
                <option value="HIGH">HIGH</option>
                <option value="MEDIUM">MEDIUM</option>
                <option value="LOW">LOW</option>
              </select>
            </div>
          </div>

          <div>
            <label className="block font-semibold text-slate-300 mb-1">
              Expected System Behavior *
            </label>
            <input
              type="text"
              required
              placeholder="e.g. Return HTTP 403 Forbidden when client submits role elevation flag without master certificate."
              value={formData.expectedBehavior}
              onChange={(e) => setFormData({ ...formData, expectedBehavior: e.target.value })}
              className="w-full px-3 py-1.5 rounded-lg border border-slate-800 bg-slate-950 text-slate-200 focus:outline-none focus:border-cyan-500"
            />
          </div>

          <div>
            <label className="block font-semibold text-slate-300 mb-1">Description</label>
            <textarea
              rows={2}
              placeholder="Describe the threat mechanism..."
              value={formData.description}
              onChange={(e) => setFormData({ ...formData, description: e.target.value })}
              className="w-full px-3 py-1.5 rounded-lg border border-slate-800 bg-slate-950 text-slate-200 focus:outline-none focus:border-cyan-500"
            />
          </div>

          <div>
            <label className="block font-semibold text-slate-300 mb-1">
              Remediation Playbook Guidance
            </label>
            <input
              type="text"
              placeholder="e.g. Strip client role attributes; derive caller permissions exclusively from signed JWT claims."
              value={formData.remediation}
              onChange={(e) => setFormData({ ...formData, remediation: e.target.value })}
              className="w-full px-3 py-1.5 rounded-lg border border-slate-800 bg-slate-950 text-slate-200 focus:outline-none focus:border-cyan-500"
            />
          </div>

          <div className="flex items-center justify-end gap-3 pt-3 border-t border-slate-800">
            <button
              type="button"
              onClick={() => setIsModalOpen(false)}
              className="px-3 py-1.5 rounded-lg border border-slate-800 text-slate-400 hover:text-slate-200"
            >
              Cancel
            </button>
            <button
              type="submit"
              className="px-4 py-1.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white font-semibold"
            >
              Add Rule to Engine
            </button>
          </div>
        </form>
      </Modal>
    </div>
  );
}
