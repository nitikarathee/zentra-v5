import React, { useState } from 'react';
import { Brain } from 'lucide-react';
import { Modal } from '../common/Modal';

interface MemoryBadgeProps {
  memories?: string[];
  /** Short description shown in the modal subtitle, e.g. "Used for CIS-NET-1.12 on LEAF01-POD2" */
  subtitle?: string;
}

/** "Used N memories" badge. Click to see exactly which past experiences the AI relied on. */
export function MemoryBadge({ memories, subtitle }: MemoryBadgeProps) {
  const [open, setOpen] = useState(false);
  const list = memories || [];
  if (list.length === 0) return null;

  return (
    <>
      <button
        type="button"
        onClick={() => setOpen(true)}
        title="Show the past experiences this answer was based on"
        className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded border border-fuchsia-500/40 bg-fuchsia-950/40 text-fuchsia-300 text-[10px] font-mono hover:bg-fuchsia-900/40 transition"
      >
        <Brain className="w-3 h-3" />
        Used {list.length} {list.length === 1 ? 'memory' : 'memories'}
      </button>
      <Modal
        isOpen={open}
        onClose={() => setOpen(false)}
        title={
          <span className="flex items-center gap-2">
            <Brain className="w-5 h-5 text-fuchsia-400" />
            Memories used ({list.length})
          </span>
        }
        subtitle={subtitle || 'Recalled from this organisation\'s persistent memory (Hindsight)'}
        maxWidth="2xl"
      >
        <ol className="space-y-2.5">
          {list.map((m, i) => (
            <li key={i} className="flex gap-3 p-3 rounded-lg border border-slate-800 bg-slate-950 text-xs text-slate-200 leading-relaxed">
              <span className="font-mono text-fuchsia-400 shrink-0">{i + 1}.</span>
              <span className="select-text">{m}</span>
            </li>
          ))}
        </ol>
      </Modal>
    </>
  );
}
