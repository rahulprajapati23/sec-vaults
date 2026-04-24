import { useState } from 'react';

// --- Reusable Toggle ---
interface ToggleProps {
  checked: boolean;
  onChange: (v: boolean) => void;
  disabled?: boolean;
}
export const Toggle = ({ checked, onChange, disabled }: ToggleProps) => (
  <button
    type="button"
    role="switch"
    aria-checked={checked}
    disabled={disabled}
    onClick={() => onChange(!checked)}
    className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors focus:outline-none focus:ring-2 focus:ring-blue-500/50 disabled:opacity-40 disabled:cursor-not-allowed ${checked ? 'bg-blue-600' : 'bg-slate-700'}`}
  >
    <span className={`inline-block h-4 w-4 transform rounded-full bg-white shadow-sm transition-transform ${checked ? 'translate-x-6' : 'translate-x-1'}`} />
  </button>
);

// --- Setting Row ---
interface SettingRowProps {
  label: string;
  description: string;
  children: React.ReactNode;
  badge?: string;
}
export const SettingRow = ({ label, description, children, badge }: SettingRowProps) => (
  <div className="flex items-start justify-between gap-6 py-4 border-b border-slate-800 last:border-0">
    <div className="flex-1 min-w-0">
      <div className="flex items-center gap-2">
        <span className="text-sm font-medium text-slate-200">{label}</span>
        {badge && <span className="text-xs bg-blue-500/20 text-blue-400 border border-blue-500/30 px-1.5 py-0.5 rounded font-medium">{badge}</span>}
      </div>
      <p className="text-xs text-slate-500 mt-0.5 leading-relaxed">{description}</p>
    </div>
    <div className="shrink-0 flex items-center">{children}</div>
  </div>
);

// --- Section Card ---
export const Section = ({ title, icon, children }: { title: string; icon: string; children: React.ReactNode }) => (
  <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden">
    <div className="px-5 py-4 border-b border-slate-800 bg-slate-800/40">
      <h2 className="text-sm font-bold text-slate-200 flex items-center gap-2">
        <span>{icon}</span> {title}
      </h2>
    </div>
    <div className="px-5 divide-y divide-slate-800/60">{children}</div>
  </div>
);

// --- Number Input ---
export const NumberInput = ({ value, onChange, min, max, unit }: { value: number; onChange: (v: number) => void; min?: number; max?: number; unit?: string }) => (
  <div className="flex items-center gap-2">
    <input
      type="number"
      value={value}
      min={min}
      max={max}
      onChange={e => onChange(Math.max(min ?? 0, parseInt(e.target.value) || 0))}
      className="w-20 bg-slate-800 border border-slate-700 rounded-lg px-3 py-1.5 text-white text-sm text-center focus:outline-none focus:border-blue-500"
    />
    {unit && <span className="text-xs text-slate-500">{unit}</span>}
  </div>
);

// --- Tag Input (for email/IP lists) ---
interface TagInputProps {
  tags: string[];
  onChange: (tags: string[]) => void;
  placeholder: string;
  validate?: (v: string) => boolean;
}
export const TagInput = ({ tags, onChange, placeholder, validate }: TagInputProps) => {
  const [input, setInput] = useState('');
  const [error, setError] = useState('');

  const add = () => {
    const val = input.trim();
    if (!val) return;
    if (validate && !validate(val)) { setError('Invalid format'); return; }
    if (tags.includes(val)) { setError('Already added'); return; }
    onChange([...tags, val]);
    setInput('');
    setError('');
  };

  return (
    <div className="w-full space-y-2">
      <div className="flex gap-2">
        <input
          type="text"
          value={input}
          onChange={e => { setInput(e.target.value); setError(''); }}
          onKeyDown={e => { if (e.key === 'Enter') { e.preventDefault(); add(); } }}
          placeholder={placeholder}
          className="flex-1 bg-slate-800 border border-slate-700 rounded-lg px-3 py-1.5 text-white text-xs placeholder-slate-600 focus:outline-none focus:border-blue-500"
        />
        <button type="button" onClick={add} className="px-3 py-1.5 bg-blue-600 hover:bg-blue-500 text-white text-xs font-medium rounded-lg transition-colors">Add</button>
      </div>
      {error && <p className="text-xs text-red-400">{error}</p>}
      {tags.length > 0 && (
        <div className="flex flex-wrap gap-1.5">
          {tags.map(tag => (
            <span key={tag} className="inline-flex items-center gap-1 bg-slate-800 border border-slate-700 text-slate-300 text-xs px-2 py-0.5 rounded-full">
              {tag}
              <button type="button" onClick={() => onChange(tags.filter(t => t !== tag))} className="text-slate-500 hover:text-red-400 transition-colors">×</button>
            </span>
          ))}
        </div>
      )}
    </div>
  );
};

// --- Save Bar ---
interface SaveBarProps {
  isDirty: boolean;
  isSaving: boolean;
  onSave: () => void;
  onDiscard: () => void;
}
export const SaveBar = ({ isDirty, isSaving, onSave, onDiscard }: SaveBarProps) => {
  if (!isDirty && !isSaving) return null;
  return (
    <div className="fixed bottom-0 left-64 right-0 z-30 bg-slate-900 border-t border-slate-700 px-8 py-3 flex items-center justify-between">
      <p className="text-xs text-slate-400">You have unsaved changes</p>
      <div className="flex items-center gap-3">
        <button type="button" onClick={onDiscard} className="px-4 py-1.5 text-slate-400 hover:text-white border border-slate-700 rounded-lg text-sm transition-colors">Discard</button>
        <button type="button" onClick={onSave} disabled={isSaving} className="px-4 py-1.5 bg-blue-600 hover:bg-blue-500 disabled:opacity-50 text-white text-sm font-semibold rounded-lg transition-colors flex items-center gap-2">
          {isSaving && <svg className="animate-spin h-3.5 w-3.5" fill="none" viewBox="0 0 24 24"><circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"/><path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z"/></svg>}
          {isSaving ? 'Saving...' : 'Save Changes'}
        </button>
      </div>
    </div>
  );
};
