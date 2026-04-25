export interface VaultFileSummary {
  id: number;
  original_name: string;
  size_bytes: number;
  scan_status?: string;
}

export interface DamEventSummary {
  event_id: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  action: string;
  actor_email?: string | null;
}
