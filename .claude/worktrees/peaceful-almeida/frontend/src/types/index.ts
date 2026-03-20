export type UserRole = "admin" | "analyst" | "viewer";

export interface User {
  id: number;
  email: string;
  full_name: string;
  role: UserRole;
  organization_id: number;
  is_active: boolean;
  is_verified: boolean;
  last_login: string | null;
  notification_email: boolean;
  notification_slack: boolean;
  created_at: string;
}

export interface Organization {
  id: number;
  name: string;
  slug: string;
  is_active: boolean;
  max_users: number;
  created_at: string;
}

export type RiskLevel = "Critical" | "High" | "Medium" | "Low" | "Info";
export type IncidentStatus =
  | "Pending"
  | "Approved"
  | "Rejected"
  | "In Progress"
  | "Resolved"
  | "Escalated";

export interface Incident {
  id: number;
  organization_id: number;
  source_ip: string | null;
  destination_ip: string | null;
  domain: string | null;
  timestamp: string | null;
  alert_type: string | null;
  summary: string | null;
  risk_level: RiskLevel | null;
  recommended_action: string | null;
  status: IncidentStatus;
  ai_prediction: "suspicious" | "normal" | null;
  ai_score: number | null;
  ai_reason: string | null;
  confidence_score: number | null;
  mitre_tactic: string | null;
  mitre_tactic_id: string | null;
  mitre_technique: string | null;
  mitre_technique_id: string | null;
  approved_by_id: number | null;
  approval_comment: string | null;
  approved_at: string | null;
  action_taken: string | null;
  is_false_positive: boolean;
  log_source: string | null;
  created_at: string;
  updated_at: string | null;
  resolved_at: string | null;
}

export interface IncidentListResponse {
  items: Incident[];
  total: number;
  page: number;
  page_size: number;
  pages: number;
}

export interface AnalyticsSummary {
  total_incidents: number;
  pending: number;
  approved: number;
  rejected: number;
  resolved: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  ai_detected_anomalies: number;
  false_positives: number;
  avg_response_time_hours: number | null;
}

export interface TokenResponse {
  access_token: string;
  refresh_token: string;
  token_type: string;
  expires_in: number;
}

export type WsEventType =
  | "connected"
  | "new_incident"
  | "incident_updated"
  | "pong";

export interface WsMessage {
  event: WsEventType;
  data: Record<string, unknown>;
}
