import { apiClient } from "./client";
import type { Incident, IncidentListResponse, AnalyticsSummary } from "@/types";

export const incidentsApi = {
  list: (params?: {
    status?: string;
    risk_level?: string;
    ai_prediction?: string;
    source_ip?: string;
    alert_type?: string;
    page?: number;
    page_size?: number;
  }) => apiClient.get<IncidentListResponse>("/incidents", { params }),

  get: (id: number) => apiClient.get<Incident>(`/incidents/${id}`),

  approve: (id: number, data?: { comment?: string; action_taken?: string }) =>
    apiClient.put(`/incidents/${id}/approve`, data ?? {}),

  reject: (id: number, data?: { comment?: string; is_false_positive?: boolean }) =>
    apiClient.put(`/incidents/${id}/reject`, data ?? {}),

  escalate: (id: number) => apiClient.put(`/incidents/${id}/escalate`),

  uploadLogs: (file: File, onProgress?: (pct: number) => void) => {
    const form = new FormData();
    form.append("file", file);
    return apiClient.post<{ incidents_found: number; total_events: number }>(
      "/incidents/upload-logs",
      form,
      {
        headers: { "Content-Type": "multipart/form-data" },
        onUploadProgress: (e) => {
          if (onProgress && e.total) {
            onProgress(Math.round((e.loaded * 100) / e.total));
          }
        },
      }
    );
  },

  analytics: () => apiClient.get<AnalyticsSummary>("/incidents/summary/analytics"),
};
