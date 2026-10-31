import axios from 'axios';
import {
  FileForensicsResponse,
  ThreatIntelReport,
  EmailForensicsResponse,
  NetworkForensicsResponse,
  EvidenceItem,
  CustodyLog,
  InvestigationSummary,
  InvestigationDetail,
  TimelineEvent,
  InvestigationIOC,
  InvestigationNote,
  EvidenceComparisonResponse,
  InvestigationGraphResponse
} from '../types';

const API_BASE = 'http://127.0.0.1:8000/api/v1';

const apiClient = axios.create({
  baseURL: API_BASE,
  timeout: 45000,
});

export const fileForensicsApi = {
  analyzeFile: async (file: File): Promise<FileForensicsResponse> => {
    const formData = new FormData();
    formData.append('file', file);
    const res = await apiClient.post<FileForensicsResponse>('/files/analyze', formData, {
      headers: { 'Content-Type': 'multipart/form-data' }
    });
    return res.data;
  }
};

export const threatIntelApi = {
  lookup: async (ioc: string): Promise<ThreatIntelReport> => {
    const res = await apiClient.get<ThreatIntelReport>('/intel/lookup', {
      params: { ioc: ioc.trim() }
    });
    return res.data;
  },
  batchLookup: async (indicators: string[]): Promise<ThreatIntelReport[]> => {
    const res = await apiClient.post<ThreatIntelReport[]>('/intel/batch', { indicators });
    return res.data;
  }
};

export const emailForensicsApi = {
  analyzeEmail: async (file?: File, rawContent?: string): Promise<EmailForensicsResponse> => {
    const formData = new FormData();
    if (file) formData.append('file', file);
    if (rawContent) formData.append('raw_content', rawContent);
    const res = await apiClient.post<EmailForensicsResponse>('/email/analyze', formData, {
      headers: { 'Content-Type': 'multipart/form-data' }
    });
    return res.data;
  }
};

export const networkForensicsApi = {
  analyzePcap: async (file: File): Promise<NetworkForensicsResponse> => {
    const formData = new FormData();
    formData.append('file', file);
    const res = await apiClient.post<NetworkForensicsResponse>('/network/analyze', formData, {
      headers: { 'Content-Type': 'multipart/form-data' }
    });
    return res.data;
  }
};

export const evidenceApi = {
  list: async (investigationId?: string): Promise<EvidenceItem[]> => {
    const res = await apiClient.get<EvidenceItem[]>('/evidence/', {
      params: investigationId ? { investigation_id: investigationId } : {}
    });
    return res.data;
  },
  get: async (id: string): Promise<EvidenceItem> => {
    const res = await apiClient.get<EvidenceItem>(`/evidence/${id}`);
    return res.data;
  },
  register: async (formData: FormData): Promise<EvidenceItem> => {
    const res = await apiClient.post<EvidenceItem>('/evidence/register', formData, {
      headers: { 'Content-Type': 'multipart/form-data' }
    });
    return res.data;
  },
  verifyIntegrity: async (
    id: string,
    verifiedBy: string,
    badgeNumber: string,
    reason: string = 'Forensic Integrity Audit',
    notes?: string
  ): Promise<CustodyLog> => {
    const res = await apiClient.post<CustodyLog>(`/evidence/${id}/verify`, {
      verified_by: verifiedBy,
      badge_number: badgeNumber,
      reason,
      notes
    });
    return res.data;
  },
  compare: async (idA: string, idB: string): Promise<EvidenceComparisonResponse> => {
    const res = await apiClient.post<EvidenceComparisonResponse>('/evidence/compare', {
      evidence_id_a: idA,
      evidence_id_b: idB
    });
    return res.data;
  },
  transferCustody: async (id: string, data: { transferred_to: string; recipient_badge: string; transferred_by?: string; releasing_badge?: string; new_location?: string; reason?: string; notes?: string }): Promise<CustodyLog> => {
    const res = await apiClient.post<CustodyLog>(`/evidence/${id}/transfer`, data);
    return res.data;
  }
};

export const investigationsApi = {
  list: async (): Promise<InvestigationSummary[]> => {
    const res = await apiClient.get<InvestigationSummary[]>('/investigations/');
    return res.data;
  },
  get: async (id: string): Promise<InvestigationDetail> => {
    const res = await apiClient.get<InvestigationDetail>(`/investigations/${id}`);
    return res.data;
  },
  getGraph: async (id: string): Promise<InvestigationGraphResponse> => {
    const res = await apiClient.get<InvestigationGraphResponse>(`/investigations/${id}/graph`);
    return res.data;
  },
  create: async (data: { title: string; description?: string; priority?: string; lead_analyst?: string }): Promise<InvestigationDetail> => {
    const res = await apiClient.post<InvestigationDetail>('/investigations/', data);
    return res.data;
  },
  update: async (id: string, data: Partial<{ title: string; description: string; status: string; priority: string; lead_analyst: string }>): Promise<InvestigationDetail> => {
    const res = await apiClient.patch<InvestigationDetail>(`/investigations/${id}`, data);
    return res.data;
  },
  addTimelineEvent: async (id: string, event: { title: string; description?: string; category: string; severity: string; source: string; raw_reference?: string }): Promise<TimelineEvent> => {
    const res = await apiClient.post<TimelineEvent>(`/investigations/${id}/timeline`, event);
    return res.data;
  },
  addIOC: async (id: string, ioc: { ioc_type: string; value: string; category: string; threat_score: number; classification: string; attribution_source: string; notes?: string }): Promise<InvestigationIOC> => {
    const res = await apiClient.post<InvestigationIOC>(`/investigations/${id}/iocs`, ioc);
    return res.data;
  },
  addNote: async (id: string, note: { author: string; badge_number: string; content: string; is_finding: string }): Promise<InvestigationNote> => {
    const res = await apiClient.post<InvestigationNote>(`/investigations/${id}/notes`, note);
    return res.data;
  }
};

export const reportsApi = {
  exportJson: async (id: string): Promise<any> => {
    const res = await apiClient.post(`/reports/${id}/export`, {
      format: 'json',
      include_evidence: true,
      include_timeline: true,
      include_iocs: true,
      include_notes: true
    });
    return res.data;
  },
  downloadPdf: async (id: string, analystSignature: string, badgeNumber: string): Promise<Blob> => {
    const res = await apiClient.post(`/reports/${id}/export`, {
      format: 'pdf',
      include_evidence: true,
      include_timeline: true,
      include_iocs: true,
      include_notes: true,
      analyst_signature: analystSignature,
      badge_number: badgeNumber
    }, {
      responseType: 'blob'
    });
    return res.data;
  }
};
