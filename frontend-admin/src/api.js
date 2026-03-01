import axios from 'axios';

const API_BASE = import.meta.env.VITE_BACKEND_URL || 'http://localhost:8000';
const WS_BASE = import.meta.env.VITE_WS_URL || 'ws://localhost:8000';

const api = axios.create({
  baseURL: API_BASE,
  timeout: 15000,
  headers: { 'Content-Type': 'application/json' },
});

/** GET /admin/stats */
export async function fetchStats() {
  const res = await api.get('/admin/stats');
  return res.data;
}

/** GET /admin/threat-log */
export async function fetchThreatLog({ action, layer, owasp_tag, page = 1, page_size = 20 } = {}) {
  const params = { page, page_size };
  if (action && action !== 'All Actions') params.action = action;
  if (layer && layer !== 'All Layers') {
    const layerMap = {
      'Prompt Injection': 1,
      'PII Leakage': 5,
      'Toxic Language': 5,
      'Data Exfiltration': 5,
      'Memory Audit': 3,
      'Tool Scanner': 2,
    };
    params.layer = layerMap[layer] || undefined;
  }
  if (owasp_tag && owasp_tag !== 'Any Tag') params.owasp_tag = owasp_tag;
  const res = await api.get('/admin/threat-log', { params });
  return res.data;
}

/** GET /admin/session/:id/detail */
export async function fetchSessionDetail(sessionId) {
  const res = await api.get(`/admin/session/${sessionId}/detail`);
  return res.data;
}

/** GET /admin/recent-events */
export async function fetchRecentEvents(limit = 20) {
  const res = await api.get('/admin/recent-events', { params: { limit } });
  return res.data;
}

/** GET /admin/active-sessions */
export async function fetchActiveSessions() {
  const res = await api.get('/admin/active-sessions');
  return res.data;
}

/** Create a WebSocket connection for admin live feed */
export function createAdminWebSocket(onMessage, onOpen, onClose, onError) {
  const ws = new WebSocket(`${WS_BASE}/ws/admin`);

  ws.onopen = () => {
    if (onOpen) onOpen();
  };

  ws.onmessage = (event) => {
    try {
      const data = JSON.parse(event.data);
      if (onMessage) onMessage(data);
    } catch {
      // Ignore non-JSON messages (e.g. pong)
    }
  };

  ws.onclose = () => {
    if (onClose) onClose();
  };

  ws.onerror = (err) => {
    if (onError) onError(err);
  };

  return ws;
}

export default api;
