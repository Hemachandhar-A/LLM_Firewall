import axios from 'axios';

const API_BASE = import.meta.env.VITE_BACKEND_URL || 'http://localhost:8000';

const api = axios.create({
  baseURL: API_BASE,
  timeout: 30000,
  headers: { 'Content-Type': 'application/json' },
});

/**
 * Send a chat message through the firewall pipeline.
 * POST /chat/message
 */
export async function sendMessage(sessionId, message, role = 'guest') {
  const response = await api.post('/chat/message', {
    session_id: sessionId,
    message,
    role,
  });
  return response.data;
}

export default api;
