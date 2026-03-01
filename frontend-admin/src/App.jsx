import { useState, useEffect, useRef, useCallback } from 'react'
import { Routes, Route } from 'react-router-dom'
import AdminLayout from './components/AdminLayout'
import LiveDashboard from './pages/LiveDashboard'
import ThreatLog from './pages/ThreatLog'
import Settings from './pages/Settings'
import PolicyManagement from './pages/PolicyManagement'
import IntegrationManagement from './pages/IntegrationManagement'
import UserManagement from './pages/UserManagement'
import { createAdminWebSocket, fetchRecentEvents } from './api'

const MAX_EVENTS = 100

function App() {
  const [wsConnected, setWsConnected] = useState(false)
  const [events, setEvents] = useState([])
  const wsRef = useRef(null)
  const reconnectTimer = useRef(null)

  const addEvent = useCallback((event) => {
    setEvents((prev) => [event, ...prev].slice(0, MAX_EVENTS))
  }, [])

  const connectWs = useCallback(() => {
    if (wsRef.current) {
      try { wsRef.current.close() } catch {} 
    }

    wsRef.current = createAdminWebSocket(
      (data) => addEvent(data),
      () => {
        setWsConnected(true)
        // Restore recent events on (re)connect
        fetchRecentEvents(20)
          .then((res) => {
            if (res.events && res.events.length > 0) {
              setEvents((prev) => {
                const ids = new Set(prev.map((e) => e.event_id))
                const fresh = res.events.filter((e) => !ids.has(e.event_id))
                return [...fresh, ...prev].slice(0, MAX_EVENTS)
              })
            }
          })
          .catch(() => {})
      },
      () => {
        setWsConnected(false)
        // Auto-reconnect after 3s
        reconnectTimer.current = setTimeout(connectWs, 3000)
      },
      () => {
        setWsConnected(false)
      }
    )
  }, [addEvent])

  useEffect(() => {
    connectWs()
    return () => {
      clearTimeout(reconnectTimer.current)
      if (wsRef.current) {
        try { wsRef.current.close() } catch {}
      }
    }
  }, [connectWs])

  return (
    <Routes>
      <Route element={<AdminLayout wsConnected={wsConnected} />}>
        <Route path="/" element={<LiveDashboard events={events} />} />
        <Route path="/threat-log" element={<ThreatLog />} />
        <Route path="/policy-management" element={<PolicyManagement />} />
        <Route path="/integration-management" element={<IntegrationManagement />} />
        <Route path="/user-management" element={<UserManagement />} />
        <Route path="/settings" element={<Settings wsConnected={wsConnected} />} />
      </Route>
    </Routes>
  )
}

export default App
