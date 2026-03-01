import React, { useState, useEffect } from 'react';
import { 
  Users, Plus, Edit3, Trash2, Lock, Unlock, Shield, 
  Clock, Activity, AlertTriangle, CheckCircle, Search,
  Filter, MoreVertical, Eye, EyeOff, Download, UserPlus
} from 'lucide-react';

const API_BASE = import.meta.env.VITE_BACKEND_URL || 'http://localhost:8000';

const UserManagement = () => {
  const [users, setUsers] = useState([]);
  const [auditLogs, setAuditLogs] = useState([]);
  const [activeSessions, setActiveSessions] = useState([]);
  const [selectedTab, setSelectedTab] = useState('users');
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [selectedUser, setSelectedUser] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [searchTerm, setSearchTerm] = useState('');
  const [filterRole, setFilterRole] = useState('all');
  const [filterStatus, setFilterStatus] = useState('all');

  useEffect(() => {
    fetchData();
  }, [selectedTab]);

  const fetchData = async () => {
    try {
      setLoading(true);
      
      if (selectedTab === 'users') {
        const response = await fetch(`${API_BASE}/api/users/users`);
        if (response.ok) {
          setUsers(await response.json());
        }
      } else if (selectedTab === 'audit') {
        const response = await fetch(`${API_BASE}/api/users/audit/logs?limit=100`);
        if (response.ok) {
          setAuditLogs(await response.json());
        }
      } else if (selectedTab === 'sessions') {
        const response = await fetch(`${API_BASE}/api/users/sessions`);
        if (response.ok) {
          setActiveSessions(await response.json());
        }
      }
    } catch (err) {
      setError('Failed to fetch data');
    } finally {
      setLoading(false);
    }
  };

  const deleteUser = async (userId) => {
    if (!window.confirm('Are you sure you want to delete this user?')) return;

    try {
      const response = await fetch(`${API_BASE}/api/users/users/${userId}`, {
        method: 'DELETE'
      });
      if (response.ok) {
        fetchData();
      }
    } catch (err) {
      setError('Failed to delete user');
    }
  };

  const terminateSession = async (sessionId) => {
    if (!window.confirm('Are you sure you want to terminate this session?')) return;

    try {
      const response = await fetch(`${API_BASE}/api/users/sessions/${sessionId}`, {
        method: 'DELETE'
      });
      if (response.ok) {
        fetchData();
      }
    } catch (err) {
      setError('Failed to terminate session');
    }
  };

  const getRoleColor = (role) => {
    switch (role) {
      case 'admin': return 'text-red-400 bg-red-500/10 border-red-500/20';
      case 'security_analyst': return 'text-purple-400 bg-purple-500/10 border-purple-500/20';
      case 'operator': return 'text-blue-400 bg-blue-500/10 border-blue-500/20';
      case 'viewer': return 'text-green-400 bg-green-500/10 border-green-500/20';
      case 'api_user': return 'text-yellow-400 bg-yellow-500/10 border-yellow-500/20';
      default: return 'text-gray-400 bg-gray-500/10 border-gray-500/20';
    }
  };

  const getStatusColor = (status) => {
    switch (status) {
      case 'active': return 'text-green-400 bg-green-500/10 border-green-500/20';
      case 'inactive': return 'text-gray-400 bg-gray-500/10 border-gray-500/20';
      case 'suspended': return 'text-yellow-400 bg-yellow-500/10 border-yellow-500/20';
      case 'locked': return 'text-red-400 bg-red-500/10 border-red-500/20';
      default: return 'text-gray-400 bg-gray-500/10 border-gray-500/20';
    }
  };

  const getActionIcon = (action) => {
    switch (action) {
      case 'login': return <Lock className="h-4 w-4 text-blue-400" />;
      case 'logout': return <Unlock className="h-4 w-4 text-gray-400" />;
      case 'create': return <Plus className="h-4 w-4 text-green-400" />;
      case 'update': return <Edit3 className="h-4 w-4 text-yellow-400" />;
      case 'delete': return <Trash2 className="h-4 w-4 text-red-400" />;
      default: return <Activity className="h-4 w-4 text-gray-400" />;
    }
  };

  const filteredUsers = users.filter(user => {
    const matchesSearch = user.username.toLowerCase().includes(searchTerm.toLowerCase()) ||
                         user.email.toLowerCase().includes(searchTerm.toLowerCase()) ||
                         user.full_name.toLowerCase().includes(searchTerm.toLowerCase());
    const matchesRole = filterRole === 'all' || user.role === filterRole;
    const matchesStatus = filterStatus === 'all' || user.status === filterStatus;
    return matchesSearch && matchesRole && matchesStatus;
  });

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin h-8 w-8 border-2 border-cyan-400 rounded-full border-t-transparent"></div>
      </div>
    );
  }

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <div className="flex items-center gap-3 mb-2">
            <div className="p-2 bg-blue-500/20 rounded-lg">
              <Users className="h-6 w-6 text-blue-400" />
            </div>
            <h1 className="text-2xl font-bold text-white">User Management</h1>
          </div>
          <p className="text-gray-400">Manage user accounts, roles, and access permissions</p>
        </div>
        <button 
          onClick={() => setShowCreateModal(true)}
          className="flex items-center gap-2 px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors"
        >
          <UserPlus className="h-4 w-4" />
          Add User
        </button>
      </div>

      {error && (
        <div className="bg-red-500/10 border border-red-500/20 rounded-lg p-4 text-red-400">
          {error}
        </div>
      )}

      {/* Stats */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <div className="bg-gray-800/30 border border-gray-700/50 rounded-lg p-4">
          <div className="flex items-center gap-3">
            <Users className="h-5 w-5 text-blue-400" />
            <div>
              <p className="text-gray-400 text-sm">Total Users</p>
              <p className="text-white text-xl font-semibold">{users.length}</p>
            </div>
          </div>
        </div>
        <div className="bg-gray-800/30 border border-gray-700/50 rounded-lg p-4">
          <div className="flex items-center gap-3">
            <CheckCircle className="h-5 w-5 text-green-400" />
            <div>
              <p className="text-gray-400 text-sm">Active Users</p>
              <p className="text-white text-xl font-semibold">
                {users.filter(u => u.status === 'active').length}
              </p>
            </div>
          </div>
        </div>
        <div className="bg-gray-800/30 border border-gray-700/50 rounded-lg p-4">
          <div className="flex items-center gap-3">
            <Activity className="h-5 w-5 text-purple-400" />
            <div>
              <p className="text-gray-400 text-sm">Active Sessions</p>
              <p className="text-white text-xl font-semibold">{activeSessions.length}</p>
            </div>
          </div>
        </div>
        <div className="bg-gray-800/30 border border-gray-700/50 rounded-lg p-4">
          <div className="flex items-center gap-3">
            <Shield className="h-5 w-5 text-red-400" />
            <div>
              <p className="text-gray-400 text-sm">Admins</p>
              <p className="text-white text-xl font-semibold">
                {users.filter(u => u.role === 'admin').length}
              </p>
            </div>
          </div>
        </div>
      </div>

      {/* Tabs */}
      <div className="flex space-x-1 bg-gray-800/30 border border-gray-700/50 rounded-lg p-1">
        {[
          { id: 'users', label: 'Users', icon: <Users className="h-4 w-4" /> },
          { id: 'sessions', label: 'Active Sessions', icon: <Activity className="h-4 w-4" /> },
          { id: 'audit', label: 'Audit Log', icon: <Clock className="h-4 w-4" /> }
        ].map(tab => (
          <button
            key={tab.id}
            onClick={() => setSelectedTab(tab.id)}
            className={`flex items-center gap-2 px-4 py-2 rounded-lg transition-colors ${
              selectedTab === tab.id 
                ? 'bg-blue-600 text-white' 
                : 'text-gray-400 hover:text-white hover:bg-gray-700/50'
            }`}
          >
            {tab.icon}
            {tab.label}
          </button>
        ))}
      </div>

      {/* Users Tab */}
      {selectedTab === 'users' && (
        <div className="space-y-6">
          {/* Filters */}
          <div className="flex flex-col sm:flex-row gap-4">
            <div className="flex-1 relative">
              <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-gray-400" />
              <input
                type="text"
                placeholder="Search users..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                className="w-full bg-gray-800/50 border border-gray-700 rounded-lg pl-10 pr-4 py-2 text-white placeholder-gray-400 focus:border-blue-500 focus:outline-none"
              />
            </div>
            <select
              value={filterRole}
              onChange={(e) => setFilterRole(e.target.value)}
              className="bg-gray-800/50 border border-gray-700 rounded-lg px-4 py-2 text-white focus:border-blue-500 focus:outline-none"
            >
              <option value="all">All Roles</option>
              <option value="admin">Admin</option>
              <option value="security_analyst">Security Analyst</option>
              <option value="operator">Operator</option>
              <option value="viewer">Viewer</option>
              <option value="api_user">API User</option>
            </select>
            <select
              value={filterStatus}
              onChange={(e) => setFilterStatus(e.target.value)}
              className="bg-gray-800/50 border border-gray-700 rounded-lg px-4 py-2 text-white focus:border-blue-500 focus:outline-none"
            >
              <option value="all">All Status</option>
              <option value="active">Active</option>
              <option value="inactive">Inactive</option>
              <option value="suspended">Suspended</option>
              <option value="locked">Locked</option>
            </select>
          </div>

          {/* Users Table */}
          <div className="bg-gray-800/30 border border-gray-700/50 rounded-lg overflow-hidden">
            <table className="w-full">
              <thead className="bg-gray-800/50">
                <tr>
                  <th className="text-left px-6 py-3 text-gray-400 font-medium">User</th>
                  <th className="text-left px-6 py-3 text-gray-400 font-medium">Role</th>
                  <th className="text-left px-6 py-3 text-gray-400 font-medium">Status</th>
                  <th className="text-left px-6 py-3 text-gray-400 font-medium">Last Login</th>
                  <th className="text-left px-6 py-3 text-gray-400 font-medium">Login Count</th>
                  <th className="text-left px-6 py-3 text-gray-400 font-medium">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-700/50">
                {filteredUsers.map((user) => (
                  <tr key={user.id} className="hover:bg-gray-800/30">
                    <td className="px-6 py-4">
                      <div>
                        <div className="text-white font-medium">{user.full_name}</div>
                        <div className="text-gray-400 text-sm">{user.username} • {user.email}</div>
                      </div>
                    </td>
                    <td className="px-6 py-4">
                      <span className={`px-2 py-1 rounded text-xs font-medium border ${getRoleColor(user.role)}`}>
                        {user.role.replace('_', ' ').toUpperCase()}
                      </span>
                    </td>
                    <td className="px-6 py-4">
                      <span className={`px-2 py-1 rounded text-xs font-medium border ${getStatusColor(user.status)}`}>
                        {user.status.toUpperCase()}
                      </span>
                    </td>
                    <td className="px-6 py-4 text-gray-300">
                      {user.last_login ? new Date(user.last_login).toLocaleString() : 'Never'}
                    </td>
                    <td className="px-6 py-4 text-gray-300">{user.login_count || 0}</td>
                    <td className="px-6 py-4">
                      <div className="flex gap-2">
                        <button
                          onClick={() => setSelectedUser(user)}
                          className="p-1 rounded hover:bg-gray-700/50 transition-colors"
                          title="View Details"
                        >
                          <Eye className="h-4 w-4 text-gray-400" />
                        </button>
                        <button className="p-1 rounded hover:bg-gray-700/50 transition-colors" title="Edit User">
                          <Edit3 className="h-4 w-4 text-gray-400" />
                        </button>
                        <button
                          onClick={() => deleteUser(user.id)}
                          className="p-1 rounded hover:bg-gray-700/50 transition-colors"
                          title="Delete User"
                        >
                          <Trash2 className="h-4 w-4 text-red-400" />
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Sessions Tab */}
      {selectedTab === 'sessions' && (
        <div className="space-y-4">
          <div className="bg-gray-800/30 border border-gray-700/50 rounded-lg overflow-hidden">
            <table className="w-full">
              <thead className="bg-gray-800/50">
                <tr>
                  <th className="text-left px-6 py-3 text-gray-400 font-medium">User</th>
                  <th className="text-left px-6 py-3 text-gray-400 font-medium">IP Address</th>
                  <th className="text-left px-6 py-3 text-gray-400 font-medium">Started</th>
                  <th className="text-left px-6 py-3 text-gray-400 font-medium">Last Activity</th>
                  <th className="text-left px-6 py-3 text-gray-400 font-medium">Expires</th>
                  <th className="text-left px-6 py-3 text-gray-400 font-medium">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-700/50">
                {activeSessions.map((session) => (
                  <tr key={session.session_id} className="hover:bg-gray-800/30">
                    <td className="px-6 py-4 text-white font-medium">{session.username}</td>
                    <td className="px-6 py-4 text-gray-300 font-mono">{session.ip_address}</td>
                    <td className="px-6 py-4 text-gray-300">
                      {new Date(session.created_at).toLocaleString()}
                    </td>
                    <td className="px-6 py-4 text-gray-300">
                      {new Date(session.last_activity).toLocaleString()}
                    </td>
                    <td className="px-6 py-4 text-gray-300">
                      {new Date(session.expires_at).toLocaleString()}
                    </td>
                    <td className="px-6 py-4">
                      <button
                        onClick={() => terminateSession(session.session_id)}
                        className="px-3 py-1 bg-red-600/20 border border-red-500/30 text-red-400 rounded hover:bg-red-600/30 transition-colors text-sm"
                      >
                        Terminate
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Audit Log Tab */}
      {selectedTab === 'audit' && (
        <div className="space-y-4">
          <div className="bg-gray-800/30 border border-gray-700/50 rounded-lg overflow-hidden">
            <table className="w-full">
              <thead className="bg-gray-800/50">
                <tr>
                  <th className="text-left px-6 py-3 text-gray-400 font-medium">Action</th>
                  <th className="text-left px-6 py-3 text-gray-400 font-medium">User</th>
                  <th className="text-left px-6 py-3 text-gray-400 font-medium">Resource</th>
                  <th className="text-left px-6 py-3 text-gray-400 font-medium">IP Address</th>
                  <th className="text-left px-6 py-3 text-gray-400 font-medium">Timestamp</th>
                  <th className="text-left px-6 py-3 text-gray-400 font-medium">Status</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-700/50">
                {auditLogs.map((log) => (
                  <tr key={log.id} className="hover:bg-gray-800/30">
                    <td className="px-6 py-4">
                      <div className="flex items-center gap-2">
                        {getActionIcon(log.action)}
                        <span className="text-white capitalize">{log.action.replace('_', ' ')}</span>
                      </div>
                    </td>
                    <td className="px-6 py-4 text-gray-300">{log.username || 'System'}</td>
                    <td className="px-6 py-4">
                      <div>
                        <div className="text-white">{log.resource_type}</div>
                        {log.resource_id && (
                          <div className="text-gray-400 text-sm font-mono">{log.resource_id}</div>
                        )}
                      </div>
                    </td>
                    <td className="px-6 py-4 text-gray-300 font-mono">{log.ip_address || 'N/A'}</td>
                    <td className="px-6 py-4 text-gray-300">
                      {new Date(log.timestamp).toLocaleString()}
                    </td>
                    <td className="px-6 py-4">
                      <span className={`px-2 py-1 rounded text-xs font-medium ${
                        log.success ? 'bg-green-500/20 text-green-400' : 'bg-red-500/20 text-red-400'
                      }`}>
                        {log.success ? 'Success' : 'Failed'}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* User Details Modal */}
      {selectedUser && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
          <div className="bg-gray-800 rounded-lg p-6 max-w-md w-full">
            <div className="flex items-center justify-between mb-6">
              <h2 className="text-xl font-semibold text-white">User Details</h2>
              <button
                onClick={() => setSelectedUser(null)}
                className="text-gray-400 hover:text-white"
              >
                ✕
              </button>
            </div>

            <div className="space-y-4">
              <div>
                <label className="text-gray-400 text-sm">Full Name</label>
                <p className="text-white">{selectedUser.full_name}</p>
              </div>
              <div>
                <label className="text-gray-400 text-sm">Username</label>
                <p className="text-white">{selectedUser.username}</p>
              </div>
              <div>
                <label className="text-gray-400 text-sm">Email</label>
                <p className="text-white">{selectedUser.email}</p>
              </div>
              <div>
                <label className="text-gray-400 text-sm">Role</label>
                <p className="text-white capitalize">{selectedUser.role.replace('_', ' ')}</p>
              </div>
              <div>
                <label className="text-gray-400 text-sm">Status</label>
                <p className="text-white capitalize">{selectedUser.status}</p>
              </div>
              <div>
                <label className="text-gray-400 text-sm">Created</label>
                <p className="text-white">
                  {selectedUser.created_at ? new Date(selectedUser.created_at).toLocaleString() : 'N/A'}
                </p>
              </div>
              <div>
                <label className="text-gray-400 text-sm">Last Login</label>
                <p className="text-white">
                  {selectedUser.last_login ? new Date(selectedUser.last_login).toLocaleString() : 'Never'}
                </p>
              </div>
              <div>
                <label className="text-gray-400 text-sm">Login Count</label>
                <p className="text-white">{selectedUser.login_count || 0}</p>
              </div>
            </div>

            <div className="flex gap-3 mt-6">
              <button
                onClick={() => setSelectedUser(null)}
                className="flex-1 px-4 py-2 border border-gray-600 text-gray-300 rounded-lg hover:bg-gray-700 transition-colors"
              >
                Close
              </button>
              <button className="flex-1 px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors">
                Edit User
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default UserManagement;