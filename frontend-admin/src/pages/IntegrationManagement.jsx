import React, { useState, useEffect } from 'react';
import { 
  Plug, Plus, Edit3, Trash2, Play, Pause, RefreshCw, 
  AlertTriangle, CheckCircle, Clock, Zap, Globe, 
  Database, Bell, BarChart3, Shield, Key, Webhook
} from 'lucide-react';

const API_BASE = import.meta.env.VITE_BACKEND_URL || 'http://localhost:8000';

const IntegrationManagement = () => {
  const [integrations, setIntegrations] = useState([]);
  const [apiKeys, setApiKeys] = useState([]);
  const [webhooks, setWebhooks] = useState([]);
  const [selectedTab, setSelectedTab] = useState('integrations');
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [healthStatus, setHealthStatus] = useState(null);

  useEffect(() => {
    fetchData();
  }, [selectedTab]);

  const fetchData = async () => {
    try {
      setLoading(true);
      
      if (selectedTab === 'integrations') {
        const [integrationsRes, healthRes] = await Promise.all([
          fetch(`${API_BASE}/api/integrations/integrations`),
          fetch(`${API_BASE}/api/integrations/integrations/health`)
        ]);
        
        if (integrationsRes.ok) {
          setIntegrations(await integrationsRes.json());
        }
        if (healthRes.ok) {
          setHealthStatus(await healthRes.json());
        }
      } else if (selectedTab === 'api-keys') {
        const response = await fetch(`${API_BASE}/api/integrations/api-keys`);
        if (response.ok) {
          setApiKeys(await response.json());
        }
      } else if (selectedTab === 'webhooks') {
        const response = await fetch(`${API_BASE}/api/integrations/webhooks`);
        if (response.ok) {
          setWebhooks(await response.json());
        }
      }
    } catch (err) {
      setError('Failed to fetch data');
    } finally {
      setLoading(false);
    }
  };

  const testIntegration = async (integrationId) => {
    try {
      const response = await fetch(`${API_BASE}/api/integrations/integrations/${integrationId}/test`, {
        method: 'POST'
      });
      const result = await response.json();
      
      if (result.status === 'success') {
        alert('Integration test successful!');
      } else {
        alert(`Integration test failed: ${result.message}`);
      }
      
      fetchData(); // Refresh data
    } catch (err) {
      alert('Test failed: ' + err.message);
    }
  };

  const deleteIntegration = async (integrationId) => {
    if (!window.confirm('Are you sure you want to delete this integration?')) return;

    try {
      const response = await fetch(`${API_BASE}/api/integrations/integrations/${integrationId}`, {
        method: 'DELETE'
      });
      if (response.ok) {
        fetchData();
      }
    } catch (err) {
      setError('Failed to delete integration');
    }
  };

  const revokeApiKey = async (keyId) => {
    if (!window.confirm('Are you sure you want to revoke this API key?')) return;

    try {
      const response = await fetch(`${API_BASE}/api/integrations/api-keys/${keyId}`, {
        method: 'DELETE'
      });
      if (response.ok) {
        fetchData();
      }
    } catch (err) {
      setError('Failed to revoke API key');
    }
  };

  const getIntegrationIcon = (type) => {
    switch (type) {
      case 'siem': return <Shield className="h-5 w-5" />;
      case 'monitoring': return <BarChart3 className="h-5 w-5" />;
      case 'notification': return <Bell className="h-5 w-5" />;
      case 'analytics': return <BarChart3 className="h-5 w-5" />;
      case 'threat_intelligence': return <Zap className="h-5 w-5" />;
      default: return <Globe className="h-5 w-5" />;
    }
  };

  const getStatusColor = (status) => {
    switch (status) {
      case 'active': return 'text-green-400 bg-green-500/10 border-green-500/20';
      case 'error': return 'text-red-400 bg-red-500/10 border-red-500/20';
      case 'pending': return 'text-yellow-400 bg-yellow-500/10 border-yellow-500/20';
      case 'inactive': return 'text-gray-400 bg-gray-500/10 border-gray-500/20';
      default: return 'text-gray-400 bg-gray-500/10 border-gray-500/20';
    }
  };

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
            <div className="p-2 bg-purple-500/20 rounded-lg">
              <Plug className="h-6 w-6 text-purple-400" />
            </div>
            <h1 className="text-2xl font-bold text-white">Integration Management</h1>
          </div>
          <p className="text-gray-400">Manage third-party integrations, API keys, and webhooks</p>
        </div>
        <button 
          onClick={() => setShowCreateModal(true)}
          className="flex items-center gap-2 px-4 py-2 bg-purple-600 text-white rounded-lg hover:bg-purple-700 transition-colors"
        >
          <Plus className="h-4 w-4" />
          Add Integration
        </button>
      </div>

      {error && (
        <div className="bg-red-500/10 border border-red-500/20 rounded-lg p-4 text-red-400">
          {error}
        </div>
      )}

      {/* Health Status */}
      {healthStatus && selectedTab === 'integrations' && (
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          <div className="bg-gray-800/30 border border-gray-700/50 rounded-lg p-4">
            <div className="flex items-center gap-3">
              <Database className="h-5 w-5 text-cyan-400" />
              <div>
                <p className="text-gray-400 text-sm">Total Integrations</p>
                <p className="text-white text-xl font-semibold">{healthStatus.total_count}</p>
              </div>
            </div>
          </div>
          <div className="bg-gray-800/30 border border-gray-700/50 rounded-lg p-4">
            <div className="flex items-center gap-3">
              <CheckCircle className="h-5 w-5 text-green-400" />
              <div>
                <p className="text-gray-400 text-sm">Active</p>
                <p className="text-white text-xl font-semibold">{healthStatus.active_count}</p>
              </div>
            </div>
          </div>
          <div className="bg-gray-800/30 border border-gray-700/50 rounded-lg p-4">
            <div className="flex items-center gap-3">
              <AlertTriangle className="h-5 w-5 text-red-400" />
              <div>
                <p className="text-gray-400 text-sm">Errors</p>
                <p className="text-white text-xl font-semibold">{healthStatus.error_count}</p>
              </div>
            </div>
          </div>
          <div className="bg-gray-800/30 border border-gray-700/50 rounded-lg p-4">
            <div className="flex items-center gap-3">
              <RefreshCw className="h-5 w-5 text-blue-400" />
              <div>
                <p className="text-gray-400 text-sm">Health Score</p>
                <p className="text-white text-xl font-semibold">
                  {healthStatus.total_count > 0 ? 
                    Math.round(((healthStatus.total_count - healthStatus.error_count) / healthStatus.total_count) * 100) : 0}%
                </p>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Tabs */}
      <div className="flex space-x-1 bg-gray-800/30 border border-gray-700/50 rounded-lg p-1">
        {[
          { id: 'integrations', label: 'Integrations', icon: <Plug className="h-4 w-4" /> },
          { id: 'api-keys', label: 'API Keys', icon: <Key className="h-4 w-4" /> },
          { id: 'webhooks', label: 'Webhooks', icon: <Webhook className="h-4 w-4" /> }
        ].map(tab => (
          <button
            key={tab.id}
            onClick={() => setSelectedTab(tab.id)}
            className={`flex items-center gap-2 px-4 py-2 rounded-lg transition-colors ${
              selectedTab === tab.id 
                ? 'bg-purple-600 text-white' 
                : 'text-gray-400 hover:text-white hover:bg-gray-700/50'
            }`}
          >
            {tab.icon}
            {tab.label}
          </button>
        ))}
      </div>

      {/* Content based on selected tab */}
      {selectedTab === 'integrations' && (
        <div className="grid grid-cols-1 lg:grid-cols-2 xl:grid-cols-3 gap-6">
          {integrations.map((integration) => (
            <div key={integration.id} className="bg-gray-800/30 border border-gray-700/50 rounded-xl p-6 hover:border-purple-500/30 transition-colors">
              {/* Integration Header */}
              <div className="flex items-start justify-between mb-4">
                <div className="flex items-center gap-3">
                  <div className="p-2 bg-purple-500/20 rounded-lg text-purple-400">
                    {getIntegrationIcon(integration.type)}
                  </div>
                  <div>
                    <h3 className="font-semibold text-white">{integration.name}</h3>
                    <p className="text-gray-400 text-sm capitalize">{integration.type.replace('_', ' ')}</p>
                  </div>
                </div>
                <span className={`px-2 py-1 rounded text-xs font-medium border ${getStatusColor(integration.status)}`}>
                  {integration.status.toUpperCase()}
                </span>
              </div>

              {/* Integration Details */}
              <div className="space-y-3 mb-4">
                <p className="text-gray-400 text-sm">{integration.description}</p>
                
                <div className="flex items-center justify-between text-sm">
                  <span className="text-gray-400">Endpoint</span>
                  <span className="text-white truncate max-w-[200px]" title={integration.endpoint}>
                    {integration.endpoint}
                  </span>
                </div>

                {integration.last_sync && (
                  <div className="flex items-center justify-between text-sm">
                    <span className="text-gray-400">Last Sync</span>
                    <span className="text-white">
                      {new Date(integration.last_sync).toLocaleString()}
                    </span>
                  </div>
                )}

                {integration.error_count > 0 && (
                  <div className="flex items-center justify-between text-sm">
                    <span className="text-gray-400">Error Count</span>
                    <span className="text-red-400">{integration.error_count}</span>
                  </div>
                )}
              </div>

              {/* Integration Tags */}
              {integration.tags && integration.tags.length > 0 && (
                <div className="flex flex-wrap gap-1 mb-4">
                  {integration.tags.map((tag, index) => (
                    <span key={index} className="px-2 py-1 bg-gray-700/50 text-gray-300 text-xs rounded">
                      {tag}
                    </span>
                  ))}
                </div>
              )}

              {/* Integration Actions */}
              <div className="flex gap-2">
                <button
                  onClick={() => testIntegration(integration.id)}
                  className="flex-1 px-3 py-2 bg-blue-600/20 border border-blue-500/30 text-blue-400 rounded-lg hover:bg-blue-600/30 transition-colors text-sm"
                >
                  Test
                </button>
                <button className="flex-1 px-3 py-2 bg-gray-600/20 border border-gray-500/30 text-gray-400 rounded-lg hover:bg-gray-600/30 transition-colors text-sm">
                  Edit
                </button>
                <button
                  onClick={() => deleteIntegration(integration.id)}
                  className="px-3 py-2 bg-red-600/20 border border-red-500/30 text-red-400 rounded-lg hover:bg-red-600/30 transition-colors"
                >
                  <Trash2 className="h-4 w-4" />
                </button>
              </div>
            </div>
          ))}
        </div>
      )}

      {selectedTab === 'api-keys' && (
        <div className="space-y-4">
          <div className="flex justify-between items-center">
            <h2 className="text-lg font-semibold text-white">API Keys</h2>
            <button className="flex items-center gap-2 px-4 py-2 bg-cyan-600 text-white rounded-lg hover:bg-cyan-700 transition-colors">
              <Plus className="h-4 w-4" />
              Generate New Key
            </button>
          </div>

          <div className="bg-gray-800/30 border border-gray-700/50 rounded-lg overflow-hidden">
            <table className="w-full">
              <thead className="bg-gray-800/50">
                <tr>
                  <th className="text-left px-6 py-3 text-gray-400 font-medium">Name</th>
                  <th className="text-left px-6 py-3 text-gray-400 font-medium">Key Preview</th>
                  <th className="text-left px-6 py-3 text-gray-400 font-medium">Permissions</th>
                  <th className="text-left px-6 py-3 text-gray-400 font-medium">Last Used</th>
                  <th className="text-left px-6 py-3 text-gray-400 font-medium">Status</th>
                  <th className="text-left px-6 py-3 text-gray-400 font-medium">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-700/50">
                {apiKeys.map((key) => (
                  <tr key={key.id} className="hover:bg-gray-800/30">
                    <td className="px-6 py-4 text-white font-medium">{key.name}</td>
                    <td className="px-6 py-4 text-gray-300 font-mono">{key.key_prefix}...</td>
                    <td className="px-6 py-4">
                      <div className="flex flex-wrap gap-1">
                        {key.permissions?.slice(0, 2).map((perm, index) => (
                          <span key={index} className="px-2 py-1 bg-blue-500/20 text-blue-400 text-xs rounded">
                            {perm}
                          </span>
                        ))}
                        {key.permissions?.length > 2 && (
                          <span className="px-2 py-1 bg-gray-500/20 text-gray-400 text-xs rounded">
                            +{key.permissions.length - 2}
                          </span>
                        )}
                      </div>
                    </td>
                    <td className="px-6 py-4 text-gray-400">
                      {key.last_used ? new Date(key.last_used).toLocaleDateString() : 'Never'}
                    </td>
                    <td className="px-6 py-4">
                      <span className={`px-2 py-1 rounded text-xs font-medium ${
                        key.enabled ? 'bg-green-500/20 text-green-400' : 'bg-gray-500/20 text-gray-400'
                      }`}>
                        {key.enabled ? 'Active' : 'Inactive'}
                      </span>
                    </td>
                    <td className="px-6 py-4">
                      <button
                        onClick={() => revokeApiKey(key.id)}
                        className="text-red-400 hover:text-red-300"
                        title="Revoke Key"
                      >
                        <Trash2 className="h-4 w-4" />
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {selectedTab === 'webhooks' && (
        <div className="space-y-4">
          <div className="flex justify-between items-center">
            <h2 className="text-lg font-semibold text-white">Webhooks</h2>
            <button className="flex items-center gap-2 px-4 py-2 bg-green-600 text-white rounded-lg hover:bg-green-700 transition-colors">
              <Plus className="h-4 w-4" />
              Add Webhook
            </button>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            {webhooks.map((webhook) => (
              <div key={webhook.id} className="bg-gray-800/30 border border-gray-700/50 rounded-lg p-6">
                <div className="flex items-start justify-between mb-4">
                  <div>
                    <h3 className="font-semibold text-white mb-1">{webhook.name}</h3>
                    <p className="text-gray-400 text-sm break-all">{webhook.url}</p>
                  </div>
                  <span className={`px-2 py-1 rounded text-xs font-medium ${
                    webhook.enabled ? 'bg-green-500/20 text-green-400' : 'bg-gray-500/20 text-gray-400'
                  }`}>
                    {webhook.enabled ? 'Active' : 'Inactive'}
                  </span>
                </div>

                <div className="space-y-3 mb-4">
                  <div>
                    <p className="text-gray-400 text-sm mb-1">Events:</p>
                    <div className="flex flex-wrap gap-1">
                      {webhook.events?.map((event, index) => (
                        <span key={index} className="px-2 py-1 bg-purple-500/20 text-purple-400 text-xs rounded">
                          {event}
                        </span>
                      ))}
                    </div>
                  </div>

                  {webhook.last_delivery && (
                    <div className="flex justify-between text-sm">
                      <span className="text-gray-400">Last Delivery:</span>
                      <span className="text-white">{new Date(webhook.last_delivery).toLocaleString()}</span>
                    </div>
                  )}

                  {webhook.failure_count > 0 && (
                    <div className="flex justify-between text-sm">
                      <span className="text-gray-400">Failures:</span>
                      <span className="text-red-400">{webhook.failure_count}</span>
                    </div>
                  )}
                </div>

                <div className="flex gap-2">
                  <button className="flex-1 px-3 py-2 bg-gray-600/20 border border-gray-500/30 text-gray-400 rounded-lg hover:bg-gray-600/30 transition-colors text-sm">
                    Edit
                  </button>
                  <button className="px-3 py-2 bg-red-600/20 border border-red-500/30 text-red-400 rounded-lg hover:bg-red-600/30 transition-colors">
                    <Trash2 className="h-4 w-4" />
                  </button>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};

export default IntegrationManagement;