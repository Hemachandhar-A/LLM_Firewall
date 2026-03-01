import React, { useState, useEffect } from 'react';
import { 
  Shield, Plus, Edit3, Trash2, Play, Pause, Copy, 
  AlertTriangle, CheckCircle, Clock, Filter, Search,
  Download, Upload, Settings, Target, Zap
} from 'lucide-react';

const API_BASE = import.meta.env.VITE_BACKEND_URL || 'http://localhost:8000';

const PolicyManagement = () => {
  const [policies, setPolicies] = useState([]);
  const [templates, setTemplates] = useState([]);
  const [selectedPolicy, setSelectedPolicy] = useState(null);
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [showTestModal, setShowTestModal] = useState(false);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [searchTerm, setSearchTerm] = useState('');
  const [filterStatus, setFilterStatus] = useState('all');

  useEffect(() => {
    fetchPolicies();
    fetchTemplates();
  }, []);

  const fetchPolicies = async () => {
    try {
      setLoading(true);
      const response = await fetch(`${API_BASE}/api/policy/policies`);
      if (response.ok) {
        const data = await response.json();
        setPolicies(data);
      }
    } catch (err) {
      setError('Failed to fetch policies');
    } finally {
      setLoading(false);
    }
  };

  const fetchTemplates = async () => {
    try {
      const response = await fetch(`${API_BASE}/api/policy/policies/templates/list`);
      if (response.ok) {
        const data = await response.json();
        setTemplates(data.templates || []);
      }
    } catch (err) {
      console.error('Failed to fetch templates:', err);
    }
  };

  const deletePolicy = async (policyId) => {
    if (!window.confirm('Are you sure you want to delete this policy?')) return;

    try {
      const response = await fetch(`${API_BASE}/api/policy/policies/${policyId}`, {
        method: 'DELETE',
      });
      if (response.ok) {
        setPolicies(policies.filter(p => p.id !== policyId));
        setSelectedPolicy(null);
      }
    } catch (err) {
      setError('Failed to delete policy');
    }
  };

  const togglePolicyStatus = async (policyId, enabled) => {
    try {
      const endpoint = enabled ? 'enable' : 'disable';
      const response = await fetch(`${API_BASE}/api/policy/policies/${policyId}/${endpoint}`, {
        method: 'POST',
      });
      if (response.ok) {
        fetchPolicies();
      }
    } catch (err) {
      setError(`Failed to ${enabled ? 'enable' : 'disable'} policy`);
    }
  };

  const filteredPolicies = policies.filter(policy => {
    const matchesSearch = policy.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
                         policy.description.toLowerCase().includes(searchTerm.toLowerCase());
    const matchesFilter = filterStatus === 'all' || 
                         (filterStatus === 'enabled' && policy.enabled) ||
                         (filterStatus === 'disabled' && !policy.enabled);
    return matchesSearch && matchesFilter;
  });

  const getRiskLevel = (rules) => {
    if (!rules || rules.length === 0) return 'low';
    const avgThreshold = rules.reduce((sum, rule) => sum + rule.threshold, 0) / rules.length;
    if (avgThreshold > 0.7) return 'high';
    if (avgThreshold > 0.4) return 'medium';
    return 'low';
  };

  const getRiskColor = (level) => {
    switch (level) {
      case 'high': return 'text-red-400 bg-red-500/10 border-red-500/20';
      case 'medium': return 'text-yellow-400 bg-yellow-500/10 border-yellow-500/20';
      case 'low': return 'text-green-400 bg-green-500/10 border-green-500/20';
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
            <div className="p-2 bg-cyan-500/20 rounded-lg">
              <Shield className="h-6 w-6 text-cyan-400" />
            </div>
            <h1 className="text-2xl font-bold text-white">Policy Management</h1>
          </div>
          <p className="text-gray-400">Configure and manage security policies for AI interactions</p>
        </div>
        <div className="flex gap-3">
          <button 
            onClick={() => setShowTestModal(true)}
            className="flex items-center gap-2 px-4 py-2 bg-purple-600/20 border border-purple-500/30 text-purple-400 rounded-lg hover:bg-purple-600/30 transition-colors"
          >
            <Target className="h-4 w-4" />
            Test Policy
          </button>
          <button 
            onClick={() => setShowCreateModal(true)}
            className="flex items-center gap-2 px-4 py-2 bg-cyan-600 text-white rounded-lg hover:bg-cyan-700 transition-colors"
          >
            <Plus className="h-4 w-4" />
            New Policy
          </button>
        </div>
      </div>

      {error && (
        <div className="bg-red-500/10 border border-red-500/20 rounded-lg p-4 text-red-400">
          {error}
        </div>
      )}

      {/* Controls */}
      <div className="flex flex-col sm:flex-row gap-4">
        <div className="flex-1 relative">
          <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-gray-400" />
          <input
            type="text"
            placeholder="Search policies..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="w-full bg-gray-800/50 border border-gray-700 rounded-lg pl-10 pr-4 py-2 text-white placeholder-gray-400 focus:border-cyan-500 focus:outline-none"
          />
        </div>
        <select
          value={filterStatus}
          onChange={(e) => setFilterStatus(e.target.value)}
          className="bg-gray-800/50 border border-gray-700 rounded-lg px-4 py-2 text-white focus:border-cyan-500 focus:outline-none"
        >
          <option value="all">All Policies</option>
          <option value="enabled">Enabled</option>
          <option value="disabled">Disabled</option>
        </select>
      </div>

      {/* Policy Templates */}
      {templates.length > 0 && (
        <div className="bg-gray-800/30 border border-gray-700/50 rounded-xl p-6">
          <h3 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
            <Settings className="h-5 w-5 text-cyan-400" />
            Quick Start Templates
          </h3>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            {templates.map((template) => (
              <div key={template.id} className="bg-gray-800/50 border border-gray-600/30 rounded-lg p-4 hover:border-cyan-500/30 transition-colors">
                <h4 className="font-medium text-white mb-2">{template.name}</h4>
                <p className="text-gray-400 text-sm mb-3">{template.description}</p>
                <button 
                  onClick={() => createFromTemplate(template.id)}
                  className="w-full px-3 py-2 bg-cyan-600/20 border border-cyan-500/30 text-cyan-400 rounded-lg hover:bg-cyan-600/30 transition-colors text-sm"
                >
                  Use Template
                </button>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Policies Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-2 xl:grid-cols-3 gap-6">
        {filteredPolicies.map((policy) => {
          const riskLevel = getRiskLevel(policy.rules);
          return (
            <div 
              key={policy.id} 
              className={`bg-gray-800/30 border rounded-xl p-6 hover:border-cyan-500/30 transition-all cursor-pointer ${
                selectedPolicy?.id === policy.id ? 'border-cyan-500/50 bg-cyan-500/5' : 'border-gray-700/50'
              }`}
              onClick={() => setSelectedPolicy(policy)}
            >
              {/* Policy Header */}
              <div className="flex items-start justify-between mb-4">
                <div>
                  <h3 className="font-semibold text-white text-lg">{policy.name}</h3>
                  <p className="text-gray-400 text-sm">{policy.description}</p>
                </div>
                <div className="flex items-center gap-2">
                  <span className={`px-2 py-1 rounded text-xs font-medium ${getRiskColor(riskLevel)}`}>
                    {riskLevel.toUpperCase()}
                  </span>
                </div>
              </div>

              {/* Policy Stats */}
              <div className="grid grid-cols-2 gap-4 mb-4">
                <div>
                  <p className="text-gray-400 text-xs uppercase tracking-wide">Rules</p>
                  <p className="text-white font-medium">{policy.rules?.length || 0}</p>
                </div>
                <div>
                  <p className="text-gray-400 text-xs uppercase tracking-wide">Priority</p>
                  <p className="text-white font-medium">{policy.priority}</p>
                </div>
              </div>

              {/* Policy Status */}
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  {policy.enabled ? (
                    <CheckCircle className="h-4 w-4 text-green-400" />
                  ) : (
                    <Clock className="h-4 w-4 text-gray-400" />
                  )}
                  <span className={policy.enabled ? 'text-green-400' : 'text-gray-400'}>
                    {policy.enabled ? 'Active' : 'Inactive'}
                  </span>
                </div>
                <div className="flex gap-1">
                  <button
                    onClick={(e) => {
                      e.stopPropagation();
                      togglePolicyStatus(policy.id, !policy.enabled);
                    }}
                    className="p-1 rounded hover:bg-gray-700/50 transition-colors"
                    title={policy.enabled ? 'Disable Policy' : 'Enable Policy'}
                  >
                    {policy.enabled ? (
                      <Pause className="h-4 w-4 text-yellow-400" />
                    ) : (
                      <Play className="h-4 w-4 text-green-400" />
                    )}
                  </button>
                  <button
                    onClick={(e) => {
                      e.stopPropagation();
                      // Edit functionality would go here
                    }}
                    className="p-1 rounded hover:bg-gray-700/50 transition-colors"
                    title="Edit Policy"
                  >
                    <Edit3 className="h-4 w-4 text-gray-400" />
                  </button>
                  <button
                    onClick={(e) => {
                      e.stopPropagation();
                      deletePolicy(policy.id);
                    }}
                    className="p-1 rounded hover:bg-gray-700/50 transition-colors"
                    title="Delete Policy"
                  >
                    <Trash2 className="h-4 w-4 text-red-400" />
                  </button>
                </div>
              </div>

              {/* Policy Tags */}
              {policy.tags && policy.tags.length > 0 && (
                <div className="flex flex-wrap gap-1 mt-3">
                  {policy.tags.map((tag, index) => (
                    <span 
                      key={index}
                      className="px-2 py-1 bg-gray-700/50 text-gray-300 text-xs rounded"
                    >
                      {tag}
                    </span>
                  ))}
                </div>
              )}
            </div>
          );
        })}
      </div>

      {/* Policy Details Sidebar */}
      {selectedPolicy && (
        <div className="fixed right-0 top-0 h-full w-96 bg-gray-900 border-l border-gray-700 p-6 overflow-y-auto z-50">
          <div className="flex items-center justify-between mb-6">
            <h2 className="text-xl font-semibold text-white">Policy Details</h2>
            <button
              onClick={() => setSelectedPolicy(null)}
              className="p-2 rounded hover:bg-gray-800 transition-colors"
            >
              ✕
            </button>
          </div>

          <div className="space-y-6">
            {/* Basic Info */}
            <div>
              <h3 className="text-lg font-medium text-white mb-3">{selectedPolicy.name}</h3>
              <p className="text-gray-400 mb-4">{selectedPolicy.description}</p>
              
              <div className="grid grid-cols-2 gap-4 text-sm">
                <div>
                  <p className="text-gray-400">Version</p>
                  <p className="text-white">{selectedPolicy.version}</p>
                </div>
                <div>
                  <p className="text-gray-400">Priority</p>
                  <p className="text-white">{selectedPolicy.priority}</p>
                </div>
                <div>
                  <p className="text-gray-400">Created</p>
                  <p className="text-white">
                    {selectedPolicy.created_at ? new Date(selectedPolicy.created_at).toLocaleDateString() : 'N/A'}
                  </p>
                </div>
                <div>
                  <p className="text-gray-400">Status</p>
                  <p className={selectedPolicy.enabled ? 'text-green-400' : 'text-gray-400'}>
                    {selectedPolicy.enabled ? 'Active' : 'Inactive'}
                  </p>
                </div>
              </div>
            </div>

            {/* Rules */}
            <div>
              <h4 className="text-lg font-medium text-white mb-3">Policy Rules</h4>
              <div className="space-y-3">
                {selectedPolicy.rules?.map((rule, index) => (
                  <div key={index} className="bg-gray-800/50 border border-gray-700 rounded-lg p-4">
                    <div className="flex items-center justify-between mb-2">
                      <span className="text-white font-medium">{rule.type.replace('_', ' ').toUpperCase()}</span>
                      <span className={`px-2 py-1 rounded text-xs ${rule.enabled ? 'bg-green-500/20 text-green-400' : 'bg-gray-500/20 text-gray-400'}`}>
                        {rule.enabled ? 'ON' : 'OFF'}
                      </span>
                    </div>
                    <div className="grid grid-cols-2 gap-2 text-sm">
                      <div>
                        <p className="text-gray-400">Threshold</p>
                        <p className="text-white">{(rule.threshold * 100).toFixed(0)}%</p>
                      </div>
                      <div>
                        <p className="text-gray-400">Action</p>
                        <p className="text-white capitalize">{rule.action}</p>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </div>

            {/* Actions */}
            <div className="space-y-3">
              <button className="w-full px-4 py-2 bg-cyan-600 text-white rounded-lg hover:bg-cyan-700 transition-colors">
                Edit Policy
              </button>
              <button 
                onClick={() => {
                  setSelectedPolicy(null);
                  setShowTestModal(true);
                }}
                className="w-full px-4 py-2 bg-purple-600/20 border border-purple-500/30 text-purple-400 rounded-lg hover:bg-purple-600/30 transition-colors"
              >
                Test Policy
              </button>
              <button className="w-full px-4 py-2 bg-gray-600/20 border border-gray-500/30 text-gray-400 rounded-lg hover:bg-gray-600/30 transition-colors">
                Duplicate Policy
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Modals would go here - CreatePolicyModal, TestPolicyModal, etc. */}
      {/* For brevity, I'm not including the full modal implementations */}
    </div>
  );
};

export default PolicyManagement;