import { useLocation, Navigate } from 'react-router-dom';
import type { ScanSession, Finding } from '../types/codesentinel';
import { ShieldCheck, AlertTriangle, FileCode, Clock, Download } from 'lucide-react';
import { SeverityBadge } from '../components/common/SeverityBadge';
import { useState } from 'react';
import clsx from 'clsx';
import { FindingDetail } from '../components/findings/FindingDetail';

export function Results() {
  const location = useLocation();
  const session = location.state?.session as ScanSession | undefined;

  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null);
  const [search, setSearch] = useState('');
  const [severityFilter, setSeverityFilter] = useState<string>('ALL');

  if (!session) {
    return <Navigate to="/" replace />;
  }

  const { project, findings, duration_seconds } = session;

  const counts = {
    CRITICAL: findings.filter(f => f.classification.severity === 'CRITICAL').length,
    HIGH: findings.filter(f => f.classification.severity === 'HIGH').length,
    MEDIUM: findings.filter(f => f.classification.severity === 'MEDIUM').length,
    LOW: findings.filter(f => f.classification.severity === 'LOW').length,
    INFO: findings.filter(f => f.classification.severity === 'INFO').length,
  };

  const filteredFindings = findings.filter(f => {
    const matchesSeverity = severityFilter === 'ALL' || f.classification.severity === severityFilter;
    const searchLower = search.toLowerCase();
    const matchesSearch = 
      f.identity.title.toLowerCase().includes(searchLower) ||
      f.identity.rule_id.toLowerCase().includes(searchLower) ||
      f.location.file.toLowerCase().includes(searchLower);
    
    return matchesSeverity && matchesSearch;
  }).sort((a, b) => b.classification.confidence - a.classification.confidence);

  const handleDownload = () => {
    const blob = new Blob([JSON.stringify(session, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `codesentinel-report-${session.id.substring(0, 8)}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  return (
    <div className="space-y-8">
      {/* Header */}
      <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4 border-b border-dark-600 pb-6">
        <div>
          <h1 className="text-2xl font-bold text-white mb-1 flex items-center gap-2">
            Security Scan Report
          </h1>
          <p className="text-gray-400 font-mono text-sm">
            {project.repository_url || project.path} {project.ref && <span className="bg-dark-700 px-2 py-0.5 rounded ml-2">{project.ref}</span>}
          </p>
        </div>
        <button 
          onClick={handleDownload}
          className="flex items-center gap-2 bg-dark-700 hover:bg-dark-600 text-white px-4 py-2 rounded-lg font-medium transition-colors border border-dark-500"
        >
          <Download className="w-4 h-4" /> Download JSON
        </button>
      </div>

      {/* Summary Metrics */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <div className="bg-dark-800 border border-dark-600 rounded-xl p-4">
          <div className="text-gray-400 text-sm mb-1 flex items-center gap-2"><FileCode className="w-4 h-4"/> Files</div>
          <div className="text-2xl font-bold text-white">{project.file_count}</div>
        </div>
        <div className="bg-dark-800 border border-dark-600 rounded-xl p-4">
          <div className="text-gray-400 text-sm mb-1 flex items-center gap-2"><Clock className="w-4 h-4"/> Duration</div>
          <div className="text-2xl font-bold text-white">{duration_seconds?.toFixed(2) || '0.00'}s</div>
        </div>
        <div className="bg-dark-800 border border-dark-600 rounded-xl p-4">
          <div className="text-gray-400 text-sm mb-1">Languages</div>
          <div className="text-xl font-bold text-white uppercase">{project.languages.join(', ') || 'N/A'}</div>
        </div>
        <div className="bg-dark-800 border border-dark-600 rounded-xl p-4">
          <div className="text-gray-400 text-sm mb-1">Total Findings</div>
          <div className="text-2xl font-bold text-white">{findings.length}</div>
        </div>
      </div>

      {/* Severity Distribution */}
      {findings.length > 0 && (
        <div className="bg-dark-800 border border-dark-600 rounded-xl p-6">
          <h3 className="text-sm font-bold text-gray-300 uppercase tracking-wider mb-4">Finding Distribution</h3>
          <div className="flex w-full h-4 rounded-full overflow-hidden">
            {counts.CRITICAL > 0 && <div style={{width: `${(counts.CRITICAL/findings.length)*100}%`}} className="bg-red-500" title={`Critical: ${counts.CRITICAL}`}></div>}
            {counts.HIGH > 0 && <div style={{width: `${(counts.HIGH/findings.length)*100}%`}} className="bg-orange-500" title={`High: ${counts.HIGH}`}></div>}
            {counts.MEDIUM > 0 && <div style={{width: `${(counts.MEDIUM/findings.length)*100}%`}} className="bg-yellow-500" title={`Medium: ${counts.MEDIUM}`}></div>}
            {counts.LOW > 0 && <div style={{width: `${(counts.LOW/findings.length)*100}%`}} className="bg-blue-500" title={`Low: ${counts.LOW}`}></div>}
            {counts.INFO > 0 && <div style={{width: `${(counts.INFO/findings.length)*100}%`}} className="bg-gray-500" title={`Info: ${counts.INFO}`}></div>}
          </div>
          <div className="flex gap-6 mt-4 text-sm font-mono">
            {counts.CRITICAL > 0 && <div className="text-red-400"><span className="text-white font-bold">{counts.CRITICAL}</span> CRITICAL</div>}
            {counts.HIGH > 0 && <div className="text-orange-400"><span className="text-white font-bold">{counts.HIGH}</span> HIGH</div>}
            {counts.MEDIUM > 0 && <div className="text-yellow-400"><span className="text-white font-bold">{counts.MEDIUM}</span> MED</div>}
          </div>
        </div>
      )}

      {findings.length === 0 ? (
        <div className="bg-dark-800 border border-dark-600 rounded-xl p-12 text-center">
          <ShieldCheck className="w-16 h-16 text-success mx-auto mb-4" />
          <h2 className="text-2xl font-bold text-white mb-2">No findings detected</h2>
          <p className="text-gray-400 max-w-md mx-auto">
            CodeSentinel did not identify vulnerabilities covered by the currently enabled deterministic security rules in this scan.
          </p>
        </div>
      ) : (
        <div className="flex flex-col lg:flex-row gap-6 items-start">
          
          {/* Findings List */}
          <div className="w-full lg:w-1/2 flex flex-col gap-4">
            <div className="flex flex-col sm:flex-row gap-3">
              <input 
                type="text" 
                placeholder="Search findings..." 
                value={search}
                onChange={e => setSearch(e.target.value)}
                className="flex-grow bg-dark-900 border border-dark-600 rounded-lg px-3 py-2 text-sm text-white outline-none focus:border-primary"
              />
              <select 
                value={severityFilter}
                onChange={e => setSeverityFilter(e.target.value)}
                className="bg-dark-900 border border-dark-600 rounded-lg px-3 py-2 text-sm text-white outline-none focus:border-primary"
              >
                <option value="ALL">All Severities</option>
                <option value="CRITICAL">Critical</option>
                <option value="HIGH">High</option>
                <option value="MEDIUM">Medium</option>
                <option value="LOW">Low</option>
                <option value="INFO">Info</option>
              </select>
            </div>

            <div className="flex flex-col gap-2 max-h-[800px] overflow-y-auto pr-2">
              {filteredFindings.map(f => (
                <div 
                  key={f.identity.id}
                  onClick={() => setSelectedFinding(f)}
                  className={clsx(
                    "bg-dark-800 border rounded-lg p-4 cursor-pointer transition-colors hover:border-primary/50",
                    selectedFinding?.identity.id === f.identity.id ? "border-primary" : "border-dark-600"
                  )}
                >
                  <div className="flex justify-between items-start mb-2">
                    <SeverityBadge severity={f.classification.severity} />
                    <span className="text-xs font-mono text-gray-500">{Math.round(f.classification.confidence * 100)}% Conf</span>
                  </div>
                  <h4 className="text-white font-bold mb-1 truncate">{f.identity.title}</h4>
                  <div className="text-xs font-mono text-gray-400 truncate">{f.location.file}:{f.location.line_start}</div>
                </div>
              ))}
              {filteredFindings.length === 0 && (
                <div className="text-center py-8 text-gray-500">No findings match your filters.</div>
              )}
            </div>
          </div>

          {/* Finding Detail */}
          <div className="w-full lg:w-1/2 sticky top-4">
            {selectedFinding ? (
              <FindingDetail finding={selectedFinding} repositoryUrl={project.repository_url} refName={project.ref} />
            ) : (
              <div className="bg-dark-800 border border-dark-600 rounded-xl p-12 text-center h-[500px] flex flex-col items-center justify-center">
                <AlertTriangle className="w-12 h-12 text-gray-600 mb-4" />
                <p className="text-gray-400">Select a finding from the list to view details, context, and remediation advice.</p>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
