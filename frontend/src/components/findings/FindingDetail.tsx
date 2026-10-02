import type { Finding } from '../../types/codesentinel';
import { SeverityBadge } from '../common/SeverityBadge';
import { ExternalLink, Terminal, BrainCircuit, Activity } from 'lucide-react';

interface Props {
  finding: Finding;
  repositoryUrl?: string;
  refName?: string;
}

export function FindingDetail({ finding, repositoryUrl, refName }: Props) {
  
  const githubUrl = repositoryUrl && refName 
    ? `${repositoryUrl}/blob/${refName}/${finding.location.file}#L${finding.location.line_start}`
    : undefined;

  return (
    <div className="bg-dark-800 border border-dark-600 rounded-xl overflow-hidden shadow-xl max-h-[85vh] overflow-y-auto">
      <div className="p-6 border-b border-dark-600 bg-dark-900/50">
        <div className="flex justify-between items-start mb-4">
          <div className="flex items-center gap-3">
            <SeverityBadge severity={finding.classification.severity} />
            <span className="text-xs font-mono text-gray-400 border border-dark-600 px-2 py-0.5 rounded">
              {finding.identity.rule_id}
            </span>
          </div>
          {githubUrl && (
            <a 
              href={githubUrl} 
              target="_blank" 
              rel="noreferrer"
              className="text-xs flex items-center gap-1 text-primary hover:text-primary-dark transition-colors"
            >
              Open on GitHub <ExternalLink className="w-3 h-3" />
            </a>
          )}
        </div>
        <h2 className="text-xl font-bold text-white mb-2">{finding.identity.title}</h2>
        <div className="text-sm font-mono text-gray-400 bg-dark-900 px-3 py-2 rounded-lg border border-dark-700 overflow-x-auto">
          {finding.location.file}:{finding.location.line_start}
        </div>
      </div>

      <div className="p-6 space-y-8">
        
        {/* Source Code */}
        <section>
          <h3 className="text-sm font-bold text-gray-300 uppercase tracking-wider mb-3 flex items-center gap-2">
            <Terminal className="w-4 h-4" /> Source Context
          </h3>
          <div className="bg-dark-900 rounded-lg border border-dark-700 overflow-hidden">
            <pre className="p-4 overflow-x-auto text-sm font-mono text-gray-300">
              <code>{finding.context.surrounding_code || finding.context.snippet}</code>
            </pre>
          </div>
        </section>

        {/* Data Flow */}
        {(finding.data_flow.sources.length > 0 || finding.data_flow.sinks.length > 0) && (
          <section>
            <h3 className="text-sm font-bold text-gray-300 uppercase tracking-wider mb-3 flex items-center gap-2">
              <Activity className="w-4 h-4" /> Data Flow
            </h3>
            <div className="bg-dark-900 rounded-lg border border-dark-700 p-4 font-mono text-sm space-y-2">
              {finding.data_flow.sources.length > 0 && (
                <div><span className="text-danger">Source:</span> {finding.data_flow.sources.join(', ')}</div>
              )}
              {finding.data_flow.sinks.length > 0 && (
                <div><span className="text-warning">Sink:</span> {finding.data_flow.sinks.join(', ')}</div>
              )}
            </div>
          </section>
        )}

        {/* AI Assessment */}
        {finding.ai_assessment && (
          <section className="bg-primary/5 border border-primary/20 rounded-lg p-5">
            <h3 className="text-sm font-bold text-primary uppercase tracking-wider mb-3 flex items-center gap-2">
              <BrainCircuit className="w-4 h-4" /> AI Verification
            </h3>
            <div className="space-y-3 text-sm">
              <div className="flex gap-2 items-center">
                <span className="text-gray-400">Likely Vulnerable:</span> 
                <span className={finding.ai_assessment.is_likely_vulnerable ? "text-danger font-bold" : "text-success font-bold"}>
                  {finding.ai_assessment.is_likely_vulnerable ? "YES" : "NO (False Positive)"}
                </span>
              </div>
              <div className="text-gray-300 leading-relaxed">
                {finding.ai_assessment.explanation}
              </div>
            </div>
          </section>
        )}

        {/* Remediation */}
        <section>
          <h3 className="text-sm font-bold text-gray-300 uppercase tracking-wider mb-3">Remediation</h3>
          <div className="space-y-3">
            <p className="text-gray-300 text-sm leading-relaxed bg-dark-900/50 p-4 rounded-lg border border-dark-700">
              {finding.remediation.explanation}
            </p>
            <div className="bg-success/10 border border-success/30 rounded-lg p-4">
              <h4 className="text-success font-bold text-sm mb-1">Recommended Fix</h4>
              <p className="text-success/90 text-sm leading-relaxed">{finding.remediation.recommended_fix}</p>
            </div>
          </div>
        </section>

      </div>
    </div>
  );
}
