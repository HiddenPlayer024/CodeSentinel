import React, { useState } from 'react';
import { Search, Loader2, GitBranch, Globe, BrainCircuit } from 'lucide-react';
import { useNavigate } from 'react-router-dom';
import { scanGithub } from '../../api/codesentinel';
import type { ScanSession } from '../../types/codesentinel';

export function ScannerForm() {
  const navigate = useNavigate();
  const [url, setUrl] = useState('');
  const [ref, setRef] = useState('');
  const [aiEnabled, setAiEnabled] = useState(false);
  const [aiProvider, setAiProvider] = useState('mock');
  const [status, setStatus] = useState<'idle' | 'scanning' | 'error'>('idle');
  const [errorMsg, setErrorMsg] = useState('');

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setErrorMsg('');
    
    if (!url.includes('github.com')) {
      setErrorMsg('Please enter a valid github.com repository URL');
      setStatus('error');
      return;
    }

    setStatus('scanning');
    
    try {
      const response: ScanSession = await scanGithub({
        repository_url: url.trim(),
        ref: ref.trim() || undefined,
        ai: aiEnabled,
        ai_provider: aiProvider
      });
      
      // Since there's no backend persistence yet, we pass state via React Router
      navigate('/results/latest', { state: { session: response } });
    } catch (err: any) {
      setErrorMsg(err.message || 'An unexpected error occurred during the scan.');
      setStatus('error');
    }
  };

  return (
    <div className="bg-dark-800 border border-dark-600 rounded-xl p-6 shadow-2xl max-w-2xl w-full mx-auto relative overflow-hidden">
      {status === 'scanning' && (
        <div className="absolute inset-0 bg-dark-900/80 backdrop-blur-sm z-10 flex flex-col items-center justify-center">
          <Loader2 className="w-12 h-12 text-primary animate-spin mb-4" />
          <h3 className="text-xl font-mono font-bold text-white mb-2">ANALYZING REPOSITORY</h3>
          <p className="text-gray-400 font-mono text-sm">Fetching repository archive...</p>
          <p className="text-gray-400 font-mono text-sm mt-1">Extracting & running security rules...</p>
        </div>
      )}

      <div className="flex items-center gap-3 mb-6 pb-4 border-b border-dark-600">
        <Search className="w-6 h-6 text-primary" />
        <h2 className="text-xl font-bold text-white">Start Security Scan</h2>
      </div>

      <form onSubmit={handleSubmit} className="space-y-5">
        <div>
          <label className="block text-sm font-medium text-gray-300 mb-1 flex items-center gap-2">
            <Globe className="w-4 h-4" /> Repository URL
          </label>
          <input
            type="url"
            required
            value={url}
            onChange={e => setUrl(e.target.value)}
            placeholder="https://github.com/owner/repository"
            className="w-full bg-dark-900 border border-dark-600 rounded-lg px-4 py-3 text-white font-mono text-sm focus:ring-2 focus:ring-primary focus:border-transparent outline-none transition-all"
            disabled={status === 'scanning'}
          />
        </div>

        <div>
          <label className="block text-sm font-medium text-gray-300 mb-1 flex items-center gap-2">
            <GitBranch className="w-4 h-4" /> Branch / Tag / Commit (Optional)
          </label>
          <input
            type="text"
            value={ref}
            onChange={e => setRef(e.target.value)}
            placeholder="main, v1.0.0, or commit SHA"
            className="w-full bg-dark-900 border border-dark-600 rounded-lg px-4 py-3 text-white font-mono text-sm focus:ring-2 focus:ring-primary focus:border-transparent outline-none transition-all"
            disabled={status === 'scanning'}
          />
        </div>

        <div className="p-4 rounded-lg bg-dark-900 border border-dark-600">
          <label className="flex items-center gap-3 cursor-pointer">
            <input 
              type="checkbox" 
              checked={aiEnabled} 
              onChange={e => setAiEnabled(e.target.checked)}
              className="w-5 h-5 rounded border-dark-500 text-primary focus:ring-primary focus:ring-offset-dark-900 bg-dark-800"
              disabled={status === 'scanning'}
            />
            <div className="flex items-center gap-2">
              <BrainCircuit className="w-5 h-5 text-primary" />
              <span className="font-medium text-white">Enable AI Verification</span>
            </div>
          </label>
          
          {aiEnabled && (
            <div className="mt-4 pl-8">
              <label className="block text-xs font-medium text-gray-400 mb-1 uppercase tracking-wider">AI Provider</label>
              <select 
                value={aiProvider}
                onChange={e => setAiProvider(e.target.value)}
                className="bg-dark-800 border border-dark-600 rounded px-3 py-2 text-white text-sm outline-none focus:border-primary w-full max-w-xs"
                disabled={status === 'scanning'}
              >
                <option value="mock">Mock (Testing)</option>
                <option value="openai">OpenAI (Requires Backend Env)</option>
                <option value="ollama">Ollama (Local Only)</option>
              </select>
            </div>
          )}
        </div>

        {status === 'error' && (
          <div className="bg-danger/10 border border-danger/50 rounded-lg p-4">
            <h4 className="text-danger font-bold text-sm mb-1">Scan Failed</h4>
            <p className="text-danger/90 text-sm">{errorMsg}</p>
          </div>
        )}

        <button
          type="submit"
          disabled={status === 'scanning'}
          className="w-full bg-primary hover:bg-primary-dark text-white font-bold py-3 px-4 rounded-lg transition-colors flex items-center justify-center gap-2 disabled:opacity-50"
        >
          <Search className="w-5 h-5" /> Scan Repository
        </button>
      </form>
    </div>
  );
}
