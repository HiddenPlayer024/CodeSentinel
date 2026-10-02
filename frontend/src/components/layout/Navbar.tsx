import { Activity, ShieldAlert, ShieldCheck } from 'lucide-react';
import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { checkHealth } from '../../api/codesentinel';

export function Navbar() {
  const [isApiOnline, setIsApiOnline] = useState<boolean | null>(null);

  useEffect(() => {
    checkHealth()
      .then(() => setIsApiOnline(true))
      .catch(() => setIsApiOnline(false));
  }, []);

  return (
    <nav className="border-b border-dark-600 bg-dark-800">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex justify-between h-16 items-center">
          <div className="flex items-center gap-2">
            <Link to="/" className="flex items-center gap-2">
              <ShieldAlert className="h-6 w-6 text-primary" />
              <span className="text-xl font-bold tracking-tight text-white">CodeSentinel</span>
            </Link>
          </div>
          
          <div className="flex items-center gap-6">
            <Link to="/" className="text-sm font-medium text-gray-300 hover:text-white transition-colors">Scanner</Link>
            <a href="https://github.com/HiddenPlayer024/CodeSentinel" target="_blank" rel="noreferrer" className="text-sm font-medium text-gray-300 hover:text-white transition-colors">GitHub</a>
            <a href={import.meta.env.VITE_API_URL + "/docs"} target="_blank" rel="noreferrer" className="text-sm font-medium text-gray-300 hover:text-white transition-colors">API</a>
            
            <div className="flex items-center gap-2 text-xs font-mono px-3 py-1.5 rounded-full bg-dark-700 border border-dark-600">
              {isApiOnline === null ? (
                <><Activity className="w-3 h-3 text-gray-400 animate-pulse" /> API Checking...</>
              ) : isApiOnline ? (
                <><ShieldCheck className="w-3 h-3 text-success" /> API Online</>
              ) : (
                <><div className="w-2 h-2 rounded-full bg-danger animate-pulse" /> API Offline</>
              )}
            </div>
          </div>
        </div>
      </div>
    </nav>
  );
}
