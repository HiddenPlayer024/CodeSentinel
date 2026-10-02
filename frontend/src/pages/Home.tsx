import { ShieldCheck, Cpu, Code2 } from 'lucide-react';
import { ScannerForm } from '../components/scan/ScannerForm';

export function Home() {
  return (
    <div className="flex flex-col items-center pt-12 pb-24">
      <div className="text-center max-w-3xl mb-12">
        <h1 className="text-4xl sm:text-5xl font-extrabold text-white tracking-tight mb-4">
          CodeSentinel
          <span className="block text-primary mt-2">AI-Assisted Source Security</span>
        </h1>
        <p className="text-xl text-gray-400 mb-8 max-w-2xl mx-auto">
          Find security vulnerabilities before they reach production.
          Scan public GitHub repositories with deterministic AST-based security analysis and optional AI verification.
        </p>
      </div>

      <ScannerForm />

      <div className="grid grid-cols-1 md:grid-cols-3 gap-8 mt-24 max-w-5xl w-full">
        <div className="bg-dark-800 border border-dark-600 rounded-xl p-6">
          <Code2 className="w-10 h-10 text-primary mb-4" />
          <h3 className="text-lg font-bold text-white mb-2">Deterministic AST Parsing</h3>
          <p className="text-gray-400 text-sm">Code is parsed into an Abstract Syntax Tree to completely eliminate regex-based false positives.</p>
        </div>
        <div className="bg-dark-800 border border-dark-600 rounded-xl p-6">
          <Cpu className="w-10 h-10 text-primary mb-4" />
          <h3 className="text-lg font-bold text-white mb-2">Data Flow Analysis</h3>
          <p className="text-gray-400 text-sm">Variables are tracked intra-procedurally from source to sink to dynamically calculate vulnerability confidence.</p>
        </div>
        <div className="bg-dark-800 border border-dark-600 rounded-xl p-6">
          <ShieldCheck className="w-10 h-10 text-primary mb-4" />
          <h3 className="text-lg font-bold text-white mb-2">AI Verification</h3>
          <p className="text-gray-400 text-sm">Uncertain findings are verified by an LLM which appends rich technical context without mutating the deterministic baseline.</p>
        </div>
      </div>
    </div>
  );
}
