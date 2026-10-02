export function Footer() {
  return (
    <footer className="border-t border-dark-600 bg-dark-900 py-8">
      <div className="max-w-7xl mx-auto px-4 text-center">
        <p className="text-sm text-gray-500 font-mono">
          CodeSentinel &copy; {new Date().getFullYear()} - Deterministic AST Security Analysis + AI Verification
        </p>
      </div>
    </footer>
  );
}
