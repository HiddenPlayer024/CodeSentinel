import clsx from 'clsx';
import type { Severity } from '../../types/codesentinel';

interface Props {
  severity: Severity;
  className?: string;
}

export function SeverityBadge({ severity, className }: Props) {
  const styles: Record<Severity, string> = {
    CRITICAL: "bg-red-900/50 text-red-400 border-red-800",
    HIGH: "bg-orange-900/50 text-orange-400 border-orange-800",
    MEDIUM: "bg-yellow-900/50 text-yellow-400 border-yellow-800",
    LOW: "bg-blue-900/50 text-blue-400 border-blue-800",
    INFO: "bg-gray-800 text-gray-300 border-gray-700"
  };

  return (
    <span className={clsx(
      "px-2.5 py-0.5 rounded text-xs font-bold font-mono border uppercase tracking-wider",
      styles[severity],
      className
    )}>
      {severity}
    </span>
  );
}
