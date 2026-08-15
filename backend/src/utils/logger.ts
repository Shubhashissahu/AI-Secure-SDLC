export interface LogEntry {
  level: "info" | "warn" | "error";
  message: string;
  timestamp: string;
  context?: Record<string, unknown>;
}

export function logInfo(message: string, context?: Record<string, unknown>) {
  const entry: LogEntry = { level: "info", message, timestamp: new Date().toISOString(), context };
  console.log(JSON.stringify(entry));
}

export function logWarn(message: string, context?: Record<string, unknown>) {
  const entry: LogEntry = { level: "warn", message, timestamp: new Date().toISOString(), context };
  console.warn(JSON.stringify(entry));
}

export function logError(message: string, context?: Record<string, unknown>) {
  const entry: LogEntry = { level: "error", message, timestamp: new Date().toISOString(), context };
  console.error(JSON.stringify(entry));
}
