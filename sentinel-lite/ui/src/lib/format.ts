export function formatBytes(n: number | null | undefined): string {
  if (n == null) return "–";
  const units = ["B", "KB", "MB", "GB", "TB"];
  let i = 0;
  let v = n;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i++;
  }
  return `${v.toFixed(v >= 100 || i === 0 ? 0 : 1)} ${units[i]}`;
}

export function formatNumber(n: number): string {
  return new Intl.NumberFormat().format(n);
}

export function timeAgo(unixSecs: number): string {
  const d = Math.max(0, Date.now() / 1000 - unixSecs);
  if (d < 60) return "just now";
  if (d < 3600) return `${Math.floor(d / 60)} min ago`;
  if (d < 86400) return `${Math.floor(d / 3600)} h ago`;
  return new Date(unixSecs * 1000).toLocaleDateString();
}

export function formatUptime(secs: number): string {
  const h = Math.floor(secs / 3600);
  const m = Math.floor((secs % 3600) / 60);
  return h > 0 ? `${h}h ${m}m` : `${m}m`;
}

/** Shorten long Windows paths for display: C:\Users\…\Downloads\file.exe */
export function shortPath(p: string, max = 64): string {
  if (p.length <= max) return p;
  const parts = p.split(/[\\/]/);
  const sep = p.includes("\\") ? "\\" : "/";
  const head = parts.slice(0, 2).join(sep);
  const tail = parts.slice(-2).join(sep);
  return `${head}${sep}…${sep}${tail}`;
}
