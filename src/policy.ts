import { existsSync, realpathSync } from "node:fs";
import { homedir } from "node:os";
import { basename, dirname, resolve } from "node:path";

export function decideWritePolicy(
  path: string,
  allowWrite: string[],
  denyWrite: string[],
  base: string = process.cwd(),
) {
  if (matchesPattern(path, denyWrite, base)) return "deny";
  if (allowWrite.length === 0 || !matchesPattern(path, allowWrite, base)) return "prompt";
  return "allow";
}

export async function resolveWritePermission({
  path,
  allowWrite,
  denyWrite,
  prompt,
  saveWritePermission,
  base = process.cwd(),
}: {
  path: string;
  allowWrite: string[];
  denyWrite: string[];
  prompt: (path: string) => Promise<{
    action: "abort" | "session" | "project" | "global";
    value: string;
  }>;
  saveWritePermission: (choice: "session" | "project" | "global", value: string) => Promise<void>;
  /** Base directory for relative patterns; defaults to the process cwd. */
  base?: string;
}) {
  const policy = decideWritePolicy(path, allowWrite, denyWrite, base);
  if (policy !== "prompt") return { action: policy };

  const choice = await prompt(path);
  if (choice.action === "abort") return { action: "abort", value: choice.value };

  await saveWritePermission(choice.action, choice.value);
  return { action: "granted", value: choice.value };
}

export function extractDomainsFromCommand(command: string): string[] {
  const urlRegex = /https?:\/\/([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/g;
  const domains = new Set<string>();
  let match: RegExpExecArray | null;
  while ((match = urlRegex.exec(command)) !== null) domains.add(match[1]);
  return [...domains];
}

export function domainMatchesPattern(domain: string, pattern: string): boolean {
  if (pattern === "*") return true;
  if (pattern.startsWith("*.")) {
    const base = pattern.slice(2);
    return domain === base || domain.endsWith("." + base);
  }
  return domain === pattern;
}

export function allowsAllDomains(allowedDomains: string[] | undefined): boolean {
  return allowedDomains?.includes("*") ?? false;
}

export function domainIsAllowed(domain: string, allowedDomains: string[]): boolean {
  return allowedDomains.some((pattern) => domainMatchesPattern(domain, pattern));
}

/**
 * Expand `~` and make the path absolute against `base`.
 *
 * Absolute paths and already-expanded `~` paths are unaffected by `base`;
 * only relative paths change. Defaults to the process cwd for back-compat.
 */
export function expandPath(filePath: string, base: string = process.cwd()): string {
  return resolve(base, filePath.replace(/^~(?=$|\/)/, homedir()));
}

/**
 * Resolve a path to its real absolute form.
 *
 * `base` is the directory relative paths resolve against; pass the session
 * working directory rather than relying on the process cwd, which in
 * headless/daemon contexts (e.g. systemd user units without
 * `WorkingDirectory=`) can be the user's home directory instead of the
 * session's project directory.
 */
export function canonicalizePath(filePath: string, base: string = process.cwd()): string {
  const absolutePath = expandPath(filePath, base);
  try {
    return realpathSync.native(absolutePath);
  } catch {
    const tail: string[] = [];
    let probe = absolutePath;
    while (!existsSync(probe)) {
      const parent = dirname(probe);
      if (parent === probe) return absolutePath;
      tail.unshift(basename(probe));
      probe = parent;
    }
    try {
      return resolve(realpathSync.native(probe), ...tail);
    } catch {
      return absolutePath;
    }
  }
}

export function matchesPattern(
  filePath: string,
  patterns: string[],
  base: string = process.cwd(),
): boolean {
  const absolutePath = canonicalizePath(filePath, base);
  return patterns.some((pattern) => {
    const absolutePattern = pattern.includes("*")
      ? expandPath(pattern, base)
      : canonicalizePath(pattern, base);
    if (pattern.includes("*")) {
      const escaped = absolutePattern.replace(/[.+^${}()|[\]\\]/g, "\\$&").replace(/\*/g, ".*");
      return new RegExp(`^${escaped}$`).test(absolutePath);
    }
    const separator = absolutePattern.endsWith("/") ? "" : "/";
    return absolutePath === absolutePattern || absolutePath.startsWith(absolutePattern + separator);
  });
}
