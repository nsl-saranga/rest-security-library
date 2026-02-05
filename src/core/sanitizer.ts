import type { Request, Response, NextFunction } from "express";

/**
 * Options for sanitization functions.
 */
export interface SanitizationOptions {
  escape?: boolean;
  trim?: boolean;
  stripTags?: boolean;
  removeDangerous?: boolean;
  escapeSql?: boolean;
  blockPathTraversal?: boolean;
  removeCrlf?: boolean;
  escapeShell?: boolean;
  // Allow extra keys for forward compatibility
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  [key: string]: any;
}

/**
 * HTML escape mapping
 */
const htmlEscapeMap: Record<string, string> = {
  "&": "&amp;",
  "<": "&lt;",
  ">": "&gt;",
  '"': "&quot;",
  "'": "&#x27;",
  "/": "&#x2F;"
};

/**
 * SQL special characters to escape (single quote, backslash, null, etc.)
 * Escaping style: backslash for \ and ', which works with MySQL and common ORMs.
 */
const sqlEscapeMap: Record<string, string> = {
  "\0": "\\0",
  "\n": "\\n",
  "\r": "\\r",
  "\u001a": "\\Z", // Ctrl+Z
  "\\": "\\\\",
  "'": "\\'",
  '"': '\\"'
};

/**
 * Shell metacharacters that can be used for command injection
 */
const SHELL_METACHARS = /[;&|$`\\<>()!#*?\[\]{}~\n\r]/g;

/**
 * Escape HTML special characters
 * @param str - String to escape
 * @returns Escaped string safe for HTML context
 */
export function escapeHtml(str: unknown): unknown {
  if (typeof str !== "string") return str;
  return str.replace(/[&<>"'\/]/g, (char) => htmlEscapeMap[char]);
}

/**
 * Escape database special characters to help prevent SQL injection.
 * Use parameterized queries as primary defense; this is a defense-in-depth measure for dynamic values.
 * @param str - String to escape (e.g. user input used in SQL)
 * @returns Escaped string safe for use in SQL string literals
 */
export function escapeSql(str: unknown): unknown {
  if (typeof str !== "string") return str;
  return str.replace(/[\0\n\r\u001a\\'"]/g, (char) => sqlEscapeMap[char]);
}

/**
 * Block file path traversal by removing or neutralizing "../" and "..\" and common encoded forms.
 * @param str - Path or filename (e.g. from query or form)
 * @returns String with path traversal sequences removed
 */
export function blockPathTraversal(str: unknown): unknown {
  if (typeof str !== "string") return str;
  let s = str;
  // Normalize backslashes to forward slashes for consistent matching
  s = s.replace(/\\/g, "/");
  // Remove ../ and ..\ and leading/trailing ..
  s = s.replace(/\.\.\/+/g, "");
  s = s.replace(/\/+\.\.(\/|$)/g, "$1");
  s = s.replace(/^\.\.\/?/, "");
  s = s.replace(/\/\.\.$/g, "/");
  // Decode common encoded traversal then strip again
  s = s.replace(/%2e%2e%2f/gi, "");
  s = s.replace(/%2e%2e\//gi, "");
  s = s.replace(/\.\.%2f/gi, "");
  s = s.replace(/%2e%2e%5c/gi, "");
  return s;
}

/**
 * Remove CRLF and newline sequences to help prevent HTTP header / CRLF injection.
 * @param str - String that might be used in headers or logs
 * @returns String with \r\n, \n\r, \r, \n removed
 */
export function removeCrlf(str: unknown): unknown {
  if (typeof str !== "string") return str;
  return str.replace(/\r\n|\n\r|\r|\n/g, "");
}

/**
 * Escape shell metacharacters to help prevent command injection when passing input to shell commands.
 * @param str - String to pass into a shell context (e.g. exec)
 * @returns Escaped string (metacharacters backslash-escaped)
 */
export function escapeShell(str: unknown): unknown {
  if (typeof str !== "string") return str;
  return str.replace(SHELL_METACHARS, "\\$&");
}

/**
 * Remove HTML tags from string
 * @param str - String potentially containing HTML
 * @returns String with HTML tags removed
 */
export function stripHtmlTags(str: unknown): unknown {
  if (typeof str !== "string") return str;
  return str.replace(/<[^>]*>/g, "");
}

/**
 * Remove potentially dangerous patterns (script tags, event handlers, etc.)
 * @param str - String to sanitize
 * @returns Sanitized string
 */
export function removeDangerousPatterns(str: unknown): unknown {
  if (typeof str !== "string") return str;

  // Remove script tags and content
  let sanitized = str.replace(
    /<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi,
    ""
  );

  // Remove event handlers (onclick, onerror, onload, etc.)
  sanitized = sanitized.replace(
    /\s*on\w+\s*=\s*["'][^"']*["']/gi,
    ""
  );
  sanitized = sanitized.replace(/\s*on\w+\s*=\s*[^\s>]*/gi, "");

  return sanitized;
}

/**
 * Trim whitespace and normalize string
 * @param str - String to trim
 * @returns Trimmed string
 */
export function trim(str: unknown): unknown {
  if (typeof str !== "string") return str;
  return str.trim();
}

/**
 * Sanitize a single value based on type.
 * Returns the same type it receives unless it is a string, which may be transformed.
 */
export function sanitizeValue(
  value: unknown,
  options: SanitizationOptions = {}
): unknown {
  const {
    escape = true,
    trim: shouldTrim = true,
    stripTags = false,
    removeDangerous = true,
    escapeSql: doEscapeSql = false,
    blockPathTraversal: doBlockPathTraversal = false,
    removeCrlf: doRemoveCrlf = false,
    escapeShell: doEscapeShell = false
  } = options;

  if (typeof value !== "string") {
    return value;
  }

  let sanitized: string = value;

  if (shouldTrim) {
    sanitized = trim(sanitized) as string;
  }

  if (doRemoveCrlf) {
    sanitized = removeCrlf(sanitized) as string;
  }

  if (doBlockPathTraversal) {
    sanitized = blockPathTraversal(sanitized) as string;
  }

  if (removeDangerous) {
    sanitized = removeDangerousPatterns(sanitized) as string;
  }

  if (stripTags) {
    sanitized = stripHtmlTags(sanitized) as string;
  }

  if (doEscapeSql) {
    sanitized = escapeSql(sanitized) as string;
  }

  if (doEscapeShell) {
    sanitized = escapeShell(sanitized) as string;
  }

  if (escape) {
    sanitized = escapeHtml(sanitized) as string;
  }

  return sanitized;
}

/**
 * Recursively sanitize an object (typically request body/query/params)
 */
export function sanitizeObject(
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  data: any,
  options: SanitizationOptions = {}
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
): any {
  if (data === null || data === undefined) {
    return data;
  }

  // Handle arrays
  if (Array.isArray(data)) {
    return data.map((item) => sanitizeObject(item, options));
  }

  // Handle objects
  if (typeof data === "object") {
    const sanitized: Record<string, unknown> = {};
    for (const [key, value] of Object.entries(data)) {
      if (typeof value === "string") {
        sanitized[key] = sanitizeValue(value, options);
      } else if (typeof value === "object") {
        sanitized[key] = sanitizeObject(value, options);
      } else {
        sanitized[key] = value;
      }
    }
    return sanitized;
  }

  // Handle primitives
  if (typeof data === "string") {
    return sanitizeValue(data, options);
  }

  return data;
}

/**
 * Express middleware for sanitizing request data
 */
export function sanitizeRequest(
  options: SanitizationOptions = {}
): (req: Request, res: Response, next: NextFunction) => void {
  return (req: Request, _res: Response, next: NextFunction): void => {
    const sanitizeOptions: SanitizationOptions = {
      escape: options.escape !== false,
      trim: options.trim !== false,
      stripTags: options.stripTags || false,
      removeDangerous: options.removeDangerous !== false,
      escapeSql: options.escapeSql || false,
      blockPathTraversal: options.blockPathTraversal || false,
      removeCrlf: options.removeCrlf || false,
      escapeShell: options.escapeShell || false,
      ...options
    };

    // Sanitize body, query, and params
    if (req.body) {
      req.body = sanitizeObject(req.body, sanitizeOptions);
    }
    if (req.query) {
      req.query = sanitizeObject(req.query, sanitizeOptions);
    }
    if (req.params) {
      req.params = sanitizeObject(req.params, sanitizeOptions);
    }

    next();
  };
}

