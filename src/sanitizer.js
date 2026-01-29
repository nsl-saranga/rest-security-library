/**
 * HTML escape mapping
 */
const htmlEscapeMap = {
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
const sqlEscapeMap = {
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
 * @param {string} str - String to escape
 * @returns {string} Escaped string safe for HTML context
 */
export function escapeHtml(str) {
  if (typeof str !== "string") return str;
  return str.replace(/[&<>"'\/]/g, char => htmlEscapeMap[char]);
}

/**
 * Escape database special characters to help prevent SQL injection.
 * Use parameterized queries as primary defense; this is a defense-in-depth measure for dynamic values.
 * @param {string} str - String to escape (e.g. user input used in SQL)
 * @returns {string} Escaped string safe for use in SQL string literals
 */
export function escapeSql(str) {
  if (typeof str !== "string") return str;
  return str.replace(/[\0\n\r\u001a\\'"]/g, char => sqlEscapeMap[char]);
}

/**
 * Block file path traversal by removing or neutralizing "../" and "..\" and common encoded forms.
 * @param {string} str - Path or filename (e.g. from query or form)
 * @returns {string} String with path traversal sequences removed
 */
export function blockPathTraversal(str) {
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
 * @param {string} str - String that might be used in headers or logs
 * @returns {string} String with \r\n, \n\r, \r, \n removed
 */
export function removeCrlf(str) {
  if (typeof str !== "string") return str;
  return str.replace(/\r\n|\n\r|\r|\n/g, "");
}

/**
 * Escape shell metacharacters to help prevent command injection when passing input to shell commands.
 * @param {string} str - String to pass into a shell context (e.g. exec)
 * @returns {string} Escaped string (metacharacters backslash-escaped)
 */
export function escapeShell(str) {
  if (typeof str !== "string") return str;
  return str.replace(SHELL_METACHARS, "\\$&");
}

/**
 * Remove HTML tags from string
 * @param {string} str - String potentially containing HTML
 * @returns {string} String with HTML tags removed
 */
export function stripHtmlTags(str) {
  if (typeof str !== "string") return str;
  return str.replace(/<[^>]*>/g, "");
}

/**
 * Remove potentially dangerous patterns (script tags, event handlers, etc.)
 * @param {string} str - String to sanitize
 * @returns {string} Sanitized string
 */
export function removeDangerousPatterns(str) {
  if (typeof str !== "string") return str;
  
  // Remove script tags and content
  let sanitized = str.replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, "");
  
  // Remove event handlers (onclick, onerror, onload, etc.)
  sanitized = sanitized.replace(/\s*on\w+\s*=\s*["'][^"']*["']/gi, "");
  sanitized = sanitized.replace(/\s*on\w+\s*=\s*[^\s>]*/gi, "");
  
  return sanitized;
}

/**
 * Trim whitespace and normalize string
 * @param {string} str - String to trim
 * @returns {string} Trimmed string
 */
export function trim(str) {
  if (typeof str !== "string") return str;
  return str.trim();
}

/**
 * Sanitize a single value based on type
 * @param {*} value - Value to sanitize
 * @param {Object} options - Sanitization options
 * @param {boolean} [options.escape=true] - Escape HTML
 * @param {boolean} [options.trim=true] - Trim whitespace
 * @param {boolean} [options.stripTags=false] - Strip HTML tags
 * @param {boolean} [options.removeDangerous=true] - Remove script/event patterns
 * @param {boolean} [options.escapeSql=false] - Escape DB special chars (SQL injection prevention)
 * @param {boolean} [options.blockPathTraversal=false] - Remove "../" path traversal
 * @param {boolean} [options.removeCrlf=false] - Remove \\r\\n (CRLF/header injection prevention)
 * @param {boolean} [options.escapeShell=false] - Escape shell metacharacters (command injection prevention)
 * @returns {*} Sanitized value
 */
export function sanitizeValue(value, options = {}) {
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

  let sanitized = value;

  if (shouldTrim) {
    sanitized = trim(sanitized);
  }

  if (doRemoveCrlf) {
    sanitized = removeCrlf(sanitized);
  }

  if (doBlockPathTraversal) {
    sanitized = blockPathTraversal(sanitized);
  }

  if (removeDangerous) {
    sanitized = removeDangerousPatterns(sanitized);
  }

  if (stripTags) {
    sanitized = stripHtmlTags(sanitized);
  }

  if (doEscapeSql) {
    sanitized = escapeSql(sanitized);
  }

  if (doEscapeShell) {
    sanitized = escapeShell(sanitized);
  }

  if (escape) {
    sanitized = escapeHtml(sanitized);
  }

  return sanitized;
}

/**
 * Recursively sanitize an object (typically request body/query/params)
 * @param {*} data - Data to sanitize (object, array, or primitive)
 * @param {Object} options - Sanitization options
 * @returns {*} Sanitized data
 */
export function sanitizeObject(data, options = {}) {
  if (data === null || data === undefined) {
    return data;
  }

  // Handle arrays
  if (Array.isArray(data)) {
    return data.map(item => sanitizeObject(item, options));
  }

  // Handle objects
  if (typeof data === "object") {
    const sanitized = {};
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
 * @param {Object} options - Sanitization options
 * @returns {Function} Express middleware
 */
export function sanitizeRequest(options = {}) {
  return (req, res, next) => {
    const sanitizeOptions = {
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
