// Utility function to sanitize strings for PostgreSQL
export function sanitizeString(str: string): string {
  if (typeof str !== 'string') return str;

  // Only remove null bytes which cause PostgreSQL 22P05 errors
  // Keep other characters like \n, \r, \t which are valid and useful
  return str.replace(/\u0000/g, '');
}

// Utility function to sanitize objects recursively
export function sanitizeObject(obj: any): any {
  if (obj === null || obj === undefined) return obj;

  if (typeof obj === 'string') {
    return sanitizeString(obj);
  }

  if (obj instanceof Date) {
    return obj.toISOString();
  }

  if (Buffer.isBuffer(obj)) {
    return sanitizeString(obj.toString('utf8'));
  }

  if (Array.isArray(obj)) {
    return obj.map(item => sanitizeObject(item));
  }

  if (typeof obj === 'object' && obj.constructor === Object) {
    // Only sanitize plain objects, leave other objects untouched
    const sanitized: any = {};
    for (const [key, value] of Object.entries(obj)) {
      sanitized[key] = sanitizeObject(value);
    }
    return sanitized;
  }

  return obj;
}
