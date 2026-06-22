// Input validation wrapper around sanitize.ts — re-exported here so
// lib/security/index.ts is a single import point for security utilities.
export { validateSupabaseUrl, validateAnonKey, sanitizeInput, ValidationError } from "@/lib/sanitize";
