import { Effect, Data } from "effect";

// Patterns that should NEVER be executed
const DENY_PATTERNS = [
  // Destructive shell commands
  /do shell script.*rm\s+(-rf?|--recursive)/i,
  /do shell script.*sudo/i,
  /do shell script.*mkfs/i,
  /do shell script.*dd\s+if=/i,
  /do shell script.*:\(\)\{.*\}.*:/i, // fork bomb
  /do shell script.*>\s*\/dev\//i,

  // Mass file operations
  /delete\s+(every|all)\s+(file|folder|item)/i,
  /remove\s+(every|all)\s+(file|folder|item)/i,

  // Credential/secret access
  /security\s+find-(generic|internet)-password/i,
  /keychain/i,

  // Network exfiltration patterns
  /do shell script.*curl.*-d.*\$\(/i,
  /do shell script.*wget.*--post/i,

  // Privilege escalation
  /with\s+administrator\s+privileges/i,

  // Dangerous System Events
  /keystroke.*password/i,
  /keystroke.*secret/i,
  /keystroke.*api.?key/i,
];

export class DenylistViolation extends Data.TaggedError("DenylistViolation")<{
  script: string;
  pattern?: string;
}> { }

export const checkDenylist = (script: string) =>
  Effect.sync(() => {
    for (const pattern of DENY_PATTERNS) {
      if (pattern.test(script)) {
        return Effect.fail(
          new DenylistViolation({
            script,
            pattern: pattern.source,
          })
        );
      }
    }
    return Effect.succeed(script);
  }).pipe(Effect.flatten);

// For logging/debugging - returns which patterns matched
export const getDenylistMatches = (script: string): string[] => {
  return DENY_PATTERNS.filter((p) => p.test(script)).map((p) => p.source);
};
