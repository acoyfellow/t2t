#!/usr/bin/env node
// Patch for Alchemy D1Database bug: withJurisdiction headers break D1 API calls
// withJurisdiction returns {} which replaces default headers, losing Content-Type
// See: https://github.com/alchemy-run/alchemy (report this bug)

import { readFileSync, writeFileSync, existsSync } from 'fs';
import { join } from 'path';

// Bun uses .ts directly, so we patch the TypeScript source
const filePath = join(process.cwd(), 'node_modules/alchemy/src/cloudflare/d1-database.ts');

if (!existsSync(filePath)) {
  console.log('[patch] Alchemy D1 TS file not found, skipping patch');
  process.exit(0);
}

let content = readFileSync(filePath, 'utf8');

// Check if already patched
if (content.includes('/* PATCHED */')) {
  console.log('[patch] Alchemy D1 already patched');
  process.exit(0);
}

// Patch the createDatabase function to preserve Content-Type header
const oldCode = `const createResponse = await api.post(
    \`/accounts/\${api.accountId}/d1/database\`,
    createPayload,
    {
      headers: withJurisdiction(props),
    },
  );`;

const newCode = `/* PATCHED */ const createResponse = await api.post(
    \`/accounts/\${api.accountId}/d1/database\`,
    createPayload,
    {
      headers: { "Content-Type": "application/json", ...withJurisdiction(props) },
    },
  );`;

if (!content.includes(oldCode)) {
  console.log('[patch] Could not find target code in Alchemy D1 TS, version may have changed');
  console.log('[patch] Looking for alternate patterns...');
  
  // Try alternate pattern matching
  const altOldCode = `headers: withJurisdiction(props),`;
  const altNewCode = `headers: { "Content-Type": "application/json", ...withJurisdiction(props) }, /* PATCHED */`;
  
  // Only patch the first occurrence in createDatabase function
  const createDbMatch = content.match(/export async function createDatabase[\s\S]*?headers: withJurisdiction\(props\),/);
  if (createDbMatch) {
    content = content.replace(
      createDbMatch[0],
      createDbMatch[0].replace(altOldCode, altNewCode)
    );
    writeFileSync(filePath, content);
    console.log('[patch] Patched Alchemy D1 (alt pattern)');
    process.exit(0);
  }
  
  console.log('[patch] Could not find any pattern to patch');
  process.exit(0);
}

content = content.replace(oldCode, newCode);
writeFileSync(filePath, content);
console.log('[patch] Patched Alchemy D1 (preserved Content-Type header)');

