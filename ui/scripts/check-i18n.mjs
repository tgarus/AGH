import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const currentDir = dirname(fileURLToPath(import.meta.url));
const plPath = resolve(currentDir, '../src/i18n/locales/pl/common.json');
const enPath = resolve(currentDir, '../src/i18n/locales/en/common.json');
const evaluatorPath = resolve(
  currentDir,
  '../../crates/asi-api/src/diff_engine/evaluator.rs',
);

function flattenEntries(obj, prefix = '') {
  const entries = new Map();
  for (const [key, value] of Object.entries(obj)) {
    const fullKey = prefix ? `${prefix}.${key}` : key;
    if (value !== null && typeof value === 'object' && !Array.isArray(value)) {
      for (const [k, v] of flattenEntries(value, fullKey)) {
        entries.set(k, v);
      }
    } else {
      entries.set(fullKey, String(value));
    }
  }
  return entries;
}

function extractPlaceholders(str) {
  const matches = str.match(/\{\{[^}]+\}\}/g) || [];
  return [...new Set(matches)].sort();
}

const pl = JSON.parse(readFileSync(plPath, 'utf8'));
const en = JSON.parse(readFileSync(enPath, 'utf8'));

const plEntries = flattenEntries(pl);
const enEntries = flattenEntries(en);

const missingInEn = [...plEntries.keys()].filter((k) => !enEntries.has(k));
const missingInPl = [...enEntries.keys()].filter((k) => !plEntries.has(k));

if (missingInEn.length > 0 || missingInPl.length > 0) {
  console.error('i18n parity check failed!');
  if (missingInEn.length > 0) {
    console.error('Missing in EN:', missingInEn);
  }
  if (missingInPl.length > 0) {
    console.error('Missing in PL:', missingInPl);
  }
  process.exit(1);
}

const placeholderMismatches = [];
for (const [key, plVal] of plEntries) {
  const enVal = enEntries.get(key) ?? '';
  const plVars = extractPlaceholders(plVal);
  const enVars = extractPlaceholders(enVal);
  if (JSON.stringify(plVars) !== JSON.stringify(enVars)) {
    placeholderMismatches.push({ key, plVars, enVars });
  }
}

if (placeholderMismatches.length > 0) {
  console.error('i18n interpolation placeholder parity check failed!', placeholderMismatches);
  process.exit(1);
}

// Cross-stack Diff Engine bullet contract: every BulletItem key emitted by evaluator.rs
// must have matching translations under bullets.<key> in both locales.
const evaluatorSource = readFileSync(evaluatorPath, 'utf8').split('#[cfg(test)]')[0] ?? '';
const bulletKeys = new Set();
for (const match of evaluatorSource.matchAll(/key:\s*"([a-z0-9_]+)"\.to_string\(\)/g)) {
  if (match[1]) {
    bulletKeys.add(match[1]);
  }
}

const missingBullets = [];
for (const bKey of bulletKeys) {
  const i18nKey = `bullets.${bKey}`;
  if (!plEntries.has(i18nKey) || !enEntries.has(i18nKey)) {
    missingBullets.push(i18nKey);
  }
}

if (missingBullets.length > 0 || bulletKeys.size === 0) {
  console.error('Diff Engine bullet i18n contract check failed!', {
    extractedCount: bulletKeys.size,
    missingBullets,
  });
  process.exit(1);
}

console.log(
  `i18n check passed (${plEntries.size} keys, placeholder parity OK, ${bulletKeys.size} diff bullet keys verified across pl/en).`,
);
