// Independent zero-src/ audit of results/GF2_*.json certificates.
// Uses NO imports from ../src so bugs in shared evaluators/verifiers cannot mask defects here.
// Checks: (1) schema & dimensions, (2) exact GF(2) RREF rank === k over BigInt,
// (3) exhaustive 2^k - 1 Gray-code minimum distance d and exact codeword count A_d,
// (4) internal non-domination summary, and (5) 4 synthetic negative controls.
import fs from 'node:fs';
import path from 'node:path';

const DIR = process.env.AUDIT_DIR || new URL('./gf2', import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, '$1');

const POP16 = new Uint8Array(65536);
for (let i = 1; i < 65536; i++) POP16[i] = POP16[i >> 1] + (i & 1);

function computeRankGF2(rowStrings, n) {
  const basis = new Map();
  for (let i = 0; i < rowStrings.length; i++) {
    const s = rowStrings[i];
    if (typeof s !== 'string' || s.length !== n) {
      throw new Error(`Row ${i} length mismatch (expected ${n})`);
    }
    let v = 0n;
    for (let c = 0; c < n; c++) {
      const ch = s[c];
      if (ch === '1') v |= 1n << BigInt(c);
      else if (ch !== '0') throw new Error(`Invalid bit char '${ch}' at row ${i}, col ${c}`);
    }
    while (v !== 0n) {
      const hb = v.toString(2).length - 1;
      const piv = basis.get(hb);
      if (piv === undefined) {
        basis.set(hb, v);
        break;
      }
      v ^= piv;
    }
  }
  return basis.size;
}

function exactMinDistanceGrayGF2(rowStrings, n, k) {
  if (k < 1 || k > 24) throw new Error(`Unsupported k=${k} for exhaustive independent Gray audit`);
  const words = Math.ceil(n / 32);
  const basis = new Uint32Array(k * words);
  for (let r = 0; r < k; r++) {
    const str = rowStrings[r];
    const base = r * words;
    for (let c = 0; c < n; c++) {
      if (str[c] === '1') {
        basis[base + (c >>> 5)] |= 1 << (c & 31);
      }
    }
  }

  const cur = new Uint32Array(words);
  const total = 1 << k;
  let minW = n + 1;
  let countMinW = 0;

  for (let g = 1; g < total; g++) {
    // Index of least-significant set bit of g equals the toggled basis row in reflected Gray code
    const rowIdx = Math.clz32((g & -g)) ^ 31;
    const base = rowIdx * words;
    let w = 0;
    for (let wi = 0; wi < words; wi++) {
      const v = (cur[wi] ^= basis[base + wi]) >>> 0;
      w += POP16[v & 0xffff] + POP16[v >>> 16];
    }
    if (w < minW) {
      minW = w;
      countMinW = 1;
    } else if (w === minW) {
      countMinW++;
    }
  }
  return { minW, countMinW };
}

export function auditSingleGF2(cert, fileName = 'synthetic.json') {
  const { n, k, d, A_d: claimedAd, generatorRows } = cert;
  if (!Number.isInteger(n) || !Number.isInteger(k) || !Number.isInteger(d)) {
    return { file: fileName, ok: false, reason: 'Invalid integer header (n, k, d)' };
  }
  if (!Array.isArray(generatorRows) || generatorRows.length !== k) {
    return { file: fileName, ok: false, reason: `generatorRows length ${generatorRows?.length} !== k=${k}` };
  }
  let rank;
  try {
    rank = computeRankGF2(generatorRows, n);
  } catch (err) {
    return { file: fileName, ok: false, reason: err.message };
  }
  if (rank !== k) {
    return { file: fileName, ok: false, reason: `GF(2) rank ${rank} !== k=${k}` };
  }
  const { minW, countMinW } = exactMinDistanceGrayGF2(generatorRows, n, k);
  if (minW !== d) {
    return { file: fileName, ok: false, reason: `Exact minW ${minW} !== claimed d=${d} (A_min=${countMinW})` };
  }
  if (typeof claimedAd === 'number' && claimedAd !== countMinW) {
    return { file: fileName, ok: false, reason: `Exact A_${d}=${countMinW} !== claimed A_d=${claimedAd}` };
  }
  return { file: fileName, ok: true, n, k, d, rank, exactAd: countMinW };
}

const isMain = process.argv[1] && path.resolve(process.argv[1]) === path.resolve(new URL(import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, '$1'));

if (isMain) {
  const files = fs.readdirSync(DIR).filter((f) => /^GF2_\d+_\d+_\d+\.json$/.test(f)).sort();
  if (files.length === 0) {
    console.log('No GF2_*.json files found in', DIR);
    process.exit(0);
  }

  const t0 = Date.now();
  const results = [];
  const certs = [];
  for (const f of files) {
    const tf = Date.now();
    const cert = JSON.parse(fs.readFileSync(path.join(DIR, f), 'utf8'));
    const res = auditSingleGF2(cert, f);
    res.ms = Date.now() - tf;
    const m = f.match(/^GF2_(\d+)_(\d+)_(\d+)\.json$/);
    if (m && (+m[1] !== cert.n || +m[2] !== cert.k || +m[3] !== cert.d)) {
      res.ok = false;
      res.reason = `Filename ${f} disagrees with JSON (${cert.n},${cert.k},${cert.d})`;
    }
    console.log(JSON.stringify(res));
    results.push(res);
    certs.push(cert);
  }

  // Negative controls on the first real certificate
  const base = certs[0];
  const negControls = [];

  // NC1: Corrupt claimed d -> d + 1
  negControls.push({
    name: 'NC1_inflated_claimed_d',
    res: auditSingleGF2({ ...base, d: base.d + 1 }, 'NC1'),
  });
  // NC2: Drop one generator row -> row count != k
  negControls.push({
    name: 'NC2_dropped_row',
    res: auditSingleGF2({ ...base, generatorRows: base.generatorRows.slice(0, -1) }, 'NC2'),
  });
  // NC3: Linearly dependent row (replace last row with XOR of rows 0 and 1)
  const xorStr = [...base.generatorRows[0]].map((c, idx) => ((c === '1') ^ (base.generatorRows[1][idx] === '1') ? '1' : '0')).join('');
  const depRows = base.generatorRows.slice();
  depRows[depRows.length - 1] = xorStr;
  negControls.push({
    name: 'NC3_linear_dependence',
    res: auditSingleGF2({ ...base, generatorRows: depRows }, 'NC3'),
  });
  // NC4: Wrong A_d claim
  negControls.push({
    name: 'NC4_wrong_Ad',
    res: auditSingleGF2({ ...base, A_d: (base.A_d ?? 1) + 1 }, 'NC4'),
  });

  const negPassed = negControls.every((nc) => !nc.res.ok);
  for (const nc of negControls) {
    console.log('NEG_CONTROL', nc.name, nc.res.ok ? 'UNEXPECTED_PASS' : `REJECTED (${nc.res.reason})`);
  }

  const passed = results.filter((r) => r.ok);
  const directNonDom = passed.filter(
    (x) => !passed.some((o) => o !== x && o.n <= x.n && o.k >= x.k && o.d >= x.d)
  );
  console.log(
    `\nGF2 AUDIT SUMMARY: ${passed.length}/${results.length} PASS in ${((Date.now() - t0) / 1000).toFixed(2)}s; ` +
    `${directNonDom.length} directly non-dominated; negControls=${negPassed ? '4/4 REJECTED (PASS)' : 'FAIL'}`
  );
  if (passed.length !== results.length || !negPassed) process.exit(1);
}
