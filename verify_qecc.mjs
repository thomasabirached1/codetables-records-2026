// Unified zero-src-import independent audit of ALL results/QECC_*.json certificates (d = 5, 6, 7, 8; ALL ranks r <= 64).
// Zero imports from ../src so bugs in shared evaluators/verifiers cannot hide here.
import fs from 'node:fs';
import path from 'node:path';

const DIR = process.env.AUDIT_DIR || new URL('./qecc', import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, '$1');

function nextPow2(x) {
  let p = 1;
  while (p < x) p <<= 1;
  return p;
}

function mix64(lo, hi) {
  let x = (lo ^ Math.imul(hi, 0x9e3779b1)) >>> 0;
  x = (x ^ (x >>> 16)) >>> 0;
  x = Math.imul(x, 0x45d9f3b) >>> 0;
  x = (x ^ (x >>> 16)) >>> 0;
  return x;
}

function popParity(v) {
  let p = 0;
  while (v) {
    v &= v - 1n;
    p ^= 1;
  }
  return p;
}

function parseCode(j) {
  const n = j.n;
  const rows = j.stabilizersXZ.map(({ x, z }) => {
    if (x.length !== n || z.length !== n) throw new Error('row length mismatch');
    let v = 0n;
    for (let c = 0; c < n; c++) {
      if (x[c] === '1') v |= 1n << BigInt(c);
      if (z[c] === '1') v |= 1n << BigInt(n + c);
    }
    return v;
  });
  return { n, claimedK: j.k, claimedD: j.d, rows };
}

let packedScratch = null;
function getPackedScratch(maxItems, htSize) {
  if (!packedScratch || packedScratch.maxItems < maxItems || packedScratch.htSize < htSize) {
    packedScratch = {
      maxItems,
      htSize,
      bitset: new Uint32Array(1 << 22),
      htHead: new Int32Array(htSize),
      htKeyLo: new Uint32Array(htSize),
      htKeyHi: new Uint32Array(htSize),
      nextArr: new Int32Array(maxItems),
      lIdx0: new Int16Array(maxItems),
      lIdx1: new Int16Array(maxItems),
      lIdx2: new Int16Array(maxItems),
      lWt: new Uint8Array(maxItems),
      lMaxQ: new Uint8Array(maxItems),
    };
  }
  packedScratch.bitset.fill(0);
  packedScratch.htHead.subarray(0, htSize).fill(-1);
  return packedScratch;
}

function verifyPackedW6(n, claimedK, claimedD, rank, opsSyn, opsVec, reduce) {
  const opLo = new Uint32Array(3 * n);
  const opHi = new Uint32Array(3 * n);
  for (let i = 0; i < 3 * n; i++) {
    opLo[i] = Number(opsSyn[i] & 0xffffffffn) >>> 0;
    opHi[i] = Number((opsSyn[i] >> 32n) & 0xffffffffn) >>> 0;
  }

  const maxItems = Math.ceil(1 + 3 * n + (n * (n - 1) / 2) * 9 + (n * (n - 1) * (n - 2) / 6) * 27) + 32;
  const htSize = nextPow2(Math.max(1024, maxItems * 2));
  const htMask = htSize - 1;
  const sc = getPackedScratch(maxItems, htSize);
  const { bitset, htHead, htKeyLo, htKeyHi, nextArr, lIdx0, lIdx1, lIdx2, lWt, lMaxQ } = sc;

  let itemCount = 0;
  let minFound = claimedD;

  function insertLeft(lo, hi, i0, i1, i2, wt, maxQ) {
    const id = itemCount++;
    lIdx0[id] = i0;
    lIdx1[id] = i1;
    lIdx2[id] = i2;
    lWt[id] = wt;
    lMaxQ[id] = maxQ;
    const bsIdx = lo & 0x7ffffff;
    bitset[bsIdx >>> 5] |= 1 << (bsIdx & 31);
    const h = mix64(lo, hi);
    let slot = h & htMask;
    while (true) {
      const hd = htHead[slot];
      if (hd === -1) {
        htKeyLo[slot] = lo;
        htKeyHi[slot] = hi;
        htHead[slot] = id;
        nextArr[id] = -1;
        break;
      }
      if (htKeyLo[slot] === lo && htKeyHi[slot] === hi) {
        nextArr[id] = hd;
        htHead[slot] = id;
        break;
      }
      slot = (slot + 1) & htMask;
    }
  }

  for (let q0 = 0; q0 < n && minFound >= claimedD; q0++) {
    const b0 = 3 * q0;
    for (let p0 = 0; p0 < 3 && minFound >= claimedD; p0++) {
      const i0 = b0 + p0;
      const lo0 = opLo[i0], hi0 = opHi[i0];
      if (lo0 === 0 && hi0 === 0 && reduce(opsVec[i0]) !== 0n) { minFound = 1; break; }
      insertLeft(lo0, hi0, i0, -1, -1, 1, q0);

      for (let q1 = q0 + 1; q1 < n && minFound >= claimedD; q1++) {
        const b1 = 3 * q1;
        for (let p1 = 0; p1 < 3 && minFound >= claimedD; p1++) {
          const i1 = b1 + p1;
          const lo1 = (lo0 ^ opLo[i1]) >>> 0, hi1 = (hi0 ^ opHi[i1]) >>> 0;
          if (lo1 === 0 && hi1 === 0 && reduce(opsVec[i0] ^ opsVec[i1]) !== 0n) {
            if (2 < minFound) minFound = 2;
            break;
          }
          insertLeft(lo1, hi1, i0, i1, -1, 2, q1);

          for (let q2 = q1 + 1; q2 < n && minFound >= claimedD; q2++) {
            const b2 = 3 * q2;
            for (let p2 = 0; p2 < 3 && minFound >= claimedD; p2++) {
              const i2 = b2 + p2;
              const lo2 = (lo1 ^ opLo[i2]) >>> 0, hi2 = (hi1 ^ opHi[i2]) >>> 0;
              if (lo2 === 0 && hi2 === 0 && reduce(opsVec[i0] ^ opsVec[i1] ^ opsVec[i2]) !== 0n) {
                if (3 < minFound) minFound = 3;
                break;
              }
              insertLeft(lo2, hi2, i0, i1, i2, 3, q2);
            }
          }
        }
      }
    }
  }
  if (minFound < claimedD) {
    return { ok: false, reason: `found weight ${minFound} < ${claimedD} in left half` };
  }

  function checkRight(lo, hi, firstQ, r0, r1, r2, rWt) {
    if (lo === 0 && hi === 0) {
      let v = opsVec[r0];
      if (r1 >= 0) v ^= opsVec[r1];
      if (r2 >= 0) v ^= opsVec[r2];
      if (rWt < minFound && reduce(v) !== 0n) { minFound = rWt; return; }
    }
    const bsIdx = lo & 0x7ffffff;
    if ((bitset[bsIdx >>> 5] & (1 << (bsIdx & 31))) === 0) return;
    let slot = mix64(lo, hi) & htMask;
    let id = -1;
    while (true) {
      const hd = htHead[slot];
      if (hd === -1) return;
      if (htKeyLo[slot] === lo && htKeyHi[slot] === hi) { id = hd; break; }
      slot = (slot + 1) & htMask;
    }
    let rVec = -1n;
    while (id !== -1) {
      if (lMaxQ[id] < firstQ) {
        const tot = lWt[id] + rWt;
        if (tot < minFound) {
          if (rVec === -1n) {
            rVec = opsVec[r0];
            if (r1 >= 0) rVec ^= opsVec[r1];
            if (r2 >= 0) rVec ^= opsVec[r2];
          }
          let totVec = rVec ^ opsVec[lIdx0[id]];
          if (lIdx1[id] >= 0) totVec ^= opsVec[lIdx1[id]];
          if (lIdx2[id] >= 0) totVec ^= opsVec[lIdx2[id]];
          if (reduce(totVec) !== 0n) {
            minFound = tot;
            return;
          }
        }
      }
      id = nextArr[id];
    }
  }

  const n3 = 3 * n;
  for (let q0 = 0; q0 < n && minFound >= claimedD; q0++) {
    const b0 = 3 * q0;
    for (let p0 = 0; p0 < 3 && minFound >= claimedD; p0++) {
      const idx0 = b0 + p0;
      const lo0 = opLo[idx0], hi0 = opHi[idx0];
      checkRight(lo0, hi0, q0, idx0, -1, -1, 1);

      for (let q1 = q0 + 1; q1 < n && minFound >= claimedD; q1++) {
        const b1 = 3 * q1;
        for (let p1 = 0; p1 < 3 && minFound >= claimedD; p1++) {
          const idx1 = b1 + p1;
          const lo1 = (lo0 ^ opLo[idx1]) >>> 0, hi1 = (hi0 ^ opHi[idx1]) >>> 0;
          checkRight(lo1, hi1, q0, idx0, idx1, -1, 2);

          for (let idx2 = 3 * (q1 + 1); idx2 < n3 && minFound >= claimedD; idx2++) {
            const lo2 = (lo1 ^ opLo[idx2]) >>> 0, hi2 = (hi1 ^ opHi[idx2]) >>> 0;
            const bsIdx = lo2 & 0x7ffffff;
            if ((bitset[bsIdx >>> 5] & (1 << (bsIdx & 31))) !== 0 || (lo2 === 0 && hi2 === 0)) {
              checkRight(lo2, hi2, q0, idx0, idx1, idx2, 3);
            }
          }
        }
      }
    }
  }

  return minFound >= claimedD
    ? { ok: true, n, k: claimedK, d: claimedD, rank, minFound }
    : { ok: false, reason: `found weight ${minFound} < ${claimedD}`, minFound };
}

function verifyD8Bitset(n, claimedK, claimedD, rank, opsSyn, opsVec, reduce) {
  const opLo = new Uint32Array(3 * n);
  const opHi = new Uint32Array(3 * n);
  for (let i = 0; i < 3 * n; i++) {
    opLo[i] = Number(opsSyn[i] & 0xffffffffn) >>> 0;
    opHi[i] = Number((opsSyn[i] >> 32n) & 0xffffffffn) >>> 0;
  }

  const bitset = new Uint32Array(1 << 22);
  const map = new Map();
  let minFound = claimedD;

  function genLeft(startQ, remW, sLo, sHi, curVec, wt) {
    if (minFound < claimedD) return;
    for (let q = startQ; q < n; q++) {
      const base = 3 * q;
      for (let p = 0; p < 3; p++) {
        const idx = base + p;
        const nLo = (sLo ^ opLo[idx]) >>> 0;
        const nHi = (sHi ^ opHi[idx]) >>> 0;
        const nVec = curVec ^ opsVec[idx];
        const nWt = wt + 1;
        if (nLo === 0 && nHi === 0 && reduce(nVec) !== 0n) {
          if (nWt < minFound) minFound = nWt;
          return;
        }
        const key = (BigInt(nHi) << 32n) | BigInt(nLo);
        const bsIdx = nLo & 0x7ffffff;
        bitset[bsIdx >>> 5] |= 1 << (bsIdx & 31);
        let arr = map.get(key);
        if (!arr) { arr = []; map.set(key, arr); }
        arr.push({ maxQ: q, vec: nVec, wt: nWt });
        if (remW > 1 && q + 1 < n) {
          genLeft(q + 1, remW - 1, nLo, nHi, nVec, nWt);
          if (minFound < claimedD) return;
        }
      }
    }
  }
  genLeft(0, 3, 0, 0, 0n, 0);
  if (minFound < claimedD) return { ok: false, reason: `found weight ${minFound} < ${claimedD} in left half` };

  function checkMatch(nLo, nHi, firstQ, r0, r1, r2, r3, rWt) {
    if (rWt > 3 && nLo === 0 && nHi === 0) {
      let v = opsVec[r0];
      if (r1 >= 0) v ^= opsVec[r1];
      if (r2 >= 0) v ^= opsVec[r2];
      if (r3 >= 0) v ^= opsVec[r3];
      if (reduce(v) !== 0n && rWt < minFound) minFound = rWt;
      return;
    }
    const bsIdx = nLo & 0x7ffffff;
    if ((bitset[bsIdx >>> 5] & (1 << (bsIdx & 31))) === 0) return;
    const key = (BigInt(nHi) << 32n) | BigInt(nLo);
    const bucket = map.get(key);
    if (!bucket) return;
    let rVec = opsVec[r0];
    if (r1 >= 0) rVec ^= opsVec[r1];
    if (r2 >= 0) rVec ^= opsVec[r2];
    if (r3 >= 0) rVec ^= opsVec[r3];
    for (let i = 0; i < bucket.length; i++) {
      const left = bucket[i];
      if (left.maxQ < firstQ) {
        const tot = left.wt + rWt;
        if (tot < minFound && reduce(left.vec ^ rVec) !== 0n) {
          minFound = tot;
          return;
        }
      }
    }
  }

  const n3 = 3 * n;
  for (let q0 = 0; q0 < n && minFound >= claimedD; q0++) {
    const b0 = 3 * q0;
    for (let p0 = 0; p0 < 3 && minFound >= claimedD; p0++) {
      const idx0 = b0 + p0;
      const lo0 = opLo[idx0], hi0 = opHi[idx0];
      checkMatch(lo0, hi0, q0, idx0, -1, -1, -1, 1);
      for (let q1 = q0 + 1; q1 < n && minFound >= claimedD; q1++) {
        const b1 = 3 * q1;
        for (let p1 = 0; p1 < 3 && minFound >= claimedD; p1++) {
          const idx1 = b1 + p1;
          const lo1 = (lo0 ^ opLo[idx1]) >>> 0, hi1 = (hi0 ^ opHi[idx1]) >>> 0;
          checkMatch(lo1, hi1, q0, idx0, idx1, -1, -1, 2);
          for (let q2 = q1 + 1; q2 < n && minFound >= claimedD; q2++) {
            const b2 = 3 * q2;
            for (let p2 = 0; p2 < 3 && minFound >= claimedD; p2++) {
              const idx2 = b2 + p2;
              const lo2 = (lo1 ^ opLo[idx2]) >>> 0, hi2 = (hi1 ^ opHi[idx2]) >>> 0;
              checkMatch(lo2, hi2, q0, idx0, idx1, idx2, -1, 3);
              for (let idx3 = 3 * (q2 + 1); idx3 < n3; idx3++) {
                const lo3 = (lo2 ^ opLo[idx3]) >>> 0;
                const hi3 = (hi2 ^ opHi[idx3]) >>> 0;
                const bsIdx = lo3 & 0x7ffffff;
                if ((bitset[bsIdx >>> 5] & (1 << (bsIdx & 31))) !== 0 || (lo3 === 0 && hi3 === 0)) {
                  checkMatch(lo3, hi3, q0, idx0, idx1, idx2, idx3, 4);
                  if (minFound < claimedD) break;
                }
              }
            }
          }
        }
      }
    }
  }
  return minFound >= claimedD
    ? { ok: true, n, k: claimedK, d: claimedD, rank, minFound }
    : { ok: false, reason: `found weight ${minFound} < ${claimedD}`, minFound };
}

export function verifyIndependentAnyQECC({ n, claimedK, claimedD, rows }) {
  const maskN = (1n << BigInt(n)) - 1n;
  const symp = (a, b) => popParity(((a & maskN) & (b >> BigInt(n))) ^ ((a >> BigInt(n)) & (b & maskN)));

  for (let i = 0; i < rows.length; i++) {
    for (let j = i; j < rows.length; j++) {
      if (symp(rows[i], rows[j])) return { ok: false, reason: `rows ${i},${j} anticommute` };
    }
  }

  const basis = new Map();
  const reduce = (v) => {
    while (v) {
      const hb = v.toString(2).length - 1;
      const b = basis.get(hb);
      if (b === undefined) return v;
      v ^= b;
    }
    return 0n;
  };
  for (const r of rows) {
    const red = reduce(r);
    if (red) basis.set(red.toString(2).length - 1, red);
  }
  const rank = basis.size;
  if (rank > 64) return { ok: false, reason: `rank ${rank} > 64` };
  const k = n - rank;
  if (k !== claimedK) return { ok: false, reason: `rank mismatch: k=${k} vs claimed=${claimedK}` };

  const gens = [...basis.values()];
  const opsSyn = new Array(3 * n);
  const opsVec = new Array(3 * n);
  for (let q = 0; q < n; q++) {
    for (let p = 0; p < 3; p++) {
      let vec = 0n;
      if (p === 0 || p === 2) vec |= 1n << BigInt(q);
      if (p === 1 || p === 2) vec |= 1n << BigInt(n + q);
      let s = 0n;
      for (let g = 0; g < gens.length; g++) if (symp(vec, gens[g])) s |= 1n << BigInt(g);
      opsSyn[3 * q + p] = s;
      opsVec[3 * q + p] = vec;
    }
  }

  const W = claimedD - 1;
  const wL = Math.floor(W / 2);
  const wR = W - wL;
  if (claimedD === 8) return verifyD8Bitset(n, claimedK, claimedD, rank, opsSyn, opsVec, reduce);
  if (wL === 3 && wR === 3 && n >= 90) return verifyPackedW6(n, claimedK, claimedD, rank, opsSyn, opsVec, reduce);

  const map = new Map();
  let minFound = claimedD;
  function genLeft(startQ, remW, curSyn, curVec, wt) {
    if (minFound < claimedD) return;
    for (let q = startQ; q < n; q++) {
      const base = 3 * q;
      for (let p = 0; p < 3; p++) {
        const idx = base + p;
        const nSyn = curSyn ^ opsSyn[idx];
        const nVec = curVec ^ opsVec[idx];
        const nWt = wt + 1;
        if (nSyn === 0n && reduce(nVec) !== 0n) {
          if (nWt < minFound) minFound = nWt;
          return;
        }
        let arr = map.get(nSyn);
        if (!arr) { arr = []; map.set(nSyn, arr); }
        arr.push({ maxQ: q, vec: nVec, wt: nWt });
        if (remW > 1 && q + 1 < n) {
          genLeft(q + 1, remW - 1, nSyn, nVec, nWt);
          if (minFound < claimedD) return;
        }
      }
    }
  }
  if (wL >= 1) genLeft(0, wL, 0n, 0n, 0);
  if (minFound < claimedD) return { ok: false, reason: `found weight ${minFound} < ${claimedD} in left half` };

  function genRight(startQ, remW, minQ, curSyn, curVec, wt) {
    if (minFound < claimedD) return;
    for (let q = startQ; q < n; q++) {
      const base = 3 * q;
      for (let p = 0; p < 3; p++) {
        const idx = base + p;
        const nSyn = curSyn ^ opsSyn[idx];
        const nVec = curVec ^ opsVec[idx];
        const nWt = wt + 1;
        if (nWt > wL && nSyn === 0n && reduce(nVec) !== 0n) {
          if (nWt < minFound) minFound = nWt;
          return;
        }
        const bucket = map.get(nSyn);
        if (bucket) {
          for (let i = 0; i < bucket.length; i++) {
            const left = bucket[i];
            if (left.maxQ < minQ) {
              const totW = left.wt + nWt;
              if (totW < minFound && reduce(left.vec ^ nVec) !== 0n) {
                minFound = totW;
                return;
              }
            }
          }
        }
        if (remW > 1 && q + 1 < n) {
          genRight(q + 1, remW - 1, minQ, nSyn, nVec, nWt);
          if (minFound < claimedD) return;
        }
      }
    }
  }
  for (let firstQ = 0; firstQ < n && minFound >= claimedD; firstQ++) {
    const base = 3 * firstQ;
    for (let p = 0; p < 3 && minFound >= claimedD; p++) {
      const idx = base + p;
      const nSyn = opsSyn[idx], nVec = opsVec[idx];
      if (1 > wL && nSyn === 0n && reduce(nVec) !== 0n) { minFound = 1; break; }
      const bucket = map.get(nSyn);
      if (bucket) {
        for (let i = 0; i < bucket.length; i++) {
          const left = bucket[i];
          if (left.maxQ < firstQ && left.wt + 1 < minFound && reduce(left.vec ^ nVec) !== 0n) {
            minFound = left.wt + 1;
            break;
          }
        }
      }
      if (wR > 1 && firstQ + 1 < n && minFound >= claimedD) {
        genRight(firstQ + 1, wR - 1, firstQ, nSyn, nVec, 1);
      }
    }
  }
  return minFound >= claimedD
    ? { ok: true, n, k, d: claimedD, rank, minFound }
    : { ok: false, reason: `found weight ${minFound} < ${claimedD}`, minFound };
}

const isMain = process.argv[1] && path.resolve(process.argv[1]) === path.resolve(new URL(import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, '$1'));
if (isMain) {
  const files = fs.readdirSync(DIR).filter((f) => /^QECC_\d+_\d+_\d+\.json$/.test(f)).sort();
  if (files.length === 0) throw new Error('No QECC_*.json files found in ' + DIR);

  // 4 negative controls
  const sample = parseCode(JSON.parse(fs.readFileSync(path.join(DIR, files[0]), 'utf8')));
  const ncBit = { ...sample, rows: sample.rows.slice() };
  ncBit.rows[0] ^= 1n;
  if (verifyIndependentAnyQECC(ncBit).ok) throw new Error('NC1 (bit-flip) unexpectedly passed');

  const ncDrop = { ...sample, rows: sample.rows.slice(1) };
  if (verifyIndependentAnyQECC(ncDrop).ok) throw new Error('NC2 (dropped row) unexpectedly passed');

  const toVec5 = (s) => {
    let v = 0n;
    for (let i = 0; i < 5; i++) {
      if (s[i] === 'X' || s[i] === 'Y') v |= 1n << BigInt(i);
      if (s[i] === 'Z' || s[i] === 'Y') v |= 1n << BigInt(5 + i);
    }
    return v;
  };
  if (verifyIndependentAnyQECC({ n: 5, claimedK: 1, claimedD: 5, rows: ['XZZXI', 'IXZZX', 'XIXZZ', 'ZXIXZ'].map(toVec5) }).ok) {
    throw new Error('NC3 ([[5,1,3]] claimed d=5) unexpectedly passed');
  }
  const trivRows = Array.from({ length: 36 }, (_, i) => 1n << BigInt(75 + i));
  if (verifyIndependentAnyQECC({ n: 75, claimedK: 39, claimedD: 8, rows: trivRows }).ok) {
    throw new Error('NC4 (trivial d=1 claimed d=8) unexpectedly passed');
  }
  console.log('[PASS] Negative controls 4/4 rejected cleanly (bit-flip, row-drop, [[5,1,3]]@d=5, d=1@d=8)');

  let passed = 0, failed = 0;
  const t0 = performance.now();
  const nonDomPool = [];
  for (const f of files) {
    const j = JSON.parse(fs.readFileSync(path.join(DIR, f), 'utf8'));
    const m = f.match(/^QECC_(\d+)_(\d+)_(\d+)\.json$/);
    if (!m || +m[1] !== j.n || +m[2] !== j.k || +m[3] !== j.d) {
      failed++;
      console.error(`[FAIL] Filename mismatch on ${f}`);
      continue;
    }
    const st = performance.now();
    const res = verifyIndependentAnyQECC(parseCode(j));
    const ms = (performance.now() - st).toFixed(0);
    if (res.ok) {
      passed++;
      nonDomPool.push({ file: f, n: j.n, k: j.k, d: j.d });
      console.log(`[PASS] ${f} (k=${res.k}, r=${res.rank}, d>=${res.d}) in ${ms}ms`);
    } else {
      failed++;
      console.error(`[FAIL] ${f}: ${res.reason}`);
    }
  }
  const nonDom = nonDomPool.filter(
    (x) => !nonDomPool.some((o) => o !== x && o.n <= x.n && o.k >= x.k && o.d >= x.d)
  );
  console.log(`\nFULL ZERO-SRC QECC AUDIT COMPLETE in ${((performance.now() - t0) / 1000).toFixed(1)}s: PASS=${passed}/${files.length}, FAIL=${failed}, NON_DOMINATED=${nonDom.length}`);
  if (failed > 0 || passed !== files.length) process.exit(1);
}
