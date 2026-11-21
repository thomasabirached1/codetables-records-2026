# New Explicit Binary Linear & Qubit Stabilizer Codes Beating `codetables.de` Bounds

This repository provides **86 non-dominated explicit record-breaking error-correcting codes** (verified on `2026-11-21T23:34:14.712Z` against live `codetables.de` bounds and 2024–November 2026 preprints), together with **zero-dependency standalone Node.js exact verifiers**.

## Summary

- **Classical Binary Linear Codes ($\text{GF}(2)$, `gf2/`):** **14 non-dominated** explicit $[n, k, d]_2$ codes (covering 4 records improving the live `codetables.de` lower bound by **+2** and 10 by **+1**), constructed via 1-generator quasi-cyclic base codes with periodic-tail extensions. Highlights include `[172, 20, 67]_2` (strictly beating the live `codetables.de` / LinCodeEvolve bound of `66`), `[215, 19, 88]_2`, `[216, 20, 88]_2`, `[213, 22, 82]_2`, and `[216, 22, 84]_2`.
- **Quantum Stabilizer Codes (Qubits, `qecc/`):** **72 non-dominated** explicit $[[n, k, d]]_2$ stabilizer codes across distances `d = 5..8` (`d=5`: 48, `d=6`: 6, `d=7`: 13, `d=8`: 5), including **10 tight small-block ($n \le 100$) breakthroughs** (`[[23, 9, 5]]_2`, `[[77, 47, 7]]_2`, `[[83, 52, 7]]_2`, `[[99, 67, 7]]_2`, `[[100, 68, 7]]_2`, `[[74, 39, 8]]_2`, `[[75, 40, 8]]_2`, `[[76, 41, 8]]_2`, `[[77, 42, 8]]_2`, `[[81, 45, 8]]_2`).
- **Full Parameter Table:** See [codes_summary.csv](codes_summary.csv).

## Standalone Independent Verification

Requires only **Node.js (>= 18)** with zero third-party packages:

```bash
# Exhaustively verifies rank === k and all 2^k - 1 codewords via Gray code + A_d match (+ 4 negative controls)
node verify_gf2.mjs

# Exhaustively verifies symplectic commutation, rank, and exact MITM minimum distance W = d - 1 (+ 4 negative controls)
node verify_qecc.mjs
```

---

## Classical GF(2) Non-Dominated Records (14)

| Code | Live LB | Live UB | Gain | Exact `A_d` | Certificate |
| :--- | :---: | :---: | :---: | :---: | :--- |
| `[171, 21, 65]_2` | 64 | 73 | **+1** | 2040 | [gf2/GF2_171_21_65.json](gf2/GF2_171_21_65.json) |
| `[172, 20, 67]_2` | 66 | 74 | **+1** | 272 | [gf2/GF2_172_20_67.json](gf2/GF2_172_20_67.json) |
| `[212, 22, 81]_2` | 80 | 92 | **+1** | 945 | [gf2/GF2_212_22_81.json](gf2/GF2_212_22_81.json) |
| `[213, 22, 82]_2` | 80 | 93 | **+2** | 2310 | [gf2/GF2_213_22_82.json](gf2/GF2_213_22_82.json) |
| `[215, 22, 83]_2` | 82 | 94 | **+1** | 1540 | [gf2/GF2_215_22_83.json](gf2/GF2_215_22_83.json) |
| `[216, 22, 84]_2` | 82 | 94 | **+2** | 4935 | [gf2/GF2_216_22_84.json](gf2/GF2_216_22_84.json) |
| `[212, 19, 85]_2` | 84 | 94 | **+1** | 422 | [gf2/GF2_212_19_85.json](gf2/GF2_212_19_85.json) |
| `[213, 20, 85]_2` | 84 | 94 | **+1** | 822 | [gf2/GF2_213_20_85.json](gf2/GF2_213_20_85.json) |
| `[213, 19, 86]_2` | 85 | 95 | **+1** | 1158 | [gf2/GF2_213_19_86.json](gf2/GF2_213_19_86.json) |
| `[214, 20, 86]_2` | 85 | 95 | **+1** | 1938 | [gf2/GF2_214_20_86.json](gf2/GF2_214_20_86.json) |
| `[214, 19, 87]_2` | 86 | 96 | **+1** | 2608 | [gf2/GF2_214_19_87.json](gf2/GF2_214_19_87.json) |
| `[215, 20, 87]_2` | 86 | 96 | **+1** | 4588 | [gf2/GF2_215_20_87.json](gf2/GF2_215_20_87.json) |
| `[215, 19, 88]_2` | 86 | 96 | **+2** | 6515 | [gf2/GF2_215_19_88.json](gf2/GF2_215_19_88.json) |
| `[216, 20, 88]_2` | 86 | 96 | **+2** | 11355 | [gf2/GF2_216_20_88.json](gf2/GF2_216_20_88.json) |

## Small-Block ($n \le 100$) Quantum Stabilizer Non-Dominated Records (10 of 72)

| Code | Live LB | Live UB | Gain | Certificate |
| :--- | :---: | :---: | :---: | :--- |
| `[[23, 9, 5]]_2` | 4 | 6 | **+1** | [qecc/QECC_23_9_5.json](qecc/QECC_23_9_5.json) |
| `[[77, 47, 7]]_2` | 6 | 10 | **+1** | [qecc/QECC_77_47_7.json](qecc/QECC_77_47_7.json) |
| `[[83, 52, 7]]_2` | 6 | 10 | **+1** | [qecc/QECC_83_52_7.json](qecc/QECC_83_52_7.json) |
| `[[99, 67, 7]]_2` | 6 | 10 | **+1** | [qecc/QECC_99_67_7.json](qecc/QECC_99_67_7.json) |
| `[[100, 68, 7]]_2` | 6 | 10 | **+1** | [qecc/QECC_100_68_7.json](qecc/QECC_100_68_7.json) |
| `[[74, 39, 8]]_2` | 7 | 12 | **+1** | [qecc/QECC_74_39_8.json](qecc/QECC_74_39_8.json) |
| `[[75, 40, 8]]_2` | 7 | 12 | **+1** | [qecc/QECC_75_40_8.json](qecc/QECC_75_40_8.json) |
| `[[76, 41, 8]]_2` | 7 | 12 | **+1** | [qecc/QECC_76_41_8.json](qecc/QECC_76_41_8.json) |
| `[[77, 42, 8]]_2` | 7 | 12 | **+1** | [qecc/QECC_77_42_8.json](qecc/QECC_77_42_8.json) |
| `[[81, 45, 8]]_2` | 7 | 12 | **+1** | [qecc/QECC_81_45_8.json](qecc/QECC_81_45_8.json) |

*(See `qecc/` and [codes_summary.csv](codes_summary.csv) for all 72 non-dominated QECC certificates across `d = 5, 6, 7, 8`.)*

---

## Methods & Attribution

- **GF(2) Codes:** 1-generator quasi-cyclic codes extended by periodic quotient tails, certified via exhaustive Gray-code enumeration over all $2^k - 1$ nonzero codewords.
- **QECC Codes:**
  - `[[23, 9, 5]]_2`: discovered via two-stage Hermitian $\mathbb{F}_4$ + canonical symplectic simulated annealing;
  - The remaining 71 stabilizer codes ($n \in [74, 254],\; d \in \{5, 6, 7, 8\}$): constructed using **Marin Girard's expurgated random Clifford encoder construction** (*arXiv:2611.08744*, November 2026) at parameter pairs not covered in that note, with exact distance certified via exhaustive Meet-in-the-Middle enumeration up to weight `d - 1`.
- Search, independent verification scripts, and table auditing were orchestrated with AI coding/research agents and independently cross-checked on every explicit certificate.
