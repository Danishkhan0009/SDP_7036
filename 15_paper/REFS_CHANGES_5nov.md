# refs.bib changes — 5 Nov 2026

Source: `docs/references/references_audit_2026-11-05.md`. Numbers [1]-[32] unchanged, so existing `\cite{}` keys still work except [29] (key renamed).

## Changed entries
| Ref | Change |
|---|---|
| [29] | SP 800-108r1 was withdrawn on 2 Feb 2024. Now SP 800-108r1-upd1, doi 10.6028/NIST.SP.800-108r1-upd1. **Key renamed `sp800108r1` -> `sp800108r1upd1`: update the `\cite`.** |
| [22] | Title now "Intel Multi-Key Total Memory Encryption Specification" (rev 1.7, Doc 336907-007US), URL added. |
| [18] | IEEE 1801-2024: year 2025 (approved Sep 2024, published 4 Mar 2025). |
| [31] | OpenTitan cited as the versioned Earl Grey 1.0.0 spec, not the moving "latest" page. |
| [23] | DOI added (10.1145/2976749.2978372). |
| [21] | Marked CWE 5.0. |
| [17] | IEEE 1619-2018 -> **IEEE 1619-2025** (supersedes 2018, published 27 Jun 2025). NIST's draft SP 800-38E Rev. 1 (3 Sep 2026) now references 1619-2025 and adds data-unit and key-scope limits: check the design meets them. |

## Added entries ([33]-[37], TVLSI only)
On Borrowed Time (NDSS 2025), Chypnosis (S&P 2026), Chypothermia (arXiv), Assertain (arXiv), ATLAS (DAC 2026).
Entries marked `% NOTE:` still need first names / pages from the papers.

## Already correct in the 2 Nov file (the audit flagged them from incomplete notes)
- [20] Kumar: first author Raghavan Kumar, 2024, DOI 10.1109/JSSC.2023.3305188 were already there.
- [7] DAE: full title was already there.
- [10] full title "Protection Against Physical Attacks Through Self-Destructive Polymorphic Latch" was already there.
- [11] SuperVAULT: 2021 DOI is the early-access date; print issue 14(2), Jun 2022 is correct.
- [13] ASCON/JasperGold: **keep it.** It is real (DOI read from your PDF R13); it just isn't indexed online. Weak venue, so cut it first if you are over the page limit.

## Not in refs.bib on purpose
Patents (NXP US11689363, EP4386594, Apple, Intel, Qualcomm, Altera, ...) stay out of the journal list (decided 2 Nov). Mention them in related work only if a reviewer asks.

## Wording fixes for the paper text (not bib)
1. Volt Boot [3]: motivation only ("held rails keep secrets"); the interlock does not stop a physical rail hold. Call RB1 "Volt-Boot-inspired" and list rail holding as out of scope.
2. Warm-boot [1]: externally powered DIMM attack; it motivates encrypting DRAM, not key erase.
3. BadRAM [14]: remove "replays past address-bound MAC". AMD's fix is a firmware alias check; SPD locking is only recommended.
4. TME-MK [22]: "at least 29-bit SHA-3 based integrity", no ECC mention (not "28-bit MAC in ECC").
5. On Borrowed Time [33]: credit that it already suggests clearing before power gating; our addition is the enforced interlock and the proof.
6. Hypnoguard [23]: "software scheme anchored in TPM and TXT".
7. CWE-1272 gap: ATLAS covers CWE-1239 and Assertain CWE-226. Claim only "no checker ties the clear to the power-isolation transition under an unconstrained power manager", and say the isolation-boundary reading of CWE-1272 is ours.
8. Battering RAM [15]: shown on DDR4; do not claim DDR5 immunity.
