# Security policy

## This is a reference implementation, not a certified antivirus

AEGIS is an original, educational/reference malware-detection engine. It is **not**
a certified or warranted security product, and detection is **provably imperfect**
(Cohen 1987 — perfect detection is undecidable). Do not rely on it as your only
defense on a production or high-risk system. It shapes and bounds error; it does
not eliminate it.

## Handling real malware samples safely

If you train or test with real malware (e.g. from MalwareBazaar / abuse.ch,
VirusShare, theZoo):

- Work only inside an **isolated VM** with no network and no shared folders you
  care about.
- AEGIS **reads bytes; it never executes a sample.** The Stage-3 dynamic sandbox
  runs only *Python* samples under an audit hook, and only when you pass
  `--dynamic`. It does not detonate native binaries.
- Keep real malicious samples in your corpus's `malicious/` folder and never
  commit them to a repository.

## Reporting a vulnerability

Open a private security advisory on the repository, or email the maintainer.
Please do not file public issues for exploitable defects until a fix is available.
