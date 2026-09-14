# Recorded responses

Responses the live adapters are tested against. The test suite never opens a socket;
these files are served through an in-memory HTTP transport.

- `src/alert_forensics/fixtures/attack/enterprise-attack.excerpt.json` (shipped in the
  package, since the live adapter falls back to it offline): cut from the real public bundle
  `enterprise-attack.json` (Enterprise ATT&CK 19.2, collection modified
  2026-08-05T21:33:58.496Z, full bundle sha256
  `dc1639caa5501d720e280cf1cbd8fbe009884a0c9b3e6e9ed9d0c25166c3d8f4`) on 2026-09-14.
  It keeps the collection object without its contents list, sixteen `attack-pattern`
  objects verbatim, and the one `revoked-by` relationship between two of them: fourteen
  for the techniques the eight scenarios declare, `T1027.010` among them since scenario
  4 declares it, and two, `T1556.006` and `T1564.008`, for the follow-on techniques
  scenario 2's investigation resolves. The three later additions were cut from the same
  bundle, verified by its sha256, on the same day.
- `virustotal/*.json`: written by hand to the documented VirusTotal v3 shapes, not
  captured from the API. Every indicator is from documentation ranges (TEST-NET-3,
  `example` names) and every hash is synthetic. A recording from the real API needs an
  API key; replace these files with a capture when one is available, the adapter test
  does not care which.
