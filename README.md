# VeilCheck

**Local-first repository hygiene scanner.** VeilCheck looks for a small set of risky coding patterns and accidental secret-like strings in a directory, then produces a readable report without sending files anywhere.

> VeilCheck is a heuristic review aid, not a vulnerability scanner or proof that a project is secure.

## Why it exists

Security reviews often start with small clues: a disabled TLS check, debug mode left on, a credential-like assignment, or a private key accidentally committed. VeilCheck groups these clues into a compact local report and redacts matched values by default.

## Design boundaries

- Reads files from a directory you choose.
- Makes no network requests.
- Does not execute scanned code.
- Skips common generated/dependency folders and symlinks.
- Caps file size and reports only relative paths and line numbers.
- Redacts secret-like values in findings.
- Uses only Python's standard library.

## Run

Requires Python 3.10+.

```bash
python veilcheck.py ./your-project
python veilcheck.py ./your-project --json veilcheck-report.json
python veilcheck.py ./your-project --include-hidden
```

Run the included tests:

```bash
python -m unittest discover -s tests -v
```

## Example findings

- `TLS_VERIFY_DISABLED`: a request appears to disable TLS certificate verification.
- `DEBUG_ENABLED`: a common debug flag appears to be enabled.
- `HARDCODED_SECRET_LIKE`: a credential-like assignment may be present.
- `PRIVATE_KEY_BLOCK`: a private-key PEM marker was found.

These checks can produce false positives and can miss real problems. Review the surrounding code and rotate any real credential that has been exposed.

## Project status

VeilCheck is an original small educational utility assembled for defensive code review. Its rules are intentionally transparent and easy to extend. It does not claim to replace tools such as dedicated secret scanners, linters, or professional security review.

## License

MIT. See [LICENSE](LICENSE).
