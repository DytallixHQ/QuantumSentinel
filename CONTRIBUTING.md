# Contributing to QuantumSentinel

QuantumSentinel's local app is open source under the [MIT license](LICENSE).
Code, documentation, detection-rule, and installer contributions are welcome.

## Good places to start

- **False positives and missed findings.** Open an issue with the asset type,
  what you expected the scan to find, and what it found.
- **Detection rules.** Propose new patterns with examples and the reason they
  matter for post-quantum migration.
- **Issues labeled** `good first issue`, `documentation`, `installer`, or
  `ux-polish`.
- **Product questions and roadmap ideas.** Use Discussions.

## Pull requests

1. Fork the repository and create a branch.
2. Run `npm ci`, `npm run lint`, `npm test`, and `npm run smoke` before you
   push.
3. Keep each pull request to one change, and describe what it changes and
   how you checked it.

Outside contributors sign off each commit under the
[Developer Certificate of Origin](https://developercertificate.org/)
(`git commit -s`). By contributing, you agree that your contribution is
licensed under the MIT license.

## Not here

- **Vulnerabilities.** Report them privately; see [SECURITY.md](SECURITY.md).
- **Sensitive data.** Do not post keys, credentials, customer data, scan
  results from systems you do not own, or internal network details.

## Conduct

The DytallixHQ [code of conduct](https://github.com/DytallixHQ/.github/blob/main/CODE_OF_CONDUCT.md)
applies to every space in this repository.
