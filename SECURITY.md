# Security policy

Report security issues privately. Do not open a public issue, pull request,
or discussion for a vulnerability.

## Reporting

- Use GitHub's private vulnerability reporting on this repository
  ("Report a vulnerability" under the Security tab), or
- email hello@dytallix.com.

Include a description, the affected component, reproduction steps or a proof
of concept when you have one, your severity assessment, and whether you want
public credit after disclosure. We aim to acknowledge new reports within 3
business days.

## Scope

the open-source local app in this repository (dashboard, local API,
scanners, installers, datastore), the hosted QuantumSentinel scan at
dytallix.com and its network connector, and anything that could make a scan
reach beyond its authorized scope, expose another user's results, or leak
submitted content.

Design flaws count. If the architecture or security model described in this
repository is wrong in a way that weakens protection, report it privately
the same way.

Out of scope: purely theoretical issues with no practical exploit path,
issues that need physical access to a device, and denial of service by
volume.

## Disclosure

We follow coordinated disclosure: give us a reasonable window to investigate
and fix before publishing, and we will credit you if you want credit.
