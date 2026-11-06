# QR Exposure Review

A local prototype for assessing publicly accessible crypto-related QR images on sites you are authorized to inspect. It crawls links and images on the starting URL's exact origin, searches page content for selected wallet strings, records unclassified QR codes for review, optionally honors robots.txt, and creates a downloadable JSON report containing classifications, exact detected values, observation times, and full page and image URLs. Results and reports can contain live secrets and sensitive URLs: handle and share them securely. Image data is not retained. Scan results are stored locally in `data/scans.sqlite3`, including exact secrets and URLs. The folder and database are created with owner-only permissions, but the database is not encrypted. Protect the host and backups.

## Run

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/python app.py
```

Open http://127.0.0.1:8765. Enter an authorized public URL and optionally set a page limit and crawl depth. Leave both blank for an unlimited crawl. Depth 0 checks only the starting page; each additional level follows another layer of links. Uncheck “Respect robots.txt” when assessing an authorized site whose rules would otherwise prevent the crawl. The results view defaults to possible secrets and private material; use the filter to see public addresses, payment links, unclassified QR codes, or everything. Export all findings or only the visible results. Export the results before stopping the server.

## Scope and limitations

- Checks static HTML links, same-origin `<script src>` resources and `<img src>` images, plus linked text, JSON, XML and JavaScript resources. It extracts text from linked PDFs using the `pdftotext` command. It does not execute JavaScript or inspect image discovery APIs, CSS backgrounds, images within PDFs, scanned PDF text (OCR), authenticated content, or external image hosts. When robots.txt is enabled, it must be available and successful; otherwise the scan stops. When disabled, the crawler does not request or enforce it. Optional page and depth limits can bound recursion; when blank, the crawler has no page or depth cap. Sites that generate endless URLs can run indefinitely and consume memory.
- Only public IPs are accepted; redirects must remain on the original scheme, host and port. DNS is checked before each request, but the HTTP client resolves again, so DNS rebinding is not fully prevented. Run only in a trusted network and do not expose the local service to untrusted users.
- Classification is heuristic, not wallet validation. Public addresses and payment URIs are informational; possible phrases and private keys need careful manual verification. A QR code or hash is not evidence of compromise or malicious activity. An exposed QR code is not necessarily an IOC.
- Locations include full URLs and query strings, which may contain secrets. Review and protect reports before sharing. The scan is not a substitute for a complete security assessment.
- No user accounts, global discovery, scheduling or concurrent-job limits are implemented. Session scan history, search, filters, JSON exports and a stop control are available; stopping waits for any in-progress request to return. The service is intended for a single trusted local operator; the database contains sensitive unencrypted evidence.

## Understanding results

Fetch errors count requests or image-processing operations that failed. The UI groups them into HTTP status, timeout, connection/DNS, redirects outside scope, response size, DNS, non-public addresses, and other errors. External and embedded images are recorded as skipped rather than failed; they are not scanned. They mean some content was not checked, not that an exposure was found. Check scope, accessibility, server logs and the 5 MB response limit, then rescan.

Page text detection covers recognizable payment URIs, common Bitcoin/Ethereum addresses, WIF-looking keys, and labeled possible hex keys or recovery phrases. Bitcoin address candidates must pass Base58Check or Bech32/Bech32m checksum and structural checks; Ethereum-style mixed-case addresses receive an EIP-55 checksum check; all-lowercase or all-uppercase addresses are labeled unchecksummed. These cannot identify which EVM network is involved. Neither proves ownership, compromise, or whether a QR is unused. Results may be false positives and incomplete; some wallet formats and JavaScript-rendered content are not covered. Unclassified QR findings indicate a readable QR code, not necessarily a crypto code. Findings show the page and, for QR findings, image location. The exact detected value and full URLs, including query strings, are included and may be highly sensitive.

The dashboard can search findings by value, URL, type or source, filter by finding category, revisit scans in the current server session, and export all or only visible results. Scan history and findings persist in the local database. A scan interrupted by a server restart is marked interrupted; its findings survive, but its crawl frontier cannot yet resume automatically.

## Secret detection

The scanner checks recognizable AWS access key IDs, GitHub, GitLab and Slack token formats, Google API keys, Stripe live keys, OpenAI-style keys, bearer tokens, PEM private-key blocks, labeled API keys, passwords, client secrets, and access/auth tokens, including some unquoted environment-style assignments. It also checks selected cryptocurrency strings and QR payloads. This is heuristic coverage, not a comprehensive secrets scanner: formats, some unquoted credentials, dynamically loaded resources and other content may be missed; example values and false positives may be reported. AWS access key IDs alone are identifiers and do not establish usable credentials. The tool does not validate, use, or transmit discovered credentials to their providers. Verify privately, rotate confirmed credentials, remove the exposure, and investigate access.

## Assessment coverage

The dashboard and JSON report include counts for HTML, text/JavaScript, extracted PDFs, unsupported content, robots exclusions, PDF extraction errors, and fetch errors. A page-limited scan is marked `limited`. PDF extraction requires `pdftotext` (Poppler); image-only PDFs require OCR and are not inspected for image text or QR codes. This tool is a prototype, not a comprehensive production assurance system. It does not enumerate client domains, search the open web, execute JavaScript, authenticate, scan repositories/cloud storage, validate credentials, or provide completeness guarantees. Use additional authorized sources and independent tools, record scope and limitations, and manually review findings before issuing client assurances.

## Deduplication and validation

Identical findings of the same type and value are grouped within a scan, with distinct source locations retained. AWS access-key IDs are identifiers, not proof of usable credentials. If an AWS secret candidate occurs in the same resource, the UI flags the proximity without claiming it is the matching pair.

The validation panel provides offline format checks for AWS IDs, Ethereum-style addresses, hexadecimal secp256k1 candidates Bitcoin WIF, and Azure Storage key candidate Base64 length. These checks do not prove ownership, funds, or live validity. The explicit AWS test calls STS GetCallerIdentity using the supplied access ID and secret, plus a session token for temporary credentials. It requires the AWS CLI and network access; it does not use the operator's AWS profiles. Provider rejections, lack of connectivity and missing context must not be interpreted as proof of safety. Live tests can be logged by the provider. Azure Storage account keys can be checked with an explicit, read-only signed Blob service-properties request. Other Azure credential types and other provider live tests are not implemented.

Findings and URLs are persisted in plaintext at rest. The local permissions protect against other OS users but not the same user, administrators, malware, or backups. Review access and retention for client evidence. To remove saved history, stop the application and securely manage or delete `data/scans.sqlite3` according to your retention policy.

GitHub prefix matches are unverified candidates, including possible examples and placeholders. The explicit GitHub test sends the selected token to GitHub’s authenticated-user endpoint. A successful response confirms that endpoint accepted the token at that time; errors and installation-token results may be inconclusive. The scanner recognizes the new dotted GitHub installation token structure without truncating it, but token formats may change. Historical saved findings are not reclassified by rule changes; run a new scan.

## Azure discovery and balance checks

The scanner flags Azure Storage, Key Vault, Azure OpenAI and Azure Websites URLs referenced by scanned text. A reference does not prove a resource is public or accessible, and referenced external domains are not automatically crawled. The Azure Storage live test requires the account name and its matching Shared Key, contacts only that account’s standard public Azure Blob endpoint, and requests service properties. A successful response confirms the pair worked for that request at that time. Rejection or network failure is inconclusive. The account and key are not saved as part of the validation result. Other Azure services and sovereign/private endpoints are not supported by this test.

The Ethereum mainnet balance check requires a public Ethereum-style address and an HTTPS public RPC URL supplied by the operator. The RPC provider receives the address; RPC URLs may include private API credentials, so protect them. The tool verifies that the provider reports chain ID 1 and obtains the native ETH balance at a recorded block. It does not verify provider honesty, prove ownership, derive addresses from private keys, or check ERC-20 tokens, NFTs, Bitcoin, other networks, future deposits, approvals, or historical activity. A zero ETH balance does not make an exposed secret safe. Validation results are not saved automatically.
# Secrets-web-crawler
