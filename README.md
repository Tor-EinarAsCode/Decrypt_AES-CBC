The code is not finished.

Part 1 – Enrich
Create a script/program to enrich the IPs from the events contained in the attachment. Use at least 2
different sources.
Suggestions:
• Whois (python-whois)
• Geo location (abstractapi.com)
• Threat Intelligence (VirusTotal, DShield, AbuseIPDB etc.)
The output should be machine readable since it needs to be parsed by a detection engine.

Part 2 - Detect
Based off the enriched information, create at least one detection rule. You may also assume that you
have access to more collected data than the enriched data from Part 1.
Examples: "Once we have seen 100 HTTP request with status 404 within 5 minutes we trigger an
alert", "If enrich source X reports a malicious verdict, trigger an alert"
Provide (approximate) queries in SPL, SIGMA or KQL format.

Part 3 - Respond
Write an alert description for at least one
detection rule, which should include at a minimum the following:
• Alert name
• Severity
• Triage steps
• MITRE tactics or/and techniques, e.g. "Reconnaissance"
Alert name: HTTP Errors Have Exceeded over 100 The Last 5 Minutes
Severity: Medium

