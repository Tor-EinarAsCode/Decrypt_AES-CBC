The code is not finished.

Part 1 – Enrich
Create a script/program to enrich the IPs from the events contained in the attachment. Use at least 2
different sources (depending on the source it might require you to create an account). Suggestions:
• Whois (python-whois)
• Geo location (abstractapi.com)
• Threat Intelligence (VirusTotal, DShield, AbuseIPDB etc.)
The output should be machine readable since it needs to be parsed by a detection engine. Note that
if you are not able to finish on time, you can add comments in the code where there are functions yet
to be implemented, preferably with descriptions or pseudo-code displaying your intent for the
functionality.

Part 2 - Detect
Based off the enriched information, create at least one detection rule. You may also assume that you
have access to more collected data than the enriched data from Part 1, if needed. (If you use this
assumed data, please specify.)
Examples: "Once we have seen 100 HTTP request with status 404 within 5 minutes we trigger an
alert", "If enrich source X reports a malicious verdict, trigger an alert"
Optional: Provide (approximate) queries in SPL, SIGMA or KQL format.

Part 3 - Respond
Once the analyst is presented with a triggered alert and enriched information, he/she needs to be
able to understand the steps on how to triage the alert. Write an alert description for at least one
detection rule, which should include at a minimum the following:
• Alert name
• Severity
• Triage steps
• MITRE tactics or/and techniques, e.g. "Reconnaissance"
Alert name: HTTP Errors Have Exceeded over 100 The Last 5 Minutes
Severity: Medium

