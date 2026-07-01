# Shared phase definitions for the 12-phase Swarm pipeline
# Sourced by pipeline.sh and todo-export.sh

PHASES=(
  "0:orchestrator:Orchestrator — scope setup, AI autopilot, interactive init"
  "1:scope:Scope registration — register target, scaffold engagement"
  "2:auth:Auth & WAF detection — get credentials, identify WAF"
  "3:intel:Passive intel — WHOIS, cloud, spoof, cloud enum"
  "4:recon:Reconnaissance — subdomains, crawl, params, secrets, cloud"
  "5:surface:Surface analysis — classify endpoints, prioritize attack surface"
  "6:hunt:Vulnerability hunting — test all bug classes"
  "7:deepthink:Deep analysis — (conditional) gap analysis when hunt yields zero"
  "8:exploit:Exploitation — deepen findings, chain, escalate impact"
  "9:search:Research — (conditional) payload/CVE research when exploit stalls"
  "10:capture:Evidence capture — screenshots, redaction, evidence hygiene"
  "11:validate:Validation — re-validate PoCs, 7-Question Gate"
  "12:report:Report — coverage check, generate final report"
)
