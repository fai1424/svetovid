# Svetovid

**An agentic DFIR desktop app that autonomously investigates digital evidence.** Point it at a folder of forensic artifacts, pick an investigation goal, and an AI agent selects the right tools, runs them sandboxed, correlates findings, maps them to MITRE ATT&CK, and writes the report — in minutes, not hours.

**Who uses it:** IR consultants, internal SOC/DFIR teams, law enforcement, and researchers who need to investigate security incidents across Windows, Linux, macOS, memory, network, cloud, mobile, and container evidence at a scale no human team could cover alone.

**Problem solved:** DFIR investigations require chaining 9+ incompatible CLI tools (Chainsaw, Volatility, YARA, Sleuth Kit…), each with its own flags and output format. A single Windows compromise takes 4+ hours of expert time, mostly parsing and report-writing. With 500 potentially compromised endpoints, there simply aren't enough senior analysts — evidence goes unexamined. Svetovid automates the mechanical work (tool selection, execution, correlation, reporting) so one operator runs dozens of investigations in parallel, reviewing findings instead of doing raw parsing. Cost drops from $1,600–6,400 per engagement to ~$0.50 in API tokens. Runs fully on-premise with Ollama (zero data egress).

**Stage:** MVP. 22 goals, 22 tool wrappers, 4 Docker images, native desktop app, 38 tests — all working end-to-end. Gaps: sidecar packaging, code signing, integration tests against live cloud APIs.

**Impact:** 3–10× analyst throughput. 30–50% report-writing time eliminated. Open-source stack replaces $4K–15K/yr commercial licenses for 80% of cases.
