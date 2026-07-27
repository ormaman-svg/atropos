# Atropos

Agent attack-path analysis. Path math and choke-point remediation for the AI
agent fabric.

Agentless, metadata-only, SaaS. We map the graph from untrusted input source →
agent → MCP server → tool → identity (human and NHI) → data store, find which
agents can reach crown-jewel data and in how many hops, and identify the single
fix that collapses the most paths.

Atropos is the Fate who cuts the thread. Her sisters spin it and measure it;
she holds the shears. That is the product — not another inventory of what
exists, but the one cut that collapses the most paths.

## Where things stand

| | |
|---|---|
| Name | Atropos — decided. Domain acquisition and trademark opinion outstanding. |
| Build order | Remediation moves ahead of UI (position 2–3) |
| `observed` edge property | In the v1 schema |
| First 10 discovery calls | 5 CISO / 5 AI platform lead, same script |

See `docs/00-name-and-thesis.md` for the naming analysis and the adversarial
pass on the thesis — weakest assumption, the platform-vendor scenario, agentless
vs. runtime signal, an adjacent wedge, and the kill criterion.

`design/rigel-console.html` is the design reference. It carries the working name
from before the rename; it is kept verbatim as the source of truth for the
tokens the port must match.

## Non-negotiables

1. **Agentless.** Read-only connectors only. No sensor, no deployment. Time to
   first path: 15 minutes.
2. **Metadata only.** We read that a secret exists and what it grants. We never
   pull its value.
3. **SaaS only.** Per-tenant isolation from commit one.
4. **The LLM never holds credentials.** The model reasons and proposes; a
   deterministic executor with a fixed action set applies. Nothing runs that the
   audit log cannot reverse. Our own agent is the most constrained agent in the
   customer's environment.
5. Every finding maps to MITRE ATLAS + OWASP Agentic Top 10 IDs.
