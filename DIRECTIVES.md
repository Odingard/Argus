# ARGUS Engineering Directives

These are the standing engineering directives for the ARGUS platform. Every
design decision, every commit, every architectural choice is evaluated against
these directives. They are not goals — they are constraints.

---

## Directive 1 — Universal Point-and-Shoot

**ARGUS infrastructure is engineered for universal fit, not per-target hacks.**

When a capability is needed for one target type, it is built as platform
infrastructure that any current or future target type can consume — not as a
patch in the adapter that needs it today. The test for whether a piece of code
satisfies this directive is:

> Could a future target adapter (Langchain, Agno, AutoGPT, a not-yet-invented
> agentic framework, a future MCP variant) consume this capability without
> modification to the capability itself?

If the answer is no, the design is wrong, regardless of whether it works for
today's target.

**Concrete consequences:**

- LLM-call resilience lives in shared infrastructure consumed by all adapters,
  not bolted into one adapter.
- Detection logic lives in shared infrastructure consumed by all agent types,
  not duplicated across agents.
- Reporting, output, schema, and result-shape decisions are made once and
  enforced platform-wide.
- "We'll split this later" is not an acceptable answer in production design.
  Things postponed in production codebases become permanent.

---

## Directive 2 — ARGUS is the Platform; the Engagement is the Product

**ARGUS is OdinGard's red team engagement tool. It is not customer-installed
software.**

ARGUS is a platform application that OdinGard owns and operates. Customers
purchase **engagements** — OdinGard runs ARGUS against the customer's
environment and delivers the findings. The codebase is internal-facing,
operated by OdinGard's red team operators (today: Andre).

ARGUS is not:

- A SaaS product customers install and self-operate.
- A demo platform for content marketing.
- A scaffold extended per-engagement with throwaway code.
- An open-source tool optimized for community contribution.

ARGUS is:

- The first autonomous AI red team platform purpose-built for Agentic AI,
  MCP, and the surrounding ecosystem.
- The toolchain behind OdinGard's red team engagement service.
- A platform whose findings appear in customer-facing reports.
- A platform whose findings, if wrong, damage OdinGard's reputation directly.
- A platform whose support burden is OdinGard's own engineering team's,
  forever.

**Reference category:** internal toolchains used by red team service firms
(Mandiant's internal kit, Trail of Bits' tooling, NCC Group's frameworks).
Comparable in *capability* to Pentera, Shannon AI, Horizon3 — but operated
as a service, not sold as a SKU.

**Customer-consumable productization is a future possibility.** When and if
ARGUS is offered as a product customers install, the directives may evolve.
Until then, optimize for OdinGard operator experience and engagement quality,
not hypothetical future SaaS deployment.

**Concrete consequences:**

- The operator persona is a red team engineer (Andre, future hires) — not an
  enterprise IT admin or a non-technical security manager. Design for the
  operator persona, not the customer persona. CLI-driven, env-var-configured,
  power-tool-shaped is correct.
- Output quality matters more than output friendliness. Findings appear in
  customer reports authored by OdinGard. The customer never sees ARGUS's raw
  output; an operator translates it. Optimize for analyst utility.
- Every finding ARGUS produces is one a customer can hand to a vendor's VDP
  triager and have validated. Findings that don't survive a triager are
  reputation damage to OdinGard. Quality is the bar.
- Module structure, naming, and architectural boundaries are designed for
  the engineering team that will operate this code in five years. Not for
  hypothetical customer review.
- Code that is good for the engagement workflow beats code that is good for
  hypothetical productization. When the two conflict, the engagement wins.

---

## How these directives interact

Directive 1 is HOW we build. Directive 2 is WHAT we are building.

Together: ARGUS is OdinGard's internal red team platform engineered for
universal fit. Every piece of infrastructure is designed to serve every
present and future target type that comes through OdinGard's engagement
pipeline. Every operator-facing surface is designed for OdinGard's red team
engineers. Customer-facing surfaces (reports, deliverables) are produced
*from* ARGUS by operators, not *by* ARGUS directly.

When the two directives conflict in a given decision (rare, but possible),
Directive 2 wins. We are building OdinGard's engagement toolchain, not
optimizing for engineering elegance or hypothetical SaaS futures.

---

*This document is canonical. When in doubt during design review, point at
this file. If a proposed design doesn't satisfy both directives, the design
needs revision before code is written.*

*Established: 2026-04-27 · OdinGard Security · Six Sense Enterprise Services*
*Revised: 2026-04-27 (Directive 2 corrected — engagement tool, not customer SaaS)*

---

## Directive 3 — UI is on the Roadmap

**ARGUS will have a UI. Visual representation matters.** Findings, attack
chains, agent slates, engagement timelines, blast radius — all of these are
fundamentally visual problems. A red team operator running an engagement
needs to *see* what happened, not parse stdout. A future hire onboarding to
operate ARGUS needs a visual model of the platform's state, not a 600-line
mental model of stdout patterns.

The UI is not built tonight, and not next week. The UI is built when the
core platform is stable and the engagement workflow is proven. But every
backend decision made between now and then is evaluated against:

> Will this design still make sense when there is a UI sitting on top of it?

**Concrete consequences:**

- **Output is structured first, formatted second.** Every result ARGUS
  produces — findings, evidence, chains, agent telemetry — is emitted as
  structured data (JSON, well-typed dataclasses). Text rendering is a
  presentation layer over the structured data, not the data itself. The
  UI consumes the same structured data the CLI does.
- **State is queryable.** Engagement state, finding state, agent state —
  anything the UI will eventually want to display — is stored in a form
  that can be queried, not just streamed to a log file. JSON files in an
  output directory are acceptable today; a SQLite database is acceptable
  tomorrow; the structure of the data is what matters.
- **Operations are addressable.** Every action ARGUS takes (start engagement,
  fire probe, evaluate finding, generate report) is invokable from a
  function call with explicit parameters, not buried in a CLI handler.
  The UI eventually wires buttons to those functions.
- **No CLI-stdout-only features.** If a feature only works by reading
  stdout, a UI cannot show it. Every operator-visible piece of information
  must exist in structured form somewhere ARGUS can read it back.

**What this directive does NOT mean:**

- It does not mean we build the UI tonight.
- It does not mean we build a web framework, API surface, or frontend
  scaffolding tonight.
- It does not mean the CLI is deprecated. The CLI remains the primary
  operator interface for the engagement-tool phase.
- It does not mean every commit must justify itself against the UI.

It means: when a design choice between "stdout only" and "structured data
+ stdout rendering" comes up, choose the latter. The cost is small today
and the cost of retrofitting it later is enormous.

