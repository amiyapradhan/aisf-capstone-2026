# Agent Card — Vroomi AI Assistant (draft)

**System:** Vroomi AI Assistant · **Owner:** _unassigned — see Section 8_ · **Status:** draft for CISO review
**Purpose of this document:** to state, in one place, what Vroomi is *allowed* to do — and how autonomously —
so that autonomy is a governed decision rather than an emergent side-effect. Softmicro's premise is that
Vroomi should become *more agentic*; this card is the control that decides how agentic she may be.

An agent card sits alongside a model card (what the model is) and a system card (how the system is wired).
This one governs behaviour: goals, permissions, autonomy tiers, and stop conditions.

**Document set.** This card is the "safeguards to add first" behind Recommendations 1, 4 and 6 of
`AI_Security_Assessment_Report.md`. Threat references use that report's numbering, which matches the card
numbers in `threat-cards.md` (Threat *n* = Card *n*). `vroomi_gov_gate.py` is the runnable demonstrator; where
it does not yet enforce something in this document, Sections 2 and 8 say so.

---

## 1. Goals and scope

**Intended purpose.** Assist internal staff with ride logistics and policy questions: book and cancel rides,
retrieve trip history, and answer questions from approved internal policy.

**In scope.** The three defined backend actions and answering from *approved, non-sensitive* knowledge-base
content.

**Out of scope.** Any action or data access not explicitly listed here. Absence from this card means *not
permitted* — the card is an allow-list, not a suggestion.

---

## 2. Permitted actions — tool allow-list

Each tool has one entry. A tool not on this list cannot be invoked, and every invocation is validated
(schema + arguments + user intent) before it runs.

| Tool | Purpose | Arguments | Reversible? | Impact tier | Autonomy level | Enforced in demonstrator? |
|---|---|---|---|---|---|---|
| `get_trip_history` | Read the caller's trip history | none | n/a (read-only) | Low | **Autonomous** | Yes — plus an intent check (see Section 3 note) |
| `book_ride` | Create a new ride booking | `destination` (string) | Yes (cancellable) | Medium | **Suggest-and-confirm** | Partly — schema, args and intent enforced; the confirm step is the calling UI's |
| `cancel_ride` | Cancel an existing ride | `trip_id` (integer) | Effectively no | High | **Human approval required** | Yes — returns APPROVAL instead of executing, even when every other check passes |

Notes:
- `destination` must be a non-empty string; `trip_id` must be a valid integer matching an existing trip.
- Unknown tools, malformed calls, or arguments that fail validation are **refused, not guessed at**.
- The enforcement column is deliberately honest. A card that claims controls the code doesn't have is worse
  than no card, because it moves the gap out of sight — this column existed as a row of "No"s before the
  demonstrator caught up with the card.

---

## 3. Autonomy policy — how much Vroomi may decide alone

Actions are routed by impact tier (the automation tiers made explicit):

- **Autonomous (low impact, read-only).** Executes without confirmation. Only `get_trip_history`.
- **Suggest-and-confirm (medium impact, reversible).** Vroomi proposes the action and the user confirms
  before it runs. Applies to `book_ride`.
- **Human approval required (high impact / irreversible).** A person must explicitly approve before
  execution. Applies to `cancel_ride` and to any future money-moving or externally-visible action.
- **Prohibited (never).** See Section 6.

*Note on "autonomous".* Autonomous means no human confirmation, not unchecked. `get_trip_history` still
passes the allow-list, argument and intent checks — the demonstrator will refuse a history read the user
never asked for, because an unrequested read is still an injection signal (threat card 1).

The default for any *new* capability is the **most restrictive** tier until it has been assessed and this
card updated. Capability is added by decision, not by discovery.

---

## 4. Human-in-the-loop (HITL) points

A human is in the loop at these points:

1. **Before any irreversible action** (`cancel_ride`) — explicit approval, not implicit consent. This is the
   control that holds when the injection defence doesn't: it fires on impact tier alone, after every other
   check has already passed.
2. **When user intent is ambiguous** — if the requested action isn't clearly supported by the user's own
   words, Vroomi asks rather than acts (this is also the prompt-injection defence — threat card 1).
3. **On any request touching sensitive data** — routed to a human; Vroomi does not auto-answer from
   sensitive records (see Section 5, threat card 3).
4. **On repeated failure or anomaly** — see stop conditions (Section 7).

---

## 5. Data access rules

- Vroomi may read **approved, low-sensitivity** knowledge-base content only.
- **High-sensitivity records (e.g. customer PII) are not placed in Vroomi's context** and are not
  retrievable through her, unless an explicit, logged authorisation exists for a specific, scoped purpose.
  *(Threat card 3.)*
- Provenance is required: only **approved** documents from **trusted sources** may inform an answer.
  Unapproved or unknown-source content is filtered out before the model sees it. *(Threat card 2.)*
- Sources are **trust-ranked**, and an answer that conflicts with high-trust content is checked before it is
  returned. *(Threat card 6.)*
- Trust and sensitivity are treated as **separate axes** — a document can be fully trusted and still be
  withheld because it is too sensitive for the task at hand.
- **Known limit.** These are source-level controls. A false document that is approved and trusted passes
  them; report Section 5 records that as residual risk on threats 2 and 6 rather than treating either as closed.

---

## 6. Prohibited actions (never, without a card revision)

- Executing any tool not on the Section 2 allow-list.
- Taking an irreversible action without human approval.
- Revealing internal configuration, system instructions, or the tool protocol. *(Threat card 5 — enforced by
  removing the path, not by instructing the model.)*
- Accessing or disclosing sensitive records outside an authorised, logged purpose.
- Acting on instructions found in user input or retrieved content that the *user* did not actually request.
- Interacting with external systems (email, ticketing, third-party APIs) — explicitly out of scope until
  assessed and added here.

---

## 7. Retry and stop conditions

- **Validation failure:** refuse the action and return a safe message; do not retry with guessed arguments.
- **Ambiguous intent:** stop and ask for confirmation.
- **Repeated failures or unexpected errors:** fail closed (take no backend action) and surface the issue —
  a gate that crashes open is not a gate.
- **Anomaly:** escalate to the owner and log the event.

---

## 8. Accountability and review

- **Owner.** A named individual must be accountable for Vroomi's behaviour and for this card. **The owner is
  unassigned as of this draft**; assigning one is Recommendation 6 of the assessment and a precondition of
  the Conditional Go. "The model did it" is not an acceptable explanation for a governed system.
- **Logging.** Every gated action records the proposed action, the tier, the decision, the reason, and the
  authoriser — providing auditable evidence that decisions were made intentionally. *(Report Recommendation 5;
  implemented in the demonstrator's audit log, including the impact tier of every proposed action.)*
- **Review trigger.** This card is re-assessed on **any capability change** (a new tool, broader data
  access, a higher autonomy tier). Change is itself the trigger to re-decide.
- **Relationship to the Go/No-Go decision.** This card *is* the "safeguards to add first" behind the
  assessment's **Conditional Go**. One thing now stands between this draft and a met Recommendation 6:
  assigning the owner. Everything else in the card is enforced today in `vroomi_gov_gate.py`, including the
  approval tier for `cancel_ride`.

### Recommendation coverage

| Report recommendation | Where it lives | Status |
|---|---|---|
| 1 · Validate every tool call | Section 2 allow-list + demonstrator `govern()` | Implemented |
| 2 · Filter the knowledge base on the read path | Section 5 | Implemented (source-level; see Section 5 known limit) |
| 3 · Remove any path from user input to internal config | Section 6 | Satisfied structurally — no debug path exists |
| 4 · Human approval for irreversible actions | Sections 2, 3, 4.1 | Implemented (`Verdict.APPROVAL`) |
| 5 · Log every gated decision | Section 8 logging | Implemented |
| 6 · Named owner + approved agent card | Section 8 owner | **Card drafted; owner unassigned** |

---

_Draft for CISO review. This is my own governance document written against the publicly-describable Vroomi
capstone; it does not reproduce cohort notebook code._
