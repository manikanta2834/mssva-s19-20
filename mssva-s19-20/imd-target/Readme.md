# Shadow Signals: Runtime Telemetry Research Lab

## Overview

Modern infrastructure relies on long‑running, privileged background services that are rarely audited at runtime.
These services often become **high‑impact attack surfaces** due to trust assumptions, blind spots in telemetry,
and undocumented behavior.

This lab places you in the role of a **security researcher / detection engineer**.

You are given:
- A critical infrastructure daemon (`IMD`)
- A runtime telemetry collector
- No vulnerabilities
- No flags
- No source‑level hints

Your task is to **observe, reason, and prove** security‑relevant behaviors using runtime evidence alone.

---

## Scenario

`IMD` (Infrastructure Management Daemon) represents an internal system service responsible for managing node‑level
configuration and helper operations.

Assumptions:
- Long‑running
- Privileged
- Trusted by the system
- Not externally exposed

Failures or abuse of such services often lead to **cluster‑level compromise**, **persistent access**, or **silent configuration drift**.

---

## Objective

Using **only telemetry output and system observation**, identify and formally define **five (5) security‑relevant findings** about IMD’s runtime behavior.

These findings are referred to as **flags**, but:
>  Flags are *not strings*  
>  Flags are *not stored in files*  
>  Flags are *not printed by the program*

Each flag must be **constructed through evidence and reasoning**.

---

## What You Are Given

### Target
- `./bin/imd`
- A long‑running infrastructure daemon
- Performs internal management operations

### Telemetry
- `./bin/imd_telemetry`
- Collects partial runtime observations
- Does not explain intent
- May miss important context

---

## Rules

✔ You may:
- Run telemetry
- Inspect `/proc`, `/tmp`, and runtime artifacts
- Correlate events over time
- Use standard system tools for observation

 You may NOT:
- Modify the daemon
- Inject exploits
- Add instrumentation
- Assume intent without evidence

---

## What Is a Flag?

A **flag is a security claim**, not a string.

Each flag represents a **provable security‑relevant behavior** of the daemon.

Example (format only, not a solution):

> “IMD performs privileged configuration mutations during steady‑state operation without an observable authorization boundary.”

---

## Required Deliverables

You must submit a report containing **exactly five (5) flags**.

Each flag must follow this structure:

### Flag‑N: *Short descriptive title*

**Claim**  
One sentence describing the security‑relevant behavior.

**Evidence**  
Concrete runtime observations supporting the claim:
- Telemetry output
- Process relationships
- File artifacts
- Network activity
- Timing correlation

**Reasoning**  
Why the evidence supports the claim.

**Security Impact**  
What attacker capability or system risk this behavior enables.

**Visibility Gap**  
What telemetry did not clearly capture (if applicable).

---

## Expected Methodology

1. Establish a baseline of normal behavior
2. Observe runtime artifacts over time
3. Correlate events across processes, files, and network state
4. Identify undocumented or unexplained behavior
5. Form defensible security claims

This mirrors how real‑world:
- Detection engineers
- Cloud security researchers
- Incident responders
work with imperfect visibility.

---

## Evaluation Criteria
```text
| Aspect | Importance |
|------|------------|
| Quality of evidence | High |
| Reasoning clarity | High |
| Security relevance | High |
| Understanding telemetry limits | Medium |
| Report quality | Medium |
```

---

## Why This Lab Matters

This exercise reflects real security research challenges:
- No perfect telemetry
- No clear attack surface
- No source‑level intent
- Only runtime behavior

Your ability to reason from incomplete data is the skill being evaluated.

---

## Final Note

There are **exactly five meaningful flags** in this environment.

Good luck.
