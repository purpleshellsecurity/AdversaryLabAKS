# How we know the detections actually work — a plain-language guide

If the other docs have started to feel like alphabet soup (Tier 1, KQL, eBPF,
fixtures…), read this one first. No jargon in the main text — every technical word
is translated in the glossary at the bottom.

---

## The one big idea

A **detection** is a tripwire. Its whole job is to notice when something bad
happens and raise an alarm.

Here's the problem every security team has: **how do you know a tripwire actually
works?** You wrote it, it looks right, but until something trips it, you're just
*hoping*. Plenty of real breaches happened where the alarm existed but never fired,
because nobody ever tested it.

So the honest rule is simple:

> **You don't trust a tripwire until you've actually tripped it and watched the
> alarm go off.**

Everything we built is a machine that does exactly that — automatically, every time
anyone changes the code.

---

## Two places we watch, so two kinds of tripwire

An attacker in a Kubernetes cluster leaves footprints in two different places, and
we can't watch both with one camera:

1. **The front desk.** Every request to the cluster ("make me a pod", "give me the
   secrets") goes through one place that keeps a logbook. Some of our tripwires read
   that logbook.

2. **Inside the room.** Once an attacker is *inside* a container, they run programs
   and open files and make network connections — and none of that shows up in the
   front-desk logbook. A separate tool watches the actual activity inside, and some
   of our tripwires read from that.

That's the only reason there are two "kinds" — they watch two different places. You
need both, because each is blind to what the other sees.

---

## What we built, in order

### Step 1 — We listed every tripwire and every attack

We wrote down all the detections and, next to each one, the **matching fake
attack** that should trip it (a small, safe script). Think of it like a fire-drill
plan: for every smoke detector, there's a note saying "hold a match under *this*
one to test it."

That list lives in **`DETECTION-COVERAGE.md`**. Each row also has a **confidence
label** so you can tell, at a glance, how much you can trust that tripwire (more on
the labels below).

### Step 2 — We built a tester for the "front desk" tripwires

We took a **recording of what an attack looks like** in the logbook, and we feed
that recording to the real tripwire and check two things:

- it **does** go off for the attack, and
- it **stays quiet** for normal, everyday activity (so it won't cry wolf).

This runs in seconds, costs nothing, and happens automatically on every change.
Today **8 front-desk tripwires** are checked this way.

### Step 3 — We built a tester for the "inside the room" tripwires

You can't fake this one with a recording — the tripwire watches *live* activity, so
we have to create live activity. So this tester **actually runs tiny, safe fake
attacks inside throwaway containers** — a pretend reverse shell that connects
nowhere, a harmless program renamed to look like a crypto-miner, a fake token file
being read — and then checks that the right alarm fired.

This also runs automatically on every change, for free. Today **6 inside-the-room
tripwires** are checked this way.

> **Everything is safe.** The "attacks" don't attack anything. The reverse shell
> dials a dead-end address. The "miner" is just the `sleep` program with a scary
> name. Nothing is exposed, nothing is mined, nothing leaves the test.

### Step 4 — We labeled how much to trust each tripwire

Not every tripwire is equally proven. The labels, in plain words:

| Label | Plain meaning |
|-------|---------------|
| ✅ **Proven** | We trip it automatically on every change and watch the alarm fire. Trust it. |
| 🟧 **Backstop** | It works, but it's easy for a careful attacker to sneak past. It's a backup, not your main line. |
| ⬜ **Template** | Not finished — it needs data we don't collect yet. Don't rely on it. |

Right now: **14 Proven, 2 Backstop, 1 Template.**

---

## What "the checks are green" actually means

When you look at a pull request (a proposed change) on GitHub and see a **green
check**, it now means something concrete and valuable:

> Every proven tripwire was just tripped by its matching fake attack, and every
> alarm fired correctly — a few seconds ago, on this exact version of the code.

If someone accidentally breaks a detection, a check turns **red** and the change
can't slip through unnoticed. That's the entire point: the tripwires can't silently
rot anymore.

**One honest limit:** these automatic checks prove the tripwire *logic* is correct.
They do **not** prove the whole real-world pipeline end to end (a real cluster, real
logs flowing for real). That last mile is a separate, slower, paid test we've left
as a future step. So "green" means "the detection is correct," not "the entire
production system is wired up." That distinction is called out honestly in the
coverage doc.

---

## Where everything lives (the map)

| If you want to… | Look at… |
|-----------------|----------|
| Understand *why* each detection is written the way it is | `DETECTIONS-FOR-BEGINNERS.md` |
| See the full list: every detection, its attack, its confidence label | `DETECTION-COVERAGE.md` |
| See a color-coded picture of coverage | `attack-navigator-layer.json` (load it in the ATT&CK Navigator site) |
| Read the actual tripwires | `detections/kql/` (front desk) and `detections/falco/` (inside the room) |
| Read the safe fake attacks | `attack-simulations/` |
| See the machines that test everything | `tools/detection-tester/` |

---

## Glossary — the scary words, translated

Keep this handy; swap it in whenever a doc uses one of these.

| Word you'll see | What it actually means |
|-----------------|------------------------|
| **Detection / rule** | A tripwire. Code that watches for something bad and raises an alarm. |
| **Trigger / attack simulation** | A small, safe, fake attack whose job is to set off one tripwire so we can test it. |
| **Management plane** | The cluster's "front desk" — the logbook of every request made to the cluster. |
| **Runtime plane** | "Inside the room" — the live activity happening inside a running container. |
| **KQL** | The query language used to write the front-desk tripwires. Think "a search filter over the logbook." |
| **Falco** | The tool that watches inside-the-room activity and runs those tripwires. |
| **CI** (the checks on a pull request) | A robot that runs all our tests automatically every time the code changes. |
| **Fixture** | A saved recording of what an attack looks like in the logbook, used to test a front-desk tripwire without a live attack. |
| **Tier 1** | The automatic tester for front-desk tripwires (uses recordings). |
| **Tier 2** | The automatic tester for inside-the-room tripwires (uses live safe fake attacks). |
| **Tier 3** | The future full end-to-end test on a real, live cloud cluster. Slower and costs money; not built yet. |
| **Proven / Backstop / Template** | How much to trust a tripwire — see the table above. |
| **MITRE ATT&CK / T-numbers (e.g. T1611)** | A standard catalog of attacker techniques. The T-number just says "which known technique this tripwire is about." |
| **Kusto emulator, eBPF, modern probe** | Plumbing. The behind-the-scenes engines that let the testers run for free without a real cloud. You don't need to know how they work to trust the result. |

---

## The 30-second summary

- A detection is a tripwire; a tripwire you've never tripped is just a hope.
- We watch two places (the front desk and inside the room), so there are two kinds.
- We built two machines that **automatically trip every tripwire and confirm the
  alarm fires**, on every change, for free.
- Green check = every proven tripwire was just tested and works.
- 14 are proven this way, 2 are weak backups, 1 isn't finished — and the labels tell
  you which is which so you're never guessing.
