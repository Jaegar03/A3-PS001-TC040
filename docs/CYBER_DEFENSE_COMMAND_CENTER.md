# Cyber Defense Command Center

The Cyber Defense Lab is a local, simulation-only demonstration surface for
Sentivra. It uses trusted server-side fixtures, invokes the existing detector
registry and RiskEngine, stores a simulation execution, and returns a separate
decision from the simulation policy adapter.

## Safety boundary

Every run is marked `SIMULATED EVENT`. The enforcement adapter can return
`SIMULATED_BLOCK`, `SIMULATED_ALLOW`, `SIMULATED_REVIEW`, or
`SIMULATED_UNAVAILABLE`, but it has no network, OS, subprocess, URL-fetch,
firewall, quarantine, or external-provider capability. The UI states:
“Simulation only. No real network traffic, system processes, or external
applications were blocked.”

The topology is conceptual. Its animated particle is synthetic event progress,
not a packet. A detection is evidence about a fixture, not proof of compromise.

## Scenarios

The registry contains SQL injection, prompt injection, synthetic network,
suspicious URL, inert file, and benign-control scenarios. Clients submit only a
scenario ID; fixture contents are selected in backend code. SQL and prompt
inputs use local rules, URL analysis never performs DNS or HTTP, the network
model is experimental/synthetic, and optional file scanners report their real
availability.

## API

- `GET /api/simulation/scenarios` — trusted scenarios and detector readiness.
- `POST /api/simulation/run` — accepts `{ "scenario_id": "...", "mode": "simulation" }`.
- `GET /api/simulation/runs?limit=25&offset=0` — bounded execution history.
- `GET /api/simulation/runs/{execution_id}` — persisted execution detail.
- `GET /api/simulation/stats` — actor-scoped aggregate simulation statistics and
  a bounded timeline; it is not calculated from the current history page.

All routes require the existing bearer authentication and scopes. Simulation
executions have their own `simulation_executions` table and link to the normal
event/alert IDs when an alert is raised. Operational metrics exclude simulated
alerts from their incident counts.

The execution row retains the normalized detector output, detector availability,
risk assessment, policy decision, timeline, source marker, and sanitized errors.
The normal pipeline's event and alert repositories are reused, so the linked
records remain subject to the existing actor isolation rules. A visual reset is
only client state and never deletes persisted rows.

## Demonstration

Start the backend and frontend using the normal project instructions, sign in,
open **Cyber Defense Lab**, select a trusted scenario, and choose **Run
simulation**. Select a history row to inspect the stored result. Reset only
clears the current visualization; it does not delete records.

For backend checks, run `python -m pytest -q` from `backend`. For the command
center presentation checks, run `npm run lint`, `npm test`, and `npm run build`
from `frontend`.

## Limitations and troubleshooting

Detector availability is determined from the actual registry at request time.
Missing ClamAV or model assets cannot produce a successful block. A synthetic
network result is not real-traffic validation, and the optional ML artifacts
remain subject to the limitations in `docs/model-card.md`.

The expected outcome in registry metadata is evaluation context only; it never
overwrites a detector result. Animated stage movement is illustrative rather
than measured telemetry. Unknown, failed, or partially completed analysis is
shown as unavailable/failure and cannot become a simulated allow or block.
