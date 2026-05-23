# Architecture

## Objective

The adversarial arena is intended to simulate red-team and blue-team behavior in a controlled workflow so that attacks, defenses, and scoring can be compared clearly.

The system is designed to support:
- repeatable simulation runs,
- objective scoring,
- defense evaluation,
- and clear analysis of outcomes.

## High-level view

The project is composed of four main parts:

- Presentation layer.
- Orchestration layer.
- Simulation layer.
- Data layer.

## Layer overview

### 1. Presentation layer
The frontend is the evaluation workspace.

Main goals:
- Show scenarios.
- Present scores.
- Display run history.
- Compare attack and defense results.

### 2. Orchestration layer
The orchestrator coordinates the simulation run.

Main goals:
- Start a scenario.
- Route actions between red and blue sides.
- Capture each step.
- Build the final result set.

### 3. Simulation layer
This layer performs the adversarial logic.

Main goals:
- Generate attacks.
- Apply defense logic.
- Calculate scores.
- Support consistent replay.

### 4. Data layer
The data layer stores experiment context.

Main goals:
- Store run history.
- Store scores.
- Preserve comparison data.
- Support future integrations.

## Example workflow

1. A scenario is selected.
2. Red-team logic generates an attack attempt.
3. Blue-team logic applies a defense response.
4. The scoring engine measures the outcome.
5. The system stores the result.
6. The analyst reviews the comparison.

## Future extensions

- Scenario library.
- Metrics dashboard.
- Replay mode.
- Exportable results.
- More advanced scoring models.

## Design principles

- Keep the workflow explainable.
- Prefer modular components over one large script.
- Make scoring transparent.
- Preserve replay history.
- Support future hardening and integration.
