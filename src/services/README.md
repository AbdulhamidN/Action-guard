# Services Layer (Policy Decision Point - PDP)

This directory serves as the Policy Decision Point (PDP) layer for ActionGuard.

## Architecture Responsibility
- Hosts core decision-making services including Risk Engine, Policy Engine, and Baseline analysis.
- Evaluates context, signals, and security rules independently from the HTTP enforcement layer.
- Keeps risk calculations, score aggregation, and policy decisions testable and decoupled from request handling.
