# Routes Layer (Policy Enforcement Point - PEP)

This directory serves as the Policy Enforcement Point (PEP) route layer for ActionGuard.

## Architecture Responsibility
- Exposes HTTP endpoints for protected applications and user interactions.
- Intercepts requests and enforces security policies via middleware before sensitive operations execute.
- Delegates security decisions to the Policy Decision Point (PDP) services.
- Never directly implements risk scoring or policy rule evaluation logic here.
