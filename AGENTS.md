# ActionGuard — Development Guidelines

## Project Purpose

ActionGuard is an open-source Zero Trust security platform designed to help applications continuously evaluate and protect user sessions and sensitive actions.

The system evaluates security context such as device, location, behavior, timing, session activity, and action sensitivity to detect suspicious activity and apply an appropriate security response.

ActionGuard is designed to help detect and contain account/session compromise and account-takeover activity before it results in irreversible high-impact actions.

## Core Security Principles

- Follow "Never Trust, Always Verify."
- Do not treat successful authentication as permanent trust.
- Continuously evaluate session and action risk.
- Re-authorize sensitive actions using current security context.
- Follow least privilege.
- Use risk-based and attribute-based access decisions.
- Assume that an authenticated account may already be compromised.
- Keep authorization decisions separate from enforcement.
- Prefer proportional responses instead of automatically blocking every anomaly.
- Do not claim guaranteed account-takeover prevention; the system detects and contains suspicious activity based on available evidence.

## Architecture Principles

- Keep the Policy Decision Point (PDP) separate from the Policy Enforcement Point (PEP).
- Keep risk evaluation, policy decisions, and enforcement as independently testable components.
- Preserve clear boundaries between modules.
- Prefer modular and replaceable components.
- Design APIs and security-event structures for external application integration.
- Avoid unnecessary coupling between the protected application and ActionGuard.

## Security Requirements

- Never store passwords in plaintext.
- Hash passwords using an appropriate password-hashing algorithm.
- Protect authentication and authorization tokens.
- Use short-lived trust and privilege where appropriate.
- Validate and sanitize external input.
- Apply rate limiting to security-sensitive endpoints.
- Protect sensitive information in transit and at rest.
- Maintain an auditable record of security decisions and important events.
- Treat device, location, and behavioral information as sensitive data.
- Collect precise location only with explicit user consent.

## Risk Evaluation

Risk decisions should consider multiple signals where available, including:

- Device identity
- IP and geographic context
- Impossible travel
- Personal behavioral deviation
- Session activity
- Action sensitivity
- Related event sequences
- Signal combinations
- Potential blast radius

A single weak signal should not automatically be treated as proof of compromise unless the configured policy explicitly requires it.

## Response

ActionGuard may produce responses such as:

- Allow
- Monitor
- Re-verify
- Delay
- Block

Responses should be configurable and proportional to the evaluated risk.

High-impact actions should receive stronger protection than ordinary actions.

## Explainability

Security decisions should be explainable.

Provide:

- Clear explanations for affected users.
- Detailed explanations for security administrators.
- Information about the signals contributing to a decision.

Avoid unexplained or arbitrary security decisions.

## Development Guidelines

- Use clear, maintainable code.
- Prefer small, focused modules.
- Avoid unnecessary dependencies.
- Avoid duplicated logic.
- Use strict typing where applicable.
- Validate external input at system boundaries.
- Write tests for security-critical behavior.
- Do not weaken security controls simply to make implementation easier.
- Do not silently change security behavior without documenting the change.
- Keep configuration separate from business logic where practical.

## Testing

Security-critical functionality should include appropriate tests.

Important areas include:

- Authentication
- Session management
- Event logging
- Risk calculation
- Policy decisions
- Step-up verification
- Blocking and restriction
- Cooling-off actions
- API authentication
- Input validation
- Rate limiting
- Policy replay
- Account/session compromise scenarios

## AI Development Rules

When modifying the repository:

1. Read the relevant documentation before changing architecture.
2. Understand existing code before creating new modules.
3. Reuse existing functionality instead of duplicating it.
4. Preserve existing security boundaries.
5. Do not remove security controls without explicit justification.
6. Do not introduce a new technology when an existing project component can solve the problem cleanly.
7. Keep changes focused on the requested task.
8. Update documentation when an architectural or security behavior changes.
9. Add or update tests for important behavior changes.
10. Never expose secrets, credentials, API keys, or private user information.

## Extensibility

ActionGuard is intended to be an open-source security project.

The implementation should therefore allow future additions such as:

- New risk signals
- New policy rules
- New response strategies
- New integrations
- Community-developed detection plugins
- Additional protected applications

New functionality should extend the system without unnecessarily rewriting existing components.

## Important

The documentation describes the intended capabilities and security principles of ActionGuard.

Implementation details may evolve during development.

Do not treat the current technology choices as permanent limitations on the project's security capabilities.

When a better implementation is required, evaluate it against the project's requirements, security model, maintainability, and integration goals before adopting it.