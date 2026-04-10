# Contributing to ARGUS

## Development Setup

```bash
git clone https://github.com/Odingard/Argus.git
cd Argus
python -m venv .venv
source .venv/bin/activate
make dev
```

## Workflow

1. Create a branch from `develop`:
   ```bash
   git checkout develop
   git checkout -b feature/your-feature
   ```

2. Make changes, ensure tests pass:
   ```bash
   make lint
   make test
   ```

3. Push and create a PR against `develop`.

## Adding an Attack Agent

Attack agents live in `src/argus/agents/`. Each agent:

1. Subclasses `BaseAttackAgent` from `argus.orchestrator.engine`
2. Sets `agent_type` to the corresponding `AgentType` enum value
3. Implements the `async run()` method
4. Emits findings via `self.emit_finding()` and partial signals via `self.emit_partial()`
5. Returns an `AgentResult` via `self.build_result()`
6. Has corresponding tests in `tests/`

## Adding Attack Patterns to the Corpus

Add patterns in `src/argus/corpus/manager.py` or create JSON files in the corpus data directory. Each pattern needs:

- Unique ID
- Category from `AttackCategory` enum
- Template with variant payloads
- Target surfaces and applicable agent types
- Source attribution

## Code Quality

- Run `make lint` before committing
- All new code must have type hints
- All findings must include reproduction steps
- All agents must validate findings before emitting
