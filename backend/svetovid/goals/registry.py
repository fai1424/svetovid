"""Auto-discovery goal registry.

Each module ``svetovid/goals/g<NN>_*.py`` exports a module-level ``goal``
attribute that is an instance of ``goals.base.Goal``. Importing this registry
module walks all such modules, imports each, collects the goal, and registers
it. Adding a goal is just dropping in a file (see docs/ADDING_A_GOAL.md).
"""

from __future__ import annotations

import importlib
import pkgutil

from .base import Goal


class _Registry:
    def __init__(self) -> None:
        self._goals: dict[str, Goal] = {}

    def register(self, goal: Goal) -> None:
        if not goal.id:
            raise ValueError(f"goal {goal!r} has no id")
        if goal.id in self._goals:
            raise ValueError(f"duplicate goal id {goal.id!r}")
        self._goals[goal.id] = goal

    def all(self) -> list[Goal]:
        return sorted(self._goals.values(), key=lambda g: g.id)

    def get(self, goal_id: str) -> Goal | None:
        return self._goals.get(goal_id)


registry = _Registry()


def _autoload() -> None:
    """Import every ``g*.py`` in this package and register its ``goal`` symbol."""
    from . import g01_attack_timeline  # noqa: F401  (explicit anchor; pkgutil below also covers it)

    pkg = importlib.import_module("svetovid.goals")
    for mod_info in pkgutil.iter_modules(pkg.__path__):
        name = mod_info.name
        if not (name.startswith("g") and name[1:3].isdigit()):
            continue
        mod = importlib.import_module(f"svetovid.goals.{name}")
        g = getattr(mod, "goal", None)
        if isinstance(g, Goal):
            # register() is idempotent-safe: skip if already present
            if g.id not in registry._goals:
                registry.register(g)


_autoload()
