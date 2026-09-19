from __future__ import annotations

from spiderforge.analysis.base import SecurityModule


class ModuleRegistry:
    def __init__(self) -> None:
        self._modules: dict[str, SecurityModule] = {}

    def register(self, module: SecurityModule) -> None:
        if module.name in self._modules:
            raise ValueError(f"Module already registered: {module.name}")
        self._modules[module.name] = module

    def get(self, name: str) -> SecurityModule | None:
        return self._modules.get(name)

    def all(self) -> list[SecurityModule]:
        return list(self._modules.values())

    def names(self) -> list[str]:
        return sorted(self._modules.keys())

    def by_category(self) -> dict[str, list[SecurityModule]]:
        out: dict[str, list[SecurityModule]] = {}
        for m in self._modules.values():
            out.setdefault(m.category, []).append(m)
        for cat in out:
            out[cat].sort(key=lambda x: x.name)
        return dict(sorted(out.items()))

    def select(
        self, include: list[str] | None = None, exclude: list[str] | None = None
    ) -> list[SecurityModule]:
        mods = list(self._modules.values())
        if include:
            wanted = {n.lower() for n in include}
            mods = [m for m in mods if m.name.lower() in wanted]
        if exclude:
            banned = {n.lower() for n in exclude}
            mods = [m for m in mods if m.name.lower() not in banned]
        return mods


# Global registry
registry = ModuleRegistry()
