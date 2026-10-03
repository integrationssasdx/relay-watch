"""``python -m relay_watch`` 入口；委托给 :mod:`relay_watch.cli`。"""

from .cli import main

if __name__ == "__main__":
    raise SystemExit(main())
