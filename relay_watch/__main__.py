"""``python -m relay_watch`` entry point; delegates to :mod:`relay_watch.cli`."""

from .cli import main

if __name__ == "__main__":
    raise SystemExit(main())
