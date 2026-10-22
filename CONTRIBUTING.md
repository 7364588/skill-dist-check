# Contributing

Start with a minimal synthetic reproduction for a parser, archive or portability
bug. Keep tests focused on the public contract. Do not submit private skill files,
credentials or machine-specific paths.

Requires Python 3.11+. Install with `python -m pip install -e .`, then run:

```sh
python -m unittest discover -s tests -v
python scripts/smoke.py
python scripts/demo.py
```

Changes to the manifest format need a versioned compatibility decision. Avoid
adding execution, automatic home-directory discovery or client-specific install
behavior. New coverage claims require fixtures and clear documented limits.
