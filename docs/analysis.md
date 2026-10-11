# Analysis: sweeps and notebooks

    python -m taintwatch.analysis sweeps            # writes results/sweeps.csv
    python -m taintwatch.analysis sweeps --confirm  # same, auto-approving confirm verdicts
    python -m taintwatch.analysis notebooks         # regenerates notebooks/*.ipynb

To open the notebooks:

    pip install -e ".[notebooks]"
    jupyter lab notebooks

- `01_report.ipynb` reproduces the evaluation report from `results/records.csv`.
- `02_ablation_and_sweeps.ipynb` plots the scorer threshold and spotlight resistance sweeps,
  the attack success versus utility trade-off, the Pareto front and the span-level versus
  whole-context ablation.

The notebooks are generated from `src/taintwatch/analysis/notebooks.py`. Edit that file, not the
`.ipynb` files; a test fails if they drift apart.

## Limits

- CI checks that notebook code cells parse and that their `taintwatch` imports resolve. It does
  not execute them or render plots.
- Spotlight sweeps depend on an assumed resistance probability. Adjacent values are not strictly
  monotone because each defense name seeds its own random stream.
- The scorer curve shows how this hand-weighted scorer behaves, not detectors in general.
