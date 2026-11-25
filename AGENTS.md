# AGENTS.md

Dette repo er en fork af [noskillish/bankmcp](https://github.com/noskillish/bankmcp).

- Drift: personlig installation på Sliplane.
- Required check: `gate` (jobbet `ci` i `.github/workflows/ci.yml`).
- Upstream synkes ugentligt af `.github/workflows/auto-update.yml` via en merge-PR. Den PR skal merges som merge commit (ikke squash), ellers mister forken upstream-historikken.
- Hemmeligheder kun via Doppler. Nævn kun navne, aldrig værdier.
- Følg fleet-standarden i [srosenlund/fleet `docs/standard.md`](https://github.com/srosenlund/fleet/blob/main/docs/standard.md).
