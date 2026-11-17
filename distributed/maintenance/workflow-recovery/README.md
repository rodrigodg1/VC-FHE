# Zero-release continuation

This procedure requires completed 480-pair/18-warm-up evidence and no consumed release slot or completed full workflow. Preparation freezes predecessor sources and reconciles identities, state, quotas and requests before a new segment. Never invoke it after any completed release. Use the exact retained source checkpoint and read the checks in `prepare.py` and `continue.py`. Its analysis derives numerical results and preserves the original failed state. See `../../OPERATIONS.md` for the required evidence.
