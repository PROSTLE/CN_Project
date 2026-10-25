# Online == offline feature check

Archive `online_20261018-193456.events.gz` replayed through the offline FlowTable: 1915 (flow, checkpoint) snapshots matched to online decisions; identical feature hash for 1911 (0.9979). By checkpoint: {"end": {"n": 1277, "identical": 1275}, "16": {"n": 199, "identical": 198}, "8": {"n": 274, "identical": 274}, "32": {"n": 165, "identical": 164}}.

Online, idle flows are also closed by a wall-clock ticker, offline only by the event-time ticker, so flow boundaries and the source-history context of other flows can differ at a few stream positions; this is the most likely cause of the mismatches (not individually traced).
