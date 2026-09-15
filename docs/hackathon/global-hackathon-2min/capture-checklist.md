# Global video capture checklist

Complete captures against the September 19, 2026 recording freeze.

## Capture settings

- 1920 x 1080, 16:9
- 30 frames per second
- Browser zoom fixed before recording
- Cursor movement deliberate and minimal
- Notifications, bookmarks, personal profile, and unrelated tabs hidden
- Synthetic workload identifiers only
- No audio required
- Record five seconds of clean lead-in and tail for every shot

## Required captures

| ID | Capture | Minimum evidence | Placeholder scene |
|---|---|---|---|
| GH-01 | Three-profile comparison | Same topology and evidence; visibly different Production, Development, and Training conclusions | 4 |
| GH-02 | Healthy baseline | Workload identity, environment, healthy state, and approved context version | 5 |
| GH-03 | Controlled fault | Fault transition, affected role, and degraded state | 5 |
| GH-04 | Contextual impact montage | Separate approved views of the affected role, contained web-tier impact, operator attention, and evidence lineage | 5 |
| GH-05 | Ranked hypotheses | Leading cause, supporting evidence, contradiction or missing evidence, and confidence | 6 |
| GH-06 | Governed guidance state | Verified versioned guidance when available, or an explicit guidance-unavailable state, plus the human decision boundary | 7 |
| GH-07 | Verified recovery | Recovered state and lifecycle continuity | 7 |

## Approval gate

- [ ] Every visible value is synthetic or explicitly approved.
- [ ] No resource IDs, tenant IDs, subscription IDs, tokens, or personal data are visible.
- [ ] No screen implies that Athena changed the workload.
- [ ] The captured UI matches the narration and on-screen claims.
- [ ] Metrics have an evidence owner and source.
- [ ] The final MP4 is silent and no longer than 2:00.

## Fallback gate

- [ ] If the live incident release is unavailable, use the verified standalone lifecycle.
- [ ] If Context Studio is unavailable, use the packaged golden proof and a conceptual governed
      context visual.
- [ ] If verified guidance is unavailable, show the explicit unavailable state and remove any
      implication that guidance was rendered.
- [ ] Do not combine fields from separate surfaces into a fabricated single product screen.
