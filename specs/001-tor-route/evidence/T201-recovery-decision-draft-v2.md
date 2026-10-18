# T201 exact recovery decision and THREAT-MODEL draft v2

Root recommendation, not applied. Independent finite feasibility review:
T201-finite-feasibility.md. T201 Acceptance4 explicitly requires approval of exact
THREAT-MODEL wording before writing it. This also presents the newly discovered
availability tradeoff rather than silently choosing it.

## Decision proposed

Persist one current delivery state before every token-reload RPC. Normal retries
and exact acknowledgment continue while the originating CP process lives. A stale
refusal remains terminal across restarts. If CP exits with an unresolved delivery,
the next CP process must require explicit offline recovery before sending tokens,
because the preceding process might have received a stale refusal and crashed
before recording it. This prevents changed YAML/restarts from reviving old tokens,
including after DP state loss. The DP keeps routing with its valid prior state.

Cost: restarting CP during an unresolved token update no longer automatically
replays that candidate. The operator must restore a known matching newer CP state,
or deliberately confirm rollback using the offline recovery procedure. Healthy
acknowledged startup and same-process DP reconnect/reseed remain supported. No DP
reload-rule change, credential history or public-network probe is added.

The present alternative—automatic pending replay on restart—cannot guarantee the
chosen T201 invariant after a stale response was not durably recorded and the DP
later loses its newer state. That demonstrated ambiguity is not waived.

Reconcile data-model1.8, control-grpc and architecture5.2/6.7 (the latter still
incorrectly describes DP-current-based renumbering), quickstart and T201's exact
path budget before implementation. Current minimum union18, not the stale budget12.
Use a bounded, explicitly confirmed host Python3/sqlite3 offline clear snippet;
no new Java command, runtime API or container entrypoint. Test that literal snippet
against a private synthetic DB, including no creation of missing DB and preservation
of generation/verifiers. Real recovery on this box is not authorized by this draft.

## Exact proposed THREAT-MODEL text

Replace the existing process-only STALE_CONFLICT/recovery statements in §5.15 with:

> Before each token reload, the control plane durably records that delivery is
> unresolved. An exact acknowledgment clears that state in the originating process
> after its clear transaction commits. On a stale refusal the control plane
> immediately stops further token delivery and records a durable stale-conflict
> marker. If recording that outcome fails, the already-durable unresolved state
> remains the restart barrier; failure does not resume delivery in the current
> process. A stale conflict
> prevents further token pushes, including after control-plane restart or changes
> to tokens.yaml. If the control plane restarts with an unresolved delivery, it
> also makes no token push until explicit offline recovery: the preceding process
> may have received a stale refusal before it could persist that outcome. The
> existing PENDING value describes unresolved delivery; STALE_CONFLICT describes
> a recorded stale refusal. Neither is proof that a credential change was applied.
>
> This can require manual recovery after a control-plane crash during an update,
> including when its acknowledgment was lost. Restore known matching newer
> control-plane state, or stop both planes, verify the intended credentials,
> preserve the newer state, move the active data-plane snapshot aside and explicitly
> clear the control-plane delivery gate before normal durable reseeding. This
> deliberate rollback may reauthorize credentials in the selected state. After
> its active snapshot is moved aside, the data plane denies admission until valid
> authority is durably installed. It may then admit those credentials even if
> the acknowledgment is lost. The operator must not treat recovery as confirmed
> until the control plane observes the exact acknowledgment and credential
> outcomes are verified. Normal same-process retry and
> acknowledged peer-recovery replay remain supported; no timeout, file edit or
> ordinary restart clears a durable conflict or unresolved restart gate. Host/root
> rollback of all trusted state remains outside this guarantee.

The surrounding current-status description will retain private volatile publication,
existing vocabulary, no timestamps/labels/history and truthful unavailable outcomes.
Implementation still needs an exact independent Astra source-plan review, genuine
behavioral RED/identical GREEN and the normal source delivery gate. Approval of this
draft does not count as source/native acceptance or authorize host mutation.

## Independent R1 feedback adjudication

Both exact-prose findings hold. Root directly inspected DP ReloadTokens: persistence
and token-set Swap precede returning ACK, so lost response can leave CP PENDING
while DP already admits installed credentials. Existing equivalent observed-ACK
admission wording in the same THREAT section must be corrected with this scope.
The proposal's safety purpose also requires explicit failed-STALE-write fallback:
in-process stop plus the earlier durable unresolved barrier. V1 and its exact
REWORK report remain preserved. This revised proposal is not yet approved/applied;
user requested a next-step question if independent review did not approve V1.
