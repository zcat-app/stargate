# T146 fixture cleanup reproduction

This is a **retrospective reconstruction**, recorded after review round 1.
It is not a claim that a preserved test-first artifact existed before the
teardown change. The earlier live run also reported owned volumes leaking;
its transient output was not retained in the candidate.

On 2026-09-25, an isolated worktree at base `9931984d352f92ce83341eeae1a8297f520e5d60`
received T146's staged patch. For the failing state, only the new
project-labelled `docker volume rm` loop was removed from
`tests/contract/stargate-cli/init_docker_test.sh`; the forced-failure test,
fixture, and dynamic-port changes remained identical to the fixed state.
The failing fixture script SHA-256 was
`bd347a43f69280333a5dd640d40e3d017f95c55f87f2cb2c3d0db3cdeeb98599`;
the test script SHA-256 in both states was
`f835b229ac6a631c3d98a7ce70e10a03acce3ff51d8d03eca27e4759e6803c3a`.

Command in the isolated worktree:

```text
$ bash tests/contract/stargate-cli/init_fixture_cleanup_test.sh
FAIL: owned volumes leaked for t088isoa-t146-872423-1790339483
exit 1
```

The test first asserts that the child reached `T146 injected failure after
project A provisioning`; otherwise it reports a different failure. After
the failed command, Docker still listed these two project-labelled volumes
and no project container:

```text
t088isoa-t146-872423-1790339483_stargate-observer-keys
t088isoa-t146-872423-1790339483_stargate-tor-cp-fabric
```

Those two disposable volumes were removed after the observation. Running
the same command in the fixed candidate, whose fixture script SHA-256 was
`65194149a9d2ac632bf0ded4902c438fca697c48e00f07950d05cc12b20610df`,
produced:

```text
$ bash tests/contract/stargate-cli/init_fixture_cleanup_test.sh
PASS: forced fixture failure cleaned owned resources and preserved a foreign volume
exit 0
```

Neither run skipped Docker. The test's foreign labelled sentinel remained
available at its assertion point in the passing run.
