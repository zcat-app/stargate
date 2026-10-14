# Task-run guard source v5

The guard now rejects the exact `-` token in the interpreter script position, even when a regular file named `-` is pinned in the working directory. The positive `./-` control still executes the pinned file; a literal dash after a real script remains an ordinary script argument.

The preserved sentinel selector passed (1 test), and the affected suite passed 57 tests with 0 failures and 0 skips. Commands and logs are recorded in `evidence-v5.json`. The actual source-v4 RED and its provenance remain in `input-v4-python-dash-red-evidence.json`.

Final hashes and modes for the four approved files are recorded in `evidence-v5.json`. Historical evidence gaps remain unresolved; this does not activate a policy or establish containment.
