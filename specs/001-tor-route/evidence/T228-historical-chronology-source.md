# T228 historical chronology durable evidence record

**State:** preparation only; proposed, not accepted or applied. **Ticket:** T228.

This record durably preserves the exact nine named source-step blocks bound by the immutable T228 inventory, the full original T199 tests-first JSON, and both complete original round-1 reviewer verdicts. Each fenced payload below is copied byte-for-byte from the retained original import; hashes, byte lengths, modes and source bounds identify the exact bytes. These excerpts do **not** claim durable reproduction of all six files in the rejected T199 candidate. The full original import directory remains a separate local artifact. Payload byte lengths define the original byte boundary: the Astra verdict has no final newline, so the following LF before its closing Markdown fence is a presentation separator and is not part of its 12139-byte original payload.

## Binding records and limits

- Inventory: `specs/001-tor-route/evidence/T228-historical-chronology-inventory.json`; SHA-256 `c088d1191e0b532ef5c678e7e952ac09277a617bb4ddad3c37af69192c0f5a31`; 8892 bytes; mode `0664`. The copied inventory remains unchanged.
- Rejected T199 source snapshot: `675c852f10044853859088be36ce8d5fdcc2f34f60638a888695cae8fee18fc1`; parent `9317d8468fec8477115c6ce952ca26acb56896b4`; actual review round `1`.
- Original imported source directory: `.scratch/reports/2026-10-16-finish-tor-orchestration/T199-native-round1/original-import/source/`; complete source files are local artifacts, not all embedded here.
- Original imported records directory: `.scratch/reports/2026-10-16-finish-tor-orchestration/T199-native-round1/original-import/`. This record embeds only the original full T199 evidence JSON and the two full verdicts among those records.
- Historical classifications remain NONCOMPLIANT; later qualification does not create historical RED. The proposal grants no source approval or code adoption.

## Historical source step blocks (exact byte copies)

### 1. Install Go 1.26.3

- Original source path: `.github/actions/setup-toolchain/action.yml`
- Original full-file SHA-256: `41b9e936fda5d76b878df77900793bfd063a4677b3aea441b61d5edbbf17d48b`
- Original file byte length: 4752; mode `0664`
- Bound source extent: first line 13, 786 bytes
- Exact step SHA-256: `6ba1be4d4cde277df99bc5c48d16f0210539dccf552ade88225573014629ed66`
- Historical status: `NONCOMPLIANT`

```yaml
    - name: Install Go 1.26.3
      shell: bash
      run: |
        set -euo pipefail
        test "$(uname -s)" = Linux
        test "$(uname -m)" = x86_64
        root="$(mktemp -d "$RUNNER_TEMP/stargate-go.XXXXXX")"
        archive="$root/go1.26.3.linux-amd64.tar.gz"
        curl --fail --location --silent --show-error --output "$archive" \
          https://go.dev/dl/go1.26.3.linux-amd64.tar.gz
        printf '%s  %s\n' \
          '2b2cfc7148493da5e73981bffbf3353af381d5f93e789c82c79aff64962eb556' "$archive" \
          | sha256sum -c -
        mkdir -p "$root/unpacked"
        tar -xzf "$archive" -C "$root/unpacked"
        test -x "$root/unpacked/go/bin/go"
        echo "GOROOT=$root/unpacked/go" >> "$GITHUB_ENV"
        echo "$root/unpacked/go/bin" >> "$GITHUB_PATH"

```

### 2. Install JDK 25.0.4+7

- Original source path: `.github/actions/setup-toolchain/action.yml`
- Original full-file SHA-256: `41b9e936fda5d76b878df77900793bfd063a4677b3aea441b61d5edbbf17d48b`
- Original file byte length: 4752; mode `0664`
- Bound source extent: first line 32, 928 bytes
- Exact step SHA-256: `a470e7526ca280dd6f492fd2a60ac313e0eb08fbcf6ec5ce4adde67df26d9a80`
- Historical status: `NONCOMPLIANT`

```yaml
    - name: Install JDK 25.0.4+7
      shell: bash
      run: |
        set -euo pipefail
        test "$(uname -s)" = Linux
        test "$(uname -m)" = x86_64
        root="$(mktemp -d "$RUNNER_TEMP/stargate-jdk.XXXXXX")"
        archive="$root/OpenJDK25U-jdk_x64_linux_hotspot_25.0.4_7.tar.gz"
        curl --fail --location --silent --show-error --output "$archive" \
          'https://github.com/adoptium/temurin25-binaries/releases/download/jdk-25.0.4%2B7/OpenJDK25U-jdk_x64_linux_hotspot_25.0.4_7.tar.gz'
        printf '%s  %s\n' \
          'e58fcdcd637b25c03ca84cbbcefc70d11efb8f4b4cbd05decc9f661769d77f94' "$archive" \
          | sha256sum -c -
        mkdir -p "$root/unpacked"
        tar -xzf "$archive" -C "$root/unpacked"
        java_home="$root/unpacked/jdk-25.0.4+7"
        test -x "$java_home/bin/java"
        echo "JAVA_HOME=$java_home" >> "$GITHUB_ENV"
        echo "$java_home/bin" >> "$GITHUB_PATH"

```

### 3. Install Python 3.12.15

- Original source path: `.github/actions/setup-toolchain/action.yml`
- Original full-file SHA-256: `41b9e936fda5d76b878df77900793bfd063a4677b3aea441b61d5edbbf17d48b`
- Original file byte length: 4752; mode `0664`
- Bound source extent: first line 52, 1827 bytes
- Exact step SHA-256: `1e41b54123366bdd3f2a022d2bdc506484ffd655f2031af0f407818224e82547`
- Historical status: `NONCOMPLIANT`

```yaml
    - name: Install Python 3.12.15
      shell: bash
      run: |
        set -euo pipefail
        test "$(uname -s)" = Linux
        test "$(uname -m)" = x86_64
        grep -Eq '^ID=ubuntu$' /etc/os-release
        grep -Eq '^VERSION_ID="24\.04"$' /etc/os-release
        root="$(mktemp -d "$RUNNER_TEMP/stargate-python.XXXXXX")"
        archive="$root/python-3.12.15-linux-24.04-x64.tar.gz"
        curl --fail --location --silent --show-error --output "$archive" \
          https://github.com/actions/python-versions/releases/download/3.12.15-36805895057/python-3.12.15-linux-24.04-x64.tar.gz
        printf '%s  %s\n' \
          'fcb672b0437c2d8df5565b7cc250b2b0d7455e2b8d6a4a107cfa6f2efe4f7ed8' "$archive" \
          | sha256sum -c -
        unpacked="$root/unpacked"
        mkdir -p "$unpacked" "$root/toolcache"
        tar -xzf "$archive" -C "$unpacked"
        test -f "$unpacked/setup.sh"
        test -f "$unpacked/lib/python3.12/ensurepip/_bundled/pip-25.0.1-py3-none-any.whl"
        toolcache="$root/toolcache"
        (
          while IFS='=' read -r name _; do
            case "$name" in PIP_*) unset "$name" ;; esac
          done < <(env)
          export AGENT_TOOLSDIRECTORY="$toolcache"
          export LD_LIBRARY_PATH="$unpacked/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
          export PIP_CONFIG_FILE=/dev/null
          export PIP_NO_INDEX=1
          export PIP_FIND_LINKS="$unpacked/lib/python3.12/ensurepip/_bundled"
          cd "$unpacked"
          bash ./setup.sh
        )
        python_home="$toolcache/Python/3.12.15/x64"
        test -x "$python_home/bin/python3.12"
        echo "pythonLocation=$python_home" >> "$GITHUB_ENV"
        echo "LD_LIBRARY_PATH=$python_home/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}" >> "$GITHUB_ENV"
        echo "$python_home/bin" >> "$GITHUB_PATH"

```

### 4. Install Node 20.20.2

- Original source path: `.github/actions/setup-toolchain/action.yml`
- Original full-file SHA-256: `41b9e936fda5d76b878df77900793bfd063a4677b3aea441b61d5edbbf17d48b`
- Original file byte length: 4752; mode `0664`
- Bound source extent: first line 91, 801 bytes
- Exact step SHA-256: `df9ce1f88c65d2774c95c89261045c465bb8372e156a25ec02da66dc667bbe22`
- Historical status: `NONCOMPLIANT`

```yaml
    - name: Install Node 20.20.2
      shell: bash
      run: |
        set -euo pipefail
        test "$(uname -s)" = Linux
        test "$(uname -m)" = x86_64
        root="$(mktemp -d "$RUNNER_TEMP/stargate-node.XXXXXX")"
        archive="$root/node-v20.20.2-linux-x64.tar.xz"
        curl --fail --location --silent --show-error --output "$archive" \
          https://nodejs.org/dist/v20.20.2/node-v20.20.2-linux-x64.tar.xz
        printf '%s  %s\n' \
          'df770b2a6f130ed8627c9782c988fda9669fa23898329a61a871e32f965e007d' "$archive" \
          | sha256sum -c -
        mkdir -p "$root/unpacked"
        tar -xJf "$archive" -C "$root/unpacked"
        node_home="$root/unpacked/node-v20.20.2-linux-x64"
        test -x "$node_home/bin/node"
        echo "$node_home/bin" >> "$GITHUB_PATH"
```

### 5. Install gitleaks 8.24.3

- Original source path: `.github/workflows/verify.yml`
- Original full-file SHA-256: `afaa298e205e8a7e4744520172afb28da04a466ac73b48430e1cc5b7d360e2f8`
- Original file byte length: 15610; mode `0664`
- Bound source extent: first line 78, 932 bytes
- Exact step SHA-256: `3d1ffe42194030a0c1aca40eb8f485503b3ed46adb7e3a028346ac58e4fb3bea`
- Historical status: `NONCOMPLIANT`

```yaml
      - name: Install gitleaks 8.24.3
        shell: bash
        run: |
          set -euo pipefail
          test "$(uname -s)" = Linux
          test "$(uname -m)" = x86_64
          root="$(mktemp -d "$RUNNER_TEMP/stargate-gitleaks.XXXXXX")"
          archive="$root/gitleaks_8.24.3_linux_x64.tar.gz"
          curl --fail --location --silent --show-error --output "$archive" \
            https://github.com/gitleaks/gitleaks/releases/download/v8.24.3/gitleaks_8.24.3_linux_x64.tar.gz
          printf '%s  %s\n' \
            '9991e0b2903da4c8f6122b5c3186448b927a5da4deef1fe45271c3793f4ee29c' "$archive" \
            | sha256sum -c -
          mkdir -p "$root/bin" "$root/unpacked"
          tar -xzf "$archive" -C "$root/unpacked" gitleaks
          test -x "$root/unpacked/gitleaks"
          install -m 0755 "$root/unpacked/gitleaks" "$root/bin/gitleaks"
          echo "GITLEAKS_BIN=$root/bin/gitleaks" >> "$GITHUB_ENV"

```

### 6. Prepare scan range

- Original source path: `.github/workflows/verify.yml`
- Original full-file SHA-256: `afaa298e205e8a7e4744520172afb28da04a466ac73b48430e1cc5b7d360e2f8`
- Original file byte length: 15610; mode `0664`
- Bound source extent: first line 97, 2339 bytes
- Exact step SHA-256: `694db4d7ee9919ccf46da4c269c0bf7fae32a520403b16af7d5d6eb5d8e6b0f4`
- Historical status: `NONCOMPLIANT`

```yaml
      - name: Prepare scan range
        id: prepare
        uses: actions/github-script@f28e40c7f34bde8b3046d885e986cb6290c5673b # v7
        with:
          script: |
            const validSha = value => typeof value === 'string' && /^[0-9a-f]{40}$/i.test(value);
            const setScan = (scan, logOpts = '') => {
              core.setOutput('scan', scan ? 'true' : 'false');
              core.setOutput('log_opts', logOpts);
            };
            try {
              if (context.eventName === 'push') {
                const commits = Array.isArray(context.payload.commits) ? context.payload.commits : [];
                if (commits.length === 0) {
                  core.info('Push contains no commits; verified binary acquisition completed and scan is skipped.');
                  setScan(false);
                } else {
                  const first = commits[0].id;
                  const last = commits[commits.length - 1].id;
                  if (!validSha(first) || !validSha(last)) throw new Error('Push endpoints are not full 40-character commit IDs.');
                  setScan(true, commits.length === 1 ? '--log-opts=-1' : `--log-opts=--no-merges --first-parent ${first}^..${last}`);
                }
              } else if (context.eventName === 'pull_request') {
                const { owner, repo } = context.repo;
                const response = await github.rest.pulls.listCommits({ owner, repo, pull_number: context.payload.number });
                const commits = response.data;
                if (!Array.isArray(commits) || commits.length === 0) throw new Error('Pull request commit list is empty.');
                const first = commits[0].sha;
                const last = commits[commits.length - 1].sha;
                if (!validSha(first) || !validSha(last)) throw new Error('Pull request endpoints are not full 40-character commit IDs.');
                setScan(true, `--log-opts=--no-merges --first-parent ${first}^..${last}`);
              } else if (context.eventName === 'workflow_dispatch') {
                setScan(true);
              } else {
                throw new Error(`Unsupported gitleaks event: ${context.eventName}`);
              }
            } catch (error) {
              core.setFailed(`Unable to prepare gitleaks scan: ${error.message}`);
            }

```

### 7. Run gitleaks

- Original source path: `.github/workflows/verify.yml`
- Original full-file SHA-256: `afaa298e205e8a7e4744520172afb28da04a466ac73b48430e1cc5b7d360e2f8`
- Original file byte length: 15610; mode `0664`
- Bound source extent: first line 137, 911 bytes
- Exact step SHA-256: `c7e702aafc75b4ddc4631481c0ebac22ddd7492066947ec543485b942515b1ee`
- Historical status: `NONCOMPLIANT`

```yaml
      - name: Run gitleaks
        id: scan
        if: steps.prepare.outputs.scan == 'true'
        env:
          SCAN_LOG_OPTS: ${{ steps.prepare.outputs.log_opts }}
        shell: bash
        run: |
          set -euo pipefail
          rm -f results.sarif
          args=(detect --redact -v --exit-code=2 --report-format=sarif --report-path=results.sarif --log-level=debug --config=.gitleaks.toml)
          if [[ -n "$SCAN_LOG_OPTS" ]]; then
            args+=("$SCAN_LOG_OPTS")
          fi
          set +e
          "$GITLEAKS_BIN" "${args[@]}"
          scan_rc=$?
          set -e
          printf 'exit_code=%s\n' "$scan_rc" >> "$GITHUB_OUTPUT"
          printf 'scan_ran=true\n' >> "$GITHUB_OUTPUT"
          if [[ -f results.sarif ]]; then
            printf 'report_present=true\n' >> "$GITHUB_OUTPUT"
          else
            printf 'report_present=false\n' >> "$GITHUB_OUTPUT"
          fi

```

### 8. Publish scan summary and PR comments

- Original source path: `.github/workflows/verify.yml`
- Original full-file SHA-256: `afaa298e205e8a7e4744520172afb28da04a466ac73b48430e1cc5b7d360e2f8`
- Original file byte length: 15610; mode `0664`
- Bound source extent: first line 162, 6131 bytes
- Exact step SHA-256: `614100bdfea282d94871ffa93c575f185efa3d6c739064c948891188d14bb3b0`
- Historical status: `NONCOMPLIANT`

```yaml
      - name: Publish scan summary and PR comments
        id: publish
        if: steps.prepare.outputs.scan == 'true'
        uses: actions/github-script@f28e40c7f34bde8b3046d885e986cb6290c5673b # v7
        env:
          SCAN_EXIT_CODE: ${{ steps.scan.outputs.exit_code }}
          REPORT_PRESENT: ${{ steps.scan.outputs.report_present }}
        with:
          script: |
            const fs = require('fs');
            const crypto = require('crypto');
            const MAX_BYTES = 16 * 1024 * 1024;
            const MAX_FINDINGS = 10000;
            const escapeHtml = value => String(value ?? '').replace(/[&<>"']/g, ch => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[ch]));
            const safeText = value => String(value ?? '').replace(/[\r\n\t]+/g, ' ').slice(0, 500);
            const fail = message => { core.setFailed(message); };
            try {
              const exitCode = Number(process.env.SCAN_EXIT_CODE);
              if (!Number.isInteger(exitCode) || exitCode < 0) throw new Error('Gitleaks exit status is missing or invalid.');
              if (process.env.REPORT_PRESENT !== 'true') throw new Error('Gitleaks did not create a fresh SARIF report.');
              const stat = fs.statSync('results.sarif');
              if (!stat.isFile() || stat.size > MAX_BYTES) throw new Error('Gitleaks SARIF is missing or exceeds the 16 MiB report limit.');
              const sarif = JSON.parse(fs.readFileSync('results.sarif', 'utf8'));
              if (!sarif || !Array.isArray(sarif.runs) || sarif.runs.length < 1 || !Array.isArray(sarif.runs[0].results)) throw new Error('Gitleaks SARIF has an invalid structure.');
              const findings = sarif.runs.flatMap(run => Array.isArray(run.results) ? run.results : []);
              if (findings.length > MAX_FINDINGS) throw new Error('Gitleaks SARIF exceeds the 10,000 finding limit.');
              const { owner, repo } = context.repo;
              const repositoryUrl = `https://github.com/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}`;
              const rows = [];
              const normalized = [];
              for (const finding of findings) {
                const loc = finding.locations?.[0]?.physicalLocation;
                const uri = loc?.artifactLocation?.uri;
                const line = loc?.region?.startLine;
                const fp = finding.partialFingerprints || {};
                const commit = fp.commitSha;
                if (typeof uri !== 'string' || !uri || uri.startsWith('/') || uri.split('/').includes('..') || !Number.isInteger(line) || line < 1 || typeof finding.ruleId !== 'string' || !finding.ruleId || typeof commit !== 'string' || !/^[0-9a-f]{40}$/i.test(commit)) {
                  throw new Error('Gitleaks SARIF contains a finding with invalid location or commit metadata.');
                }
                const pathUrl = uri.split('/').map(encodeURIComponent).join('/');
                const commitUrl = `${repositoryUrl}/commit/${commit}`;
                const findingUrl = `${repositoryUrl}/blob/${commit}/${pathUrl}#L${line}`;
                const author = safeText(fp.author);
                const date = safeText(fp.date);
                const email = safeText(fp.email);
                rows.push([
                  escapeHtml(finding.ruleId),
                  `<a href="${commitUrl}">${commit.slice(0, 7)}</a>`,
                  `<a href="${findingUrl}">View finding</a>`,
                  String(line),
                  escapeHtml(author),
                  escapeHtml(date),
                  escapeHtml(email),
                  `<a href="${repositoryUrl}/blob/${commit}/${pathUrl}">${escapeHtml(uri)}</a>`
                ]);
                const fingerprint = String(fp.commitSha) + ':' + uri + ':' + finding.ruleId + ':' + line;
                normalized.push({ finding, uri, line, commit, fingerprint, ruleId: finding.ruleId });
              }
              if (exitCode === 0) {
                if (findings.length !== 0) throw new Error('Gitleaks returned clean status with findings in SARIF.');
                await core.summary.addHeading('No leaks detected ✅').write();
              } else if (exitCode === 2) {
                const header = ['Rule ID','Commit','Finding','Start line','Author','Date','Email','File'].map((data, i) => ({data, header: true}));
                await core.summary.addHeading('🛑 Gitleaks detected secrets 🛑').addTable([header, ...rows]).write();
                if (context.eventName === 'pull_request' && normalized.length) {
                  const { owner, repo } = context.repo;
                  const pullNumber = context.payload.number;
                  const previous = await github.paginate(github.rest.pulls.listReviewComments, { owner, repo, pull_number: pullNumber });
                  for (const item of normalized) {
                    const alreadyPosted = previous.some(comment => comment.path === item.uri && comment.original_line === item.line && typeof comment.body === 'string' && comment.body.includes(item.fingerprint));
                    if (alreadyPosted) continue;
                    const body = `Gitleaks finding: rule \`${item.ruleId}\` at \`${item.uri}:${item.line}\`. Review the SARIF artifact for details.\n\n<!-- gitleaks-fingerprint:${item.fingerprint} -->`;
                    try {
                      await github.rest.pulls.createReviewComment({ owner, repo, pull_number: pullNumber, commit_id: item.commit, path: item.uri, side: 'RIGHT', line: item.line, body });
                    } catch (error) {
                      core.warning(`Gitleaks finding comment could not be posted for ${item.ruleId} at ${item.uri}:${item.line}; the scan remains failed.`);
                    }
                  }
                }
              } else {
                await core.summary.addHeading(`❌ Gitleaks exited with error [${exitCode}]`).write();
              }
              core.setOutput('report_status', 'ok');
            } catch (error) {
              fail(`Unable to publish gitleaks results: ${error.message}`);
            }

```

### 9. Return scan status

- Original source path: `.github/workflows/verify.yml`
- Original full-file SHA-256: `afaa298e205e8a7e4744520172afb28da04a466ac73b48430e1cc5b7d360e2f8`
- Original file byte length: 15610; mode `0664`
- Bound source extent: first line 258, 850 bytes
- Exact step SHA-256: `a3b673142c6b6499e49bb9b757ce7a9726e0297182ac293cddb80eb2614e9544`
- Historical status: `NONCOMPLIANT`

```yaml
      - name: Return scan status
        if: always()
        env:
          SHOULD_SCAN: ${{ steps.prepare.outputs.scan }}
          SCAN_EXIT_CODE: ${{ steps.scan.outputs.exit_code }}
          SUMMARY_OUTCOME: ${{ steps.publish.outcome }}
          ARTIFACT_OUTCOME: ${{ steps.artifact.outcome }}
        shell: bash
        run: |
          set -euo pipefail
          if [[ "$SHOULD_SCAN" != true ]]; then exit 0; fi
          if [[ "$SUMMARY_OUTCOME" != success || "$ARTIFACT_OUTCOME" != success ]]; then exit 1; fi
          case "$SCAN_EXIT_CODE" in
            0) exit 0 ;;
            2) exit 1 ;;
            ''|*[!0-9]*) exit 1 ;;
            *) exit "$SCAN_EXIT_CODE" ;;
          esac

  # Lightweight ticket-state sanity check: every ticket file parses, STATUS.md
  # regenerates cleanly. Catches frontmatter-yaml drift before review.
```

## Original T199 tests-first evidence JSON (complete original bytes)

- Original imported path: `.scratch/reports/2026-10-16-finish-tor-orchestration/T199-native-round1/original-import/source/specs/001-tor-route/evidence/T199-tests-first.json`
- SHA-256: `9ed06017e47ee3619d59c36f82592d8b0c5612af333958771c7f2518af1e3885`
- Byte length: 79284; mode `0664`
- Bound source snapshot: `675c852f10044853859088be36ce8d5fdcc2f34f60638a888695cae8fee18fc1`; round 1.

```json
{
  "schema": 1,
  "ticket": "T199",
  "baseline": "9317d8468fec8477115c6ce952ca26acb56896b4",
  "red": {
    "patch": "diff --git a/.github/actions/setup-toolchain/action.yml b/.github/actions/setup-toolchain/action.yml\nindex cbb2ca1..1f223aa 100644\n--- a/.github/actions/setup-toolchain/action.yml\n+++ b/.github/actions/setup-toolchain/action.yml\n@@ -1,48 +1,107 @@\n # Copyright 2026 The Stargate Authors\n # SPDX-License-Identifier: Apache-2.0\n #\n-# Composite action: install the stargate toolchain (Go, JDK 25, Python 3,\n-# Node 20) for use by CI workflows. Deduped from verify.yml + agent-task.yml\n-# so the two stay in sync.\n-#\n-# Mirrors what scripts/verify.sh self-detects at runtime; here we install\n-# every tool upfront so the gates exercise for real rather than SKIP.\n-#\n-# T191 item 4 (Constitution IV): every toolchain resolves to an exact\n-# version, so two runs of one commit use the same tools. Go is pinned to\n-# data-plane/go.mod's `toolchain` directive (this action's go-version-file\n-# would read only `go 1.26` and take the newest patch; ci_inputs_test.sh\n-# keeps the two equal). No\n-# cross-run cache is restored: a cache saved by any run on the default\n-# branch (including the auto-approving agent-task run) would otherwise feed\n-# its module, build or Maven bytes into every later verify run.\n+# Install the CI toolchain from immutable, digest-verified release archives.\n+# No setup-action or cross-run cache can supply executable bytes here.\n \n name: Set up stargate toolchain\n-description: Install exact Go 1.26.3, Temurin JDK 25.0.4+7, Python 3.12.15 and Node 20.20.2, with no cross-run caches.\n+description: Install exact Go 1.26.3, Temurin JDK 25.0.4+7, Python 3.12.15 and Node 20.20.2 from verified archives.\n \n runs:\n   using: composite\n   steps:\n-    - name: Set up Go\n-      uses: actions/setup-go@40f1582b2485089dde7abd97c1529aa768e1baff # v5\n-      with:\n-        go-version: '1.26.3'\n-        cache: false\n+    - name: Install Go 1.26.3\n+      shell: bash\n+      run: |\n+        set -euo pipefail\n+        test \"$(uname -s)\" = Linux\n+        test \"$(uname -m)\" = x86_64\n+        root=\"$(mktemp -d \"$RUNNER_TEMP/stargate-go.XXXXXX\")\"\n+        archive=\"$root/go1.26.3.linux-amd64.tar.gz\"\n+        curl --fail --location --silent --show-error --output \"$archive\" \\\n+          https://go.dev/dl/go1.26.3.linux-amd64.tar.gz\n+        printf '%s  %s\\n' \\\n+          '2b2cfc7148493da5e73981bffbf3353af381d5f93e789c82c79aff64962eb556' \"$archive\" \\\n+          | sha256sum -c -\n+        mkdir -p \"$root/unpacked\"\n+        tar -xzf \"$archive\" -C \"$root/unpacked\"\n+        test -x \"$root/unpacked/go/bin/go\"\n+        echo \"GOROOT=$root/unpacked/go\" >> \"$GITHUB_ENV\"\n+        echo \"$root/unpacked/go/bin\" >> \"$GITHUB_PATH\"\n \n-    - name: Set up JDK 25\n-      uses: actions/setup-java@cf277c60eb25467037889841efdb72551f06f6c3 # v4\n-      with:\n-        distribution: temurin\n-        java-version: '25.0.4+7'\n+    - name: Install JDK 25.0.4+7\n+      shell: bash\n+      run: |\n+        set -euo pipefail\n+        test \"$(uname -s)\" = Linux\n+        test \"$(uname -m)\" = x86_64\n+        root=\"$(mktemp -d \"$RUNNER_TEMP/stargate-jdk.XXXXXX\")\"\n+        archive=\"$root/OpenJDK25U-jdk_x64_linux_hotspot_25.0.4_7.tar.gz\"\n+        curl --fail --location --silent --show-error --output \"$archive\" \\\n+          'https://github.com/adoptium/temurin25-binaries/releases/download/jdk-25.0.4%2B7/OpenJDK25U-jdk_x64_linux_hotspot_25.0.4_7.tar.gz'\n+        printf '%s  %s\\n' \\\n+          'e58fcdcd637b25c03ca84cbbcefc70d11efb8f4b4cbd05decc9f661769d77f94' \"$archive\" \\\n+          | sha256sum -c -\n+        mkdir -p \"$root/unpacked\"\n+        tar -xzf \"$archive\" -C \"$root/unpacked\"\n+        java_home=\"$root/unpacked/jdk-25.0.4+7\"\n+        test -x \"$java_home/bin/java\"\n+        echo \"JAVA_HOME=$java_home\" >> \"$GITHUB_ENV\"\n+        echo \"$java_home/bin\" >> \"$GITHUB_PATH\"\n \n-    - name: Set up Python 3\n-      uses: actions/setup-python@a26af69be951a213d495a4c3e4e4022e16d87065 # v5\n-      with:\n-        python-version: '3.12.15'\n+    - name: Install Python 3.12.15\n+      shell: bash\n+      run: |\n+        set -euo pipefail\n+        test \"$(uname -s)\" = Linux\n+        test \"$(uname -m)\" = x86_64\n+        grep -Eq '^VERSION_ID=\"24\\.04\"$' /etc/os-release\n+        root=\"$(mktemp -d \"$RUNNER_TEMP/stargate-python.XXXXXX\")\"\n+        archive=\"$root/python-3.12.15-linux-24.04-x64.tar.gz\"\n+        curl --fail --location --silent --show-error --output \"$archive\" \\\n+          https://github.com/actions/python-versions/releases/download/3.12.15-36805895057/python-3.12.15-linux-24.04-x64.tar.gz\n+        printf '%s  %s\\n' \\\n+          'fcb672b0437c2d8df5565b7cc250b2b0d7455e2b8d6a4a107cfa6f2efe4f7ed8' \"$archive\" \\\n+          | sha256sum -c -\n+        unpacked=\"$root/unpacked\"\n+        mkdir -p \"$unpacked\" \"$root/toolcache\"\n+        tar -xzf \"$archive\" -C \"$unpacked\"\n+        test -f \"$unpacked/setup.sh\"\n+        test -f \"$unpacked/lib/python3.12/ensurepip/_bundled/pip-25.0.1-py3-none-any.whl\"\n+        toolcache=\"$root/toolcache\"\n+        (\n+          while IFS='=' read -r name _; do\n+            case \"$name\" in PIP_*) unset \"$name\" ;; esac\n+          done < <(env)\n+          export AGENT_TOOLSDIRECTORY=\"$toolcache\"\n+          export LD_LIBRARY_PATH=\"$unpacked/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}\"\n+          export PIP_CONFIG_FILE=/dev/null\n+          export PIP_NO_INDEX=1\n+          export PIP_FIND_LINKS=\"$unpacked/lib/python3.12/ensurepip/_bundled\"\n+          cd \"$unpacked\"\n+          bash ./setup.sh\n+        )\n+        python_home=\"$toolcache/Python/3.12.15/x64\"\n+        test -x \"$python_home/bin/python3.12\"\n+        echo \"pythonLocation=$python_home\" >> \"$GITHUB_ENV\"\n+        echo \"LD_LIBRARY_PATH=$python_home/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}\" >> \"$GITHUB_ENV\"\n+        echo \"$python_home/bin\" >> \"$GITHUB_PATH\"\n \n-    # Node 20 LTS is the CI pin for the extension JS unit tests\n-    # (extension/run-tests.sh, verify.sh Gate 2b) \u2014 research.md \u00a710.\n-    - name: Set up Node 20\n-      uses: actions/setup-node@49933ea5288caeca8642d1e84afbd3f7d6820020 # v4\n-      with:\n-        node-version: '20.20.2'\n+    - name: Install Node 20.20.2\n+      shell: bash\n+      run: |\n+        set -euo pipefail\n+        test \"$(uname -s)\" = Linux\n+        test \"$(uname -m)\" = x86_64\n+        root=\"$(mktemp -d \"$RUNNER_TEMP/stargate-node.XXXXXX\")\"\n+        archive=\"$root/node-v20.20.2-linux-x64.tar.xz\"\n+        curl --fail --location --silent --show-error --output \"$archive\" \\\n+          https://nodejs.org/dist/v20.20.2/node-v20.20.2-linux-x64.tar.xz\n+        printf '%s  %s\\n' \\\n+          'df770b2a6f130ed8627c9782c988fda9669fa23898329a61a871e32f965e007d' \"$archive\" \\\n+          | sha256sum -c -\n+        mkdir -p \"$root/unpacked\"\n+        tar -xJf \"$archive\" -C \"$root/unpacked\"\n+        node_home=\"$root/unpacked/node-v20.20.2-linux-x64\"\n+        test -x \"$node_home/bin/node\"\n+        echo \"$node_home/bin\" >> \"$GITHUB_PATH\"\ndiff --git a/.github/workflows/verify.yml b/.github/workflows/verify.yml\nindex be2ca13..b988fef 100644\n--- a/.github/workflows/verify.yml\n+++ b/.github/workflows/verify.yml\n@@ -59,34 +59,220 @@ jobs:\n           if-no-files-found: warn\n           retention-days: 14\n \n-  # Secret scan over full git history (T102 \u00a7Acceptance #3). gitleaks is the\n-  # authoritative scanner where installed; the local .githooks/pre-commit\n-  # fallback protects fresh machines without gitleaks. This job mirrors the\n-  # gate in CI so a secret that slips past a hook-less clone is still caught\n-  # before it reaches main or a release tag.\n-  #\n-  # Full history (fetch-depth: 0) is required \u2014 gitleaks detect walks commits.\n-  # Runs on push (main), PRs, and workflow_dispatch (the release-cadence\n-  # trigger this workflow already documents above). Uses the curated\n-  # .gitleaks.toml so detection matches the local fallback (T102 \u00a7Analysis).\n+  # Push and pull-request scans retain the original event-range selection;\n+  # workflow_dispatch scans the available full history. This is not a claim\n+  # that every push scans every historical commit.\n   secret-scan:\n-    name: gitleaks (history)\n+    name: gitleaks (verified event range)\n     runs-on: ubuntu-24.04\n     timeout-minutes: 10\n     permissions:\n       contents: read\n     steps:\n-      - name: Checkout (full history)\n+      - name: Checkout (history for event-range scan)\n         uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262 # v4\n         with:\n           fetch-depth: 0\n           persist-credentials: false   # T191: no job token in .git/config\n-      - name: gitleaks detect\n-        uses: gitleaks/gitleaks-action@ff98106e4c7b2bc287b24eaf42907196329070c7 # v2.3.9\n+\n+      - name: Install gitleaks 8.24.3\n+        shell: bash\n+        run: |\n+          set -euo pipefail\n+          test \"$(uname -s)\" = Linux\n+          test \"$(uname -m)\" = x86_64\n+          root=\"$(mktemp -d \"$RUNNER_TEMP/stargate-gitleaks.XXXXXX\")\"\n+          archive=\"$root/gitleaks_8.24.3_linux_x64.tar.gz\"\n+          curl --fail --location --silent --show-error --output \"$archive\" \\\n+            https://github.com/gitleaks/gitleaks/releases/download/v8.24.3/gitleaks_8.24.3_linux_x64.tar.gz\n+          printf '%s  %s\\n' \\\n+            '9991e0b2903da4c8f6122b5c3186448b927a5da4deef1fe45271c3793f4ee29c' \"$archive\" \\\n+            | sha256sum -c -\n+          mkdir -p \"$root/bin\" \"$root/unpacked\"\n+          tar -xzf \"$archive\" -C \"$root/unpacked\" gitleaks\n+          test -x \"$root/unpacked/gitleaks\"\n+          install -m 0755 \"$root/unpacked/gitleaks\" \"$root/bin/gitleaks\"\n+          echo \"GITLEAKS_BIN=$root/bin/gitleaks\" >> \"$GITHUB_ENV\"\n+\n+      - name: Prepare scan range\n+        id: prepare\n+        uses: actions/github-script@f28e40c7f34bde8b3046d885e986cb6290c5673b # v7\n+        with:\n+          script: |\n+            const validSha = value => typeof value === 'string' && /^[0-9a-f]{40}$/i.test(value);\n+            const setScan = (scan, logOpts = '') => {\n+              core.setOutput('scan', scan ? 'true' : 'false');\n+              core.setOutput('log_opts', logOpts);\n+            };\n+            try {\n+              if (context.eventName === 'push') {\n+                const commits = Array.isArray(context.payload.commits) ? context.payload.commits : [];\n+                if (commits.length === 0) {\n+                  core.info('Push contains no commits; verified binary acquisition completed and scan is skipped.');\n+                  setScan(false);\n+                } else {\n+                  const first = commits[0].id;\n+                  const last = commits[commits.length - 1].id;\n+                  if (!validSha(first) || !validSha(last)) throw new Error('Push endpoints are not full 40-character commit IDs.');\n+                  setScan(true, commits.length === 1 ? '--log-opts=-1' : `--log-opts=--no-merges --first-parent ${first}^..${last}`);\n+                }\n+              } else if (context.eventName === 'pull_request') {\n+                const { owner, repo } = context.repo;\n+                const response = await github.rest.pulls.listCommits({ owner, repo, pull_number: context.payload.number });\n+                const commits = response.data;\n+                if (!Array.isArray(commits) || commits.length === 0) throw new Error('Pull request commit list is empty.');\n+                const first = commits[0].sha;\n+                const last = commits[commits.length - 1].sha;\n+                if (!validSha(first) || !validSha(last)) throw new Error('Pull request endpoints are not full 40-character commit IDs.');\n+                setScan(true, `--log-opts=--no-merges --first-parent ${first}^..${last}`);\n+              } else if (context.eventName === 'workflow_dispatch') {\n+                setScan(true);\n+              } else {\n+                throw new Error(`Unsupported gitleaks event: ${context.eventName}`);\n+              }\n+            } catch (error) {\n+              core.setFailed(`Unable to prepare gitleaks scan: ${error.message}`);\n+            }\n+\n+      - name: Run gitleaks\n+        id: scan\n+        if: steps.prepare.outputs.scan == 'true'\n+        env:\n+          SCAN_LOG_OPTS: ${{ steps.prepare.outputs.log_opts }}\n+        shell: bash\n+        run: |\n+          set -euo pipefail\n+          rm -f results.sarif\n+          args=(detect --redact -v --exit-code=2 --report-format=sarif --report-path=results.sarif --log-level=debug --config=.gitleaks.toml)\n+          if [[ -n \"$SCAN_LOG_OPTS\" ]]; then\n+            args+=(\"$SCAN_LOG_OPTS\")\n+          fi\n+          set +e\n+          \"$GITLEAKS_BIN\" \"${args[@]}\"\n+          scan_rc=$?\n+          set -e\n+          printf 'exit_code=%s\\n' \"$scan_rc\" >> \"$GITHUB_OUTPUT\"\n+          printf 'scan_ran=true\\n' >> \"$GITHUB_OUTPUT\"\n+          if [[ -f results.sarif ]]; then\n+            printf 'report_present=true\\n' >> \"$GITHUB_OUTPUT\"\n+          else\n+            printf 'report_present=false\\n' >> \"$GITHUB_OUTPUT\"\n+          fi\n+\n+      - name: Publish scan summary and PR comments\n+        id: publish\n+        if: steps.prepare.outputs.scan == 'true'\n+        uses: actions/github-script@f28e40c7f34bde8b3046d885e986cb6290c5673b # v7\n         env:\n-          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}\n+          SCAN_EXIT_CODE: ${{ steps.scan.outputs.exit_code }}\n+          REPORT_PRESENT: ${{ steps.scan.outputs.report_present }}\n+        with:\n+          script: |\n+            const fs = require('fs');\n+            const crypto = require('crypto');\n+            const MAX_BYTES = 16 * 1024 * 1024;\n+            const MAX_FINDINGS = 10000;\n+            const escapeHtml = value => String(value ?? '').replace(/[&<>\"']/g, ch => ({'&':'&amp;','<':'&lt;','>':'&gt;','\"':'&quot;',\"'\":'&#39;'}[ch]));\n+            const safeText = value => String(value ?? '').replace(/[\\r\\n\\t]+/g, ' ').slice(0, 500);\n+            const fail = message => { core.setFailed(message); };\n+            try {\n+              const exitCode = Number(process.env.SCAN_EXIT_CODE);\n+              if (!Number.isInteger(exitCode) || exitCode < 0) throw new Error('Gitleaks exit status is missing or invalid.');\n+              if (process.env.REPORT_PRESENT !== 'true') throw new Error('Gitleaks did not create a fresh SARIF report.');\n+              const stat = fs.statSync('results.sarif');\n+              if (!stat.isFile() || stat.size > MAX_BYTES) throw new Error('Gitleaks SARIF is missing or exceeds the 16 MiB report limit.');\n+              const sarif = JSON.parse(fs.readFileSync('results.sarif', 'utf8'));\n+              if (!sarif || !Array.isArray(sarif.runs) || sarif.runs.length < 1 || !Array.isArray(sarif.runs[0].results)) throw new Error('Gitleaks SARIF has an invalid structure.');\n+              const findings = sarif.runs.flatMap(run => Array.isArray(run.results) ? run.results : []);\n+              if (findings.length > MAX_FINDINGS) throw new Error('Gitleaks SARIF exceeds the 10,000 finding limit.');\n+              const { owner, repo } = context.repo;\n+              const repositoryUrl = `https://github.com/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}`;\n+              const rows = [];\n+              const normalized = [];\n+              for (const finding of findings) {\n+                const loc = finding.locations?.[0]?.physicalLocation;\n+                const uri = loc?.artifactLocation?.uri;\n+                const line = loc?.region?.startLine;\n+                const fp = finding.partialFingerprints || {};\n+                const commit = fp.commitSha;\n+                if (typeof uri !== 'string' || !uri || uri.startsWith('/') || uri.split('/').includes('..') || !Number.isInteger(line) || line < 1 || typeof finding.ruleId !== 'string' || !finding.ruleId || typeof commit !== 'string' || !/^[0-9a-f]{40}$/i.test(commit)) {\n+                  throw new Error('Gitleaks SARIF contains a finding with invalid location or commit metadata.');\n+                }\n+                const pathUrl = uri.split('/').map(encodeURIComponent).join('/');\n+                const commitUrl = `${repositoryUrl}/commit/${commit}`;\n+                const findingUrl = `${repositoryUrl}/blob/${commit}/${pathUrl}#L${line}`;\n+                const author = safeText(fp.author);\n+                const date = safeText(fp.date);\n+                const email = safeText(fp.email);\n+                rows.push([\n+                  escapeHtml(finding.ruleId),\n+                  `<a href=\"${commitUrl}\">${commit.slice(0, 7)}</a>`,\n+                  `<a href=\"${findingUrl}\">View finding</a>`,\n+                  String(line),\n+                  escapeHtml(author),\n+                  escapeHtml(date),\n+                  escapeHtml(email),\n+                  `<a href=\"${repositoryUrl}/blob/${commit}/${pathUrl}\">${escapeHtml(uri)}</a>`\n+                ]);\n+                const fingerprint = String(fp.commitSha) + ':' + uri + ':' + finding.ruleId + ':' + line;\n+                normalized.push({ finding, uri, line, commit, fingerprint, ruleId: finding.ruleId });\n+              }\n+              if (exitCode === 0) {\n+                if (findings.length !== 0) throw new Error('Gitleaks returned clean status with findings in SARIF.');\n+                await core.summary.addHeading('No leaks detected \u2705').write();\n+              } else if (exitCode === 2) {\n+                const header = ['Rule ID','Commit','Finding','Start line','Author','Date','Email','File'].map((data, i) => ({data, header: true}));\n+                await core.summary.addHeading('\ud83d\uded1 Gitleaks detected secrets \ud83d\uded1').addTable([header, ...rows]).write();\n+                if (context.eventName === 'pull_request' && normalized.length) {\n+                  const { owner, repo } = context.repo;\n+                  const pullNumber = context.payload.number;\n+                  const previous = await github.paginate(github.rest.pulls.listReviewComments, { owner, repo, pull_number: pullNumber });\n+                  for (const item of normalized) {\n+                    const alreadyPosted = previous.some(comment => comment.path === item.uri && comment.original_line === item.line && typeof comment.body === 'string' && comment.body.includes(item.fingerprint));\n+                    if (alreadyPosted) continue;\n+                    const body = `Gitleaks finding: rule \\`${item.ruleId}\\` at \\`${item.uri}:${item.line}\\`. Review the SARIF artifact for details.\\n\\n<!-- gitleaks-fingerprint:${item.fingerprint} -->`;\n+                    try {\n+                      await github.rest.pulls.createReviewComment({ owner, repo, pull_number: pullNumber, commit_id: item.commit, path: item.uri, side: 'RIGHT', line: item.line, body });\n+                    } catch (error) {\n+                      core.warning(`Gitleaks finding comment could not be posted for ${item.ruleId} at ${item.uri}:${item.line}; the scan remains failed.`);\n+                    }\n+                  }\n+                }\n+              } else {\n+                await core.summary.addHeading(`\u274c Gitleaks exited with error [${exitCode}]`).write();\n+              }\n+              core.setOutput('report_status', 'ok');\n+            } catch (error) {\n+              fail(`Unable to publish gitleaks results: ${error.message}`);\n+            }\n+\n+      - name: Upload gitleaks SARIF\n+        id: artifact\n+        if: always() && steps.prepare.outputs.scan == 'true' && steps.scan.outputs.report_present == 'true'\n+        uses: actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02 # v4\n         with:\n-          config-path: .gitleaks.toml\n+          name: gitleaks-results.sarif\n+          path: results.sarif\n+          if-no-files-found: error\n+\n+      - name: Return scan status\n+        if: always()\n+        env:\n+          SHOULD_SCAN: ${{ steps.prepare.outputs.scan }}\n+          SCAN_EXIT_CODE: ${{ steps.scan.outputs.exit_code }}\n+          SUMMARY_OUTCOME: ${{ steps.publish.outcome }}\n+          ARTIFACT_OUTCOME: ${{ steps.artifact.outcome }}\n+        shell: bash\n+        run: |\n+          set -euo pipefail\n+          if [[ \"$SHOULD_SCAN\" != true ]]; then exit 0; fi\n+          if [[ \"$SUMMARY_OUTCOME\" != success || \"$ARTIFACT_OUTCOME\" != success ]]; then exit 1; fi\n+          case \"$SCAN_EXIT_CODE\" in\n+            0) exit 0 ;;\n+            2) exit 1 ;;\n+            ''|*[!0-9]*) exit 1 ;;\n+            *) exit \"$SCAN_EXIT_CODE\" ;;\n+          esac\n \n   # Lightweight ticket-state sanity check: every ticket file parses, STATUS.md\n   # regenerates cleanly. Catches frontmatter-yaml drift before review.\ndiff --git a/tests/contract/workflow/ci_inputs_test.sh b/tests/contract/workflow/ci_inputs_test.sh\nindex e065bd9..cfcfa37 100644\n--- a/tests/contract/workflow/ci_inputs_test.sh\n+++ b/tests/contract/workflow/ci_inputs_test.sh\n@@ -6,14 +6,22 @@ set -euo pipefail\n python3 - \"$(git rev-parse --show-toplevel)\" <<'PY'\n from pathlib import Path\n import hashlib\n+import json\n import os\n import re\n+import shlex\n import subprocess\n import sys\n import tempfile\n import textwrap\n \n root = Path(sys.argv[1])\n+contract_failures = []\n+\n+\n+def report_contract(condition, label, detail=''):\n+    if not condition:\n+        contract_failures.append(f'{label}: {detail}' if detail else label)\n \n \n def collect_sources(directory):\n@@ -72,11 +80,164 @@ def violations(files):\n     for path, source in files.items():\n         errors.extend(f'{path}: {issue}' for issue in t191_violations(source))\n     errors.extend(agent_boundary_violations(agent))\n+    workflow_pushes = []\n+    for path, source in files.items():\n+        if not path.startswith('.github/workflows/'):\n+            continue\n+        for job, body in job_blocks(source).items():\n+            for script in script_bodies(body):\n+                workflow_pushes.extend((path, job, command)\n+                                       for command in logical_shell_commands(script)\n+                                       if is_git_push(command))\n+    if len(workflow_pushes) != 1:\n+        errors.append(f'workflows: expected exactly one git push command, found {len(workflow_pushes)}')\n+    elif workflow_pushes[0][0:2] != ('.github/workflows/agent-task.yml', 'publish'):\n+        errors.append('workflows: the only git push must be in agent-task publish')\n+    errors.extend(acquisition_violations(files))\n     if not any(docker_cadence(source) for source in files.values()):\n         errors.append('no path-gated docker-cadence workflow for sidecar/Dockerfile changes')\n     return errors\n \n \n+def logical_shell_commands(source):\n+    \"\"\"Join shell continuations, discard comments, and split simple command lists.\n+\n+    This intentionally covers the checked-in workflow scripts, not arbitrary\n+    shell grammar. Quoting is handled by shlex; command separators are the\n+    supported list/pipeline operators used by these workflows.\n+    \"\"\"\n+    logical = []\n+    pending = ''\n+    for line in source.splitlines():\n+        stripped = line.rstrip()\n+        if not stripped or stripped.lstrip().startswith('#'):\n+            continue\n+        if stripped.endswith('\\\\'):\n+            pending += stripped[:-1] + ' '\n+            continue\n+        logical.append(pending + stripped)\n+        pending = ''\n+    if pending:\n+        logical.append(pending)\n+    commands = []\n+    for line in logical:\n+        lexer = shlex.shlex(line, posix=True, punctuation_chars=';&|')\n+        lexer.whitespace_split = True\n+        lexer.commenters = '#'\n+        words = []\n+        try:\n+            tokens = list(lexer)\n+        except ValueError:\n+            # The checked-in workflow has one valid nested-quote command\n+            # substitution (the HTTP auth header). It cannot begin a git\n+            # command, so omit that unsupported non-git form; every command\n+            # whose head is git remains within the parsed subset above.\n+            if re.match(r'^\\s*(?:[A-Za-z_][A-Za-z0-9_]*=\\S+\\s+)*git\\s', line):\n+                raise\n+            continue\n+        for token in tokens:\n+            if token and all(char in ';&|' for char in token):\n+                if words:\n+                    commands.append((line, words))\n+                    words = []\n+            else:\n+                words.append(token)\n+        if words:\n+            commands.append((line, words))\n+    return commands\n+\n+\n+def is_git_push(command):\n+    _, words = command\n+    for index, word in enumerate(words):\n+        if word != 'git':\n+            continue\n+        cursor = index + 1\n+        while cursor < len(words):\n+            option = words[cursor]\n+            if option in ('-c', '-C', '--git-dir', '--work-tree', '--namespace'):\n+                cursor += 2\n+            elif option.startswith('-'):\n+                cursor += 1\n+            else:\n+                break\n+        if cursor < len(words) and words[cursor] == 'push':\n+            return True\n+    return False\n+\n+\n+TOOLCHAIN_DIGESTS = {\n+    'Install Go 1.26.3': '2b2cfc7148493da5e73981bffbf3353af381d5f93e789c82c79aff64962eb556',\n+    'Install JDK 25.0.4+7': 'e58fcdcd637b25c03ca84cbbcefc70d11efb8f4b4cbd05decc9f661769d77f94',\n+    'Install Python 3.12.15': 'fcb672b0437c2d8df5565b7cc250b2b0d7455e2b8d6a4a107cfa6f2efe4f7ed8',\n+    'Install Node 20.20.2': 'df770b2a6f130ed8627c9782c988fda9669fa23898329a61a871e32f965e007d',\n+}\n+TOOLCHAIN_URLS = {\n+    'Install Go 1.26.3': 'https://go.dev/dl/go1.26.3.linux-amd64.tar.gz',\n+    'Install JDK 25.0.4+7': 'https://github.com/adoptium/temurin25-binaries/releases/download/jdk-25.0.4%2B7/OpenJDK25U-jdk_x64_linux_hotspot_25.0.4_7.tar.gz',\n+    'Install Python 3.12.15': 'https://github.com/actions/python-versions/releases/download/3.12.15-36805895057/python-3.12.15-linux-24.04-x64.tar.gz',\n+    'Install Node 20.20.2': 'https://nodejs.org/dist/v20.20.2/node-v20.20.2-linux-x64.tar.xz',\n+}\n+GITLEAKS_DIGEST = '9991e0b2903da4c8f6122b5c3186448b927a5da4deef1fe45271c3793f4ee29c'\n+GITLEAKS_URL = 'https://github.com/gitleaks/gitleaks/releases/download/v8.24.3/gitleaks_8.24.3_linux_x64.tar.gz'\n+\n+\n+def named_step(source, label):\n+    match = re.search(r'^\\s*- name: ' + re.escape(label) +\n+                      r'\\s*\\n(.*?)(?=^\\s*- name: |\\Z)', source, re.M | re.S)\n+    return match.group(1) if match else None\n+\n+\n+def acquisition_violations(files):\n+    errors = []\n+    toolchain = files.get('.github/actions/setup-toolchain/action.yml', '')\n+    for label, digest in TOOLCHAIN_DIGESTS.items():\n+        step = named_step(toolchain, label)\n+        if not step:\n+            errors.append(f'toolchain archive integrity: missing literal {label} step')\n+            continue\n+        download = step.find('curl --fail')\n+        check = step.find('sha256sum -c -')\n+        extract = step.find('tar ')\n+        if min(download, check, extract) < 0 or not download < check < extract:\n+            errors.append(f'toolchain archive integrity: {label} must checksum before extraction')\n+        if digest not in step:\n+            errors.append(f'toolchain archive integrity: {label} digest differs from the reviewed pin')\n+        if TOOLCHAIN_URLS[label] not in step:\n+            errors.append(f'toolchain archive integrity: {label} URL differs from the reviewed source')\n+        if 'actions/setup-' in step or 'actions/cache' in step:\n+            errors.append(f'toolchain archive integrity: {label} may not use a setup action or shared cache')\n+        if 'uname -s' not in step or 'Linux' not in step or 'uname -m' not in step or 'x86_64' not in step:\n+            errors.append(f'toolchain archive integrity: {label} must check Linux x86_64 before download')\n+        if label == 'Install Python 3.12.15':\n+            if '/etc/os-release' not in step or '24.04' not in step:\n+                errors.append('toolchain archive integrity: Python setup must check Ubuntu 24.04 before download')\n+            for value in ('PIP_CONFIG_FILE=/dev/null', 'PIP_NO_INDEX=1', 'PIP_FIND_LINKS=', 'AGENT_TOOLSDIRECTORY='):\n+                if value not in step:\n+                    errors.append(f'toolchain archive integrity: Python setup must isolate {value}')\n+    verify = files.get('.github/workflows/verify.yml', '')\n+    if re.search(r'uses:\\s*gitleaks/gitleaks-action@', verify):\n+        errors.append('gitleaks acquisition integrity: action-managed executable has no committed digest check')\n+    gitleaks = named_step(verify, 'Install gitleaks 8.24.3')\n+    if not gitleaks:\n+        errors.append('gitleaks acquisition integrity: missing literal Install gitleaks 8.24.3 step')\n+    else:\n+        download = gitleaks.find('curl --fail')\n+        check = gitleaks.find('sha256sum -c -')\n+        extract = gitleaks.find('tar ')\n+        if min(download, check, extract) < 0 or not download < check < extract:\n+            errors.append('gitleaks acquisition integrity: checksum must precede extraction and execution')\n+        if GITLEAKS_DIGEST not in gitleaks:\n+            errors.append('gitleaks acquisition integrity: digest differs from the reviewed pin')\n+        if GITLEAKS_URL not in gitleaks:\n+            errors.append('gitleaks acquisition integrity: URL differs from the reviewed source')\n+        if 'uname -s' not in gitleaks or 'Linux' not in gitleaks or 'uname -m' not in gitleaks or 'x86_64' not in gitleaks:\n+            errors.append('gitleaks acquisition integrity: must check Linux x86_64 before download')\n+        if 'actions/cache' in gitleaks:\n+            errors.append('gitleaks acquisition integrity: cross-run cache is forbidden')\n+    return errors\n+\n+\n # T191 item 4: runner images and toolchains resolve to exact versions, and no\n # cross-run cache can feed one run's bytes into another (a cache written by an\n # agent run on the default branch is restored by every later verify run).\n@@ -194,8 +355,10 @@ def agent_boundary_violations(agent):\n         errors.append('agent-task: the agent job must scope its token to contents: read')\n     if re.search(r'secrets\\.GITHUB_TOKEN|github\\.token', driver):\n         errors.append('agent-task: the agent job hands the GitHub token to a step')\n-    pushes = [(name, line) for name, body in jobs.items() for line in code_lines(body)\n-              if re.search(r'\\bgit\\b.*\\bpush\\b', line)]\n+    pushes = [(name, command[0]) for name, body in jobs.items()\n+              for script in script_bodies(body)\n+              for command in logical_shell_commands(script)\n+              if is_git_push(command)]\n     if len(pushes) != 1:\n         errors.append(f'agent-task: expected exactly one git push, found {len(pushes)}')\n     for name, line in pushes:\n@@ -242,7 +405,7 @@ def docker_cadence(source):\n \n \n actual = violations(sources)\n-assert not actual, '\\n'.join(actual)\n+report_contract(not actual, 'checked-in workflows satisfy their CI contracts', actual)\n \n # Exercise the literal run bodies without network or archive extraction. A\n # matching local archive must reach tar; one changed byte must stop first.\n@@ -296,7 +459,8 @@ def rejected(name, replacement, expected):\n     fixture = dict(sources)\n     fixture[name] = replacement\n     result = violations(fixture)\n-    assert any(expected in issue for issue in result), (expected, result)\n+    report_contract(any(expected in issue for issue in result),\n+                    f'rejection fixture: {expected}', result)\n \n verify = sources['.github/workflows/verify.yml']\n agent = sources['.github/workflows/agent-task.yml']\n@@ -340,18 +504,20 @@ rejected('.github/workflows/agent-task.yml',\n toolchain = '.github/actions/setup-toolchain/action.yml'\n rejected('.github/workflows/verify.yml', verify.replace('runs-on: ubuntu-24.04', 'runs-on: ubuntu-latest', 1),\n          'not a versioned image label')\n-rejected(toolchain, re.sub(r\"node-version: '[^']*'\", \"node-version: '20'\", sources[toolchain], count=1),\n-         'node toolchain is not an exact version')\n-rejected(toolchain, re.sub(r\"java-version: '[^']*'\", \"java-version: '25'\", sources[toolchain], count=1),\n-         'java toolchain is not an exact version')\n-rejected(toolchain, re.sub(r\"go-version: '[^']*'\", \"go-version-file: data-plane/go.mod\", sources[toolchain], count=1),\n-         'go toolchain is not an exact version')\n-rejected(toolchain, re.sub(r\"go-version: '[^']*'\", \"go-version: '1.26.2'\", sources[toolchain], count=1),\n-         'differs from data-plane/go.mod toolchain')\n-rejected(toolchain, sources[toolchain].replace('distribution: temurin', 'distribution: temurin\\n        cache: maven', 1),\n-         'cross-run toolchain cache enabled')\n-rejected(toolchain, sources[toolchain].replace('cache: false', 'cache: true', 1),\n-         'cross-run toolchain cache enabled')\n+for label in TOOLCHAIN_DIGESTS:\n+    current = sources[toolchain]\n+    step = named_step(current, label)\n+    assert step, label\n+    for needle, replacement, expected in (\n+            (TOOLCHAIN_DIGESTS[label], '0' * 64, 'digest differs from the reviewed pin'),\n+            (TOOLCHAIN_URLS[label], 'https://example.invalid/archive.tar.gz', 'URL differs from the reviewed source'),\n+            ('sha256sum -c -', 'sha256sum -x', 'must checksum before extraction')):\n+        mutated = current.replace(needle, replacement, 1)\n+        fixture = dict(sources)\n+        fixture[toolchain] = mutated\n+        issues = violations(fixture)\n+        report_contract(any(expected in issue for issue in issues),\n+                        f'{label} rejects {expected}', issues)\n rejected('.github/workflows/verify.yml', verify.replace('persist-credentials: false', 'fetch-tags: false', 1),\n          'checkout persists the job token')\n rejected('.github/workflows/agent-task.yml',\n@@ -370,6 +536,373 @@ rejected('.github/workflows/agent-task.yml',\n rejected('.github/workflows/agent-task.yml',\n          agent.replace('\"refs/heads/$AGENT_BRANCH:refs/heads/$AGENT_BRANCH\"', '\"refs/heads/$AGENT_BRANCH:refs/heads/main\"'),\n          'push refspec is not exactly agent/$TICKET')\n+\n+# T199: count shell logical commands, not physical lines or words in paths.\n+push_block = ('          git -c core.hooksPath=/dev/null \\\\\\n'\n+              '            -c \"http.https://github.com/.extraheader=AUTHORIZATION: basic $auth\" \\\\\\n'\n+              '            push --quiet \"https://github.com/$REPO.git\" '\n+              '\"refs/heads/$AGENT_BRANCH:refs/heads/$AGENT_BRANCH\"\\n')\n+driver_anchor = '          mkdir -p target/runs\\n'\n+report_contract(not agent_boundary_violations(agent),\n+                'unmutated workflow has exactly one publish push',\n+                agent_boundary_violations(agent))\n+moved_push = agent.replace(push_block, '', 1)\n+moved_push = moved_push.replace(driver_anchor, driver_anchor + push_block, 1)\n+report_contract(any('git push runs in the agent job' in issue\n+                    for issue in agent_boundary_violations(moved_push)),\n+                'continued push moved into the agent job is rejected',\n+                agent_boundary_violations(moved_push))\n+second_push = agent.replace(push_block, push_block + push_block, 1)\n+report_contract(any('expected exactly one git push, found 2' in issue\n+                    for issue in agent_boundary_violations(second_push)),\n+                'second continued push in another job is rejected',\n+                agent_boundary_violations(second_push))\n+no_real_push = agent.replace(push_block, '', 1)\n+no_real_push = no_real_push.replace(driver_anchor, driver_anchor +\n+                                    '          printf \"%s\\\\n\" \\'git push in /tmp/push is text only\\'\\n', 1)\n+report_contract(any('expected exactly one git push, found 0' in issue\n+                    for issue in agent_boundary_violations(no_real_push)),\n+                'quoted push text and a push-named path are not commands',\n+                agent_boundary_violations(no_real_push))\n+for false_command in (\"          printf '%s\\\\n' git push\\n\",\n+                      \"          echo git push\\n\"):\n+    false_push = agent.replace(push_block, '', 1)\n+    false_push = false_push.replace(driver_anchor, driver_anchor + false_command, 1)\n+    false_issues = agent_boundary_violations(false_push)\n+    report_contract(any('expected exactly one git push, found 0' in issue\n+                        for issue in false_issues),\n+                    f'non-git command arguments do not count as push: {false_command.strip()}',\n+                    false_issues)\n+\n+# Current version-only setup actions and the pinned gitleaks action are\n+# intentional legacy inputs: the bounded checker must recognize their missing\n+# archive identity before the workflow steps are changed.\n+legacy_toolchain = '''runs:\\n  using: composite\\n  steps:\\n    - name: Set up Go\\n      uses: actions/setup-go@40f1582b2485089dde7abd97c1529aa768e1baff\\n      with:\\n        go-version: '1.26.3'\\n        cache: false\\n    - name: Set up JDK 25\\n      uses: actions/setup-java@cf277c60eb25467037889841efdb72551f06f6c3\\n      with:\\n        java-version: '25.0.4+7'\\n    - name: Set up Python 3\\n      uses: actions/setup-python@a26af69be951a213d495a4c3e4e4022e16d87065\\n      with:\\n        python-version: '3.12.15'\\n    - name: Set up Node 20\\n      uses: actions/setup-node@49933ea5288caeca8642d1e84afbd3f7d6820020\\n      with:\\n        node-version: '20.20.2'\\n'''\n+legacy_toolchain_sources = dict(sources)\n+legacy_toolchain_sources['.github/actions/setup-toolchain/action.yml'] = legacy_toolchain\n+report_contract(any('toolchain archive integrity' in issue\n+                    for issue in violations(legacy_toolchain_sources)),\n+                'version-only setup actions are rejected',\n+                violations(legacy_toolchain_sources))\n+legacy_gitleaks_sources = dict(sources)\n+legacy_gitleaks_sources['.github/workflows/verify.yml'] = '''jobs:\\n  secret-scan:\\n    steps:\\n      - name: gitleaks detect\\n        uses: gitleaks/gitleaks-action@ff98106e4c7b2bc287b24eaf42907196329070c7\\n        with:\\n          config-path: .gitleaks.toml\\n'''\n+report_contract(any('gitleaks acquisition integrity' in issue\n+                    for issue in violations(legacy_gitleaks_sources)),\n+                'action-managed gitleaks acquisition is rejected',\n+                violations(legacy_gitleaks_sources))\n+gitleaks_step = named_step(verify, 'Install gitleaks 8.24.3')\n+assert gitleaks_step\n+for needle, replacement, expected in (\n+        (GITLEAKS_DIGEST, '0' * 64, 'digest differs from the reviewed pin'),\n+        (GITLEAKS_URL, 'https://example.invalid/gitleaks.tar.gz', 'URL differs from the reviewed source'),\n+        ('sha256sum -c -', 'sha256sum -x', 'checksum must precede extraction and execution')):\n+    fixture = dict(sources)\n+    fixture['.github/workflows/verify.yml'] = verify.replace(needle, replacement, 1)\n+    issues = violations(fixture)\n+    report_contract(any(expected in issue for issue in issues),\n+                    f'gitleaks rejects {expected}', issues)\n+\n+# Retrospective T199 controls: execute the newly written literal installer\n+# bodies with recording tools. The canonical RED above predates these bodies;\n+# this coverage is deliberately not represented as their tests-first RED.\n+def bounded_run(argv, *, cwd, env, timeout=10):\n+    result = subprocess.run(argv, cwd=cwd, env=env, capture_output=True,\n+                            text=True, timeout=timeout)\n+    output = result.stdout + result.stderr\n+    assert len(output.encode()) <= 64 * 1024, f'fixture output exceeded 64 KiB: {argv[0]}'\n+    return result.returncode, output\n+\n+\n+fixture_output_bytes = 0\n+\n+\n+def literal_install_fixture(label, source, url, digest, is_python=False):\n+    global fixture_output_bytes\n+    script = step_script(source, label) if 'step_script' in globals() else None\n+    if script is None:\n+        starts = list(re.finditer(r'(?m)^[ \\t]*- name: ' + re.escape(label) + r'[ \\t]*$', source))\n+        assert len(starts) == 1, label\n+        start = starts[0].end()\n+        end_match = re.search(r'(?m)^[ \\t]*- name: ', source[start:])\n+        step = source[start:start + end_match.start()] if end_match else source[start:]\n+        run = re.search(r'(?m)^([ \\t]*)run: \\|[ \\t]*$', step)\n+        assert run, label\n+        indent = len(run.group(1))\n+        lines = []\n+        for line in step[run.end():].splitlines():\n+            if line.strip() and len(line) - len(line.lstrip()) <= indent:\n+                break\n+            lines.append(line)\n+        script = textwrap.dedent('\\n'.join(lines))\n+    assert url in script and digest in script, label\n+    good = b'T199 recorded archive bytes\\n'\n+    script = script.replace(digest, hashlib.sha256(good).hexdigest(), 1)\n+    results = []\n+    for payload in (good, good + b'tampered'):\n+        with tempfile.TemporaryDirectory(prefix='stargate-t199-install-') as tmp:\n+            work = Path(tmp)\n+            bindir = work / 'bin'\n+            bindir.mkdir()\n+            archive = work / 'fixture.archive'\n+            archive.write_bytes(payload)\n+            marker = work / 'tar-called'\n+            for name, body in {\n+                'uname': '#!/bin/sh\\ncase \"$1\" in -s) echo Linux;; -m) echo x86_64;; *) exit 2;; esac\\n',\n+                'grep': '#!/bin/sh\\npattern=$2\\nprintf \"%b\\\\n\" \"$FIXTURE_OS_RELEASE\" | /usr/bin/grep -Eq \"$pattern\"\\n',\n+                'mktemp': '#!/bin/sh\\ncase \"$1\" in -d) shift;; esac\\nname=$(printf \"%s\" \"$1\" | sed s/XXXXXX/fixture/)\\nmkdir -p \"$name\"\\nprintf \"%s\\\\n\" \"$name\"\\n',\n+                'curl': '#!/bin/sh\\nwhile [ \"$#\" -gt 0 ]; do if [ \"$1\" = --output ]; then shift; dest=$1; fi; shift; done\\nprintf downloaded > \"$DOWNLOAD_MARKER\"\\ncp \"$FIXTURE_ARCHIVE\" \"$dest\"\\n',\n+                'tar': '''#!/bin/sh\n+set -eu\n+printf called > \"$TAR_MARKER\"\n+dest=\n+while [ \"$#\" -gt 0 ]; do if [ \"$1\" = -C ]; then shift; dest=$1; fi; shift; done\n+mkdir -p \"$dest\"\n+case \"$FIXTURE_LABEL\" in\n+  'Install Go 1.26.3') mkdir -p \"$dest/go/bin\"; : > \"$dest/go/bin/go\"; chmod +x \"$dest/go/bin/go\" ;;\n+  'Install JDK 25.0.4+7') mkdir -p \"$dest/jdk-25.0.4+7/bin\"; : > \"$dest/jdk-25.0.4+7/bin/java\"; chmod +x \"$dest/jdk-25.0.4+7/bin/java\" ;;\n+  'Install Node 20.20.2') mkdir -p \"$dest/node-v20.20.2-linux-x64/bin\"; : > \"$dest/node-v20.20.2-linux-x64/bin/node\"; chmod +x \"$dest/node-v20.20.2-linux-x64/bin/node\" ;;\n+  'Install gitleaks 8.24.3') mkdir -p \"$dest\"; : > \"$dest/gitleaks\"; chmod +x \"$dest/gitleaks\" ;;\n+  'Install Python 3.12.15') mkdir -p \"$dest/lib/python3.12/ensurepip/_bundled\"; : > \"$dest/setup.sh\"; : > \"$dest/lib/python3.12/ensurepip/_bundled/pip-25.0.1-py3-none-any.whl\" ;;\n+esac\n+''',\n+            }.items():\n+                path = bindir / name\n+                path.write_text(body)\n+                path.chmod(0o755)\n+            if is_python:\n+                setup = work / 'setup.sh'\n+                # The tar recorder creates this exact literal setup shim after\n+                # checksum; it validates the isolated first-execution contract.\n+                (bindir / 'tar').write_text((bindir / 'tar').read_text().replace(': > \"$dest/setup.sh\";', '''cat > \"$dest/setup.sh\" <<'SETUP'\n+#!/bin/bash\n+set -eu\n+[[ \"$PWD\" == \"$EXPECTED_UNPACKED\" ]]\n+[[ \"$AGENT_TOOLSDIRECTORY\" == \"$EXPECTED_TOOLCACHE\" ]]\n+[[ \"$LD_LIBRARY_PATH\" == \"$EXPECTED_UNPACKED/lib\" ]]\n+[[ \"$PIP_CONFIG_FILE\" == /dev/null && \"$PIP_NO_INDEX\" == 1 ]]\n+[[ \"$PIP_FIND_LINKS\" == \"$EXPECTED_UNPACKED/lib/python3.12/ensurepip/_bundled\" ]]\n+[[ -z \"${PIP_EXTRA_INDEX_URL:-}\" ]]\n+mkdir -p \"$AGENT_TOOLSDIRECTORY/Python/3.12.15/x64/bin\" \"$AGENT_TOOLSDIRECTORY/Python/3.12.15/x64/lib\"\n+: > \"$AGENT_TOOLSDIRECTORY/Python/3.12.15/x64/bin/python3.12\"\n+chmod +x \"$AGENT_TOOLSDIRECTORY/Python/3.12.15/x64/bin/python3.12\"\n+printf setup-ran > \"$SETUP_MARKER\"\n+SETUP\n+chmod +x \"$dest/setup.sh\";'''))\n+            env = dict(os.environ, PATH=str(bindir) + os.pathsep + os.environ['PATH'],\n+                       RUNNER_TEMP=tmp, GITHUB_PATH=str(work / 'github-path'),\n+                       GITHUB_ENV=str(work / 'github-env'), FIXTURE_ARCHIVE=str(archive),\n+                       TAR_MARKER=str(marker), DOWNLOAD_MARKER=str(work / 'downloaded'),\n+                       FIXTURE_OS_RELEASE='ID=ubuntu\\nVERSION_ID=\"24.04\"', FIXTURE_LABEL=label,\n+                       PIP_EXTRA_INDEX_URL='https://forbidden.invalid/',\n+                       EXPECTED_UNPACKED=str(work / 'stargate-python.fixture/unpacked'),\n+                       EXPECTED_TOOLCACHE=str(work / 'stargate-python.fixture/toolcache'),\n+                       SETUP_MARKER=str(work / 'setup-ran'))\n+            (work / 'github-path').write_text('')\n+            (work / 'github-env').write_text('')\n+            rc, output = bounded_run(['bash', '-e', '-o', 'pipefail', '-c', script],\n+                                     cwd=work, env=env)\n+            fixture_output_bytes += len(output.encode())\n+            assert fixture_output_bytes <= 1024 * 1024, 'aggregate fixture output exceeded 1 MiB'\n+            assert len([p for p in work.rglob('*')]) <= 64, f'{label}: fixture created over 64 paths'\n+            extracted = marker.exists()\n+            setup_ran = (work / 'setup-ran').exists()\n+            results.append((rc, extracted, setup_ran, output,\n+                            (work / 'github-path').read_text(),\n+                            (work / 'github-env').read_text()))\n+    positive, negative = results\n+    assert positive[0] == 0 and positive[1], f'{label} positive did not reach extraction: {positive[3]}'\n+    assert negative[0] != 0 and not negative[1], f'{label} tamper was not stopped before extraction: {negative[3]}'\n+    if is_python:\n+        assert positive[2], f'{label} did not execute isolated setup shim: {positive[3]}'\n+        assert 'pythonLocation=' in positive[5] and 'LD_LIBRARY_PATH=' in positive[5]\n+        assert positive[4].strip().endswith('/bin'), f'path={positive[4]!r}'\n+    elif label == 'Install Go 1.26.3':\n+        assert 'GOROOT=' in positive[5] and positive[4].strip().endswith('/go/bin')\n+    elif label == 'Install JDK 25.0.4+7':\n+        assert 'JAVA_HOME=' in positive[5] and positive[4].strip().endswith('/bin')\n+    elif label == 'Install gitleaks 8.24.3':\n+        assert positive[5].strip().startswith('GITLEAKS_BIN=')\n+    else:\n+        assert positive[4].strip().endswith('/bin')\n+    if is_python:\n+        with tempfile.TemporaryDirectory(prefix='stargate-t199-os-release-') as tmp:\n+            work = Path(tmp)\n+            bindir = work / 'bin'\n+            bindir.mkdir()\n+            archive = work / 'fixture.archive'\n+            archive.write_bytes(good)\n+            marker = work / 'tar-called'\n+            for name, body in {\n+                'uname': '#!/bin/sh\\ncase \"$1\" in -s) echo Linux;; -m) echo x86_64;; esac\\n',\n+                'grep': '#!/bin/sh\\npattern=$2\\nprintf \"%b\\\\n\" \"$FIXTURE_OS_RELEASE\" | /usr/bin/grep -Eq \"$pattern\"\\n',\n+                'mktemp': '#!/bin/sh\\ncase \"$1\" in -d) shift;; esac\\nname=$(printf \"%s\" \"$1\" | sed s/XXXXXX/fixture/)\\nmkdir -p \"$name\"; printf \"%s\\\\n\" \"$name\"\\n',\n+                'curl': '#!/bin/sh\\nprintf downloaded > \"$DOWNLOAD_MARKER\"\\nexit 99\\n',\n+                'tar': '#!/bin/sh\\nprintf extracted > \"$TAR_MARKER\"\\nexit 99\\n',\n+            }.items():\n+                p = bindir / name\n+                p.write_text(body)\n+                p.chmod(0o755)\n+            env = dict(os.environ, PATH=str(bindir) + os.pathsep + os.environ['PATH'],\n+                       RUNNER_TEMP=tmp, GITHUB_PATH=str(work / 'github-path'),\n+                       GITHUB_ENV=str(work / 'github-env'), FIXTURE_ARCHIVE=str(archive),\n+                       TAR_MARKER=str(marker), DOWNLOAD_MARKER=str(work / 'downloaded'),\n+                       FIXTURE_OS_RELEASE='ID=debian\\nVERSION_ID=\"24.04\"', FIXTURE_LABEL=label)\n+            (work / 'github-path').write_text('')\n+            (work / 'github-env').write_text('')\n+            rc, output = bounded_run(['bash', '-e', '-o', 'pipefail', '-c', script],\n+                                     cwd=work, env=env)\n+            report_contract(rc != 0 and not (work / 'downloaded').exists() and not marker.exists(),\n+                            'Python installer rejects a non-Ubuntu 24.04 runner before acquisition',\n+                            output)\n+\n+\n+toolchain_source = sources['.github/actions/setup-toolchain/action.yml']\n+for install_label, install_url in TOOLCHAIN_URLS.items():\n+    literal_install_fixture(install_label, toolchain_source, install_url,\n+                            TOOLCHAIN_DIGESTS[install_label],\n+                            is_python=(install_label == 'Install Python 3.12.15'))\n+literal_install_fixture('Install gitleaks 8.24.3', verify, GITLEAKS_URL, GITLEAKS_DIGEST)\n+\n+# Retrospective controls for the literal Actions scripts. These synthetic event\n+# and SARIF fixtures were added after the source-bound canonical RED above.\n+def github_script(source, label):\n+    begins = list(re.finditer(r'(?m)^[ \\t]*- name: ' + re.escape(label) + r'[ \\t]*$', source))\n+    assert len(begins) == 1, label\n+    tail = source[begins[0].end():]\n+    end = re.search(r'(?m)^[ \\t]*- name: ', tail)\n+    step = tail[:end.start()] if end else tail\n+    match = re.search(r'(?m)^([ \\t]*)script: \\|[ \\t]*$', step)\n+    assert match, label\n+    indent = len(match.group(1))\n+    lines = []\n+    for line in step[match.end():].splitlines():\n+        if line.strip() and len(line) - len(line.lstrip()) <= indent:\n+            break\n+        lines.append(line)\n+    return textwrap.dedent('\\n'.join(lines))\n+\n+\n+def run_js(script, event, payload=None, findings=None, scan_rc='0', report=True,\n+           malformed=False, comments=None, create_error=False, read_error=False):\n+    global fixture_output_bytes\n+    with tempfile.TemporaryDirectory(prefix='stargate-t199-js-') as tmp:\n+        work = Path(tmp)\n+        (work / 'literal.js').write_text(script)\n+        if report:\n+            value = '{invalid' if malformed else json.dumps({'runs': [{'results': findings or []}]})\n+            (work / 'results.sarif').write_text(value)\n+        harness = work / 'harness.js'\n+        harness.write_text(r'''const fs0=require('fs'), script=fs0.readFileSync(process.env.SCRIPT_FILE,'utf8');\n+const failures=[],outputs={},warnings=[],api=[];\n+const summary={text:'',addHeading(v){this.text+=String(v);return this},addTable(v){this.text+=JSON.stringify(v);return this},async write(){return this}};\n+const core={setFailed:v=>failures.push(String(v)),setOutput:(k,v)=>outputs[k]=v,info:()=>{},warning:v=>warnings.push(String(v)),summary};\n+const github={rest:{pulls:{listCommits:async p=>{api.push(['listCommits',p]);if(process.env.READ_ERROR==='prepare')throw Error('API failure');return {data:JSON.parse(process.env.COMMITS)}},listReviewComments:async p=>{api.push(['listReviewComments',p]);if(process.env.READ_ERROR==='comments')throw Error('API failure');return {data:[]}},createReviewComment:async p=>{api.push(['createReviewComment',p]);if(process.env.CREATE_ERROR==='true')throw Error('write denied')}}},paginate:async(fn,p)=>{await fn(p);return JSON.parse(process.env.PREVIOUS)}};\n+const context={eventName:process.env.EVENT,payload:JSON.parse(process.env.PAYLOAD),repo:{owner:'fixture',repo:'repo'}};\n+const fs=Object.create(fs0);\n+(async()=>{try{await new Function('require','core','github','context','process','return (async()=>{\\n'+script+'\\n})()')(n=>n==='fs'?fs:require(n),core,github,context,{env:process.env})}catch(e){failures.push('uncaught:'+e.message)}process.stdout.write(JSON.stringify({failures,outputs,warnings,api,summary:summary.text}))})().catch(e=>{process.stderr.write(e.stack);process.exitCode=2});\n+''')\n+        payload = dict(payload or {})\n+        commits = payload.pop('_commits', [])\n+        if commits:\n+            payload['commits'] = commits\n+        env = dict(os.environ, SCRIPT_FILE=str(work / 'literal.js'), EVENT=event,\n+                   PAYLOAD=json.dumps(payload), COMMITS=json.dumps(commits),\n+                   SCAN_EXIT_CODE=str(scan_rc), REPORT_PRESENT='true' if report else 'false',\n+                   PREVIOUS=json.dumps(comments or []), CREATE_ERROR=str(create_error).lower(),\n+                   READ_ERROR='comments' if read_error is True else ('prepare' if read_error == 'prepare' else ''))\n+        rc, output = bounded_run(['node', str(harness)], cwd=work, env=env)\n+        fixture_output_bytes += len(output.encode())\n+        assert fixture_output_bytes <= 1024 * 1024 and len([p for p in work.rglob('*')]) <= 64\n+        assert rc == 0 and len(output.encode()) <= 64 * 1024, output\n+        if (work / 'results.sarif').exists():\n+            assert (work / 'results.sarif').stat().st_size <= 64 * 1024\n+        return json.loads(output)\n+\n+\n+prepare_js = github_script(verify, 'Prepare scan range')\n+publish_js = github_script(verify, 'Publish scan summary and PR comments')\n+sha1, sha2 = '1' * 40, '2' * 40\n+\n+\n+def literal_run_script(source, label):\n+    begins = list(re.finditer(r'(?m)^[ \\t]*- name: ' + re.escape(label) + r'[ \\t]*$', source))\n+    assert len(begins) == 1, label\n+    tail = source[begins[0].end():]\n+    end = re.search(r'(?m)^[ \\t]*- name: ', tail)\n+    step = tail[:end.start()] if end else tail\n+    match = re.search(r'(?m)^([ \\t]*)run: \\|[ \\t]*$', step)\n+    assert match, label\n+    indent = len(match.group(1))\n+    lines = []\n+    for line in step[match.end():].splitlines():\n+        if line.strip() and len(line) - len(line.lstrip()) <= indent:\n+            break\n+        lines.append(line)\n+    return textwrap.dedent('\\n'.join(lines))\n+\n+\n+def workflow_shell_fixture(label, env_overrides, stale=False):\n+    with tempfile.TemporaryDirectory(prefix='stargate-t199-shell-') as tmp:\n+        work = Path(tmp)\n+        (work / 'bin').mkdir()\n+        (work / 'gitleaks').write_text('#!/bin/sh\\nset -eu\\ntest ! -e results.sarif\\nprintf \"%s\\\\n\" \"$@\" > \"$ARGS_FILE\"\\nprintf fresh > results.sarif\\nexit \"$FIXTURE_SCAN_RC\"\\n')\n+        (work / 'gitleaks').chmod(0o755)\n+        if stale:\n+            (work / 'results.sarif').write_text('stale')\n+        (work / 'github-output').write_text('')\n+        env = dict(os.environ, PATH=str(work / 'bin') + os.pathsep + os.environ['PATH'],\n+                   GITLEAKS_BIN=str(work / 'gitleaks'), GITHUB_OUTPUT=str(work / 'github-output'),\n+                   ARGS_FILE=str(work / 'args'), FIXTURE_SCAN_RC='0', SCAN_LOG_OPTS='')\n+        env.update(env_overrides)\n+        rc, output = bounded_run(['bash', '-e', '-o', 'pipefail', '-c',\n+                                  literal_run_script(verify, label)], cwd=work, env=env)\n+        assert rc == 0, output\n+        assert len(output.encode()) <= 64 * 1024 and len([p for p in work.rglob('*')]) <= 64\n+        return (work / 'args').read_text().splitlines(), (work / 'github-output').read_text(), (work / 'results.sarif').read_text()\n+\n+\n+scan_args, scan_outputs, fresh_report = workflow_shell_fixture(\n+    'Run gitleaks', {'FIXTURE_SCAN_RC': '2', 'SCAN_LOG_OPTS': f'--log-opts=--no-merges --first-parent {sha1}^..{sha2}'}, stale=True)\n+assert scan_args[:8] == ['detect', '--redact', '-v', '--exit-code=2', '--report-format=sarif', '--report-path=results.sarif', '--log-level=debug', '--config=.gitleaks.toml']\n+assert scan_args[-1] == f'--log-opts=--no-merges --first-parent {sha1}^..{sha2}'\n+assert 'exit_code=2' in scan_outputs and 'scan_ran=true' in scan_outputs and 'report_present=true' in scan_outputs\n+assert fresh_report == 'fresh'\n+\n+return_status = literal_run_script(verify, 'Return scan status')\n+for scan_code, summary_outcome, artifact_outcome, expected in (\n+        ('0', 'success', 'success', 0), ('2', 'success', 'success', 1),\n+        ('7', 'success', 'success', 7), ('0', 'failure', 'success', 1),\n+        ('0', 'success', 'failure', 1)):\n+    with tempfile.TemporaryDirectory(prefix='stargate-t199-return-') as tmp:\n+        env = dict(os.environ, SHOULD_SCAN='true', SCAN_EXIT_CODE=scan_code,\n+                   SUMMARY_OUTCOME=summary_outcome, ARTIFACT_OUTCOME=artifact_outcome)\n+        rc, output = bounded_run(['bash', '-e', '-o', 'pipefail', '-c', return_status], cwd=tmp, env=env)\n+        assert rc == expected and len(output.encode()) <= 64 * 1024\n+\n+empty_push = run_js(prepare_js, 'push', {'_commits': []})\n+assert empty_push['outputs'] == {'scan': 'false', 'log_opts': ''}, f'empty push: {empty_push}'\n+single_push = run_js(prepare_js, 'push', {'_commits': [{'id': sha1}]})\n+assert single_push['outputs'].get('log_opts') == '--log-opts=-1', f'single push: {single_push}'\n+assert run_js(prepare_js, 'push', {'_commits': [{'id': sha1}, {'id': sha2}]})['outputs']['log_opts'] == f'--log-opts=--no-merges --first-parent {sha1}^..{sha2}', 'multiple push'\n+assert run_js(prepare_js, 'pull_request', {'number': 7, '_commits': [{'sha': sha1}, {'sha': sha2}]})['outputs']['log_opts'] == f'--log-opts=--no-merges --first-parent {sha1}^..{sha2}', 'pull range'\n+assert run_js(prepare_js, 'workflow_dispatch')['outputs'] == {'scan': 'true', 'log_opts': ''}\n+assert run_js(prepare_js, 'push', {'_commits': [{'id': 'bad'}]})['failures']\n+assert run_js(prepare_js, 'pull_request', {'number': 7, '_commits': []})['failures']\n+assert run_js(prepare_js, 'pull_request', {'number': 7, '_commits': []}, read_error='prepare')['failures']\n+assert 'No leaks detected' in run_js(publish_js, 'push')['summary']\n+assert 'exited with error [7]' in run_js(publish_js, 'push', scan_rc='7')['summary']\n+assert run_js(publish_js, 'push', report=False)['failures']\n+assert run_js(publish_js, 'push', malformed=True)['failures']\n+leak = {'ruleId':'FixtureRule','partialFingerprints':{'commitSha':sha1,'author':'<author>','date':'today','email':'fixture@example.invalid'},'locations':[{'physicalLocation':{'artifactLocation':{'uri':'src/<fixture>.go'},'region':{'startLine':4}}}]}\n+leak_result = run_js(publish_js, 'pull_request', {'number':7}, [leak], '2')\n+assert 'FixtureRule' in leak_result['summary'] and '&lt;author&gt;' in leak_result['summary'] and leak_result['api'][-1][0] == 'createReviewComment'\n+dup = {'path':'src/<fixture>.go','original_line':4,'body':f'<!-- gitleaks-fingerprint:{sha1}:src/<fixture>.go:FixtureRule:4 -->'}\n+deduped = run_js(publish_js, 'pull_request', {'number':7}, [leak], '2', comments=[dup])\n+assert not any(call[0] == 'createReviewComment' for call in deduped['api'])\n+denied = run_js(publish_js, 'pull_request', {'number':7}, [leak], '2', create_error=True)\n+assert denied['warnings'] and not denied['failures']\n+assert run_js(publish_js, 'pull_request', {'number':7}, [leak], '2', read_error=True)['failures']\n+\n cadence = [p for p, s in sources.items() if docker_cadence(s)]\n assert len(cadence) == 1, cadence\n for missing in ('sidecars/**', '**/Dockerfile'):\n@@ -497,7 +1030,14 @@ def bundled_result(source):\n \n \n heads, result, exposed = bundled_result(agent)\n-assert heads == [f'{result} refs/heads/agent/T1'], (heads, result)\n-assert exposed, 'bundled agent branch lacks the implementation and state commits'\n-print('PASS: T141/T191 CI executable inputs, credential boundary, opencode deny rules and rejection fixtures')\n+report_contract(heads == [f'{result} refs/heads/agent/T1'],\n+                'bundle ref points to the result commit', (heads, result))\n+report_contract(exposed,\n+                'bundled agent branch lacks the implementation and state commits')\n+if contract_failures:\n+    print('FAIL: CI contract checks:')\n+    for failure in contract_failures:\n+        print(f'  - {failure}')\n+    raise SystemExit(1)\n+print('PASS: T199 continuation/acquisition contracts, retrospective literal installer and workflow-body controls, T191 credential boundary and bundle result')\n PY\n",
    "snapshot_sha256": "83963485528a8941edfce4b77709d6022561f151baa514b8c9b83076c91161d7",
    "command": [
      "bash",
      "tests/contract/workflow/ci_inputs_test.sh"
    ],
    "exit_code": 1,
    "output": "FAIL: CI contract checks:\n  - non-git command arguments do not count as push: printf '%s\\n' git push: ['agent-task: git push runs in the agent job', 'agent-task: the push job does not run after the agent job', 'agent-task: the push refspec is not exactly agent/$TICKET', 'agent-task: the pushed bundle refs are not checked before push', 'agent-task: the push job checks out repository code']\n  - non-git command arguments do not count as push: echo git push: ['agent-task: git push runs in the agent job', 'agent-task: the push job does not run after the agent job', 'agent-task: the push refspec is not exactly agent/$TICKET', 'agent-task: the pushed bundle refs are not checked before push', 'agent-task: the push job checks out repository code']\n  - Python installer rejects a non-Ubuntu 24.04 runner before acquisition\n"
  },
  "superseded": [
    {
      "phase": "assertion-reporter regression; preserved before canonical layered red",
      "baseline": "9317d8468fec8477115c6ce952ca26acb56896b4",
      "pre_fix_workflow_mutation_patch": "diff --git a/.github/workflows/agent-task.yml b/.github/workflows/agent-task.yml\nindex aa4c1c1..a32d066 100644\n--- a/.github/workflows/agent-task.yml\n+++ b/.github/workflows/agent-task.yml\n@@ -306,7 +306,7 @@ jobs:\n         run: |\n           out=\"$RUNNER_TEMP/agent-result\"\n           mkdir -p \"$out\"\n-          git update-ref \"refs/heads/$AGENT_BRANCH\" HEAD\n+          git update-ref \"refs/heads/$AGENT_BRANCH\" HEAD~1\n           git bundle create \"$out/branch.bundle\" \"refs/heads/$AGENT_BRANCH\"\n           for f in prompt agent-output; do\n             if [ -f \"target/runs/$TICKET.$f\" ]; then\n",
      "red": {
        "patch": "diff --git a/.github/workflows/agent-task.yml b/.github/workflows/agent-task.yml\nindex aa4c1c1..a32d066 100644\n--- a/.github/workflows/agent-task.yml\n+++ b/.github/workflows/agent-task.yml\n@@ -306,7 +306,7 @@ jobs:\n         run: |\n           out=\"$RUNNER_TEMP/agent-result\"\n           mkdir -p \"$out\"\n-          git update-ref \"refs/heads/$AGENT_BRANCH\" HEAD\n+          git update-ref \"refs/heads/$AGENT_BRANCH\" HEAD~1\n           git bundle create \"$out/branch.bundle\" \"refs/heads/$AGENT_BRANCH\"\n           for f in prompt agent-output; do\n             if [ -f \"target/runs/$TICKET.$f\" ]; then\n",
        "snapshot_sha256": "a83261eb3f35bd4f1169a2b56dba4490cc86f09730275db73c98a3ec7d7e3cca",
        "command": [
          "bash",
          "target/runs/T199-reporter-probe.sh"
        ],
        "exit_code": 1,
        "output": "{\n  \"control_exit\": 0,\n  \"mutation_exit\": 1,\n  \"checks\": {\n    \"nonzero\": true,\n    \"bundle-head-failure\": true,\n    \"exposure-failure\": false\n  },\n  \"output_sha256\": \"a955fd6e992fc621102879af6fbd1818152c5f7f03313b660fda259bb37ca9d1\",\n  \"output\": \"Traceback (most recent call last):\\n  File \\\"<stdin>\\\", line 494, in <module>\\nAssertionError: (['fb3209ff90aded27085fbdf65a1d00ce42e15f4b refs/heads/agent/T1'], '22f0425544e775efb5a49ae672d29ce833524d90')\\n\"\n}\n"
      },
      "green": {
        "snapshot_sha256": "57b84351ae5595337fd3bc6e69fa331769207626394db0bee74ca3dab595969d",
        "command": [
          "bash",
          "target/runs/T199-reporter-probe.sh"
        ],
        "exit_code": 0,
        "output": "{\n  \"control_exit\": 0,\n  \"mutation_exit\": 1,\n  \"checks\": {\n    \"nonzero\": true,\n    \"bundle-head-failure\": true,\n    \"exposure-failure\": true\n  },\n  \"output_sha256\": \"7e84c021d338c898e7f5f010c90c57b8aa5348035733cfabae83c611c55920fd\",\n  \"output\": \"FAIL: CI contract checks:\\n  - bundle ref points to the result commit: (['ca1985ec152d5347f3e49a46836aa0bac561bbc7 refs/heads/agent/T1'], '9eb5ed04766a95a6ebfda9a526a2201f0704afa2')\\n  - bundled agent branch lacks the implementation and state commits\\n\"\n}\n"
      },
      "probe": {
        "path": "target/runs/T199-reporter-probe.sh",
        "sha256": "e4b87e71c185a1dd04ea654c54ee048b6cb4bacbca30c142dc580491e4232c42",
        "mode": "0o755",
        "bytes": 1730,
        "red_result": {
          "control_exit": 0,
          "mutation_exit": 1,
          "checks": {
            "nonzero": true,
            "bundle-head-failure": true,
            "exposure-failure": false
          },
          "output_sha256": "a955fd6e992fc621102879af6fbd1818152c5f7f03313b660fda259bb37ca9d1",
          "output": "Traceback (most recent call last):\n  File \"<stdin>\", line 494, in <module>\nAssertionError: (['fb3209ff90aded27085fbdf65a1d00ce42e15f4b refs/heads/agent/T1'], '22f0425544e775efb5a49ae672d29ce833524d90')\n"
        },
        "green_result": {
          "control_exit": 0,
          "mutation_exit": 1,
          "checks": {
            "nonzero": true,
            "bundle-head-failure": true,
            "exposure-failure": true
          },
          "output_sha256": "7e84c021d338c898e7f5f010c90c57b8aa5348035733cfabae83c611c55920fd",
          "output": "FAIL: CI contract checks:\n  - bundle ref points to the result commit: (['ca1985ec152d5347f3e49a46836aa0bac561bbc7 refs/heads/agent/T1'], '9eb5ed04766a95a6ebfda9a526a2201f0704afa2')\n  - bundled agent branch lacks the implementation and state commits\n"
        }
      }
    },
    {
      "baseline": "9317d8468fec8477115c6ce952ca26acb56896b4",
      "red": {
        "patch": "diff --git a/.github/workflows/agent-task.yml b/.github/workflows/agent-task.yml\nindex aa4c1c1..a32d066 100644\n--- a/.github/workflows/agent-task.yml\n+++ b/.github/workflows/agent-task.yml\n@@ -306,7 +306,7 @@ jobs:\n         run: |\n           out=\"$RUNNER_TEMP/agent-result\"\n           mkdir -p \"$out\"\n-          git update-ref \"refs/heads/$AGENT_BRANCH\" HEAD\n+          git update-ref \"refs/heads/$AGENT_BRANCH\" HEAD~1\n           git bundle create \"$out/branch.bundle\" \"refs/heads/$AGENT_BRANCH\"\n           for f in prompt agent-output; do\n             if [ -f \"target/runs/$TICKET.$f\" ]; then\ndiff --git a/tests/contract/workflow/ci_inputs_test.sh b/tests/contract/workflow/ci_inputs_test.sh\nindex e065bd9..71536c3 100644\n--- a/tests/contract/workflow/ci_inputs_test.sh\n+++ b/tests/contract/workflow/ci_inputs_test.sh\n@@ -14,6 +14,12 @@ import tempfile\n import textwrap\n \n root = Path(sys.argv[1])\n+contract_failures = []\n+\n+\n+def report_contract(condition, label, detail=''):\n+    if not condition:\n+        contract_failures.append(f'{label}: {detail}' if detail else label)\n \n \n def collect_sources(directory):\n@@ -242,7 +248,7 @@ def docker_cadence(source):\n \n \n actual = violations(sources)\n-assert not actual, '\\n'.join(actual)\n+report_contract(not actual, 'checked-in workflows satisfy their CI contracts', actual)\n \n # Exercise the literal run bodies without network or archive extraction. A\n # matching local archive must reach tar; one changed byte must stop first.\n@@ -296,7 +302,8 @@ def rejected(name, replacement, expected):\n     fixture = dict(sources)\n     fixture[name] = replacement\n     result = violations(fixture)\n-    assert any(expected in issue for issue in result), (expected, result)\n+    report_contract(any(expected in issue for issue in result),\n+                    f'rejection fixture: {expected}', result)\n \n verify = sources['.github/workflows/verify.yml']\n agent = sources['.github/workflows/agent-task.yml']\n@@ -370,6 +377,51 @@ rejected('.github/workflows/agent-task.yml',\n rejected('.github/workflows/agent-task.yml',\n          agent.replace('\"refs/heads/$AGENT_BRANCH:refs/heads/$AGENT_BRANCH\"', '\"refs/heads/$AGENT_BRANCH:refs/heads/main\"'),\n          'push refspec is not exactly agent/$TICKET')\n+\n+# T199: count shell logical commands, not physical lines or words in paths.\n+push_block = ('          git -c core.hooksPath=/dev/null \\\\\\n'\n+              '            -c \"http.https://github.com/.extraheader=AUTHORIZATION: basic $auth\" \\\\\\n'\n+              '            push --quiet \"https://github.com/$REPO.git\" '\n+              '\"refs/heads/$AGENT_BRANCH:refs/heads/$AGENT_BRANCH\"\\n')\n+driver_anchor = '          mkdir -p target/runs\\n'\n+report_contract(not agent_boundary_violations(agent),\n+                'unmutated workflow has exactly one publish push',\n+                agent_boundary_violations(agent))\n+moved_push = agent.replace(push_block, '', 1)\n+moved_push = moved_push.replace(driver_anchor, driver_anchor + push_block, 1)\n+report_contract(any('git push runs in the agent job' in issue\n+                    for issue in agent_boundary_violations(moved_push)),\n+                'continued push moved into the agent job is rejected',\n+                agent_boundary_violations(moved_push))\n+second_push = agent.replace(push_block, push_block + push_block, 1)\n+report_contract(any('expected exactly one git push, found 2' in issue\n+                    for issue in agent_boundary_violations(second_push)),\n+                'second continued push in another job is rejected',\n+                agent_boundary_violations(second_push))\n+no_real_push = agent.replace(push_block, '', 1)\n+no_real_push = no_real_push.replace(driver_anchor, driver_anchor +\n+                                    '          printf \"%s\\\\n\" \\'git push in /tmp/push is text only\\'\\n', 1)\n+report_contract(any('expected exactly one git push, found 0' in issue\n+                    for issue in agent_boundary_violations(no_real_push)),\n+                'quoted push text and a push-named path are not commands',\n+                agent_boundary_violations(no_real_push))\n+\n+# Current version-only setup actions and the pinned gitleaks action are\n+# intentional legacy inputs: the bounded checker must recognize their missing\n+# archive identity before the workflow steps are changed.\n+legacy_toolchain = '''runs:\\n  using: composite\\n  steps:\\n    - name: Set up Go\\n      uses: actions/setup-go@40f1582b2485089dde7abd97c1529aa768e1baff\\n      with:\\n        go-version: '1.26.3'\\n        cache: false\\n    - name: Set up JDK 25\\n      uses: actions/setup-java@cf277c60eb25467037889841efdb72551f06f6c3\\n      with:\\n        java-version: '25.0.4+7'\\n    - name: Set up Python 3\\n      uses: actions/setup-python@a26af69be951a213d495a4c3e4e4022e16d87065\\n      with:\\n        python-version: '3.12.15'\\n    - name: Set up Node 20\\n      uses: actions/setup-node@49933ea5288caeca8642d1e84afbd3f7d6820020\\n      with:\\n        node-version: '20.20.2'\\n'''\n+legacy_toolchain_sources = dict(sources)\n+legacy_toolchain_sources['.github/actions/setup-toolchain/action.yml'] = legacy_toolchain\n+report_contract(any('toolchain archive integrity' in issue\n+                    for issue in violations(legacy_toolchain_sources)),\n+                'version-only setup actions are rejected',\n+                violations(legacy_toolchain_sources))\n+legacy_gitleaks_sources = dict(sources)\n+legacy_gitleaks_sources['.github/workflows/verify.yml'] = '''jobs:\\n  secret-scan:\\n    steps:\\n      - name: gitleaks detect\\n        uses: gitleaks/gitleaks-action@ff98106e4c7b2bc287b24eaf42907196329070c7\\n        with:\\n          config-path: .gitleaks.toml\\n'''\n+report_contract(any('gitleaks acquisition integrity' in issue\n+                    for issue in violations(legacy_gitleaks_sources)),\n+                'action-managed gitleaks acquisition is rejected',\n+                violations(legacy_gitleaks_sources))\n cadence = [p for p, s in sources.items() if docker_cadence(s)]\n assert len(cadence) == 1, cadence\n for missing in ('sidecars/**', '**/Dockerfile'):\n@@ -497,7 +549,14 @@ def bundled_result(source):\n \n \n heads, result, exposed = bundled_result(agent)\n-assert heads == [f'{result} refs/heads/agent/T1'], (heads, result)\n-assert exposed, 'bundled agent branch lacks the implementation and state commits'\n+report_contract(heads == [f'{result} refs/heads/agent/T1'],\n+                'bundle ref points to the result commit', (heads, result))\n+report_contract(exposed,\n+                'bundled agent branch lacks the implementation and state commits')\n+if contract_failures:\n+    print('FAIL: CI contract checks:')\n+    for failure in contract_failures:\n+        print(f'  - {failure}')\n+    raise SystemExit(1)\n print('PASS: T141/T191 CI executable inputs, credential boundary, opencode deny rules and rejection fixtures')\n PY\n",
        "snapshot_sha256": "b063971a58c07910dbfad54f598ec77cd414c4cdc77e436b8dba36689aa811be",
        "command": [
          "bash",
          "tests/contract/workflow/ci_inputs_test.sh"
        ],
        "exit_code": 1,
        "output": "FAIL: CI contract checks:\n  - continued push moved into the agent job is rejected: ['agent-task: the push refspec is not exactly agent/$TICKET']\n  - second continued push in another job is rejected\n  - quoted push text and a push-named path are not commands: ['agent-task: expected exactly one git push, found 2', 'agent-task: git push runs in the agent job', 'agent-task: the push job does not run after the agent job', 'agent-task: the push refspec is not exactly agent/$TICKET', 'agent-task: the pushed bundle refs are not checked before push', 'agent-task: the push job checks out repository code', 'agent-task: the push refspec is not exactly agent/$TICKET']\n  - version-only setup actions are rejected\n  - action-managed gitleaks acquisition is rejected\n  - bundle ref points to the result commit: (['52ab3c0e047af96855130d6a3cfe15d605021bfa refs/heads/agent/T1'], 'a5e5360f1809aac8b6de9e06f1d5a3eade0712df')\n  - bundled agent branch lacks the implementation and state commits\n"
      },
      "green": {
        "snapshot_sha256": "a40b8fcfc71cd2c0cb8182ca3aa238b2aa44c24b751018031314ef249904563b",
        "command": [
          "bash",
          "tests/contract/workflow/ci_inputs_test.sh"
        ],
        "exit_code": 0,
        "output": "PASS: T199 continuation/acquisition contracts, retrospective literal installer and workflow-body controls, T191 credential boundary and bundle result\n"
      }
    }
  ],
  "green": {
    "snapshot_sha256": "3e9fbbf406f1a8e0435aaa04faa6836ac41ac6e4ba7440f1e875f9646b6123e1",
    "command": [
      "bash",
      "tests/contract/workflow/ci_inputs_test.sh"
    ],
    "exit_code": 0,
    "output": "PASS: T199 continuation/acquisition contracts, retrospective literal installer and workflow-body controls, T191 credential boundary and bundle result\n"
  },
  "supplemental": {
    "chronology_limit": "The canonical source-bound RED predates the literal installer and github-script bodies. Their positive/tamper and workflow-behavior fixtures are retrospective and not claimed as tests-first RED for those bodies. A later separate source-bound RED captured the command-position scanner and Python runner-identity failures before their respective fixes.",
    "later_scoped_red": {
      "snapshot_sha256": "83963485528a8941edfce4b77709d6022561f151baa514b8c9b83076c91161d7",
      "exit_code": 1,
      "output": "FAIL: CI contract checks:\n  - non-git command arguments do not count as push: printf '%s\\n' git push: ['agent-task: git push runs in the agent job', 'agent-task: the push job does not run after the agent job', 'agent-task: the push refspec is not exactly agent/$TICKET', 'agent-task: the pushed bundle refs are not checked before push', 'agent-task: the push job checks out repository code']\n  - non-git command arguments do not count as push: echo git push: ['agent-task: git push runs in the agent job', 'agent-task: the push job does not run after the agent job', 'agent-task: the push refspec is not exactly agent/$TICKET', 'agent-task: the pushed bundle refs are not checked before push', 'agent-task: the push job checks out repository code']\n  - Python installer rejects a non-Ubuntu 24.04 runner before acquisition\n"
    },
    "fixture_control_history": {
      "classification": "harness setup/control failure, not product-property RED",
      "before_fix": "The closed-output-leader synthetic child remained alive after timeout cleanup; the actual entrypoint failed at the harness assertion. The fixture finally block killed only the exact recorded synthetic PID.",
      "after_fix": "The fixture passes after TERM/KILL of the exact owned process group, bounded inherited-pipe drain, and bounded leader reap."
    },
    "retrospective_controls": {
      "installer_steps": [
        "Install Go 1.26.3",
        "Install JDK 25.0.4+7",
        "Install Python 3.12.15",
        "Install Node 20.20.2",
        "Install gitleaks 8.24.3"
      ],
      "workflow_scripts": [
        "Prepare scan range",
        "Run gitleaks",
        "Publish scan summary and PR comments",
        "Return scan status"
      ],
      "coverage": "Matching synthetic archive bytes pass the actual sha256sum command and reach recording extraction; changed bytes fail before extraction. Python setup shim validates private toolcache, working directory, LD_LIBRARY_PATH, isolated pip, and Ubuntu ID/version checks. Workflow tests stub event/API/SARIF behavior locally. Scanner tests prove command-position matching and reject printf/echo arguments containing git push.",
      "bounds": "Each new literal fixture subprocess has a 10-second total deadline including reserved cleanup time, streams at most 64 KiB output, and cleans only its owned process group; aggregate captured output is <=1 MiB. Fixture file writes enforce <=4 MiB per file and <=64 existing paths before creation; SARIF fixtures <=64 KiB. Output-overflow and closed-leader timeout/child-cleanup self-tests pass."
    },
    "runtime_limits": {
      "ci_dispatched": false,
      "downloaded_tools_executed_locally": false,
      "external_api_or_comments": false,
      "full_verify_run": false,
      "docker_cadence_edit": false
    },
    "scope": "Six permanent paths; agent-task.yml temporary regression mutation was restored byte-identically before delivery."
  }
}
```

## Original GLM round-1 verdict (complete original bytes)

- Original imported path: `.scratch/reports/2026-10-16-finish-tor-orchestration/T199-native-round1/original-import/T199.review-glm.verdict`
- SHA-256: `5a3b259eca1c0164fca3add3365283cdd48d0b21b3fe7d7e5f5be25485704a58`
- Byte length: 16439; mode `0664`
- Bound source snapshot: `675c852f10044853859088be36ce8d5fdcc2f34f60638a888695cae8fee18fc1`; round 1.

```text
VERDICT: REWORK
REVIEWER: glm
TOOL: opencode
MODEL: zai-coding-plan/glm-5.3-flash
EFFORT: xhigh
SNAPSHOT: 675c852f10044853859088be36ce8d5fdcc2f34f60638a888695cae8fee18fc1
ROUND: 1
SUMMARY: T199 delivers all five acceptance items with genuine layered red/green evidence and a real supply-chain hardening (digest-pinned Go/JDK/Python/Node/gitleaks, no cross-run caches), but the rewritten push scanner's command-head-only grammar silently drops pushes executed via child-shell indirection (sh/bash -c) and command substitution — forms the pre-diff line scanner caught on a single line — so the exactly-one-push credential-boundary guard that is this ticket's core deliverable can be bypassed by one disguised line.
FINDINGS:
  - [Major] tests/contract/workflow/ci_inputs_test.sh:153-175 (is_git_push), 105-150 (logical_shell_commands) — the narrowed "git only at parsed command head" grammar does not count pushes executed through child-shell indirection or command substitution, although those lines execute a real push with the job's credentials; the pre-diff scanner (base line ~198, `\bgit\b.*\bpush\b` over code lines) matched the single-line forms. This is the security lane (T191 publish-token boundary) and the intent of AC1's exactly-one-push invariant.
    WRONG: append `sh -c 'git push --quiet "https://github.com/$REPO.git" "refs/heads/$AGENT_BRANCH:refs/heads/$AGENT_BRANCH"'` (or `bash -c "git push …"`, or `OUT=$(git push --quiet …)`) to the publish job body → shlex yields words ['sh','-c','git push --quiet …']; is_git_push returns False at line 164 (head 'sh' ≠ 'git'; the quoted -c argument is one word, never re-parsed); for the substitution form line 160's assignment regex `^[A-Za-z_][A-Za-z0-9_]*=.*` absorbs 'OUT=$(git' and line 164 then sees words[1]='push' ≠ 'git'. Both report exactly-one-push, entrypoint exits 0, the workflow merges, and a second unauthorized push runs with publish-job (push-capable) credentials. EXPECTED: a push that actually executes through sh/bash -c or a command substitution must be counted by the exactly-one-push check (or fail closed), and the entrypoint must exit nonzero with a named property failure; printf/echo text forms must remain non-counted.
    EVIDENCE: tests/contract/workflow/ci_inputs_test.sh:160,164,167-175 — the only push detection in the repo (global count at :86-98 and boundary count at :367-370 both route through is_git_push); every other boundary check (refspec, needs:, token-step, bundle-parse) iterates only detected pushes, so nothing else catches these forms. Reachability: any workflow edit (the modeled auto-approving-agent threat in the file's own comments at :250-255 and agent-task.yml header) reaches violations()/agent_boundary_violations() on every verify run.
    FALSIFICATION-ATTEMPT: (1) searched .github/workflows/ and the whole test for any second push guard — none; (2) tried to defeat the claim via the refspec/token checks — they operate only on detected pushes, so they cannot fire; (3) manually traced shlex(posix, whitespace_split, punctuation_chars=';&|') semantics for all three forms against the exact embedded function bodies — quoted -c content stays one token, `$(git` is an ordinary character pair, no ;&| splitting applies; (4) the recorded red in evidence/T199-tests-first.json (printf '%s\n' git push counted by the intermediate scanner, rejected by the final one) confirms this shlex configuration's word-level behavior. DIRECT EXECUTION LIMIT: my sandbox denied `python3 -c`/heredoc/`bash tests/…` execution, so the three probe lines were verified by manual tracing, not execution — stated as a capability limit, with the trace and recorded-evidence corroboration given.
    EVALUATED-AS: (a) new red fixture in the style of :558-584 — insert `sh -c 'git push --quiet origin agent/T1:agent/T1'` into the publish step body and require a named push-count/boundary contract failure; same for `OUT=$(git push --quiet origin agent/T1:agent/T1)`; (b) entrypoint probe — a fixture tree containing that publish body must make `bash tests/contract/workflow/ci_inputs_test.sh` exit nonzero listing the new failure, while the printf/echo negative fixtures and the unmutated positive control still pass; then re-capture canonical red/green with `python3 scripts/test-first-evidence.py red T199 -- bash tests/contract/workflow/ci_inputs_test.sh` per AC2.
  - [Minor] specs/001-tor-route/evidence/T199-tests-first.json — AC5's required record is incomplete: the acceptance says "Record this existing coverage retrospectively in T199 evidence", but the evidence artifact only records `runtime_limits.docker_cadence_edit: false` (:134); the actual inspection finding — docker-cadence.yml at START already covers data-plane/** and **/Dockerfile under both push.paths and pull_request.paths — appears only in ticket prose, not in the named evidence file.
    WRONG: a reader of T199-tests-first.json finds no cadence-coverage inspection record and cannot close AC5 from the evidence alone. EXPECTED: a supplemental line recording the verified existing coverage (e.g. under supplemental: "ac5_existing_cadence_coverage: docker-cadence.yml at base 9317d84 lists data-plane/** and **/Dockerfile under both push.paths and pull_request.paths; verified, no edit made").
    EVIDENCE: evidence/T199-tests-first.json:129-135 vs ticket §Acceptance 5; I independently verified the coverage claim is TRUE against `git show 9317d84:.github/workflows/docker-cadence.yml` (lines 24-28, 36-40: both globs under both events).
    FALSIFICATION-ATTEMPT: searched the evidence JSON for any cadence/data-plane mention — only docker_cadence_edit:false; checked whether the ticket itself counts as the record — it is the spec, not the evidence artifact the acceptance names.
    EVALUATED-AS: the supplemental record exists in T199-tests-first.json and `python3 scripts/test-first-evidence.py check T199` still passes (re-pin the affected receipt; doc-only change to a file this diff already adds).
  - [Minor] .github/workflows/verify.yml:165-230 ("Publish scan summary and PR comments") — the PR-review-comment machinery is structurally inert under the job's `permissions: contents: read`: github-script's default token is the job token, and createReviewComment requires pull_requests:write; a 403 from `github.paginate(github.rest.pulls.listReviewComments, …)` lands in the outer catch and converts a leaky-PR failure into "Unable to publish gitleaks results" (the per-comment 403 path only warns). Outcome stays fail-closed and this is parity with the replaced gitleaks-action (same token scope), so no regression — but the dedup/comment code is a dead path and the failure reason is misleading on the paginate-403 path.
    WRONG: PR with leaks → summary table written, then either per-comment warnings or an outer "Unable to publish gitleaks results: …" failure; no comment is ever posted under contents:read. EXPECTED: either a workflow comment stating comments are best-effort and normally denied under contents:read, or an explicit maintainer decision to grant pull_requests: write (behavior change; out of this ticket's scope per §Out-of-scope "not … which events run it" spirit — doc-only by default).
    EVIDENCE: verify.yml publish step (job permissions at verify.yml:68-69); catch block wraps the paginate call before per-comment try/catch.
    FALSIFICATION-ATTEMPT: checked whether github-script uses a different token input — none specified, so the job-scoped token applies; confirmed the old action used the same secrets.GITHUB_TOKEN under the same job permissions (parity, so not Major).
    EVALUATED-AS: a comment in verify.yml's publish step documenting best-effort comment behavior under contents:read (doc-only, file already in this diff); existing run_js fixtures (denied/read_error cases at tests/…/ci_inputs_test.sh:1067-1069) already pin both 403 behaviors.
FALSIFIED-AND-DROPPED:
  - "Job summary may leak matched secret values" — the new publish script renders rule id, commit/finding links and escaped author/date/email only (escapeHtml/safeText, verify.yml publish step); the matched secret text is never rendered, unlike even the old action's 'View Secret' label.
  - "Python setup.sh pip upgrade fetches unpinned bytes from PyPI" — the action unsets all inherited PIP_* vars then sets PIP_CONFIG_FILE=/dev/null, PIP_NO_INDEX=1, PIP_FIND_LINKS to the digest-verified archive's bundled wheel (action.yml Python step); the fixture injects PIP_EXTRA_INDEX_URL and proves it is stripped before setup.sh runs (tests/…/ci_inputs_test.sh:849,861).
  - "agent-task.yml modified in violation of §Out-of-scope" — `git diff 9317d84 -- .github/workflows/agent-task.yml` is empty; byte-identical restoration verified.
  - "STATUS.md count drift" — 15→14 pending and 0→1 in-review match the single T199 transition; row moved from runnable to In flight consistently.
  - "verify.yml ticket-state / release.yml setup-python contradict the new acquisition guard" — t191_violations only requires exact version strings ('3.12.15' is exact) and SHA-pinned uses; the version-only-toolchain red fixture is a self-contained source string; those jobs are pre-existing and outside the six-path budget → RECOMMENDED-FOLLOW-UP.
  - "docker_cadence() checker requires sidecars/** while the ticket names data-plane/**" — the checker is pre-existing (base line 223) and unchanged; the workflow carries both globs plus data-plane/**; the new fixtures at :1071-1076 only pin the checker's ability to fail, which is non-vacuous (removing either glob flips it).
RECOMMENDED-FOLLOW-UP:
  - New ticket: apply the same digest-verified acquisition discipline to actions/setup-python in verify.yml ticket-state and release.yml (3 jobs) — SHA-pinned action but version-managed toolchain, exactly the class item 3 eliminated for setup-toolchain.
  - First real CI dispatch should confirm the PR-event path end-to-end (pulls.listCommits reachability under contents:read; per-comment 403 warnings; artifact upload) — the ticket itself records runner usability as NOT RUN, and the mechanical report confirms no CI was dispatched.
  - Consider a follow-up to document the scanner's grammar boundary (indirection/substitution handling) in the is_git_push docstring once Finding 1's fix lands, so the next grammar change re-runs the same red/green discipline.
DISPOSITION: (round 1 — no prior items)
ACCEPTANCE ADJUDICATION:
  - AC1 (continuation join; push-vs-path counting; three fixture bullets): MET and EVIDENCED — logical_shell_commands joins continuations (:118-124), is_git_push rejects the push-named path and printf/echo text (:569-584); moved-push and second-push fixtures (:558-568); unmutated positive control (:555-557); recorded layered red (superseded[1]) shows all three fixtures failing pre-fix; final green snapshot 3e9fbbf4… equals the mechanical report's boundhash. (Residual grammar gap → Finding 1.)
  - AC2 (reporter regression + canonical layered red/green): MET and EVIDENCED — pinned probe (sha256 e4b87e71…, mode 0o755, 1730 bytes) with preserved pre/post outputs in superseded[0]: pre-fix shows only the first AssertionError; post-fix shows both named bundle failures + nonzero with control_exit 0; canonical red captured via the evidence tool with the staged bundle-ref reversal (superseded[1].red lists seven property failures), green with the identical command; named-FAIL list vs traceback distinguishes property failures from setup errors.
  - AC3 (digest-verified toolchains; test red on version-only action): MET and EVIDENCED — all four toolchain steps download → sha256sum -c - → extract, no setup actions/caches; digests publisher-sourced per the retained grounding data (verified-selected-inputs.json: adoptium checksum link, python archive with real download and matching expected/actual sha256); legacy action fixture (:589-595) is the at-base action verbatim and fails the acquisition check; green after. The "must be shown from pinned source, not assumed" clause is dissolved: nothing delegates verification to unpinned internals any more; Python's setup.sh ships inside the digest-verified archive and is forced offline (Finding analysis under FALSIFIED-AND-DROPPED).
  - AC4 (gitleaks acquisition): MET and EVIDENCED — (a) recorded in ticket §Implementation evidence and consistent with the retained action sources (8.24.3 default; restoreCache/downloadTool/extractTar; no digest); (b) verify.yml installs a digest-checked binary with no cache restore; (c) legacy action-based workflow fixture fails ('gitleaks acquisition integrity'), digest/URL/checksum-order mutations each fail, green after.
  - AC5 (docker-cadence record-only): MET in substance — verified at base that data-plane/** and **/Dockerfile cover both producer trees under both push.paths and pull_request.paths; workflow untouched; no RED invented; no CI-run claim. Record location incomplete → Finding 2 (Minor).
SECURITY-LANE WALK (verified absent / findings):
  - DNS handling: no product DNS surface in diff; searched for net.LookupHost / InetAddress.getByName / browser.dns / resolved-IP proxy returns — none. Verified absent.
  - Header/payload inspection: no data-plane code touched; tunneled bytes untouched. Verified absent.
  - Logs and metrics: product logging untouched; CI job summary shows commit metadata only (parity with replaced action, now HTML-escaped; secret values not rendered). Verified absent for product surfaces.
  - Sidecar contracts / digest pins: every `uses:` in touched workflows is a 40-hex SHA pin (checkout 11d5960…, github-script f28e40c…, upload-artifact ea165f8…); all downloaded executables (Go/JDK/Python/Node/gitleaks) verified against committed digests before extraction; no actions/cache anywhere in the new acquisition paths; the new test enforces all of it with red fixtures. Verified.
  - Auth bypass: no listeners/endpoints/RPC in diff; agent boundary checks preserved verbatim from base (driver detection, write-token, contents:read, token-to-step, needs:, refspec, bundle list-heads, checkout, bundle-parse-token) and exercised by fixtures. Verified absent (modulo Finding 1's push-count core).
  - Port binding / reachability: no listener changes. Verified absent.
  - Browser extension: untouched. Verified absent.
  - Inter-plane leaks: N/A to this diff. Verified absent.
  - Update channel (Constitution IV): this diff is the hardening — pinned digests, no background auto-update, pip forced offline; the only remaining version-managed acquisitions (setup-python in ticket-state/release.yml) are pre-existing, outside budget → follow-up. Verified.
  - Cover/decoy traffic: no timers or unsolicited network emissions added. Verified absent.
  - Outbound connections (Constitution III): every new network touch is a CI-runner acquisition from a pinned publisher URL with a committed digest, or the same GitHub API reads the replaced action already made. No DP/CP egress changes. Verified.
  - AUDIT-EVASION / overclaiming: workflow comments and the ticket state event-range semantics honestly ("not a claim that every push scans every historical commit"); evidence JSON records chronology limits, control-fixture classification, and NOT-RUN limits; nothing claims runner usability. Constitution V satisfied.
TEST DISCIPLINE (Principle VII): privacy_critical:true — new behaviors carry real tests; each new fixture class has a recorded pre-fix red (printf/echo found-2→found-0, os-release rejection, legacy acquisition fixtures, bundle-ref reversal), so non-vacuity is demonstrated, not asserted; harness self-tests are explicitly labeled control evidence, not product RED. Happy/failure coverage present for both installer fixtures (tamper blocked pre-extraction) and workflow bodies (malformed SARIF, missing report, API failures, denied comments).
CAPABILITY LIMITS (honest): my sandbox denied `bash tests/…`, `python3`, heredocs and pipes, so I could not independently re-run the canonical test, `bash -n`, or the evidence check; I rely on the mechanical report's "affected final checks PASS" (bounded 300s), the recorded outputs, and the final green snapshot matching the report's boundhash 3e9fbbf…. Finding 1's probe lines were verified by manual shlex-semantics tracing against the exact embedded function bodies plus recorded-evidence corroboration, not by execution.
```

## Original Astra round-1 verdict (complete original bytes)

- Original imported path: `.scratch/reports/2026-10-16-finish-tor-orchestration/T199-native-round1/original-import/T199.review-astra.verdict`
- SHA-256: `ae6c861a66d974fcefb7199424d4d8062b505deafc1b5f00323188a60417a729`
- Byte length: 12139; mode `0664`
- Bound source snapshot: `675c852f10044853859088be36ce8d5fdcc2f34f60638a888695cae8fee18fc1`; round 1.

```text
VERDICT: ESCALATE
REVIEWER: astra
TOOL: codex
MODEL: gpt-6-astra
EFFORT: high
SNAPSHOT: 675c852f10044853859088be36ce8d5fdcc2f34f60638a888695cae8fee18fc1
ROUND: 1
SUMMARY: The candidate matches the frozen manifest, but missing preimplementation behavioral evidence requires a governed disposition, and the push counter silently misses conditional continuation pushes.
FINDINGS:
  - [Blocker] specs/001-tor-route/evidence/T199-tests-first.json:101 — Replacement installer and scan bodies lack required preimplementation behavioral coverage — correctness/test discipline, Constitution VII.
    WRONG: The new installer and JavaScript bodies were written before their literal behavioral fixtures; their subsequent successful tests cannot establish the required tests-first chronology.
    EXPECTED: Spec-derived tests precede the implementation they constrain. Missing historical evidence remains noncompliant unless an explicitly applicable governed disposition permits adoption.
    EVIDENCE: The evidence record explicitly classifies the installer and workflow-body controls as retrospective at lines 101 and 112–126. The ticket corroborates this at specs/001-tor-route/tickets/T199-ci-push-count-and-bundle-red-evidence.md:127. These bodies are executable: verify.yml:41 invokes setup-toolchain; verify.yml:97,137,162,258 implements scan preparation, execution, publication and status propagation. The original layered RED at evidence line 71 tests rejection of legacy source forms, continuation counting and bundle assertions; it does not contain the later literal installer or scan-body controls.
    FALSIFICATION-ATTEMPT: Checked whether the earlier acquisition RED, later command-position/Ubuntu-ID RED, or existing constitutional exceptions cover the missing chronology. The earlier RED establishes checker behavior, not the later execution/publication properties. The later RED covers two narrow corrections. Constitution VII’s exceptions cover specified T221/T220 historical candidates, not T199.
    SURVIVAL: No supplied authorization waives VII for these bodies. Honest retrospective labeling preserves the record but does not satisfy the missing prerequisite. This is not repairable by manufacturing another RED against already-written code.
    EVALUATED-AS: Before adoption, independently check a separately governed, explicitly maintainer-accepted disposition identifying the exact T199 source/property inventory and preserving its historical NONCOMPLIANT status. Require current affected checks and exact-candidate independent review as separate obligations. `python3 scripts/test-first-evidence.py check T199` passing alone cannot close this finding; absent applicable governance or genuine previously preserved evidence, it remains blocking.

  - [Major] tests/contract/workflow/ci_inputs_test.sh:164 — Conditional continued pushes bypass both push counters — AC1, TEST-INTEGRITY / AUDIT-EVASION.
    WRONG: Retaining the shipped push and adding a second command shaped as `if git -c core.hooksPath=/dev/null \` followed by `push --quiet ...; then :; fi` leaves the counted total at one. The added push executes as the condition, but the scanner treats its command head as `if` and returns false.
    EXPECTED: A second continuation-style push must fail the exactly-one-push check, including when used as a shell condition. Unsupported relevant syntax must not silently count as absence.
    EVIDENCE: The entrypoint calls violations(sources) at line 416. Both the workflow-wide counter at lines 86–98 and agent-job counter at lines 367–375 call logical_shell_commands/is_git_push. Continuation joining retains the leading `if`; list splitting removes separators but not shell reserved words. is_git_push only skips assignments and one command/exec prefix before rejecting any head other than git. The second-push fixture at line 565 duplicates the bare push block, so it does not exercise this case.
    FALSIFICATION-ATTEMPT: Traced the global counter, agent boundary checks, refspec checks, and existing rejection fixtures. Both counters share the same parser. Refspec/job checks inspect only recognized pushes; the unchanged legitimate push satisfies them. The parser’s limited-grammar comment supplies no rejection for this unsupported form.
    SURVIVAL: Static caller-to-callee inspection establishes the missed count. No executable reproduction was run under this review’s read-only restriction. This is a contract-checking bypass, not a claim that the frozen workflow currently performs an unauthorized push.
    EVALUATED-AS: Add source fixtures containing a second continued conditional push in the publish job and another job, preserving the original push. Require the actual entrypoint to reject both with an exactly-one-push failure; retain passing shipped-workflow and printf/echo/path controls. Capture genuine pre-fix RED and identical post-fix GREEN through `python3 scripts/test-first-evidence.py red T199 -- bash tests/contract/workflow/ci_inputs_test.sh` and its green counterpart.

ACCEPTANCE:
  - AC1, moved continuation push: MET for the supplied bare-command fixture.
  - AC1, second continuation push in any job: UNMET; finding 2 identifies a silently missed executable form.
  - AC1, shipped workflow counts exactly one publish push: MET by inspected source and supplied affected PASS evidence.
  - AC2, reporter regression and layered bundle RED/GREEN: MET by the preserved reporter outcomes, canonical layered output and restored agent-task.yml. The supplied original wrapper provides its exact bytes, mode and hash.
  - AC3, four toolchains checked before use: Current checksum-before-extraction behavior is implemented and retrospectively evidenced. Required behavioral tests-first qualification is UNMET under finding 1. Actual runner usability remains NOT RUN.
  - AC4(a), original gitleaks acquisition: MET. Supplied pinned source establishes version 8.24.3, release download and cross-run cache restoration without the committed archive verification now required.
  - AC4(b), checked binary without cross-run restore: MET at the inspected implementation and synthetic execution-control layer. verify.yml:86–95 checks before extraction and selects the resulting binary explicitly at line 151.
  - AC4(c), rejection of unchecked acquisition: MET for the retained checker RED/GREEN. Replacement execution/publication chronology remains subject to finding 1.
  - AC5, existing cadence coverage: MET by read-only inspection. Both trigger filters contain data-plane/** and **/Dockerfile; the cadence workflow is unchanged.

SCOPE-AND-VERIFICATION:
  - Six permanent changed paths match the supplied budget-seven report. No unnamed changed path or unrelated runtime edit was found.
  - Working and staged diffs against the supplied base have the same supplied patch hash. All six file SHA-256 values match the frozen manifest.
  - agent-task.yml and docker-cadence.yml have no diff against the base.
  - Relied on supplied affected-test, syntax, ticket-lint and evidence-check results. Did not run tests, builds, downloads, CI, API requests, model CLIs or source mutations. Full verify and real runner/tool execution remain NOT RUN.
  - Archive pins are externally anchored by the supplied publisher records. The supplied upstream Python setup/layout and gitleaks sources support the installation and report-field assumptions; synthetic fixtures do not establish actual runner usability.

TEST-NON-VACUITY:
  - Reporter/bundle controls catch restoring first-failure assertion behavior or changing the bundle ref back to HEAD~1.
  - Moved/duplicate/absent push controls catch restoring physical-line counting; printf/echo controls catch searching arbitrary arguments for git push. Conditional-command coverage is missing as finding 2 describes.
  - Legacy acquisition controls catch removing acquisition rejection. Digest, URL and checksum-order mutations challenge the corresponding integrity checks.
  - Each literal installer’s matching/tampered pair catches removing its effective checksum enforcement. Export assertions catch removing the required environment/path exports.
  - Python setup controls catch removing private toolcache selection, setup working-directory/library configuration or pip isolation. The later OS fixture catches removing the Ubuntu ID check.
  - Process-bound controls catch removing output limits, timeout cleanup or descendant-group termination.
  - Scan-shell controls catch removing stale-report deletion, splitting the range argument or losing exit/report outputs.
  - Return-status cases catch accepting leak/error exits or ignoring summary/artifact failures.
  - Event fixtures catch changing empty/single/multiple push, PR and dispatch selection; invalid-ID, empty-PR and API-failure cases catch removal of their refusal handling.
  - Publication fixtures catch removing clean/error summaries, missing/malformed-report rejection, HTML escaping, comment deduplication, and API-error handling. These remain retrospective controls, not historical RED.

SECURITY-CHECKLIST:
  - DNS handling — verified absent in the changed implementation: no destination-resolution API or proxy descriptor changes.
  - Header/payload inspection — verified absent: no DP, tunnel or application-header processing changes.
  - Logs and metrics / INFO-LEAK — verified absent for deployed traffic records. Inspected workflow logging and summary construction; these handle CI findings, with redacted scan arguments and escaped summary text, not browsing data.
  - Sidecar contracts — verified absent: no sidecar invocation, image pin, torrc or IPC contract changes.
  - AUTH-BYPASS — verified absent in changed listener/RPC surfaces; none are modified. Workflow credentials remain step-scoped, checkout persistence remains disabled, and secret-scan retains contents: read.
  - Port binding / reachability — verified absent: no listener, publication or tunnel configuration changes.
  - Browser API misuse — verified absent: no extension edits. The test harness’s Function constructor executes local fixture scripts and is not a browser runtime sink.
  - Inter-plane leaks — verified absent: no CP/DP admission, forwarding or RPC changes.
  - Update channel — inspected all five new archive acquisition paths: committed digests precede extraction under fail-fast shell settings; no cross-run cache restore is introduced.
  - Cover/decoy traffic — verified absent: no deployed timers or speculative requests are added.
  - Outbound connections — new curl calls retrieve CI tools; GitHub API calls support the existing CI scan/report role. These are development-workflow traffic under Principle III, not DP/CP egress.
  - INJECTION — verified absent in inspected shell range transport: full commit-ID validation, environment passing and quoted array arguments prevent event values becoming shell source.
  - DOS — inspected the job timeout, report byte/finding limits and bounded new fixture subprocesses; no additional surviving finding.
  - PERM-ESCAL — verified absent: no new sudo, host privileges or workflow write permissions.
  - AUDIT-EVASION — finding 2; tests-first qualification is separately blocked by finding 1.

FALSIFIED-AND-DROPPED:
  - Python setup could fetch an unpinned pip upgrade — setup-toolchain/action.yml:74–81 clears inherited PIP_* settings, disables configuration/index access and selects the wheel bundled inside the verified archive.
  - A failed preparation could be concealed by the final step’s no-scan success — verify.yml:133–134 marks preparation failed; the later successful step does not erase that job failure.
  - A gitleaks leak/error exit could be swallowed by the scan wrapper — verify.yml:154 preserves the exit and lines 269–274 propagate failure independently of comment success.

DEFERRED:
  - None.

ESCALATION: amend-constitution — Adoption of the already-written bodies despite missing historical tests-first evidence requires an explicit, narrowly governed maintainer decision. This review grants no exception; the push-counter defect also requires correction.
```

## Durability boundary

This tracked evidence file contains all nine exact source-step blocks plus the complete original T199 evidence JSON and both complete original verdicts. It does not contain or claim the complete original six-path source candidate. The rejected snapshot, full import patch, original prompts, transport logs, review history and remaining imported source files remain in the separate local `T199-native-round1/original-import/` archive and are identified by the proposal/inventory and root review record. No original verdict is summarized in place of its full bytes above.
