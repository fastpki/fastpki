# Workflows

- **`ci.yml`** — the gate. Fires on `workflow_dispatch`, on a push to `release-candidate`
  or `release-candidate-*`, and when a release is published. **Not on pull requests**:
  `pull_request` runs a fork's own code on submission unless the repository's "require
  approval for all outside collaborators" Actions setting is on. Approve the PR into the
  release-candidate branch and the push trigger covers it.

  Three jobs. `gate` builds the build stage, runs the **source** tier against it (cppcheck,
  build warnings, fuzz lane — the three that need a compiler and a configured cmake tree),
  then builds the runtime image and runs the whole suite inside it via
  `tests/run-in-container.sh`. `sanitizers` is separate only because `-DFASTPKI_SANITIZE=ON`
  is a build argument. `cloud-image` builds the deployment image with Packer as a bootable
  disk and boots it under QEMU, so the cloud path is proven by a machine that starts rather
  than by a build that merely succeeded.

  `cloud-image` runs on `workflow_dispatch` only, and never gates a release candidate. The
  lab node has two CPUs and shares them with the runner and the deployment, so it gets
  through roughly 15 of the image's 70 objects an hour — a full build needs about four,
  which no job timeout on a shared node can accommodate. Run it by hand, on a machine with
  cores, when the cloud path has changed:

  ```sh
  gh workflow run ci.yml --field only=cloud-image   # just that lane
  gh workflow run ci.yml --field only=all           # everything
  ```

  `only` exists for the same reason: iterating on one lane should not re-run the suite and
  the sanitizer lane against code that has not changed. A release-candidate push and a
  published release always run everything they gate.

  Wall-clock on a shared node is the binding constraint, not billed minutes: the runners
  are self-hosted in the lab and are not billed at all. What the trigger list buys is the
  lab itself — a gate run drives load average past 6 on 2 CPUs, and those nodes also serve
  the deployment somebody may be testing against.

  Layer caching is `type=local` under `$HOME/.cache/fastpki/`, one directory per lane,
  rotated after each run because `--cache-to` writes a fresh tree rather than pruning the
  one it restored from. The runners persist between runs, so each lane keeps a warm cache
  of its own — the gate and sanitizer builds share almost nothing above the `deps` layer,
  and they run on different nodes.

- **`fuzz-campaign.yml`** — the fuzzing campaign: a long run over a corpus that persists
  between runs, which is the whole point of it (`tests/fuzz_lane.sh` inside `run_all.sh` is
  the gate, and it re-seeds an identical corpus every time by design).

  It runs on a release candidate and on a release, never on `main` — a campaign is five
  harnesses at fifteen minutes each before the image build, and `main` moves too often to
  pay that per push. The same file serves both repositories: the public release is a
  snapshot of this tree, candidates are cut here and releases are published there, so both
  triggers are listed rather than edited in on the way out.
