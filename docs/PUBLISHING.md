# Publishing this prepared repository

This package is prepared locally. No remote repository, invitation, issue or
Discord message is created by these tools.

## Before the first push

1. Run the offline checks and review the staged file list with `git diff --cached --stat`
   and `git diff --cached --name-only`. No firmware or local-work paths should appear.
2. Configure your own Git author name/email (a GitHub noreply email is suitable).
   The preparation does not invent an author identity or erase upstream attribution.
3. Create an empty GitHub repository, for example `bms46-q28g-research`.
   Use the actual owner/URL from GitHub; no guessed owner is embedded here.
4. Commit the prepared source, add that remote, then push `main`.
5. Configure branch protection/review requirements as described in CONTRIBUTING.
6. Invite collaborators explicitly through GitHub. They should use branches and PRs.

The source ZIP can also be attached to a release after publication. Generate it
with `python tools/package.py --output ../bms46-q28g-research-source.zip`.
It has a file-by-file SHA-256 manifest and a separate archive hash. Do not upload
the workspace folder or `local-work/` recursively.

## Possible Discord reply before publication

> I maintain and extend this BMS46 Q28G Ghidra research project. It builds on
> existing community work, including Bartek0x00's BMS46 research and the Ghidra
> CPU32 work, so I don't claim sole authorship. I'm preparing a reproducible
> GitHub package with annotations, tools, tests and documentation for collaboration.
> This version isn't published yet; I'll share the link once it's available.

After publishing, replace the last sentence with the actual repository link.
Do not imply that this is official BMW software or that the ECU has been fully
reverse engineered.
