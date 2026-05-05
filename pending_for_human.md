## 2026-04-28: rotate OPENAI_API_KEY for CI smoke

**Why blocked**: Repo secret `OPENAI_API_KEY` returns 401 in CI → honeypot
L3 self-test degrades to `openai-api-error:AuthenticationError` → smoke
gate fails on every PR. Direct push to `main` blocked by branch protection
requiring this gate.

**Steps for human**:
1. Generate new OpenAI key: https://platform.openai.com/api-keys
2. Update GitHub repo secret:
   https://github.com/jonathanmoregard/injection-scanner/settings/secrets/actions
   → edit `OPENAI_API_KEY` → paste new value.
3. Re-run failed check on PR #2:
   `gh run rerun 25044433780 --failed -R jonathanmoregard/injection-scanner`
4. Merge once green:
   `gh pr merge 2 --squash --delete-branch -R jonathanmoregard/injection-scanner`

**Everything else done**: 4 universal proposals authored, committed
(`5a3f...` on branch `proposals/sota-review-2026-04-28`), pushed, PR #2
opened with summary. repo-check side fully merged + pushed (7 proposals
on master).
