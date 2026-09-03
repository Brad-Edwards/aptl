.PHONY: policy devmain

policy:
	bash tools/vale-lint-all.sh

# Open the dev -> main promotion PR with the standardized title (issue #852).
#
# The title matters: `chore(main): promote dev` is the preferred explicit title,
# and `chore` is a no-release type so the promotion never computes a bump of its
# own. The guard also recognizes GitHub's default branch title for the exact
# same-repository branch pair, so web-created promotions are not fragile.
#
# The merge method matters more. Release Please derives the version and
# CHANGELOG.md from the Conventional Commit subjects on `main`; squashing the
# promotion collapses every feature commit in the batch into one subject and
# loses the release's changelog entries. This target can state that requirement
# but cannot enforce it — only a server-side branch rule can.
#
# Deliberately thin: no ahead/behind precheck. GitHub already refuses a PR with
# no commits between the branches, and computing it here would either read stale
# local refs or add a fetch side effect to a target whose job is to open a PR.
# `gh` failures propagate as-is. `--head dev` is explicit so the head is never
# inferred from the current checkout.
devmain:
	@gh pr create --base main --head dev \
	  --title "chore(main): promote dev" \
	  --body "Promotes \`dev\` to \`main\`. Merge with a merge commit — squashing collapses the Conventional Commit subjects Release Please needs and loses this release's CHANGELOG."
