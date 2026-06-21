# Sonar configuration artifacts

SonarCloud tooling for APTL. The scanner config (`sonar-project.properties`)
stays at the repository root because the Sonar scanner reads it from there.

## Layout

- `assert_no_new_issues.py`: CI guard that queries SonarCloud after scanner
  completion and fails the job when the current pull request or branch has
  any open issue in the new-code leak period.

## New-issue gate

The CI `SonarCloud quality gate` job runs the scanner with
`-Dsonar.qualitygate.wait=true`, then runs `tools/sonar/assert_no_new_issues.py`.
The script uses `SONAR_TOKEN` only for SonarCloud API authentication, derives
the pull request number from the GitHub event payload, and prints only issue
metadata when it fails. This keeps the repo-side merge gate stricter than a
SonarCloud project gate that may still allow non-blocking code smells.
