#!/usr/bin/env bash
set -euo pipefail

fail() {
  echo "repo hygiene check failed: $1" >&2
  exit 1
}

scratch_hits="$(find . -maxdepth 2 \( -name 'good*.txt' -o -name 'mean*.txt' -o -name 'a*.txt' -o -name 's*.txt' -o -name 'wr*.txt' -o -name 'launch*.txt' -o -name 'tmp.logs*' -o -name 'dummy.cfg' -o -name '.DS_Store' \) | sort)"
if [[ -n "$scratch_hits" ]]; then
  printf '%s\n' "$scratch_hits" >&2
  fail "scratch files or .DS_Store are still present"
fi

paper_hits="$(find paper -maxdepth 1 -type f \( -name 'main.aux' -o -name 'main.bbl' -o -name 'main.blg' -o -name 'main.fdb_latexmk' -o -name 'main.fls' -o -name 'main.log' -o -name 'main.out' -o -name 'main.pdf' -o -name 'zitpit_main.pdf' -o -name '.DS_Store' \) | sort)"
if [[ -n "$paper_hits" ]]; then
  printf '%s\n' "$paper_hits" >&2
  fail "tracked paper build outputs or duplicate PDFs are still present"
fi

if [[ ! -f paper/zitpit-v1.0-paper.pdf ]]; then
  fail "canonical paper PDF is missing"
fi

echo "repo hygiene check passed"
