# SPDX-License-Identifier: Apache-2.0
"""The threat model is stated in three places, in the same words.

DESIGN-host-allowlisting.md section 6 is the source. The README and
SECURITY.md each carry its two lists, "It stops" and "It does not stop",
word for word (design section 12), so a user reads the same promise the
design makes. Edit section 6 and copy it; these tests fail until the copies
match.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent


def _section6() -> tuple[str, str]:
    text = (ROOT / "DESIGN-host-allowlisting.md").read_text()
    part = text[text.index("## 6. Threat model\n"):text.index("## 7. Alternatives considered")]
    stops = part[part.index("**It stops**"):part.index("**It does not stop.**")]
    nots = part[part.index("**It does not stop.**"):]
    stops = stops.split("\n", 1)[1].strip()  # the items, without the heading line
    nots = nots.split("\n", 1)[1].strip().rstrip("-").strip()
    return stops, nots


@pytest.mark.parametrize("doc", ["README.md", "SECURITY.md"])
def test_the_threat_model_is_copied_word_for_word(doc):
    stops, nots = _section6()
    text = (ROOT / doc).read_text()
    print(f"{doc}: {len(stops.splitlines())} 'stops' lines, {len(nots.splitlines())} 'does not stop' lines")
    assert stops in text, f"{doc}'s 'It stops' list differs from design section 6"
    assert nots in text, f"{doc}'s 'It does not stop' list differs from design section 6"


def test_section_6_lists_nine_residuals_and_ten_things_it_stops():
    # Guards the extraction above: an edit that broke the markers would make
    # the copy test compare empty strings and pass.
    stops, nots = _section6()
    said = [line for line in stops.splitlines() if line.startswith("- ")]
    numbered = re.findall(r"^\d+\. \*\*", nots, flags=re.MULTILINE)
    print(len(said), "stops;", len(numbered), "residuals")
    assert len(said) == 10 and len(numbered) == 9


def test_no_doc_still_says_hosts_are_not_enforced():
    stale = re.compile(r"not enforced yet|aren't enforced|on the roadmap|allowlists are planned|"
                       r"ports, not host", re.IGNORECASE)
    for doc in ("README.md", "SECURITY.md"):
        found = [line for line in (ROOT / doc).read_text().splitlines() if stale.search(line)]
        print(doc, found)
        assert not found, f"{doc} still says host names aren't enforced: {found}"
