#!/usr/bin/env python3
"""Check two learned Mealy machines (SSH-State-Learner *_long.dot files) for semantic equivalence.

Walks the product automaton from the initial states (s0) and reports the shortest input word on which the
two machines produce different outputs. State numbering is irrelevant. Socket state is ignored (it is not
part of LONG edge labels).

Usage: compare_state_machines.py a_long.dot b_long.dot
"""
import re
import sys
from collections import deque

EDGE = re.compile(r'^\s*(\w+)\s*->\s*(\w+)\s*\[.*?\blabel="([^"]*)"')


def parse(path):
    delta = {}
    for line in open(path, encoding="utf-8"):
        m = EDGE.match(line)
        if not m:
            continue
        src, tgt, label = m.groups()
        inp, sep, out = label.partition(" / ")
        if not sep:
            sys.exit(f"{path}: unexpected edge label {label!r} (use the *_long.dot file)")
        delta[(src, inp.strip())] = (out.strip(), tgt)
    if not delta:
        sys.exit(f"{path}: no transitions found")
    return delta


def main():
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    a, b = parse(sys.argv[1]), parse(sys.argv[2])
    alph_a = {i for _, i in a}
    alph_b = {i for _, i in b}
    if alph_a != alph_b:
        print(f"Alphabets differ:\n  only in A: {sorted(alph_a - alph_b)}\n  only in B: {sorted(alph_b - alph_a)}")
        return 2
    alphabet = sorted(alph_a)

    start = ("s0", "s0")
    parent = {start: None}
    queue = deque([start])
    while queue:
        pair = queue.popleft()
        qa, qb = pair
        for i in alphabet:
            ta, tb = a.get((qa, i)), b.get((qb, i))
            if ta is None or tb is None or ta[0] != tb[0]:
                word = [i]
                p = pair
                while parent[p] is not None:
                    p, sym = parent[p]
                    word.append(sym)
                word.reverse()
                print("NOT equivalent. Separating word:")
                print("  " + " ".join(word))
                print(f"  A outputs: {ta[0] if ta else '<missing transition>'}")
                print(f"  B outputs: {tb[0] if tb else '<missing transition>'}")
                return 1
            nxt = (ta[1], tb[1])
            if nxt not in parent:
                parent[nxt] = (pair, i)
                queue.append(nxt)
    print(f"Equivalent ({len({p[0] for p in parent})} reachable states in A, "
          f"{len({p[1] for p in parent})} in B, {len(parent)} product states).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
