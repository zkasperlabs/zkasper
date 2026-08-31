"""Head-vote participation on mainnet, deduplicated by validator.

Answers the one chain measurement the FCR feasibility note left open: does a
single slot carry enough head votes for a one-slot confirmation, or does the
window have to be two?

Measured 2026-08-31 over 48 slots from 15109158: median 99.74%, min 95.47%,
**48/48 at or above the 95% a one-slot confirmation needs**. Usage:

    python3 scripts/head_vote_participation.py [n_slots]

Two caveats the number carries. It counts validators, and the rule weighs
balance, so it is only the same number if participation is uncorrelated with
effective balance. And the worst slot cleared by half a point, which is margin
enough to measure and not enough to design against -- support k=2.

For each slot: which of that slot's assigned validators cast a head vote, and
what fraction of them named the slot's canonical block. Attestations are read
from blocks n+1 and n+2, so this is a LOWER bound on what a prover collecting
from gossip at t=8s sees.

Electra: `aggregation_bits` indexes the concatenation of the committees named by
`committee_bits`, in increasing committee index."""
import json, sys, urllib.request, collections

U = open('/root/.openclaw/workspace/.chainstack-beacon-url').read().strip()

def get(path):
    with urllib.request.urlopen(U + path, timeout=40) as r:
        return json.load(r)

def bitlist(hexstr):
    """SSZ Bitlist -> list of bools, dropping the length-delimiter bit."""
    b = bytes.fromhex(hexstr[2:])
    n = int.from_bytes(b, 'little')
    width = n.bit_length() - 1          # the highest set bit is the delimiter
    return [(n >> i) & 1 == 1 for i in range(width)]

def bitvector(hexstr, size):
    b = bytes.fromhex(hexstr[2:])
    n = int.from_bytes(b, 'little')
    return [(n >> i) & 1 == 1 for i in range(size)]

head = int(get('/eth/v1/beacon/headers/head')['data']['header']['message']['slot'])
start = head - 70
N = int(sys.argv[1]) if len(sys.argv) > 1 else 10
print(f'head {head}; slots {start}..{start+N-1}, votes read from blocks n+1 and n+2')

print(f'{"slot":>10} {"assigned":>9} {"voted":>7} {"for head":>9} {"head/assigned":>14} {"other":>6}')
fracs = []
for s in range(start, start + N):
    try:
        croot = get(f'/eth/v1/beacon/headers/{s}')['data']['root']
        comms = get(f'/eth/v1/beacon/states/{s}/committees?slot={s}')['data']
    except Exception:
        print(f'{s:>10}  no block at this slot (skipped)')
        continue
    by_index = {int(c['index']): [int(v) for v in c['validators']] for c in comms}
    assigned = sum(len(v) for v in by_index.values())

    voted = {}                      # validator -> head root it named
    for off in (1, 2):
        try:
            blk = get(f'/eth/v2/beacon/blocks/{s+off}')['data']['message']
        except Exception:
            continue
        for a in blk['body'].get('attestations', []):
            if int(a['data']['slot']) != s:
                continue
            root = a['data']['beacon_block_root']
            cbits = bitvector(a['committee_bits'], 64)
            members = []
            for ci in sorted(i for i, on in enumerate(cbits) if on):
                members.extend(by_index.get(ci, []))
            for i, on in enumerate(bitlist(a['aggregation_bits'])):
                if on and i < len(members):
                    voted.setdefault(members[i], root)

    for_head = sum(1 for r in voted.values() if r == croot)
    frac = for_head / assigned if assigned else 0
    fracs.append(frac)
    print(f'{s:>10} {assigned:>9} {len(voted):>7} {for_head:>9} {frac:>13.2%} {len(voted)-for_head:>6}')

if fracs:
    fracs.sort()
    print(f'\nmedian {fracs[len(fracs)//2]:.2%}  min {fracs[0]:.2%}  max {fracs[-1]:.2%}  n={len(fracs)}')
    print(f'slots at or above 95%: {sum(1 for f in fracs if f >= 0.95)}/{len(fracs)}')
