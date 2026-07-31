// Repo position hashing + the bilateral open message, mirroring
// circuits/lib/src/repo.nr and harness/src/repo.rs byte-for-byte
// (vector-gated in vectors.test.ts).
import { Fr } from './fields';
import { p2 } from './poseidon2';

export const DOMAIN_POS = 8n;
export const DOMAIN_OPEN = 9n;
export const DOMAIN_CLOSE = 10n;

export interface PositionTerms {
  borrowerPkX: Fr;
  lenderPkX: Fr;
  cash: bigint;
  coll: bigint;
  rateBps: bigint;
  haircutBps: bigint;
  openTs: bigint;
  maturityTs: bigint;
}

export function termHash(p: PositionTerms): Fr {
  return p2([p.rateBps, p.haircutBps, p.openTs, p.maturityTs]);
}

export function amtHash(cash: bigint, coll: bigint): Fr {
  return p2([cash, coll]);
}

export function posLeaf(p: PositionTerms): Fr {
  return p2([DOMAIN_POS, p.borrowerPkX, p.lenderPkX, p2([termHash(p), amtHash(p.cash, p.coll)])]);
}

/** The bilateral open signing message (binds terms + both nonces). */
export function openMessage(p: PositionTerms, borrowerNonce: bigint, lenderNonce: bigint): Fr {
  return p2([
    DOMAIN_OPEN,
    p.borrowerPkX,
    p.lenderPkX,
    p2([termHash(p), amtHash(p.cash, p.coll), borrowerNonce, lenderNonce]),
  ]);
}

/** Combined state root over both trees. */
export function stateRoot(accountRoot: Fr, positionRoot: Fr): Fr {
  return p2([accountRoot, positionRoot]);
}
