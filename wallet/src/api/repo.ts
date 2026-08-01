// Repo-desk signing flows: create/countersign open intents and close
// positions. All messages are verified locally before POSTing (as in sign.ts:
// never let a signature the circuit would reject leave the wallet).
import { evenYFromX, pkFromSk } from '../crypto/grumpkin';
import { frToHex32, hexToFr } from '../crypto/fields';
import { closeMessage, openMessage, PositionTerms } from '../crypto/repo';
import { authMessage, sign, verify } from '../crypto/schnorr';
import { accountOrNull, api, Intent, Position, WireSig } from './sequencer';

function wireSig(sig: ReturnType<typeof sign>): WireSig {
  return {
    r_x: frToHex32(sig.r_x),
    r_y: frToHex32(sig.r_y),
    s_lo: frToHex32(sig.s_lo),
    s_hi: frToHex32(sig.s_hi),
  };
}

/**
 * Fetch intents for the wallet's own key, proving control of it with a
 * fresh signed challenge (issue #1 L12: listings are no longer public).
 */
export function listIntents(sk: bigint): Promise<{ incoming: Intent[]; outgoing: Intent[] }> {
  const me = pkFromSk(sk);
  const ts = Math.floor(Date.now() / 1000);
  const sig = sign(sk, authMessage(me.x, BigInt(ts)));
  return api.intents(frToHex32(me.x), { ts, pk_y: frToHex32(me.y), sig: wireSig(sig) });
}

export interface NewIntent {
  /** The initiator's role in the repo. */
  role: 'borrower' | 'lender';
  counterpartyPkX: string;
  cash: bigint;
  coll: bigint;
  rateBps: number;
  haircutBps: number;
  termSecs: number;
}

/** Build, sign, and post a half-signed open intent. */
export async function createIntent(sk: bigint, p: NewIntent): Promise<{ id: number }> {
  const me = pkFromSk(sk);
  const cp = evenYFromX(hexToFr(p.counterpartyPkX));
  const [borrower, lender] = p.role === 'borrower' ? [me, cp] : [cp, me];

  // Both nonces are baked into the signed message (PLAN.md 6.3): fetch the
  // live pending nonces. A counterparty that transacts before acceptance
  // invalidates the intent (it gets dropped at build time).
  const [bAcct, lAcct] = await Promise.all([
    accountOrNull(frToHex32(borrower.x)),
    accountOrNull(frToHex32(lender.x)),
  ]);
  if (!bAcct || !lAcct) throw new Error('both parties must have funded rollup accounts');

  const now = Math.floor(Date.now() / 1000);
  const terms: PositionTerms = {
    borrowerPkX: borrower.x,
    lenderPkX: lender.x,
    cash: p.cash,
    coll: p.coll,
    rateBps: BigInt(p.rateBps),
    haircutBps: BigInt(p.haircutBps),
    openTs: BigInt(now),
    maturityTs: BigInt(now + p.termSecs),
  };
  const msg = openMessage(terms, BigInt(bAcct.pending_nonce), BigInt(lAcct.pending_nonce));
  const sig = sign(sk, msg);
  if (!verify(me.x, me.y, msg, sig)) {
    throw new Error('local signature verification failed — refusing to submit');
  }
  return api.submitIntent({
    initiator: p.role,
    borrower_pk_x: frToHex32(borrower.x),
    borrower_pk_y: frToHex32(borrower.y),
    lender_pk_x: frToHex32(lender.x),
    lender_pk_y: frToHex32(lender.y),
    cash: p.cash.toString(),
    coll: p.coll.toString(),
    rate_bps: p.rateBps,
    haircut_bps: p.haircutBps,
    open_ts: now,
    maturity_ts: now + p.termSecs,
    borrower_nonce: bAcct.pending_nonce,
    lender_nonce: lAcct.pending_nonce,
    sig: wireSig(sig),
  });
}

export function intentTerms(i: Intent): PositionTerms {
  return {
    borrowerPkX: hexToFr(i.borrower_pk_x),
    lenderPkX: hexToFr(i.lender_pk_x),
    cash: BigInt(i.cash),
    coll: BigInt(i.coll),
    rateBps: BigInt(i.rate_bps),
    haircutBps: BigInt(i.haircut_bps),
    openTs: BigInt(i.open_ts),
    maturityTs: BigInt(i.maturity_ts),
  };
}

/** Countersign an incoming intent (we are the non-initiating party). */
export async function acceptIntent(sk: bigint, intent: Intent): Promise<{ id: number }> {
  const me = pkFromSk(sk);
  const msg = openMessage(
    intentTerms(intent),
    BigInt(intent.borrower_nonce),
    BigInt(intent.lender_nonce),
  );
  const sig = sign(sk, msg);
  if (!verify(me.x, me.y, msg, sig)) {
    throw new Error('local signature verification failed — refusing to submit');
  }
  return api.acceptIntent(intent.id, wireSig(sig));
}

export function positionTerms(p: Position): PositionTerms {
  return {
    borrowerPkX: hexToFr(p.borrower_pk_x),
    lenderPkX: hexToFr(p.lender_pk_x),
    cash: BigInt(p.cash),
    coll: BigInt(p.coll),
    rateBps: BigInt(p.rate_bps),
    haircutBps: BigInt(p.haircut_bps),
    openTs: BigInt(p.open_ts),
    maturityTs: BigInt(p.maturity_ts),
  };
}

/** Borrower-signed close (repay with interest at inclusion time). */
export async function closePosition(
  sk: bigint,
  position: Position,
  pendingNonce: number,
): Promise<{ id: number }> {
  const me = pkFromSk(sk);
  const msg = closeMessage(BigInt(position.slot), positionTerms(position), BigInt(pendingNonce));
  const sig = sign(sk, msg);
  if (!verify(me.x, me.y, msg, sig)) {
    throw new Error('local signature verification failed — refusing to submit');
  }
  return api.close({
    pos_index: position.slot,
    borrower_pk_x: frToHex32(me.x),
    borrower_pk_y: frToHex32(me.y),
    nonce: pendingNonce,
    sig: wireSig(sig),
  });
}

/**
 * The liquidation trigger price (XLM-per-tUST × 1e7) below which this
 * position becomes liquidatable: price < cash·(2·10⁴+haircut)·10⁷ / (coll·2·10⁴).
 */
export function liquidationPrice(p: Position): bigint {
  const cash = BigInt(p.cash);
  const coll = BigInt(p.coll);
  const num = cash * (20_000n + BigInt(p.haircut_bps)) * 10_000_000n;
  return num / (coll * 20_000n);
}
