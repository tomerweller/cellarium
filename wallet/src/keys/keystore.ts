// L2 key custody. Spike-grade: the secret lives in localStorage (documented
// XSS caveat). A key is a Grumpkin scalar; the account id is pk_x.
//
// Every path that persists a key MUST canonicalize it to even-y form first:
// the circuit (is_even_y on active spends) and the sequencer (pk_from_coords)
// reject odd-y keys, so a non-canonical sk can receive deposits (which bind
// only pk_x) but can never sign a send, withdrawal, intent, or close.
// Canonicalizing is loss-free: negating sk flips pk_y only; pk_x — the
// account id — is unchanged.
import { frToHex32, hexToFr, randScalar, scalarToHex32 } from '../crypto/fields';
import { canonicalizeSk, pkFromSk } from '../crypto/grumpkin';

const STORAGE_KEY = 'cellarium.v1.sk';
const LINK_KEY = 'cellarium.v1.linkedAddress';

export interface Wallet {
  sk: bigint;
  pkX: string; // 0x hex
  pkY: string; // 0x hex
  /** Stellar address this key was derived from (if via Freighter). */
  linkedAddress?: string;
}

function fromSk(sk: bigint): Wallet {
  const pk = pkFromSk(sk);
  const linked = localStorage.getItem(LINK_KEY) ?? undefined;
  return { sk, pkX: frToHex32(pk.x), pkY: frToHex32(pk.y), linkedAddress: linked };
}

export function load(): Wallet | null {
  const raw = localStorage.getItem(STORAGE_KEY);
  if (!raw) return null;
  try {
    // Heal any stored non-canonical key (from generate/import before they
    // canonicalized): same pk_x, signing-capable form.
    const sk = canonicalizeSk(hexToFr(raw));
    if (scalarToHex32(sk) !== raw.toLowerCase()) localStorage.setItem(STORAGE_KEY, scalarToHex32(sk));
    return fromSk(sk);
  } catch {
    return null;
  }
}

/** Persist a Freighter-derived key plus the Stellar address it's bound to. */
export function saveDerived(sk: bigint, linkedAddress: string): Wallet {
  localStorage.setItem(STORAGE_KEY, scalarToHex32(sk));
  localStorage.setItem(LINK_KEY, linkedAddress);
  return fromSk(sk);
}

export function generate(): Wallet {
  const sk = canonicalizeSk(randScalar());
  localStorage.setItem(STORAGE_KEY, scalarToHex32(sk));
  localStorage.removeItem(LINK_KEY); // random/imported keys aren't wallet-bound
  return fromSk(sk);
}

export function importSk(hex: string): Wallet {
  let sk: bigint;
  try {
    sk = hexToFr(hex);
  } catch {
    throw new Error('Not a valid secret key — expected 0x followed by exactly 64 hex characters.');
  }
  if (sk === 0n) throw new Error('Secret key must be nonzero.');
  sk = canonicalizeSk(sk);
  localStorage.setItem(STORAGE_KEY, scalarToHex32(sk));
  localStorage.removeItem(LINK_KEY);
  return fromSk(sk);
}

/** The raw secret hex, for export (guard behind a confirm in the UI). */
export function exportSk(): string | null {
  return localStorage.getItem(STORAGE_KEY);
}

export function clear(): void {
  localStorage.removeItem(STORAGE_KEY);
  localStorage.removeItem(LINK_KEY);
}
