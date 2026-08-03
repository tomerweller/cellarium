// Regression for the odd-y throwaway-key bug: generate() and importSk() must
// persist even-y canonical secrets. A non-canonical sk can receive deposits
// (they bind only pk_x) but the sequencer and circuit reject every signature
// it makes, bricking the account for sends, intents, and closes.
import { beforeEach, describe, expect, it } from 'vitest';
import { frToHex32, scalarToHex32 } from '../crypto/fields';
import { pkFromSk } from '../crypto/grumpkin';
import { generate, importSk, load } from './keystore';

// keystore touches localStorage at call time; tests run in a node env.
const store = new Map<string, string>();
(globalThis as { localStorage?: unknown }).localStorage = {
  getItem: (k: string) => store.get(k) ?? null,
  setItem: (k: string, v: string) => void store.set(k, v),
  removeItem: (k: string) => void store.delete(k),
};

// Find a small scalar whose public key has odd y (non-canonical form).
let oddSk = 0n;
for (let sk = 2n; sk < 64n; sk++) {
  if ((pkFromSk(sk).y & 1n) === 1n) {
    oddSk = sk;
    break;
  }
}
const ODD_Y_SK = frToHex32(oddSk);

beforeEach(() => store.clear());

describe('keystore canonicalization', () => {
  it('generate() always persists an even-y key', () => {
    for (let i = 0; i < 16; i++) {
      const w = generate();
      expect(pkFromSk(w.sk).y & 1n).toBe(0n);
      expect(store.get('cellarium.v1.sk')).toBe(scalarToHex32(w.sk));
    }
  });

  it('importSk() canonicalizes but preserves the account id (pk_x)', () => {
    expect(oddSk).not.toBe(0n); // premise: an odd-y scalar exists in range
    const rawPk = pkFromSk(oddSk);
    const w = importSk(ODD_Y_SK);
    expect(pkFromSk(w.sk).y & 1n).toBe(0n);
    expect(w.pkX).toBe(frToHex32(rawPk.x)); // same account
    expect(w.sk).not.toBe(oddSk);
  });

  it('load() heals a stored non-canonical key in place', () => {
    store.set('cellarium.v1.sk', ODD_Y_SK);
    const w = load();
    expect(w).not.toBeNull();
    expect(pkFromSk(w!.sk).y & 1n).toBe(0n);
    expect(w!.pkX).toBe(frToHex32(pkFromSk(oddSk).x));
    expect(store.get('cellarium.v1.sk')).toBe(scalarToHex32(w!.sk));
  });
});
