// Grumpkin: y^2 = x^3 - 17 over the BN254 scalar field, cofactor 1.
// Generator pinned identically to circuits/lib/src/schnorr.nr GEN and
// ark-grumpkin's Affine::generator().
import { Field } from '@noble/curves/abstract/modular.js';
import { weierstrass } from '@noble/curves/abstract/weierstrass.js';
import { N_GRUMPKIN, P_BN254_FR } from './fields';
// N_GRUMPKIN used by canonicalizeSk

export const Grumpkin = weierstrass({
  p: P_BN254_FR,
  n: N_GRUMPKIN,
  h: 1n,
  a: 0n,
  b: P_BN254_FR - 17n,
  Gx: 1n,
  Gy: 0x0000000000000002cf135e7506a45d632d270d45f1181294833fc48d823f272cn,
});

export type AffinePoint = { x: bigint; y: bigint };

export function mulBase(k: bigint): AffinePoint {
  const p = Grumpkin.BASE.multiply(k).toAffine();
  return { x: p.x, y: p.y };
}

export function pkFromSk(sk: bigint): AffinePoint {
  return mulBase(sk);
}

/**
 * Even-y canonical secret key (matches harness Keypair::from_sk and the
 * circuit's is_even_y check on active spends). If sk*G has odd y, return -sk.
 */
export function canonicalizeSk(sk: bigint): bigint {
  let s = ((sk % N_GRUMPKIN) + N_GRUMPKIN) % N_GRUMPKIN;
  if (s === 0n) s = 1n;
  const pk = mulBase(s);
  if ((pk.y & 1n) === 1n) {
    s = (N_GRUMPKIN - s) % N_GRUMPKIN;
  }
  return s === 0n ? 1n : s;
}

/** Validates the point is on the curve; throws otherwise. */
export function pointFromAffine(x: bigint, y: bigint) {
  const p = Grumpkin.fromAffine({ x, y });
  p.assertValidity();
  return p;
}

const Fp = Field(P_BN254_FR);

/**
 * Recover the canonical even-y public key from its x-coordinate. Every
 * active spend key on the rollup is even-y canonical (circuit-enforced), so
 * knowing a counterparty's pk_x is enough to reconstruct their full point.
 * Throws if x is not on the curve.
 */
export function evenYFromX(x: bigint): AffinePoint {
  const y2 = Fp.add(Fp.mul(Fp.mul(x, x), x), P_BN254_FR - 17n);
  const y = Fp.sqrt(y2); // throws if no root (x not on curve)
  const even = (y & 1n) === 0n ? y : P_BN254_FR - y;
  return { x, y: even };
}
