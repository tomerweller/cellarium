// Local record of L1 deposits the wallet has submitted whose L2 credit
// hasn't landed yet. Entries are written the moment Stellar ACCEPTS the
// transaction (issue #19: an ambiguous confirmation timeout must never lose
// the hash), carry the asset and the pre-deposit balance baseline
// (issue #24: existing cash must not clear a new deposit, and tUST deposits
// reconcile against the collateral balance), and are only removed on a
// definitive outcome — never silently aged out.
const KEY = 'cellarium.v2.pendingDeposits';

export interface PendingDeposit {
  pkX: string;
  /** 0 = cash (XLM), 1 = collateral (tUST). */
  asset: number;
  amount: string; // base units, decimal
  /** L2 balance of `asset` when the deposit was submitted. */
  baseline: string;
  txHash: string;
  at: number;
  /** submitted = accepted by Stellar, confirmation unknown; confirmed = L1 success, awaiting L2 credit. */
  status: 'submitted' | 'confirmed';
}

function readAll(): PendingDeposit[] {
  try {
    return JSON.parse(localStorage.getItem(KEY) ?? '[]') as PendingDeposit[];
  } catch {
    return [];
  }
}

function writeAll(all: PendingDeposit[]): void {
  localStorage.setItem(KEY, JSON.stringify(all));
}

export function list(pkX: string): PendingDeposit[] {
  return readAll().filter((d) => d.pkX === pkX);
}

export function add(d: PendingDeposit): void {
  writeAll([...readAll(), d]);
}

/** Mark a submitted deposit as confirmed on L1 (still awaiting L2 credit). */
export function markConfirmed(txHash: string): void {
  writeAll(readAll().map((d) => (d.txHash === txHash ? { ...d, status: 'confirmed' as const } : d)));
}

/** Remove after a DEFINITIVE outcome (L1 failure, or manual dismissal). */
export function remove(txHash: string): void {
  writeAll(readAll().filter((d) => d.txHash !== txHash));
}

/**
 * Drop entries whose credit has landed: the balance of the entry's asset has
 * reached baseline + amount. Unresolved entries are kept indefinitely —
 * they render as pending/unknown rather than disappearing (issue #24).
 */
export function reconcile(pkX: string, cash: bigint, coll: bigint): void {
  const all = readAll();
  const kept = all.filter((d) => {
    if (d.pkX !== pkX) return true;
    const balance = d.asset === 1 ? coll : cash;
    return balance < BigInt(d.baseline) + BigInt(d.amount);
  });
  if (kept.length !== all.length) writeAll(kept);
}
