// Issue #23: every kind × role renders the right asset unit, direction,
// and label — table-driven over both assets and both repo counterparties.
import { describe, expect, it } from 'vitest';
import { entryView } from './activity';

describe('entryView', () => {
  const cases: Array<{
    kind: string;
    asset: number;
    sign: '+' | '−' | '';
    unit: 'XLM' | 'tUST';
  }> = [
    { kind: 'deposit', asset: 0, sign: '+', unit: 'XLM' },
    { kind: 'deposit', asset: 1, sign: '+', unit: 'tUST' },
    { kind: 'transfer_in', asset: 0, sign: '+', unit: 'XLM' },
    { kind: 'transfer_in', asset: 1, sign: '+', unit: 'tUST' },
    { kind: 'transfer_out', asset: 0, sign: '−', unit: 'XLM' },
    { kind: 'transfer_out', asset: 1, sign: '−', unit: 'tUST' },
    { kind: 'withdraw', asset: 0, sign: '−', unit: 'XLM' },
    { kind: 'withdraw', asset: 1, sign: '−', unit: 'tUST' },
    // Repo cash legs (asset 0): value flows borrower ← lender at open and
    // borrower → lender at close.
    { kind: 'repo_open_borrower', asset: 0, sign: '+', unit: 'XLM' },
    { kind: 'repo_open_lender', asset: 0, sign: '−', unit: 'XLM' },
    { kind: 'repo_close_borrower', asset: 0, sign: '−', unit: 'XLM' },
    { kind: 'repo_close_lender', asset: 0, sign: '+', unit: 'XLM' },
    // Settlement collateral legs (asset 1): collateral moves to the lender.
    { kind: 'repo_default_borrower', asset: 1, sign: '−', unit: 'tUST' },
    { kind: 'repo_default_lender', asset: 1, sign: '+', unit: 'tUST' },
    { kind: 'repo_liquidation_borrower', asset: 1, sign: '−', unit: 'tUST' },
    { kind: 'repo_liquidation_lender', asset: 1, sign: '+', unit: 'tUST' },
  ];

  it.each(cases)('$kind asset=$asset → $sign $unit', ({ kind, asset, sign, unit }) => {
    const v = entryView({ kind, asset, amount: '12345678' });
    expect(v.sign).toBe(sign);
    expect(v.unit).toBe(unit);
    expect(v.amount).toBe('1.2345678');
    expect(v.label).not.toBe(kind); // every known kind has a human label
  });

  it('legacy role-less repo rows render without claiming a direction', () => {
    for (const kind of ['repo_open', 'repo_close', 'repo_default', 'repo_liquidation']) {
      expect(entryView({ kind, asset: 0, amount: '1' }).sign).toBe('');
    }
  });

  it('unknown kinds fall back to the raw kind with no sign', () => {
    const v = entryView({ kind: 'mystery_event', asset: 0, amount: '1' });
    expect(v.label).toBe('mystery_event');
    expect(v.sign).toBe('');
  });
});
