// How a history entry renders (issue #23): units come from `entry.asset`,
// and direction comes from the role-encoded kind — never guessed from the
// event class alone (repo cash flows point opposite ways for the two
// counterparties).
import type { HistoryEntry } from './api/sequencer';
import { stroopsToXlm } from './format';

export interface EntryView {
  label: string;
  /** '+' credits this account, '−' debits it, '' unknown (legacy rows). */
  sign: '+' | '−' | '';
  unit: 'XLM' | 'tUST';
  /** Decimal amount (both assets use 7 decimals). */
  amount: string;
}

const VIEWS: Record<string, { label: string; sign: '+' | '−' | '' }> = {
  deposit: { label: 'Deposit', sign: '+' },
  transfer_in: { label: 'Received', sign: '+' },
  transfer_out: { label: 'Sent', sign: '−' },
  withdraw: { label: 'Withdrawal', sign: '−' },
  // Repo lifecycle, per role. Open/close rows carry the cash leg (asset 0);
  // default/liquidation rows carry the collateral leg (asset 1).
  repo_open_borrower: { label: 'Repo opened · borrowed', sign: '+' },
  repo_open_lender: { label: 'Repo opened · lent', sign: '−' },
  repo_close_borrower: { label: 'Repo repaid', sign: '−' },
  repo_close_lender: { label: 'Repo repayment received', sign: '+' },
  repo_default_borrower: { label: 'Repo default · collateral forfeited', sign: '−' },
  repo_default_lender: { label: 'Repo default · collateral received', sign: '+' },
  repo_liquidation_borrower: { label: 'Repo liquidated · collateral forfeited', sign: '−' },
  repo_liquidation_lender: { label: 'Repo liquidated · collateral received', sign: '+' },
  // Legacy rows written before roles were encoded: direction is unknowable,
  // so show the event without claiming a sign.
  repo_open: { label: 'Repo opened', sign: '' },
  repo_close: { label: 'Repo closed', sign: '' },
  repo_default: { label: 'Repo defaulted', sign: '' },
  repo_liquidation: { label: 'Repo liquidated', sign: '' },
};

export function entryView(e: Pick<HistoryEntry, 'kind' | 'asset' | 'amount'>): EntryView {
  const v = VIEWS[e.kind] ?? { label: e.kind, sign: '' as const };
  return {
    label: v.label,
    sign: v.sign,
    unit: e.asset === 1 ? 'tUST' : 'XLM',
    amount: stroopsToXlm(BigInt(e.amount)),
  };
}
