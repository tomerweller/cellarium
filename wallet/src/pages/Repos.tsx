// The repo desk (PLAN.md 1.9): post open intents, countersign incoming ones,
// watch open positions with live accrued interest + liquidation price, and
// close as borrower.
import { useEffect, useState } from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { useAccount } from '../api/queries';
import {
  acceptIntent,
  closePosition,
  createIntent,
  intentTerms,
  liquidationPrice,
  listIntents,
} from '../api/repo';
import { api, Intent, Position } from '../api/sequencer';
import { interest } from '../crypto/repo';
import { POLL_MS } from '../config';
import { useKey } from '../keys/KeyContext';
import { CopyableHex, ErrorText } from '../components/common';
import { formatTs, isCanonicalPkX, shortHex, stroopsToXlm } from '../format';
import { Onboarding } from './Onboarding';

const TUST_PER_UNIT = 10_000_000n;

function tustFmt(base: bigint): string {
  const whole = base / TUST_PER_UNIT;
  const frac = (base % TUST_PER_UNIT).toString().padStart(7, '0').replace(/0+$/, '');
  return frac ? `${whole}.${frac}` : whole.toString();
}

function useNow(): number {
  const [now, setNow] = useState(() => Math.floor(Date.now() / 1000));
  useEffect(() => {
    const t = setInterval(() => setNow(Math.floor(Date.now() / 1000)), 1000);
    return () => clearInterval(t);
  }, []);
  return now;
}

export function Repos() {
  const { wallet } = useKey();
  if (!wallet) return <Onboarding />;
  return <Desk pkX={wallet.pkX} sk={wallet.sk} />;
}

function Desk({ pkX, sk }: { pkX: string; sk: bigint }) {
  const qc = useQueryClient();
  const { data: positions } = useQuery({
    queryKey: ['positions', pkX],
    queryFn: () => api.positions(pkX),
    refetchInterval: POLL_MS,
  });
  const { data: intents } = useQuery({
    queryKey: ['intents', pkX],
    // Signed read-auth (issue #1 L12): listings require proof of key control.
    queryFn: () => listIntents(sk),
    refetchInterval: POLL_MS,
  });
  const refresh = () => {
    qc.invalidateQueries({ queryKey: ['positions'] });
    qc.invalidateQueries({ queryKey: ['intents'] });
    qc.invalidateQueries({ queryKey: ['account'] });
  };

  return (
    <div className="stack">
      <PositionList pkX={pkX} sk={sk} positions={positions?.positions ?? []} onChange={refresh} />
      <IncomingIntents sk={sk} intents={intents?.incoming ?? []} onChange={refresh} />
      <OutgoingIntents intents={intents?.outgoing ?? []} />
      <NewIntentForm sk={sk} onCreated={refresh} />
    </div>
  );
}

function PositionList({
  pkX,
  sk,
  positions,
  onChange,
}: {
  pkX: string;
  sk: bigint;
  positions: Position[];
  onChange: () => void;
}) {
  const now = useNow();
  const { data: account } = useAccount(pkX);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);

  async function close(p: Position) {
    if (!account) return;
    setBusy(true);
    setError(null);
    try {
      await closePosition(sk, p, account.pending_nonce);
      onChange();
    } catch (e) {
      setError(e);
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className="panel">
      <h2>Open positions</h2>
      {positions.length === 0 && <p className="muted">No open repos.</p>}
      {positions.map((p) => {
        const borrower = p.borrower_pk_x === pkX;
        const elapsed = BigInt(Math.max(0, now - p.open_ts));
        const accrued = interest(BigInt(p.cash), BigInt(p.rate_bps), elapsed);
        const matured = now > p.maturity_ts;
        return (
          <div key={p.slot} className="panel" data-testid={`position-${p.slot}`}>
            <div>
              <strong>{borrower ? 'Borrowing' : 'Lending'}</strong>{' '}
              {stroopsToXlm(BigInt(p.cash))} XLM vs {tustFmt(BigInt(p.coll))} tUST
            </div>
            <div className="muted">
              {(p.rate_bps / 100).toFixed(2)}% · haircut {(p.haircut_bps / 100).toFixed(2)}% ·
              slot {p.slot}
            </div>
            <div className="muted">
              {borrower ? 'counterparty (lender)' : 'counterparty (borrower)'}:{' '}
              <CopyableHex value={borrower ? p.lender_pk_x : p.borrower_pk_x} />
            </div>
            <div>
              accrued interest: <strong>{stroopsToXlm(accrued)} XLM</strong>
              {' · '}repay now: {stroopsToXlm(BigInt(p.cash) + accrued)} XLM
            </div>
            <div className="muted">
              liquidation below {stroopsToXlm(liquidationPrice(p))} XLM/tUST · matures{' '}
              {formatTs(p.maturity_ts)}
              {matured && <strong> — MATURED (defaultable)</strong>}
            </div>
            {borrower && !matured && (
              <button disabled={busy} onClick={() => close(p)}>
                Close (repay {stroopsToXlm(BigInt(p.cash) + accrued)} XLM)
              </button>
            )}
          </div>
        );
      })}
      <ErrorText error={error} />
    </section>
  );
}

function IncomingIntents({
  sk,
  intents,
  onChange,
}: {
  sk: bigint;
  intents: Intent[];
  onChange: () => void;
}) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);

  async function accept(i: Intent) {
    setBusy(true);
    setError(null);
    try {
      await acceptIntent(sk, i);
      onChange();
    } catch (e) {
      setError(e);
    } finally {
      setBusy(false);
    }
  }

  if (intents.length === 0) return null;
  return (
    <section className="panel">
      <h2>Incoming intents</h2>
      {intents.map((i) => {
        const theyBorrow = i.initiator === 'borrower';
        const terms = intentTerms(i);
        return (
          <div key={i.id} className="panel" data-testid={`intent-${i.id}`}>
            <div>
              <strong>{shortHex(theyBorrow ? i.borrower_pk_x : i.lender_pk_x)}</strong> wants to{' '}
              {theyBorrow ? 'borrow' : 'lend'} {stroopsToXlm(terms.cash)} XLM vs{' '}
              {tustFmt(terms.coll)} tUST
            </div>
            <div className="muted">
              {(i.rate_bps / 100).toFixed(2)}% · haircut {(i.haircut_bps / 100).toFixed(2)}% ·
              matures {formatTs(i.maturity_ts)}
            </div>
            <div className="muted">
              your role: <strong>{theyBorrow ? 'lender' : 'borrower'}</strong>
              {theyBorrow
                ? ` — you fund ${stroopsToXlm(terms.cash)} XLM`
                : ` — you post ${tustFmt(terms.coll)} tUST collateral`}
            </div>
            <button disabled={busy} onClick={() => accept(i)}>
              Accept &amp; countersign
            </button>
          </div>
        );
      })}
      <ErrorText error={error} />
    </section>
  );
}

function OutgoingIntents({ intents }: { intents: Intent[] }) {
  if (intents.length === 0) return null;
  return (
    <section className="panel">
      <h2>Awaiting counterparty</h2>
      {intents.map((i) => (
        <div key={i.id} className="muted">
          #{i.id}: {i.initiator === 'borrower' ? 'borrow' : 'lend'}{' '}
          {stroopsToXlm(BigInt(i.cash))} XLM vs {tustFmt(BigInt(i.coll))} tUST —{' '}
          {(i.rate_bps / 100).toFixed(2)}%
        </div>
      ))}
    </section>
  );
}

function NewIntentForm({ sk, onCreated }: { sk: bigint; onCreated: () => void }) {
  const [role, setRole] = useState<'borrower' | 'lender'>('borrower');
  const [counterparty, setCounterparty] = useState('');
  const [cash, setCash] = useState('');
  const [coll, setColl] = useState('');
  const [rate, setRate] = useState('4.30');
  const [haircut, setHaircut] = useState('2.00');
  const [termHours, setTermHours] = useState('24');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const [ok, setOk] = useState<string | null>(null);

  const valid =
    isCanonicalPkX(counterparty) &&
    Number(cash) > 0 &&
    Number(coll) > 0 &&
    Number(rate) >= 0 &&
    Number(haircut) >= 0 &&
    Number(termHours) > 0;

  async function submit() {
    setBusy(true);
    setError(null);
    setOk(null);
    try {
      const res = await createIntent(sk, {
        role,
        counterpartyPkX: counterparty.trim(),
        cash: BigInt(Math.round(Number(cash) * 1e7)),
        coll: BigInt(Math.round(Number(coll) * 1e7)),
        rateBps: Math.round(Number(rate) * 100),
        haircutBps: Math.round(Number(haircut) * 100),
        termSecs: Math.round(Number(termHours) * 3600),
      });
      setOk(`Intent #${res.id} posted — waiting for the counterparty to countersign.`);
      setCounterparty('');
      setCash('');
      setColl('');
      onCreated();
    } catch (e) {
      setError(e);
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className="panel">
      <h2>New repo intent</h2>
      <label>
        I want to
        <select value={role} onChange={(e) => setRole(e.target.value as 'borrower' | 'lender')}>
          <option value="borrower">borrow cash (post tUST collateral)</option>
          <option value="lender">lend cash (receive tUST collateral)</option>
        </select>
      </label>
      <label>
        Counterparty L2 key (pk_x)
        <input
          value={counterparty}
          onChange={(e) => setCounterparty(e.target.value)}
          placeholder="0x…"
        />
      </label>
      <label>
        Cash leg (XLM)
        <input value={cash} onChange={(e) => setCash(e.target.value)} placeholder="10" />
      </label>
      <label>
        Collateral (tUST)
        <input value={coll} onChange={(e) => setColl(e.target.value)} placeholder="1.5" />
      </label>
      <label>
        Rate (% annualized, ACT/360)
        <input value={rate} onChange={(e) => setRate(e.target.value)} />
      </label>
      <label>
        Haircut (%)
        <input value={haircut} onChange={(e) => setHaircut(e.target.value)} />
      </label>
      <label>
        Term (hours)
        <input value={termHours} onChange={(e) => setTermHours(e.target.value)} />
      </label>
      <button disabled={!valid || busy} onClick={submit}>
        Sign &amp; post intent
      </button>
      {ok && <p className="ok">{ok}</p>}
      <ErrorText error={error} />
    </section>
  );
}
