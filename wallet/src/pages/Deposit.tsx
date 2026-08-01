import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useQueryClient } from '@tanstack/react-query';
import { useAccount, useParams } from '../api/queries';
import { useKey } from '../keys/KeyContext';
import { awaitTx, connectFreighter, deposit, friendbotUrl, fundingStatus } from '../api/stellar';
import * as pendingDeposits from '../keys/pendingDeposits';
import { txUrl } from '../config';
import { stroopsToXlm, xlmToStroops } from '../format';
import { ErrorText, Stepper } from '../components/common';
import { Onboarding } from './Onboarding';

const STEPS = ['Connect Freighter', 'Confirm in Freighter', 'Waiting for Stellar', 'Credited'];

export function Deposit() {
  const { wallet } = useKey();
  const { data: params } = useParams();
  const { data: account } = useAccount(wallet?.pkX);
  const navigate = useNavigate();
  const qc = useQueryClient();
  const [amount, setAmount] = useState('');
  const [asset, setAsset] = useState<0 | 1>(0);
  const [step, setStep] = useState<number>(-1); // -1 idle; 0..3 active; 4 done
  const [gAddr, setGAddr] = useState<string | null>(null);
  const [needsFunding, setNeedsFunding] = useState(false);
  const [unknownHash, setUnknownHash] = useState<string | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [, setBump] = useState(0); // re-render after pendingDeposits changes
  const rerender = () => setBump((n) => n + 1);

  if (!wallet) return <Onboarding />;

  // Confirmation-ambiguous deposits block a blind retry (issue #19): the
  // earlier submission may still land, and submitting again doubles it.
  const unresolved = pendingDeposits.list(wallet.pkX);
  const hasUnknown = unresolved.some((d) => d.status === 'submitted');
  const busy = step >= 0 && step < 4;

  async function run() {
    if (!params || !wallet) return;
    setError(null);
    setNeedsFunding(false);
    setUnknownHash(null);
    try {
      const stroops = xlmToStroops(amount);
      setStep(0);
      const addr = await connectFreighter(params);
      setGAddr(addr);
      // Friendbot is offered only for the RPC's definitive account-missing
      // answer; a transport failure is an error, not "unfunded" (issue #29).
      const funding = await fundingStatus(params, addr);
      if (funding === 'unfunded') {
        setNeedsFunding(true);
        setStep(-1);
        return;
      }
      if (funding === 'unknown') {
        throw new Error(
          'Could not check your Stellar account (RPC unreachable). Nothing was submitted — try again.',
        );
      }
      setStep(1);
      const hash = await deposit(params, addr, wallet.pkX, asset, stroops);
      // Stellar ACCEPTED the transaction: persist the hash NOW, before any
      // polling can time out ambiguously (issue #19), with the asset and the
      // pre-deposit balance baseline for reconciliation (issue #24).
      const baseline = asset === 1 ? (account?.coll ?? '0') : (account?.cash ?? '0');
      pendingDeposits.add({
        pkX: wallet.pkX,
        asset,
        amount: stroops.toString(),
        baseline,
        txHash: hash,
        at: Date.now(),
        status: 'submitted',
      });
      setStep(2);
      const outcome = await awaitTx(params, hash);
      if (outcome === 'failed') {
        // Definitive L1 failure: nothing to wait for, retry is safe.
        pendingDeposits.remove(hash);
        throw new Error(
          `The deposit transaction failed on Stellar (tx ${hash.slice(0, 8)}…). No funds were credited — try again.`,
        );
      }
      if (outcome === 'timeout') {
        // Ambiguous: the tx may still succeed. Keep the record, show it as
        // pending/unknown, and warn against a duplicate submission.
        setUnknownHash(hash);
        setStep(-1);
        return;
      }
      pendingDeposits.markConfirmed(hash);
      setStep(4);
      qc.invalidateQueries({ queryKey: ['account'] });
      qc.invalidateQueries({ queryKey: ['status'] });
    } catch (e) {
      setError(e);
      setStep(-1);
    }
  }

  /** Re-poll an ambiguous deposit to a terminal state (resumable across reloads). */
  async function recheck(hash: string) {
    if (!params) return;
    setError(null);
    const outcome = await awaitTx(params, hash);
    if (outcome === 'success') pendingDeposits.markConfirmed(hash);
    if (outcome === 'failed') pendingDeposits.remove(hash);
    if (outcome !== 'timeout') setUnknownHash(null);
    qc.invalidateQueries({ queryKey: ['account'] });
    rerender();
  }

  return (
    <div className="panel">
      <a className="back" onClick={() => navigate('/')}>← Wallet</a>
      <h2>Deposit</h2>
      <p className="muted">
        Move XLM or tUST from your Stellar account (via Freighter) into the rollup. It credits
        your L2 account when the next batch settles — usually within seconds.
        {asset === 1 && ' (Your Stellar account needs tUST first — ask the operator to mint some: scripts/mint_tust.sh.)'}
      </p>
      <label>
        Asset{' '}
        <select value={asset} onChange={(e) => setAsset(Number(e.target.value) as 0 | 1)} disabled={busy}>
          <option value={0}>XLM (cash)</option>
          <option value={1}>tUST (collateral)</option>
        </select>
      </label>
      <label>Amount ({asset === 0 ? 'XLM' : 'tUST'})</label>
      <input
        placeholder="0.0"
        value={amount}
        onChange={(e) => setAmount(e.target.value)}
        disabled={busy}
      />
      <div style={{ marginTop: '1rem' }}>
        <button className="primary" onClick={run} disabled={busy || hasUnknown || amount.length === 0}>
          {busy ? 'Depositing…' : 'Deposit with Freighter'}
        </button>
        {hasUnknown && !busy && (
          <p className="muted">
            A previous deposit hasn't reached a definitive outcome yet — check its status below
            before submitting again, or you risk depositing twice.
          </p>
        )}
      </div>

      {step >= 0 && <Stepper steps={STEPS} current={step} />}

      {needsFunding && gAddr && (
        <p className="muted">
          Your Stellar account {gAddr.slice(0, 8)}… isn't funded on testnet.{' '}
          <a href={friendbotUrl(gAddr)} target="_blank" rel="noreferrer">Fund it with friendbot</a>, then retry.
        </p>
      )}
      {unknownHash && (
        <p className="muted" role="alert">
          Stellar hasn't confirmed the deposit yet — it may still succeed, so it is tracked below
          rather than discarded.{' '}
          <a href={txUrl(unknownHash)} target="_blank" rel="noreferrer">View on stellar.expert</a>.
        </p>
      )}
      {step === 4 && (
        <p className="ok">Deposited. Your balance updates when the next batch settles.</p>
      )}
      <ErrorText error={error} />

      {unresolved.length > 0 && (
        <section style={{ marginTop: '1.2rem' }}>
          <h3>In-flight deposits</h3>
          {unresolved.map((d) => (
            <div className="list-row" key={d.txHash}>
              <div className="who">
                <span className="kind">
                  {stroopsToXlm(BigInt(d.amount))} {d.asset === 1 ? 'tUST' : 'XLM'} —{' '}
                  {d.status === 'confirmed' ? 'confirmed, awaiting L2 credit' : 'confirmation unknown'}
                </span>
                <span className="cp">
                  <a href={txUrl(d.txHash)} target="_blank" rel="noreferrer">
                    tx {d.txHash.slice(0, 8)}…
                  </a>
                </span>
              </div>
              {d.status === 'submitted' && (
                <button className="btn-inline" onClick={() => recheck(d.txHash)}>
                  Check status
                </button>
              )}
            </div>
          ))}
        </section>
      )}
    </div>
  );
}
