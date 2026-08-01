import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useQueryClient } from '@tanstack/react-query';
import { useParams } from '../api/queries';
import { useKey } from '../keys/KeyContext';
import { awaitTx, connectFreighter, deposit, friendbotUrl, fundingStatus } from '../api/stellar';
import * as pendingDeposits from '../keys/pendingDeposits';
import { xlmToStroops } from '../format';
import { ErrorText, Stepper } from '../components/common';
import { Onboarding } from './Onboarding';

const STEPS = ['Connect Freighter', 'Confirm in Freighter', 'Waiting for Stellar', 'Credited'];

export function Deposit() {
  const { wallet } = useKey();
  const { data: params } = useParams();
  const navigate = useNavigate();
  const qc = useQueryClient();
  const [amount, setAmount] = useState('');
  const [asset, setAsset] = useState<0 | 1>(0);
  const [step, setStep] = useState<number>(-1); // -1 idle; 0..3 active; 4 done
  const [gAddr, setGAddr] = useState<string | null>(null);
  const [needsFunding, setNeedsFunding] = useState(false);
  const [error, setError] = useState<unknown>(null);

  if (!wallet) return <Onboarding />;

  const busy = step >= 0 && step < 4;

  async function run() {
    if (!params || !wallet) return;
    setError(null);
    setNeedsFunding(false);
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
      setStep(2);
      const outcome = await awaitTx(params, hash);
      if (outcome === 'failed') {
        throw new Error(
          `The deposit transaction failed on Stellar (tx ${hash.slice(0, 8)}…). No funds were credited — try again.`,
        );
      }
      if (outcome === 'timeout') {
        throw new Error(
          "Stellar hasn't confirmed the deposit yet. Give it a minute — if your balance doesn't update, retry.",
        );
      }
      // Track locally so the "settling" indicator shows until the L2 credit lands.
      pendingDeposits.add({ pkX: wallet.pkX, amount: stroops.toString(), txHash: hash, at: Date.now() });
      setStep(4);
      qc.invalidateQueries({ queryKey: ['account'] });
      qc.invalidateQueries({ queryKey: ['status'] });
    } catch (e) {
      setError(e);
      setStep(-1);
    }
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
        <button className="primary" onClick={run} disabled={busy || amount.length === 0}>
          {busy ? 'Depositing…' : 'Deposit with Freighter'}
        </button>
      </div>

      {step >= 0 && <Stepper steps={STEPS} current={step} />}

      {needsFunding && gAddr && (
        <p className="muted">
          Your Stellar account {gAddr.slice(0, 8)}… isn't funded on testnet.{' '}
          <a href={friendbotUrl(gAddr)} target="_blank" rel="noreferrer">Fund it with friendbot</a>, then retry.
        </p>
      )}
      {step === 4 && (
        <p className="ok">Deposited. Your balance updates when the next batch settles.</p>
      )}
      <ErrorText error={error} />
    </div>
  );
}
