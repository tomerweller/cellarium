# Walkthrough: a repo from open to close

This is a screenshot tour of the [hosted wallet](https://blob.tomerweller.com/cellarium/)
driving one repurchase agreement through its complete lifecycle on the live
testnet deployment: **fund → negotiate → open → accrue interest → close
(repay) → withdraw**, with every state transition settled on Stellar testnet
by an UltraHonk validity proof.

> ⚠️ Everything here is a **proof of concept on testnet** — unaudited, no real
> value. See the [README warning](../README.md) and
> [Trust model & limitations](../README.md#trust-model--limitations).

The cast: a **borrower** who owns tokenized collateral (`tUST`, a mock
tokenized-Treasury token) and wants cash, and a **lender** with idle XLM. They
agree bilaterally on terms — the venue never sees an order book:

| term | value in this walkthrough |
|---|---|
| cash leg | 10 XLM |
| collateral | 2 tUST (worth 50 XLM at the oracle price of 25 XLM/tUST) |
| rate | 4.30% annualized, ACT/360 on seconds |
| haircut | 2.00% |
| term | 24 hours |

Every screenshot below was captured live against
`https://cellarium.fly.dev` (see [how this walkthrough was made](#how-this-walkthrough-was-made)).

## Step 1 — Create a rollup account

Open the wallet. There is no sign-up: a rollup account is just a keypair, and
the normal path derives it from the Stellar wallet you already have. Click
**Connect Freighter & derive account**, sign one message, and the signature
deterministically becomes your L2 key — same wallet, same key, on any device.

![Onboarding](walkthrough/01-onboarding.png)

Under **+ advanced** you can instead import a raw L2 secret or generate a
throwaway key (this scripted walkthrough uses throwaway keys, since a browser
robot has no Freighter):

![Onboarding, advanced options](walkthrough/02-onboarding-advanced.png)

Either way you land on an empty wallet — two balances (XLM cash, tUST
collateral), both zero:

![Fresh empty wallet](walkthrough/03-home-empty.png)

## Step 2 — Fund the account

**Deposit** moves value from your Stellar account into the rollup's escrow
contract. The form builds a Soroban transaction that calls `deposit` on the
rollup contract; Freighter signs it. Each asset has its own FIFO deposit
queue, and queued deposits are credited to your L2 balance when the sequencer
folds them into the next proven batch — typically under a minute.

![Deposit page](walkthrough/04-deposit-page.png)

For this walkthrough the borrower deposited **2 tUST + 1 XLM** (collateral
plus a buffer for interest) and the lender **15 XLM**. Once the batch lands,
the Wallet page shows credited balances:

![Funded wallet](walkthrough/05-home-funded.png)

## Step 3 — Exchange account ids

A counterparty is addressed by their L2 account id (`pk_x`, a 32-byte hex
string). **Receive** shows yours as text and QR — share it out-of-band, like
an IBAN:

![Receive page](walkthrough/06-receive.png)

## Step 4 — The borrower posts an intent

On **Repos → New repo intent**, the borrower picks their role, pastes the
lender's account id, and enters the terms. Nothing here is an order on a
book: the intent is a *half-signed bilateral agreement* — the wallet signs
the exact integer terms (stroops, base units, bps, seconds) with the
borrower's L2 key, and the sequencer will show it **only** to the named
counterparty.

![New intent form, filled](walkthrough/07-intent-form.png)

After posting, the borrower sees it waiting:

![Intent posted, awaiting counterparty](walkthrough/08-intent-posted.png)

## Step 5 — The lender countersigns

The lender's Repos page shows the incoming intent with their role spelled
out — *you fund 10 XLM* — and one button:

![Incoming intent, lender view](walkthrough/09-intent-incoming.png)

**Accept & countersign** adds the lender's signature over the same message
and hands the now fully-signed open to the sequencer. In the next batch, the
circuit verifies **both** Grumpkin-Schnorr signatures, checks the lender has
the cash, the borrower has the collateral, and that the collateral is
adequate at the oracle price bound into the proof — then moves 10 XLM to the
borrower and locks 2 tUST into the position. One proof later, both parties
have a live position:

![Open position, lender view](walkthrough/10-position-lender.png)

## Step 6 — The open position

The borrower's view of the same position. Interest accrues per second
(ACT/360: `interest = ⌊cash · rate_bps · elapsed / (10⁴ · 360 · 86400)⌋`,
floor division enforced in-circuit) and the card shows the live repay-now
amount, the **liquidation price** (the oracle price below which anyone may
liquidate), and the maturity deadline after which the lender can claim
default:

![Open position, borrower view with accruing interest](walkthrough/11-position-borrower.png)

## Step 7 — The borrower closes (repays)

Before maturity, only the borrower can close. The **Close** button signs a
close order for principal + interest; the interest actually charged is
computed from the *settlement batch's timestamp*, so the on-screen number is
an estimate that grows until inclusion. In this run about a
minute of settlement time elapsed between the opening and closing batches,
and the circuit charged exactly **8 stroops** (0.0000008 XLM) of interest on
the 10 XLM — check it by hand:
`⌊100,000,000 · 430 · 60 / 311,040,000,000⌋ = 8`.

After the closing batch settles: collateral back to the borrower, principal +
interest to the lender.

![Wallet after close](walkthrough/12-home-after-close.png)

**Activity** shows the full story from the borrower's perspective — deposits,
the repo opening, and the close with the exact repayment:

![Activity feed](walkthrough/13-activity.png)

## Step 8 — Withdraw back to Stellar

**Send** doubles as the exit: paste a Stellar `G...` address instead of an L2
account id and the transfer becomes a withdrawal that leaves the rollup.

![Withdrawal form](walkthrough/14-withdraw-form.png)

Withdrawals are irreversible, so the wallet asks you to confirm the exact
amount and destination:

![Withdrawal confirmation](walkthrough/15-withdraw-confirm.png)

When the batch settles, the rollup contract pays the tokens out of escrow
straight to the Stellar address — the tUST arrives as a regular Soroban token
balance, no trustline needed.

## Step 9 — Verify it all on-chain

Everything above settled as UltraHonk proofs verified by the rollup contract
on Stellar testnet. The **Explorer** tab shows the receipts: the sequencer's
state root against the root the contract accepted on-chain (they must match),
and one row per proven batch — including a downloadable DA blob from which
the full state can be reconstructed:

![Explorer: batches and matching roots](walkthrough/16-explorer.png)

## The two other endings

This walkthrough took the happy path. A position that is not repaid ends one
of two other ways, neither of which needs the borrower's cooperation:

- **Default at maturity.** Once `batch_ts > maturity_ts`, default is
  permissionless: the sequencer's maturity watcher submits it automatically,
  and the circuit hands the locked collateral to the lender (the borrower
  keeps the cash — that's the title-transfer analog).
- **Liquidation on a margin breach.** If the oracle price falls far enough
  that the collateral no longer covers the loan at half the initial haircut
  (`coll·price·2·10⁴ < cash·(2·10⁴+haircut)·10⁷`), anyone may liquidate at
  the price bound into the batch — the margin watcher does it automatically.
  The position card's "liquidation below …" line (Step 6) is exactly this
  threshold, solved for the price.

Both paths run end-to-end in [`scripts/e2e_testnet.sh`](../scripts/e2e_testnet.sh)
(a short-maturity repo auto-defaults; an admin price crash triggers a
liquidation), and [`scripts/demo.sh`](../scripts/demo.sh) narrates the same
lifecycle as this document from the command line.

## How this walkthrough was made

The screenshots are real: a Playwright script drove the production wallet at
`blob.tomerweller.com/cellarium` against the live sequencer at
`cellarium.fly.dev` (contract `CDI3WL…OSV6` on Stellar testnet), on
2026-08-03. Two browser profiles played borrower and lender with generated
throwaway keys. The only step a human does differently is signing: real users
derive their key and sign deposits with Freighter, which a headless browser
cannot drive, so the script used the advanced throwaway-key path and the
deposits were submitted by the operator's CLI identity on the users' behalf.
Every other action — intent, countersign, close, withdraw — was clicked in
the UI exactly as a user would, signed client-side by the wallet's own code.
