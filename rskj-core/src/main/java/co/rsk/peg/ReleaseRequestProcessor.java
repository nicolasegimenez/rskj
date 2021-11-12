package co.rsk.peg;

import static org.ethereum.config.blockchain.upgrades.ConsensusRule.RSKIP271;

import co.rsk.bitcoinj.core.BtcTransaction;
import co.rsk.bitcoinj.core.Coin;
import co.rsk.bitcoinj.core.Context;
import co.rsk.bitcoinj.core.TransactionInput;
import co.rsk.bitcoinj.core.UTXO;
import co.rsk.bitcoinj.wallet.Wallet;
import co.rsk.core.RskAddress;
import co.rsk.crypto.Keccak256;
import co.rsk.peg.ReleaseTransactionBuilder.BuildResult;
import java.io.IOException;
import java.util.List;
import java.util.Optional;
import org.ethereum.config.blockchain.upgrades.ActivationConfig;
import org.ethereum.config.blockchain.upgrades.ConsensusRule;

public class ReleaseRequestProcessor {

    private BridgeStorageProvider provider;
    private Context btcContext;
    private ActivationConfig.ForBlock activations;
    private FederationSupport federationSupport;

    private static final int MAX_RELEASE_ITERATIONS = 30;
    public static final RskAddress BURN_ADDRESS = new RskAddress("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF");
    
    public ReleaseRequestProcessor(Context btcContext, BridgeStorageProvider provider) {
        this.btcContext =btcContext;
        this.provider = provider;
    }

    /**
     * Processes the current btc release request queue
     * and tries to build btc transactions using (and marking as spent)
     * the current active federation's utxos.
     * Newly created btc transactions are added to the btc release tx set,
     * and failed attempts are kept in the release queue for future
     * processing.
     *
     */
    public void processReleaseRequests(long nextPegoutCreationBlockNumber) {
        final Wallet activeFederationWallet;
        final ReleaseRequestQueue releaseRequestQueue;

        try {
            activeFederationWallet = getActiveFederationWallet(true);
            releaseRequestQueue = provider.getReleaseRequestQueue();
        } catch (IOException e) {
            logger.error("Unexpected error accessing storage while attempting to process release requests", e);
            return;
        }

        // Releases are attempted using the currently active federation
        // wallet.
        final ReleaseTransactionBuilder txBuilder = new ReleaseTransactionBuilder(
            btcContext.getParams(),
            activeFederationWallet,
            getFederationAddress(),
            getFeePerKb(),
            activations
        );

        // We have a BTC transaction, mark the UTXOs as spent and add the tx to the release set.
        List<UTXO> availableUTXOs;
        ReleaseTransactionSet releaseTransactionSet;
        // Attempt access to storage first
        // (any of these could fail and would invalidate both the tx build and utxo selection, so treat as atomic)
        try {
            availableUTXOs = getActiveFederationBtcUTXOs();
            releaseTransactionSet = provider.getReleaseTransactionSet();
        } catch (IOException exception) {
            // Unexpected error accessing storage, log and fail
            logger.error("Unexpected error accessing storage while attempting to processReleaseRequests ", exception);
            return;
        }

        // Instead of creating a pegout transaction for every element in the release request queue,
        // check if the elapsed time or blocks have gone by before creating the pegout transaction including all elements in the release request queue.
        // Under a rush hour of peg-outs, the Bridge may need to create more than one peg-out transaction
        // simultaneously per peg-out event to reduce the transaction size, and input count.
        // Pending: Define the limit of the transaction size

        if (activations.isActive(RSKIP271)) {
            processReleasesInBatch(releaseRequestQueue, txBuilder, availableUTXOs, releaseTransactionSet);
        } else {
            processReleasesIndividually(releaseRequestQueue, txBuilder, availableUTXOs, releaseTransactionSet);
        }
    }

    private void processReleasesIndividually(ReleaseRequestQueue releaseRequestQueue,
        ReleaseTransactionBuilder txBuilder,
        List<UTXO> availableUTXOs,
        ReleaseTransactionSet releaseTransactionSet){
        releaseRequestQueue.process(MAX_RELEASE_ITERATIONS, (ReleaseRequestQueue.Entry releaseRequest) -> {
            Optional<BuildResult> result = txBuilder.buildAmountTo(
                releaseRequest.getDestination(),
                releaseRequest.getAmount()
            );

            // Couldn't build a transaction to release these funds
            // Log the event and return false so that the request remains in the
            // queue for future processing.
            // Further logging is done at the tx builder level.
            if (!result.isPresent()) {
                logger.warn(
                    "Couldn't build a release BTC tx for <{}, {}>",
                    releaseRequest.getDestination().toBase58(),
                    releaseRequest.getAmount());
                return false;
            }

            BtcTransaction generatedTransaction = result.get().getBtcTx();
            addPegoutTxToReleaseTransactionSet(generatedTransaction, releaseTransactionSet, releaseRequest);

            // Mark UTXOs as spent
            List<UTXO> selectedUTXOs = result.get().getSelectedUTXOs();
            availableUTXOs.removeAll(selectedUTXOs);

            // TODO: (Ariel Mendelzon, 07/12/2017)
            // TODO: Balance adjustment assumes that change output is output with index 1.
            // TODO: This will change if we implement multiple releases per BTC tx, so
            // TODO: it would eventually need to be fixed.
            // Adjust balances in edge cases
            adjustBalancesIfChangeOutputWasDust(generatedTransaction, releaseRequest.getAmount());

            return true;
        });
    }

    /**
     * If federation change output value had to be increased to be non-dust, the federation now has
     * more BTC than it should. So, we burn some sBTC to make balances match.
     *
     * @param btcTx      The btc tx that was just completed
     * @param sentByUser The number of sBTC originaly sent by the user
     */
    private void adjustBalancesIfChangeOutputWasDust(BtcTransaction btcTx, Coin sentByUser) {
        if (btcTx.getOutputs().size() <= 1) {
            // If there is no change, do-nothing
            return;
        }
        Coin sumInputs = Coin.ZERO;
        for (TransactionInput transactionInput : btcTx.getInputs()) {
            sumInputs = sumInputs.add(transactionInput.getValue());
        }
        Coin change = btcTx.getOutput(1).getValue();
        Coin spentByFederation = sumInputs.subtract(change);
        if (spentByFederation.isLessThan(sentByUser)) {
            Coin coinsToBurn = sentByUser.subtract(spentByFederation);
            TransferExecutor t = new TransferExecutor(rskRepository, subtraces);
            t.transferTo(BURN_ADDRESS, co.rsk.core.Coin.fromBitcoin(coinsToBurn));
        }
    }

    private void processReleasesInBatch(ReleaseRequestQueue releaseRequestQueue,
        ReleaseTransactionBuilder txBuilder,
        List<UTXO> availableUTXOs,
        ReleaseTransactionSet releaseTransactionSet,
        long currentBlockNumber,
        long nextPegoutCreationBlockNumber) {
        
        if (currentBlockNumber >= nextPegoutCreationBlockNumber) {
            // batch pegout transactions
            Optional<ReleaseTransactionBuilder.BuildResult> result = txBuilder.buildBatchedPegouts(releaseRequestQueue.getEntries());

            if (!result.isPresent()) {
                logger.warn(
                    "Couldn't build a release BTC tx for <{}, with sum {}>",
                    releaseRequestQueue.getEntries().hashCode(),
                    releaseRequestQueue.getEntries().stream().mapToDouble(e -> e.getAmount().value).sum());
                return;
            }

            BtcTransaction generatedTransaction = result.get().getBtcTx();
            addPegoutTxToReleaseTransactionSet(generatedTransaction, releaseTransactionSet);

            // Mark UTXOs as spent
            List<UTXO> selectedUTXOs = result.get().getSelectedUTXOs();
            availableUTXOs.removeAll(selectedUTXOs);

            // update next Pegout height
            long nextPegoutHeight = currentBlockNumber + bridgeConstants.getNumberOfBlocksBetweenPegouts();
            provider.setNextPegoutHeight(nextPegoutHeight);

            // TODO: Update Adjust balances in edge cases

        }
    }

    private void addPegoutTxToReleaseTransactionSet(BtcTransaction generatedTransaction,
        ReleaseTransactionSet releaseTransactionSet,
        ReleaseRequestQueue.Entry releaseRequest) {
        if (activations.isActive(ConsensusRule.RSKIP146)) {
            Keccak256 rskTxHash = releaseRequest.getRskTxHash();
            // Add the TX
            releaseTransactionSet.add(generatedTransaction, rskExecutionBlock.getNumber(), rskTxHash);
            // For a short time period, there could be items in the release request queue that don't have the rskTxHash
            // (these are releases created right before the consensus rule activation, that weren't processed before its activation)
            // We shouldn't generate the event for those releases
            if (rskTxHash != null) {
                // Log the Release request
                eventLogger.logReleaseBtcRequested(rskTxHash.getBytes(), generatedTransaction, releaseRequest.getAmount());
            }
        } else {
            releaseTransactionSet.add(generatedTransaction, rskExecutionBlock.getNumber());
        }
    }

    
}
