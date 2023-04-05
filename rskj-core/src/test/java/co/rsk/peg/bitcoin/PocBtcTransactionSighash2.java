package co.rsk.peg.bitcoin;

import co.rsk.bitcoinj.core.Address;
import co.rsk.bitcoinj.core.BtcECKey;
import co.rsk.bitcoinj.core.BtcTransaction;
import co.rsk.bitcoinj.core.Coin;
import co.rsk.bitcoinj.core.NetworkParameters;
import co.rsk.bitcoinj.core.Sha256Hash;
import co.rsk.bitcoinj.core.TransactionInput;
import co.rsk.bitcoinj.core.TransactionOutput;
import co.rsk.bitcoinj.crypto.TransactionSignature;
import co.rsk.bitcoinj.script.Script;
import co.rsk.bitcoinj.script.ScriptBuilder;
import co.rsk.bitcoinj.script.ScriptChunk;
import co.rsk.config.BridgeConstants;
import co.rsk.config.BridgeRegTestConstants;
import co.rsk.peg.BridgeUtils;
import co.rsk.peg.Federation;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static co.rsk.peg.PegTestUtils.createBaseInputScriptThatSpendsFromTheFederation;

class PocBtcTransactionSighash2 {

    private final BridgeConstants bridgeConstantsRegtest = BridgeRegTestConstants.getInstance();
    private final NetworkParameters btcRegTestParams = bridgeConstantsRegtest.getBtcParams();


    @Test
    void test_sighash_is_unique_for_same_tx() throws IOException {
        boolean signatureCanonical = false;

        List<BtcECKey> federatorPrivateKeys = BridgeRegTestConstants.REGTEST_FEDERATION_PRIVATE_KEYS;
        List<BtcECKey> privateKeysToSignWith = Arrays.asList(federatorPrivateKeys.get(0), federatorPrivateKeys.get(1));
        Federation federation = bridgeConstantsRegtest.getGenesisFederation();

        BtcTransaction prevTx = new BtcTransaction(btcRegTestParams);
        TransactionOutput prevOut = new TransactionOutput(btcRegTestParams, prevTx, Coin.FIFTY_COINS, federation.getAddress());
        prevTx.addOutput(prevOut);

        BtcTransaction t = new BtcTransaction(btcRegTestParams);
        TransactionOutput output = new TransactionOutput(btcRegTestParams, t, Coin.COIN, new BtcECKey().toAddress(btcRegTestParams));
        t.addOutput(output);
        t.addInput(prevOut).setScriptSig(createBaseInputScriptThatSpendsFromTheFederation(federation));

        //addOutput(federation, btcTx);

        Script inputScript = t.getInputs().get(0).getScriptSig();
        List<ScriptChunk> chunks = inputScript.getChunks();
        byte[] program = chunks.get(chunks.size() - 1).data;
        Script redeemScript = new Script(program);
        Sha256Hash sighash = t.hashForSignature(0, redeemScript, BtcTransaction.SigHash.ALL, false);

        BtcECKey.ECDSASignature sig = privateKeysToSignWith.get(0).sign(sighash);
        if (!signatureCanonical) {
            sig = new BtcECKey.ECDSASignature(sig.r, BtcECKey.CURVE.getN().subtract(sig.s));
        }
        byte[] derEncodedSig = sig.encodeToDER();

        List derEncodedSigs = new ArrayList();
        for (int i = 0; i < 1; i++) {
            derEncodedSigs.add(derEncodedSig);
        }

        processSigning(findPublicKeySignedBy(federation.getBtcPublicKeys(), privateKeysToSignWith.get(0)), derEncodedSigs, t);
    }

    private void addOutput(Federation federation, BtcTransaction btcTx) {

    }

    private BtcECKey findPublicKeySignedBy(List<BtcECKey> pubs, BtcECKey pk) {
        for (BtcECKey pub : pubs) {
            if (Arrays.equals(pk.getPubKey(), pub.getPubKey())) {
                return pub;
            }
        }
        return pk;
    }

    private boolean processSigning(BtcECKey federatorPublicKey, List<byte[]> signatures, BtcTransaction btcTx) {
        // Build input hashes for signatures
        int numInputs = btcTx.getInputs().size();

        List<Sha256Hash> sighashes = new ArrayList<>();
        List<TransactionSignature> txSigs = new ArrayList<>();
        for (int i = 0; i < numInputs; i++) {
            TransactionInput txIn = btcTx.getInput(i);
            Script inputScript = txIn.getScriptSig();
            List<ScriptChunk> chunks = inputScript.getChunks();
            byte[] program = chunks.get(chunks.size() - 1).data;
            Script redeemScript = new Script(program);
            sighashes.add(btcTx.hashForSignature(i, redeemScript, BtcTransaction.SigHash.ALL, false));
        }

        // Verify given signatures are correct before proceeding
        for (int i = 0; i < numInputs; i++) {
            BtcECKey.ECDSASignature sig;
            try {
                sig = BtcECKey.ECDSASignature.decodeFromDER(signatures.get(i));
            } catch (RuntimeException e) {
                throw new IllegalStateException("Error decoding DER");
            }

            Sha256Hash sighash = sighashes.get(i);

            if (!federatorPublicKey.verify(sighash, sig)) {
                throw new IllegalStateException("Verification failed");
            }

            TransactionSignature txSig = new TransactionSignature(sig, BtcTransaction.SigHash.ALL, false);
            txSigs.add(txSig);
            if (!txSig.isCanonical()) {
                throw new IllegalStateException("It is not canonical");
            }
        }

        boolean signed = false;

        // All signatures are correct. Proceed to signing
        for (int i = 0; i < numInputs; i++) {
            Sha256Hash sighash = sighashes.get(i);
            TransactionInput input = btcTx.getInput(i);
            Script inputScript = input.getScriptSig();

            boolean alreadySignedByThisFederator = BridgeUtils.isInputSignedByThisFederator(
                federatorPublicKey,
                sighash,
                input);

            // Sign the input if it wasn't already
            if (!alreadySignedByThisFederator) {
                try {
                    int sigIndex = inputScript.getSigInsertionIndex(sighash, federatorPublicKey);
                    inputScript = ScriptBuilder.updateScriptWithSignature(inputScript, txSigs.get(i).encodeToBitcoin(), sigIndex, 1, 1);
                    input.setScriptSig(inputScript);
                    signed = true;
                } catch (IllegalStateException e) {
                    throw new IllegalStateException("Error signing");
                }
            } else {
                throw new IllegalStateException("Already signed");
            }
        }

        return signed;
    }

    private BtcTransaction createTransaction(int toPk, Coin value) {
        return createTransaction(toPk, value, new BtcECKey());
    }

    private BtcTransaction createTransaction(int toPk, Coin value, BtcECKey btcECKey) {
        NetworkParameters params = NetworkParameters.fromID(NetworkParameters.ID_REGTEST);
        BtcTransaction input = new BtcTransaction(params);

        input.addOutput(Coin.COIN, btcECKey.toAddress(params));

        Address to = BtcECKey.fromPrivate(BigInteger.valueOf(toPk)).toAddress(params);

        BtcTransaction result = new BtcTransaction(params);
        result.addInput(input.getOutput(0));
        result.getInput(0).disconnect();
        result.addOutput(value, to);
        return result;
    }
}
