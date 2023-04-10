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
import org.apache.commons.lang3.tuple.Pair;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Stream;

import static co.rsk.peg.PegTestUtils.createBaseInputScriptThatSpendsFromTheFederation;

class PocBtcTransactionSighash {
    private static final BridgeConstants bridgeConstantsRegtest = BridgeRegTestConstants.getInstance();
    private static final NetworkParameters btcRegTestParams = bridgeConstantsRegtest.getBtcParams();


    private static Address addressOf(int privateKey) {
        return BtcECKey.fromPrivate(BigInteger.valueOf(privateKey)).toAddress(btcRegTestParams);
    }

    private static Address randomAddress() {
        return new BtcECKey().toAddress(btcRegTestParams);
    }

    private static BtcTransaction createTransaction(Address from, Address to, Coin value) {
        BtcTransaction input = new BtcTransaction(btcRegTestParams);
        input.addOutput(Coin.COIN, from);
        BtcTransaction result = new BtcTransaction(btcRegTestParams);
        result.addInput(input.getOutput(0));
        //result.getInput(0).disconnect();
        result.addOutput(value, to);
        return result;
    }

    private Sha256Hash extractSighashFromSignedBtcTx(int inputIndex, BtcTransaction signedBtcTx) {
        //Script scriptPubKey = signedBtcTx.getInput(inputIndex).getConnectedOutput().getScriptPubKey();
        Script script = extractReedemScript(signedBtcTx.getInput(inputIndex));
        return signedBtcTx.hashForSignature(inputIndex, script, BtcTransaction.SigHash.ALL, false);
    }

    private Script extractReedemScript(TransactionInput txIn) {
        Script inputScript = txIn.getScriptSig();
        List<ScriptChunk> chunks = inputScript.getChunks();
        byte[] program = chunks.get(chunks.size() - 1).data;
        if(program != null)
            return new Script(program);
        else
            return inputScript;
    }

    // [82, 33, 2, -51, 83, -4, 83, -96, 127, 33, 22, 65, -90, 119, -46, 80, -10, -34, -103, -54, -10, 32, -24, -25, 112, 113, -24, 17, -94, -117, 59, -51, -33, 11, -31, 33, 3, 98, 99, 74, -75, 125, -82, -100, -77, 115, -91, -43, 54, -26, 106, -116, 79, 103, 70, -117, -68, -5, 6, 56, 9, -70, -74, 67, 7, 45, 120, -95, 36, 33, 3, -59, -108, 107, 63, -70, -32, 58, 101, 66, 55, -38, -122, 60, -98, -43, 52, -32, -121, -122, 87, 23, 91, 19, 43, -116, -90, 48, -14, 69, +5 more]


    private static Stream<Arguments> providePrivateKeysAndBtcTx() {
        List<BtcECKey> privateKeys = new ArrayList<>();
        BtcECKey btcECKey = new BtcECKey();
        privateKeys.add(btcECKey);
        Address address = btcECKey.toAddress(btcRegTestParams);

        BtcTransaction btcTransaction = new BtcTransaction(btcRegTestParams);
        Script outputScript = ScriptBuilder.createOutputScript(address);
        addInputsAndOutputs(address, btcTransaction, 2, outputScript);
        btcTransaction.addOutput(Coin.MILLICOIN, address);

        Federation federation = bridgeConstantsRegtest.getGenesisFederation();
        List<BtcECKey> federatorPrivateKeys = BridgeRegTestConstants.REGTEST_FEDERATION_PRIVATE_KEYS;
        List<BtcECKey> fedPrivateKeys = Arrays.asList(federatorPrivateKeys.get(0), federatorPrivateKeys.get(1));
        BtcTransaction btcTxFederation = new BtcTransaction(btcRegTestParams);

        addInputsAndOutputs(federation.getAddress(), btcTxFederation, 2, createBaseInputScriptThatSpendsFromTheFederation(federation));
        btcTxFederation.addOutput(Coin.MILLICOIN, federation.getAddress());

        return Stream.of(
            //Arguments.of(privateKeys, btcTransaction),
            Arguments.of(fedPrivateKeys, btcTxFederation)
        );
    }

    private static BtcTransaction addInputsAndOutputs(Address from, BtcTransaction btcTransaction, int numberOfInputs, Script scriptSignature) {
        for (int i = 0; i < numberOfInputs; i++) {
            BtcTransaction prevBtcTx = createTransaction(randomAddress(), from, Coin.COIN);
            btcTransaction.addInput(prevBtcTx.getOutput(0)).setScriptSig(scriptSignature);
            btcTransaction.addOutput(Coin.MILLICOIN, randomAddress());
        }
        return btcTransaction;
    }

    @ParameterizedTest
    @MethodSource("providePrivateKeysAndBtcTx")
    void test_sighash_is_unique(List<BtcECKey> privateKeys, BtcTransaction btcTransaction) {
        test_sighash(privateKeys, btcTransaction);
    }

    private void test_sighash(List<BtcECKey> privateKeys, BtcTransaction btcTransaction) {
        List<TransactionInput> inputs = btcTransaction.getInputs();
        Set<Sha256Hash> sighashesAll = new HashSet<>(inputs.size());
        Set<byte[]> signaturesAll = new HashSet<>(inputs.size());
        Set<BtcECKey.ECDSASignature> ecdsaSignaturesAll = new HashSet<>(inputs.size());

        for (BtcECKey privateKey: privateKeys) {
            List<Sha256Hash> sighashes = new ArrayList<>(inputs.size());
            List<byte[]> signatures = new ArrayList<>(inputs.size());
            List<BtcECKey.ECDSASignature> ecdsaSignatures = new ArrayList<>(inputs.size());
            for (int i = 0; i < inputs.size(); i++) {
                TransactionInput input = btcTransaction.getInput(i);
                Script script = extractReedemScript(input);

                Pair<Sha256Hash, byte[]> pair = generateSignature(privateKey, btcTransaction, script, i, input);

                Sha256Hash sighash = pair.getLeft();
                byte[] signature = pair.getRight();

                sighashes.add(sighash);
                sighashesAll.add(sighash);

                signatures.add(signature);
                signaturesAll.add(signature);
            }

            for (int i = 0; i < inputs.size(); i++) {
                BtcECKey.ECDSASignature ecdsaSignature = verifySignature(sighashes, signatures, privateKey, i);
                ecdsaSignatures.add(ecdsaSignature);
                ecdsaSignaturesAll.add(ecdsaSignature);
            }

            for (int i = 0; i < inputs.size(); i++) {
                addSignature(btcTransaction, privateKey, i, ecdsaSignatures.get(i), sighashes.get(i));
            }
        }

        for (int i = 0; i < inputs.size(); i++) {
            Assertions.assertTrue(sighashesAll.contains(extractSighashFromSignedBtcTx(i, btcTransaction)));
//            for (int j = i; j < inputs.size(); j++) {
//                Assertions.assertEquals(extractSighashFromSignedBtcTx(i, btcTransaction), extractSighashFromSignedBtcTx(j, btcTransaction));
//            }
        }

//        Sha256Hash sighashFromSignedBtcTx1 = extractSighashFromSignedBtcTx(0, btcTransaction);
//        Sha256Hash sighashFromSignedBtcTx1 = extractSighashFromSignedBtcTx(1, btcTransaction);
//        Assertions.assertEquals(sighashFromSignedBtcTx1, sighashFromSignedBtcTx1);
//        for (int i = 0; i < inputs.size(); i++) {
//
//
//            //Sha256Hash sighash = sighashes.get(i);
//            Assertions.assertEquals(sighash, sighashFromSignedBtcTx);
//        }

    }

    private BtcECKey.ECDSASignature verifySignature(List<Sha256Hash> sighashes, List<byte[]> signatures, BtcECKey privateKey, int i) {
        BtcECKey.ECDSASignature sig;
        try {
            sig = BtcECKey.ECDSASignature.decodeFromDER(signatures.get(i));
        } catch (RuntimeException e) {
            throw new IllegalStateException("Error decoding DER");
        }

        Sha256Hash sighash = sighashes.get(i);

        if (!privateKey.verify(sighash, sig)) {
            throw new IllegalStateException("Verification failed");
        }
        return sig;
    }

    private void addSignature(BtcTransaction btcTransaction, BtcECKey privateKey, int i, BtcECKey.ECDSASignature sig, Sha256Hash sighash) {
        TransactionSignature txSig = new TransactionSignature(sig, BtcTransaction.SigHash.ALL, false);
        TransactionInput input = btcTransaction.getInput(i);
        Script inputScript = input.getScriptSig();

        boolean alreadySignedByThisFederator = BridgeUtils.isInputSignedByThisFederator(
            privateKey,
            sighash,
            input);

        if (alreadySignedByThisFederator)
            throw new IllegalStateException("Already signed");
                /*TransactionInput input = btcTransaction.getInput(i);
                input.setScriptSig(ScriptBuilder.createInputScript(txSig, privateKey));*/
        int sigIndex = inputScript.getSigInsertionIndex(sighash, privateKey);
        //inputScript = ScriptBuilder.updateScriptWithSignature(inputScript, sighashes.get(i).encodeToBitcoin(), sigIndex, 1, 1);
        inputScript = ScriptBuilder.updateScriptWithSignature(inputScript, txSig.encodeToBitcoin(), sigIndex, 1, 1);
        input.setScriptSig(inputScript);
    }

    private Pair<Sha256Hash, byte[]> generateSignature(BtcECKey btcECKey, BtcTransaction btcTransactionToSign, Script script, int i, TransactionInput input) {
        Sha256Hash sighash = btcTransactionToSign.hashForSignature(i, script, BtcTransaction.SigHash.ALL, false);
        BtcECKey.ECDSASignature sig = btcECKey.sign(sighash);
        TransactionSignature txSig = new TransactionSignature(sig, BtcTransaction.SigHash.ALL, false);

        if (!txSig.isCanonical()) {
            throw new IllegalStateException("It is not canonical");
        }

        if (!btcECKey.verify(sighash, sig)) {
            throw new IllegalStateException("Verification failed");
        }

        return Pair.of(sighash, sig.encodeToDER());
    }


    @Test
    void test_sighash_is_unique_for_same_tx() throws Exception {
        List<BtcECKey> federatorPrivateKeys = BridgeRegTestConstants.REGTEST_FEDERATION_PRIVATE_KEYS;
        List<BtcECKey> keys = Arrays.asList(federatorPrivateKeys.get(0), federatorPrivateKeys.get(1));
        addSignatureFromValidFederator(keys, 1, true, false, "FullySigned");
    }

    private boolean processSigning(BtcECKey federatorPublicKey, List<byte[]> signatures, BtcTransaction btcTx) {
        // Build input hashes for signatures
        int numInputs = btcTx.getInputs().size();

        List<Sha256Hash> sighashes = new ArrayList<>();
        List<TransactionSignature> txSigs = new ArrayList<>();
        for (int i = 0; i < numInputs; i++) {
            TransactionInput txIn = btcTx.getInput(i);
            // 0a07dacee73070ed07a16d42e155bdf52cb778920fe8681bb66816ce0a59e49e:0
            // [0, 0, 0, 76, 105, 82, 33, 2, -51, 83, -4, 83, -96, 127, 33, 22, 65, -90, 119, -46, 80, -10, -34, -103, -54, -10, 32, -24, -25, 112, 113, -24, 17, -94, -117, 59, -51, -33, 11, -31, 33, 3, 98, 99, 74, -75, 125, -82, -100, -77, 115, -91, -43, 54, -26, 106, -116, 79, 103, 70, -117, -68, -5, 6, 56, 9, -70, -74, 67, 7, 45, 120, -95, 36, 33, 3, -59, -108, 107, 63, -70, -32, 58, 101, 66, 55, -38, -122, 60, -98, -43, 52, -32, -121, -122, 87, 23, 91, 19, 43, +10 more]
            // [0, 71, 48, 68, 2, 32, 11, 12, -125, 57, 45, 93, -125, -101, -116, -72, 68, -125, -81, 48, 54, 54, -65, 79, -51, 102, 33, 125, 125, 12, 22, 6, -26, -100, -68, 58, -34, -74, 2, 32, 49, -99, 35, 101, -27, 16, -18, -114, -113, 21, 115, 113, -11, 66, 58, -67, -107, 8, -84, 115, -67, 72, 73, -19, -1, -104, 111, 20, -71, -87, 42, 82, 1, 0, 76, 105, 82, 33, 2, -51, 83, -4, 83, -96, 127, 33, 22, 65, -90, 119, -46, 80, -10, -34, -103, -54, -10, 32, -24, -25, +81 more]
            Script redeemScript = extractReedemScript(txIn);
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

            // 9725d09b3c3c087a8fcf6010c32daa9b3258a34a19500108137e6f7f946b33d2
            // 9725d09b3c3c087a8fcf6010c32daa9b3258a34a19500108137e6f7f946b33d2
            // [-105, 37, -48, -101, 60, 60, 8, 122, -113, -49, 96, 16, -61, 45, -86, -101, 50, 88, -93, 74, 25, 80, 1, 8, 19, 126, 111, 127, -108, 107, 51, -46]
            // [-105, 37, -48, -101, 60, 60, 8, 122, -113, -49, 96, 16, -61, 45, -86, -101, 50, 88, -93, 74, 25, 80, 1, 8, 19, 126, 111, 127, -108, 107, 51, -46]
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

    /**
     * Helper method to test addSignature() with a valid federatorPublicKey parameter and both valid/invalid signatures
     *
     * @param privateKeysToSignWith keys used to sign the tx. Federator key when we want to produce a valid signature, a random key when we want to produce an invalid signature
     * @param numberOfInputsToSign  There is just 1 input. 1 when testing the happy case, other values to test attacks/bugs.
     * @param signatureCanonical    Signature should be canonical. true when testing the happy case, false to test attacks/bugs.
     * @param signTwice             Sign again with the same key
     * @param expectedResult        "InvalidParameters", "PartiallySigned" or "FullySigned"
     */
    private void addSignatureFromValidFederator(List<BtcECKey> privateKeysToSignWith, int numberOfInputsToSign, boolean signatureCanonical, boolean signTwice, String expectedResult) throws Exception {
        // Federation is the genesis federation ATM
        Federation federation = bridgeConstantsRegtest.getGenesisFederation();

        BtcTransaction prevTx = new BtcTransaction(btcRegTestParams);
        TransactionOutput prevOut = new TransactionOutput(btcRegTestParams, prevTx, Coin.FIFTY_COINS, federation.getAddress());
        prevTx.addOutput(prevOut);

        BtcTransaction t = new BtcTransaction(btcRegTestParams);
        TransactionOutput output = new TransactionOutput(btcRegTestParams, t, Coin.COIN, new BtcECKey().toAddress(btcRegTestParams));
        t.addOutput(output);
        t.addInput(prevOut).setScriptSig(createBaseInputScriptThatSpendsFromTheFederation(federation));

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
        for (int i = 0; i < numberOfInputsToSign; i++) {
            derEncodedSigs.add(derEncodedSig);
        }

        processSigning(findPublicKeySignedBy(federation.getBtcPublicKeys(), privateKeysToSignWith.get(0)), derEncodedSigs, t);
        if (privateKeysToSignWith.size() > 1) {
            BtcECKey.ECDSASignature sig2 = privateKeysToSignWith.get(1).sign(sighash);
            byte[] derEncodedSig2 = sig2.encodeToDER();
            List derEncodedSigs2 = new ArrayList();
            for (int i = 0; i < numberOfInputsToSign; i++) {
                derEncodedSigs2.add(derEncodedSig2);
            }
            processSigning(findPublicKeySignedBy(federation.getBtcPublicKeys(), privateKeysToSignWith.get(1)), derEncodedSigs2, t);
        }


    }


    private BtcECKey findPublicKeySignedBy(List<BtcECKey> pubs, BtcECKey pk) {
        for (BtcECKey pub : pubs) {
            if (Arrays.equals(pk.getPubKey(), pub.getPubKey())) {
                return pub;
            }
        }
        return pk;
    }

}
