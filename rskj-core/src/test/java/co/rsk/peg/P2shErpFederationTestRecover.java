package co.rsk.peg;

import co.rsk.bitcoinj.core.*;
import co.rsk.bitcoinj.crypto.TransactionSignature;
import co.rsk.bitcoinj.script.Script;
import co.rsk.bitcoinj.script.ScriptBuilder;
import co.rsk.config.BridgeTestNetConstants;
import org.bouncycastle.util.encoders.Hex;
import org.ethereum.config.blockchain.upgrades.ActivationConfig;
import org.ethereum.config.blockchain.upgrades.ConsensusRule;
import org.ethereum.crypto.ECKey;
import org.junit.jupiter.api.Test;

import java.time.ZonedDateTime;
import java.util.Arrays;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class P2shErpFederationTestRecover {

    @Test
    public void spendFromErpFedTestnet() {

        // Created with GenNodeKeyId using seed 'fed1'
        byte[] publicKeyBytes = Hex.decode("04fb8e1d5d0392d35ca8c3656acb6193dbf392b3e89b9b7b86693f5c80f7ce858140d297d921121aed8ec0af529e2b173326ba1c1c0f2d83cdd8a63e86aecebf0b");
        BtcECKey btcKey = BtcECKey.fromPublicOnly(publicKeyBytes);
        ECKey rskKey = ECKey.fromPublicOnly(publicKeyBytes);
        FederationMember fed1 = new FederationMember(btcKey, rskKey, rskKey);
        BtcECKey fed1PrivKey = BtcECKey.fromPrivate(Hex.decode("5caf46b71d022990c623e104b3ea61f089e92b765556bbc103ba650a74db8bf7"));

        // Created with GenNodeKeyId using seed 'fed3', used for fed2 to keep keys sorted
        publicKeyBytes = Hex.decode("045a2f522aea776fab5241ad72f7f05918e8606676461cb6ce38265a52d4ca9ed66fea4bd8276ae402c4f9474b7c4640bc5bfc73f33dfc59730c0067e2bcca9548");
        btcKey = BtcECKey.fromPublicOnly(publicKeyBytes);
        rskKey = ECKey.fromPublicOnly(publicKeyBytes);
        FederationMember fed2 = new FederationMember(btcKey, rskKey, rskKey);
        BtcECKey fed2PrivKey = BtcECKey.fromPrivate(Hex.decode("70edda394cab94c0e8b4299c6a4a736cc50ce44e6394941f94eab6a3ef39e658"));

        // Created with GenNodeKeyId using seed 'fed2', used for fed3 to keep keys sorted
        publicKeyBytes = Hex.decode("04afc230c2d355b1a577682b07bc2646041b5d0177af0f98395a46018da699b6da4c82aada8182b5735bc23ee96384fcb9200f6faab7df5a16459ac9a6e8ac9e26");
        btcKey = BtcECKey.fromPublicOnly(publicKeyBytes);
        rskKey = ECKey.fromPublicOnly(publicKeyBytes);
        FederationMember fed3 = new FederationMember(btcKey, rskKey, rskKey);
        BtcECKey fed3PrivKey = BtcECKey.fromPrivate(Hex.decode("1c9465957c2100290ae9ae43a3a2ada689a2e2a5ac492ec6568bc8b3a5e81cd1"));

        // Created with GenNodeKeyId using seed 'fed4'
        publicKeyBytes = Hex.decode("032822626c45fc1c4e3a3def5b4983636d6291a7a6677f66874c337e78bc3b7784");
        btcKey = BtcECKey.fromPublicOnly(publicKeyBytes);
        rskKey = ECKey.fromPublicOnly(publicKeyBytes);
        FederationMember fed4 = new FederationMember(btcKey, rskKey, rskKey);

        // Created with GenNodeKeyId using seed 'fed5'
        publicKeyBytes = Hex.decode("0225e892391625854128c5c4ea4340de0c2a70570f33db53426fc9c746597a03f4");
        btcKey = BtcECKey.fromPublicOnly(publicKeyBytes);
        rskKey = ECKey.fromPublicOnly(publicKeyBytes);
        FederationMember fed5 = new FederationMember(btcKey, rskKey, rskKey);

        // Created with GenNodeKeyId using seed 'erp1'
        publicKeyBytes = Hex.decode("0216c23b2ea8e4f11c3f9e22711addb1d16a93964796913830856b568cc3ea21d3");
        BtcECKey erp1Key = BtcECKey.fromPublicOnly(publicKeyBytes);

        // Created with GenNodeKeyId using seed 'erp2'
        publicKeyBytes = Hex.decode("034db69f2112f4fb1bb6141bf6e2bd6631f0484d0bd95b16767902c9fe219d4a6f");
        BtcECKey erp2Key = BtcECKey.fromPublicOnly(publicKeyBytes);

        // Created with GenNodeKeyId using seed 'erp3'
        publicKeyBytes = Hex.decode("0275562901dd8faae20de0a4166362a4f82188db77dbed4ca887422ea1ec185f14");
        BtcECKey erp3Key = BtcECKey.fromPublicOnly(publicKeyBytes);

        ActivationConfig.ForBlock activations = mock(ActivationConfig.ForBlock.class);
        when(activations.isActive(ConsensusRule.RSKIP284)).thenReturn(true);
        when(activations.isActive(ConsensusRule.RSKIP293)).thenReturn(false);

        P2shErpFederation p2shErpFederation = new P2shErpFederation(Arrays.asList(fed1, fed2, fed3, fed4, fed5),
                ZonedDateTime.parse("2017-06-10T02:30:00Z").toInstant(),
                0L,
                BridgeTestNetConstants.getInstance().getBtcParams(),
                Arrays.asList(erp1Key, erp2Key, erp3Key),
                BridgeTestNetConstants.getInstance().getErpFedActivationDelay(),
                activations
        );

        System.out.println("P2shErpFederation getAddress: " + p2shErpFederation.getAddress()); // Expected fed address: 2N1rW3cBZNzs2ZxSfyNW7cMcNBktt6fzs88

        // Below code can be used to create a transaction spending from the emergency multisig in testnet or mainnet
        String RAW_FUND_TX = "020000000001028a22f157b27eb1ccdb3707873974a64e720de0db661300bfe39512298015234c0000000000fdffffffe15a43930256eb08ce2c79d1cb16326c0db70a5bcc1cd4cae9afaa1df6ee25a60000000000fdffffff0240420f000000000017a9145e6cf80958803e9b3c81cd90422152520d2a505c87402c660000000000160014f0823603361fa285d97f716ea205a81f8750bb6902473044022051861b90eabf84c31ba9a5263b2d508cd9593a4556ff9e959ca4159f02038e4302202084d5bf15aa8a75a4235e7bdb1bc4e2283433917b189b1b332794c84f50dd42012102db9731ba3448d3b7f135f04631bd512d19815fcb7882a40007c6b4e6851e9a1b0247304402207146a9e8f6aa64ab3a03614613c38e052c4dcd41800be6397f9451fed83bb1890220030aca5bb0fc31b0f8551d0c4ddd6e2f3602681aec8149ee6b449c7ed0b41670012102db9731ba3448d3b7f135f04631bd512d19815fcb7882a40007c6b4e6851e9a1b2ef42400";
        BtcTransaction pegInTx = new BtcTransaction(BridgeTestNetConstants.getInstance().getBtcParams(), Hex.decode(RAW_FUND_TX));
        int outputIndex = 0; // Remember to change this value accordingly in case of using an existing raw tx

        Address destinationAddress = Address.fromBase58(BridgeTestNetConstants.getInstance().getBtcParams(), "2N5nt4dFGz9jtXdigVAZggoEkAQBzhoVKpd");
        BtcTransaction pegOutTx = new BtcTransaction(BridgeTestNetConstants.getInstance().getBtcParams());
        pegOutTx.addInput(pegInTx.getOutput(outputIndex));
        pegOutTx.addOutput(Coin.valueOf(0), ScriptBuilder.createOpReturnScript(Hex.decode("52534b54010000000000000000000000000000000001000006"))); // OP_RETURN BRIDGE ADDRESS
        pegOutTx.addOutput(Coin.valueOf(999_000), destinationAddress);
        pegOutTx.setVersion(2);
//        pegOutTx.getInput(0).setSequenceNumber(BridgeTestNetConstants.getInstance().getErpFedActivationDelay());

        // Create signatures
        Sha256Hash sigHash = pegOutTx.hashForSignature(
                0,
                p2shErpFederation.getRedeemScript(),
                BtcTransaction.SigHash.ALL,
                false
        );

        BtcECKey.ECDSASignature signature1 = fed1PrivKey.sign(sigHash);
        BtcECKey.ECDSASignature signature2 = fed2PrivKey.sign(sigHash);
        BtcECKey.ECDSASignature signature3 = fed3PrivKey.sign(sigHash);

        // Try different signature permutations
        Script inputScript = createInputScriptTestnetRecover(p2shErpFederation.getRedeemScript(), signature2, signature3, signature1, false);
        pegOutTx.getInput(0).setScriptSig(inputScript);
        inputScript.correctlySpends(pegOutTx, 0, pegInTx.getOutput(outputIndex).getScriptPubKey());

        // Uncomment to print the raw tx in console and broadcast https://blockstream.info/testnet/tx/push
        System.out.println(Hex.toHexString(pegOutTx.bitcoinSerialize()));
    }

    private Script createInputScriptTestnetRecover(
            Script fedRedeemScript,
            BtcECKey.ECDSASignature signature1,
            BtcECKey.ECDSASignature signature2,
            BtcECKey.ECDSASignature signature3,
            boolean signWithTheEmergencyMultisig) {

        TransactionSignature txSignature1 = new TransactionSignature(
                signature1,
                BtcTransaction.SigHash.ALL,
                false
        );
        byte[] txSignature1Encoded = txSignature1.encodeToBitcoin();

        TransactionSignature txSignature2 = new TransactionSignature(
                signature2,
                BtcTransaction.SigHash.ALL,
                false
        );
        byte[] txSignature2Encoded = txSignature2.encodeToBitcoin();

        TransactionSignature txSignature3 = new TransactionSignature(
                signature3,
                BtcTransaction.SigHash.ALL,
                false
        );
        byte[] txSignature3Encoded = txSignature3.encodeToBitcoin();

        int flowOpCode = signWithTheEmergencyMultisig ? 1 : 0;
        ScriptBuilder scriptBuilder = new ScriptBuilder();
        return scriptBuilder
                .number(0)
                .data(txSignature1Encoded)
                .data(txSignature2Encoded)
                .data(txSignature3Encoded)
                .number(flowOpCode)
                .data(fedRedeemScript.getProgram())
                .build();
    }
}
