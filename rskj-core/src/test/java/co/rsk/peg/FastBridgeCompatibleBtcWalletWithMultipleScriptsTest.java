package co.rsk.peg;

import co.rsk.bitcoinj.core.Context;
import co.rsk.bitcoinj.core.Sha256Hash;
import co.rsk.bitcoinj.script.FastBridgeErpRedeemScriptParser;
import co.rsk.bitcoinj.script.FastBridgeRedeemScriptParser;
import co.rsk.bitcoinj.script.Script;
import co.rsk.bitcoinj.script.ScriptBuilder;
import co.rsk.bitcoinj.wallet.RedeemData;
import co.rsk.config.BridgeConstants;
import co.rsk.config.BridgeRegTestConstants;
import co.rsk.crypto.Keccak256;
import co.rsk.peg.fastbridge.FastBridgeFederationInformation;
import org.ethereum.config.blockchain.upgrades.ActivationConfig;
import org.ethereum.config.blockchain.upgrades.ConsensusRule;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import java.time.Instant;
import java.util.Arrays;
import java.util.List;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class FastBridgeCompatibleBtcWalletWithMultipleScriptsTest {

    protected final BridgeConstants bridgeConstantsRegtest = BridgeRegTestConstants.getInstance();

    private Federation activeFederation;
    private Federation retiringFederation;
    private ErpFederation erpActiveFederation;
    private ErpFederation erpRetiringFederation;
    private List<Federation> federationList;
    private List<Federation> erpFederationList;

    @Before
    public void setup() {
        ActivationConfig.ForBlock activations = mock(ActivationConfig.ForBlock.class);
        when(activations.isActive(ConsensusRule.RSKIP284)).thenReturn(true);
        when(activations.isActive(ConsensusRule.RSKIP293)).thenReturn(true);

        activeFederation = PegTestUtils.createFederation(bridgeConstantsRegtest, "fa04", "fa05", "fa06");
        retiringFederation = PegTestUtils.createFederation(bridgeConstantsRegtest, "fa01", "fa02", "fa03");

        erpActiveFederation = new ErpFederation(
            FederationTestUtils.getFederationMembers(3),
            Instant.ofEpochMilli(1000),
            0L,
            bridgeConstantsRegtest.getBtcParams(),
            PegTestUtils.createRandomBtcECKeys(3),
            5063,
            activations
        );

        erpRetiringFederation = new ErpFederation(
            FederationTestUtils.getFederationMembers(3),
            Instant.ofEpochMilli(1000),
            0L,
            bridgeConstantsRegtest.getBtcParams(),
            PegTestUtils.createRandomBtcECKeys(3),
            5064,
            activations
        );

        federationList = Arrays.asList(activeFederation, retiringFederation);
        erpFederationList = Arrays.asList(erpActiveFederation, erpRetiringFederation);
    }

    protected FastBridgeFederationInformation createFastBridgeFederationInformation(Keccak256 fastBridgeDerivationHash, Federation federation) {
        Script fastBridgeScript = FastBridgeRedeemScriptParser.createMultiSigFastBridgeRedeemScript(
            federation.getRedeemScript(),
            Sha256Hash.wrap(fastBridgeDerivationHash.getBytes())
        );

        Script fastBridgeScriptHash = ScriptBuilder.createP2SHOutputScript(fastBridgeScript);

        return new FastBridgeFederationInformation(
            fastBridgeDerivationHash,
            federation.getP2SHScript().getPubKeyHash(),
            fastBridgeScriptHash.getPubKeyHash()
        );
    }

    @Test
    public void findRedeemDataFromScriptHash_with_fastBridgeInformation() {
        FastBridgeFederationInformation activeFbFedInfo =
            createFastBridgeFederationInformation(
                PegTestUtils.createHash3(2),
                activeFederation
            );

        FastBridgeFederationInformation retiringFbFedInfo =
            createFastBridgeFederationInformation(
                PegTestUtils.createHash3(2),
                retiringFederation
            );

        FastBridgeCompatibleBtcWalletWithMultipleScripts fastBridgeCompatibleBtcWalletWithMultipleScripts = new FastBridgeCompatibleBtcWalletWithMultipleScripts(
            mock(Context.class),
            federationList,
            Arrays.asList(activeFbFedInfo, retiringFbFedInfo));

        RedeemData redeemData = fastBridgeCompatibleBtcWalletWithMultipleScripts.findRedeemDataFromScriptHash(
            activeFbFedInfo.getFastBridgeFederationRedeemScriptHash());

        Script fastBridgeRedeemScript = FastBridgeRedeemScriptParser.createMultiSigFastBridgeRedeemScript(
            activeFederation.getRedeemScript(), Sha256Hash.wrap(activeFbFedInfo.getDerivationHash().getBytes())
        );

        Assert.assertNotNull(redeemData);
        Assert.assertEquals(fastBridgeRedeemScript, redeemData.redeemScript);
    }

    @Test
    public void findRedeemDataFromScriptHash_with_fastBridgeInformation_and_erp_federation() {
        FastBridgeFederationInformation activeFbFedInfo =
            createFastBridgeFederationInformation(
                PegTestUtils.createHash3(2),
                erpActiveFederation
            );

        FastBridgeFederationInformation retiringFbFedInfo =
            createFastBridgeFederationInformation(
                PegTestUtils.createHash3(2),
                erpRetiringFederation
            );

        FastBridgeCompatibleBtcWalletWithMultipleScripts fastBridgeCompatibleBtcWalletWithMultipleScripts = new FastBridgeCompatibleBtcWalletWithMultipleScripts(
            mock(Context.class),
            erpFederationList,
            Arrays.asList(activeFbFedInfo, retiringFbFedInfo));

        RedeemData redeemData = fastBridgeCompatibleBtcWalletWithMultipleScripts.findRedeemDataFromScriptHash(
            retiringFbFedInfo.getFastBridgeFederationRedeemScriptHash());

        Script fastBridgeRedeemScript = FastBridgeErpRedeemScriptParser.createFastBridgeErpRedeemScript(
            erpRetiringFederation.getRedeemScript(),
            Sha256Hash.wrap(retiringFbFedInfo.getDerivationHash().getBytes())
        );

        Assert.assertNotNull(redeemData);
        Assert.assertEquals(fastBridgeRedeemScript, redeemData.redeemScript);
    }
}
