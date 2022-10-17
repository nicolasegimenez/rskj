/*
 * This file is part of RskJ
 * Copyright (C) 2017 RSK Labs Ltd.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

package co.rsk.config;

import co.rsk.bitcoinj.core.BtcECKey;
import co.rsk.bitcoinj.core.Coin;
import co.rsk.bitcoinj.core.NetworkParameters;
import co.rsk.peg.AddressBasedAuthorizer;
import co.rsk.peg.Federation;
import co.rsk.peg.FederationMember;
import org.bouncycastle.util.encoders.Hex;
import org.ethereum.crypto.ECKey;

import java.time.Instant;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

public class BridgeTestNetConstants extends BridgeConstants {
    private static BridgeTestNetConstants instance = new BridgeTestNetConstants();

    BridgeTestNetConstants() {
        btcParamsString = NetworkParameters.ID_TESTNET;

        BtcECKey federator0PublicKey = BtcECKey.fromPublicOnly(Hex.decode("021549fff7ab02f06c8ee6375b428abeef45ab553a5837f42db6f2e5c5a19ca495"));
        BtcECKey federator1PublicKey = BtcECKey.fromPublicOnly(Hex.decode("0243a0ab0169f577de86ec47ad4d2679ab1d41316ada2f97e0b8d2bd3e17f93d04"));
        BtcECKey federator2PublicKey = BtcECKey.fromPublicOnly(Hex.decode("02e81d94dc61728d5eb53133b39e04ca72fa68b8da71fd8c15b0ef2c20e39b08c6"));

        List<BtcECKey> genesisFederationPublicKeys = Arrays.asList(federator0PublicKey, federator1PublicKey, federator2PublicKey);

        // IMPORTANT: BTC, RSK and MST keys are the same.
        List<FederationMember> federationMembers = FederationMember.getFederationMembersFromKeys(genesisFederationPublicKeys);

        // Currently set to:
        // 2022-08-29T00:00:00.000Z
        Instant genesisFederationAddressCreatedAt = Instant.ofEpochMilli(1661731200);

        genesisFederation = new Federation(
                federationMembers,
                genesisFederationAddressCreatedAt,
                1L,
                getBtcParams()
        );

        btc2RskMinimumAcceptableConfirmations = 2;
        btc2RskMinimumAcceptableConfirmationsOnRsk = 10;
        rsk2BtcMinimumAcceptableConfirmations = 10;

        updateBridgeExecutionPeriod = 3 * 60 * 1000; // 3 minutes

        maxBtcHeadersPerRskBlock = 500;

        legacyMinimumPeginTxValueInSatoshis = Coin.valueOf(100_000);
        minimumPeginTxValueInSatoshis = Coin.valueOf(50_000);
        legacyMinimumPegoutTxValueInSatoshis = Coin.valueOf(50_000);
        minimumPegoutTxValueInSatoshis = Coin.valueOf(25_000);

        // Passphrases are kept private
        List<ECKey> federationChangeAuthorizedKeys = Arrays.stream(new String[]{
                "040e67a1daba745be62206fa944bacc02a9b87c017b0a0d672ddb349fe838450dd163ffeeecc403c19ced7415f7ec589b3136f26bc0a641747b2876e3e167909ec",
                "04196385ffd175d0d129aa25574a2449d1deec93c88dfc3ebbcdc01db06d4dd00d4bb9979937f0d9a83c43d1017d3f30fa89f0c6414e1f3bbda87ad3a52a8c4da2",
                "0449f2a32d967b5223e69235f5fc3881ab3d0dada8d26026ef7f394caebc13051f1919b37cf48e631a8c6f3f55e466d944fa28b69bf38153014ef7810b5d22acb6"
        }).map(hex -> ECKey.fromPublicOnly(Hex.decode(hex))).collect(Collectors.toList());

        federationChangeAuthorizer = new AddressBasedAuthorizer(
                federationChangeAuthorizedKeys,
                AddressBasedAuthorizer.MinimumRequiredCalculation.MAJORITY
        );

        // Passphrases are kept private
        List<ECKey> lockWhitelistAuthorizedKeys = Arrays.stream(new String[]{
                "040e67a1daba745be62206fa944bacc02a9b87c017b0a0d672ddb349fe838450dd163ffeeecc403c19ced7415f7ec589b3136f26bc0a641747b2876e3e167909ec"
        }).map(hex -> ECKey.fromPublicOnly(Hex.decode(hex))).collect(Collectors.toList());

        lockWhitelistChangeAuthorizer = new AddressBasedAuthorizer(
                lockWhitelistAuthorizedKeys,
                AddressBasedAuthorizer.MinimumRequiredCalculation.ONE
        );

        federationActivationAge = 60L;

        fundsMigrationAgeSinceActivationBegin = 0L;
        fundsMigrationAgeSinceActivationEnd = 900L;

        List<ECKey> feePerKbAuthorizedKeys = Arrays.stream(new String[]{
            "040e67a1daba745be62206fa944bacc02a9b87c017b0a0d672ddb349fe838450dd163ffeeecc403c19ced7415f7ec589b3136f26bc0a641747b2876e3e167909ec",
            "04196385ffd175d0d129aa25574a2449d1deec93c88dfc3ebbcdc01db06d4dd00d4bb9979937f0d9a83c43d1017d3f30fa89f0c6414e1f3bbda87ad3a52a8c4da2",
            "0449f2a32d967b5223e69235f5fc3881ab3d0dada8d26026ef7f394caebc13051f1919b37cf48e631a8c6f3f55e466d944fa28b69bf38153014ef7810b5d22acb6"
        }).map(hex -> ECKey.fromPublicOnly(Hex.decode(hex))).collect(Collectors.toList());

        feePerKbChangeAuthorizer = new AddressBasedAuthorizer(
                feePerKbAuthorizedKeys,
                AddressBasedAuthorizer.MinimumRequiredCalculation.MAJORITY
        );

        genesisFeePerKb = Coin.MILLICOIN;

        maxFeePerKb = Coin.valueOf(5_000_000L);

        List<ECKey> increaseLockingCapAuthorizedKeys = Arrays.stream(new String[]{
            "040e67a1daba745be62206fa944bacc02a9b87c017b0a0d672ddb349fe838450dd163ffeeecc403c19ced7415f7ec589b3136f26bc0a641747b2876e3e167909ec",
            "04196385ffd175d0d129aa25574a2449d1deec93c88dfc3ebbcdc01db06d4dd00d4bb9979937f0d9a83c43d1017d3f30fa89f0c6414e1f3bbda87ad3a52a8c4da2",
            "0449f2a32d967b5223e69235f5fc3881ab3d0dada8d26026ef7f394caebc13051f1919b37cf48e631a8c6f3f55e466d944fa28b69bf38153014ef7810b5d22acb6"
        }).map(hex -> ECKey.fromPublicOnly(Hex.decode(hex))).collect(Collectors.toList());

        increaseLockingCapAuthorizer = new AddressBasedAuthorizer(
                increaseLockingCapAuthorizedKeys,
                AddressBasedAuthorizer.MinimumRequiredCalculation.ONE
        );

        lockingCapIncrementsMultiplier = 2;
        initialLockingCap = Coin.COIN.multiply(200); // 200 BTC

        btcHeightWhenBlockIndexActivates = 2_351_815; // Block generated at 2022-10-13T08:34:56Z
        maxDepthToSearchBlocksBelowIndexActivation = 4_320; // 30 days in BTC blocks (considering 1 block every 10 minutes)

        erpFedActivationDelay = 52_560; // 1 year in BTC blocks (considering 1 block every 10 minutes)

        erpFedPubKeysList = Arrays.stream(new String[] {
            "02910dc283b2d30e055d44f9b1bf4bb8ae6fb6da4b99770b2a805388e7d4561f2e",
            "0344249c412ffdb5f42131527040d5879803a44b4968eea9a5244b4d044945829c",
            "03ba98e552f5b5c80b7e1851c78fdda36f86661d38237915aede5a1427c315140c",
            "03ddec21ecc90d3611cdef846a970e1fc7a14c132013f3bfcc4368f2e4be22329d"
        }).map(hex -> BtcECKey.fromPublicOnly(Hex.decode(hex))).collect(Collectors.toList());

        // Multisig address created in bitcoind with the following private keys:
        // 47129ffed2c0273c75d21bb8ba020073bb9a1638df0e04853407461fdd9e8b83
        // 9f72d27ba603cfab5a0201974a6783ca2476ec3d6b4e2625282c682e0e5f1c35
        // e1b17fcd0ef1942465eee61b20561b16750191143d365e71de08b33dd84a9788
        oldFederationAddress = "2N7ZgQyhFKm17RbaLqygYbS7KLrQfapyZzu";

        minSecondsBetweenCallsReceiveHeader = 300;  // 5 minutes in seconds
        maxDepthBlockchainAccepted = 25;

        minimumPegoutValuePercentageToReceiveAfterFee = 80;

        maxInputsPerPegoutTransaction = 50;

        numberOfBlocksBetweenPegouts = 30; // 15' of RSK blocks (considering 1 block every 30 seconds)
    }

    public static BridgeTestNetConstants getInstance() {
        return instance;
    }

}
