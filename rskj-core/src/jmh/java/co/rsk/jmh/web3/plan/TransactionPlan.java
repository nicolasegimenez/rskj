/*
 * This file is part of RskJ
 * Copyright (C) 2023 RSK Labs Ltd.
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

package co.rsk.jmh.web3.plan;

import co.rsk.jmh.helpers.BenchmarkHelper;
import co.rsk.jmh.web3.BenchmarkWeb3Exception;
import co.rsk.jmh.web3.e2e.RskModuleWeb3j;
import co.rsk.jmh.web3.factory.TransactionFactory;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.openjdk.jmh.annotations.*;
import org.openjdk.jmh.infra.BenchmarkParams;
import org.web3j.protocol.core.Request;
import org.web3j.protocol.core.methods.request.Transaction;
import org.web3j.protocol.core.methods.response.EthBlock;

import java.math.BigInteger;
import java.util.Iterator;
import java.util.List;
import java.util.Optional;

@State(Scope.Benchmark)
public class TransactionPlan extends BasePlan {

    private Iterator<Transaction> transactionsVT;
    private Iterator<Transaction> transactionsContractCreation;
    private Iterator<Transaction> transactionsContractCall;
    private JsonNode ethBlockJsonNode;

    @Override
    @Setup(Level.Trial) // move to "Level.Iteration" in case we set a batch size at some point
    public void setUp(BenchmarkParams params) throws BenchmarkWeb3Exception {
        super.setUp(params);

        String address = configuration.getString("sendTransaction.from");

        long nonce = Optional.ofNullable(web3Connector.ethGetTransactionCount(address))
                .map(BigInteger::longValue)
                .orElseThrow(() -> new BenchmarkWeb3Exception("Could not get account nonce"));

        long warmupIters = (long) params.getWarmup().getCount() * params.getWarmup().getBatchSize(); // in case we set a batch size at some point
        long measurementIters = (long) params.getMeasurement().getCount() * params.getMeasurement().getBatchSize();  // in case we set a batch size at some point
        long numOfTransactions = warmupIters + measurementIters;

        transactionsVT = TransactionFactory.createTransactions(TransactionFactory.TransactionType.VT, configuration, nonce, numOfTransactions).listIterator();
        transactionsContractCreation = TransactionFactory.createTransactions(TransactionFactory.TransactionType.CONTRACT_CREATION, configuration, nonce, numOfTransactions).listIterator();
        transactionsContractCall = TransactionFactory.createTransactions(TransactionFactory.TransactionType.CONTRACT_CALL, configuration, nonce, numOfTransactions).listIterator();

        ethBlockJsonNode = getBlockJsonNode(configuration.getString("eth.blockNumber"));
    }

    private JsonNode getBlockJsonNode(String ethBlockNumber) {
        try {
            Request<?, RskModuleWeb3j.GenericJsonResponse> req = rskModuleWeb3j.ethGetBlockByNumber(ethBlockNumber);
            RskModuleWeb3j.GenericJsonResponse response = req.send();
            String ethBlockStr = response.getResult().toString();
            return objectMapper.readTree(ethBlockStr);
        } catch (Exception e) {
            e.printStackTrace();
        }

        return null;
    }

    @TearDown(Level.Trial) // move to "Level.Iteration" in case we set a batch size at some point
    public void tearDown() throws InterruptedException {
        // wait for new blocks to have free account slots for transaction creation
        BenchmarkHelper.waitForBlocks(configuration);
    }

    public Iterator<Transaction> getTransactionsVT() {
        return transactionsVT;
    }

    public Iterator<Transaction> getTransactionsContractCreation() {
        return transactionsContractCreation;
    }

    public Iterator<Transaction> getTransactionsContractCall() {
        return transactionsContractCall;
    }

    public JsonNode getEthBlockJsonNode() {
        return ethBlockJsonNode;
    }

    public RskModuleWeb3j.EthCallArguments getEthCallArguments(int index) {
        JsonNode transaction = ethBlockJsonNode.get("transactions").get(index);

        RskModuleWeb3j.EthCallArguments args = new RskModuleWeb3j.EthCallArguments();

        args.setFrom(Optional.ofNullable(transaction.get("from")).map(JsonNode::asText).orElse(null));
        args.setTo(Optional.ofNullable(transaction.get("to")).map(JsonNode::asText).orElse(null));
        args.setGas(Optional.ofNullable(transaction.get("gas")).map(JsonNode::asText).orElse(null));
        args.setGasPrice(Optional.ofNullable(transaction.get("gasPrice")).map(JsonNode::asText).orElse(null));
        args.setValue(Optional.ofNullable(transaction.get("value")).map(JsonNode::asText).orElse(null));
        args.setNonce(Optional.ofNullable(transaction.get("nonce")).map(JsonNode::asText).orElse(null));
        args.setChainId(Optional.ofNullable(transaction.get("chainId")).map(JsonNode::asText).orElse(null));
        args.setData("0xd96a094a0000000000000000000000000000000000000000000000000000000000000001");
        args.setType("0x00");

        return args;
    }
}
