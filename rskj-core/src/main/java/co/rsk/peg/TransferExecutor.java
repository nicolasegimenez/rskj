package co.rsk.peg;

import co.rsk.core.RskAddress;
import co.rsk.rpc.modules.trace.CallType;
import co.rsk.rpc.modules.trace.ProgramSubtrace;
import java.util.Collections;
import org.ethereum.vm.DataWord;
import org.ethereum.vm.PrecompiledContracts;
import org.ethereum.vm.program.ProgramResult;
import org.ethereum.vm.program.invoke.TransferInvoke;

public class TransferExecutor {

    public TransferExecutor(Repository rskRepository, List<> subtraces) {

    }

    /**
     * Internal method to transfer RSK to an RSK account
     * It also produce the appropiate internal transaction subtrace if needed
     *
     * @param receiver  address that receives the amount
     * @param amount    amount to transfer
     */
    public void transferTo(RskAddress receiver, co.rsk.core.Coin amount) {
        rskRepository.transfer(
            PrecompiledContracts.BRIDGE_ADDR,
            receiver,
            amount
        );

        DataWord from = DataWord.valueOf(PrecompiledContracts.BRIDGE_ADDR.getBytes());
        DataWord to = DataWord.valueOf(receiver.getBytes());
        long gas = 0L;
        DataWord value = DataWord.valueOf(amount.getBytes());

        TransferInvoke invoke = new TransferInvoke(from, to, gas, value);
        ProgramResult result     = ProgramResult.empty();
        ProgramSubtrace subtrace = ProgramSubtrace.newCallSubtrace(CallType.CALL, invoke, result, null, Collections.emptyList());

        logger.info("Transferred {} weis to {}", amount, receiver);

        this.subtraces.add(subtrace);
    }
}
