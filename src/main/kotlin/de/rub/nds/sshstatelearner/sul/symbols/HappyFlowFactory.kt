/*
 * SSH State Learner - A tool for extracting state machines from SSH server implementations
 *
 * Copyright 2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.sshstatelearner.sul.symbols

import de.rub.nds.sshattacker.core.constants.KeyExchangeAlgorithm
import de.rub.nds.sshattacker.core.constants.KeyExchangeFlowType
import de.rub.nds.sshattacker.core.protocol.authentication.message.UserAuthPasswordMessage
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelOpenMessage
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelRequestExecMessage
import de.rub.nds.sshattacker.core.protocol.transport.message.DhGexKeyExchangeInitMessage
import de.rub.nds.sshattacker.core.protocol.transport.message.DhGexKeyExchangeRequestMessage
import de.rub.nds.sshattacker.core.protocol.transport.message.DhKeyExchangeInitMessage
import de.rub.nds.sshattacker.core.protocol.transport.message.EcdhKeyExchangeInitMessage
import de.rub.nds.sshattacker.core.protocol.transport.message.KeyExchangeInitMessage
import de.rub.nds.sshattacker.core.protocol.transport.message.NewKeysMessage
import de.rub.nds.sshattacker.core.protocol.transport.message.ServiceRequestMessage
import de.rub.nds.sshattacker.core.protocol.transport.message.VersionExchangeMessage
import de.rub.nds.sshstatelearner.sul.ProtocolStage
import net.automatalib.words.Word

/**
 * This object is capable of constructing happy flows for different SSH protocol stages. A happy flow is considered any
 * valid combination of input symbols that lead to a desired output. For the TRANSPORT protocol, this is a successful
 * key exchange, for the AUTHENTICATION protocol a successful authentication and for the CONNECTION protocol a successful
 * command execution.
 */
object HappyFlowFactory {
    /**
     * Constructs an array of key exchange specific messages based on the flow type of the selected key exchange algorithm.
     *
     * @param kex The selected key exchange algorithm.
     * @return An array of key exchange specific messages in valid order.
     */
    private fun constructKexFlow(kex: KeyExchangeAlgorithm): Array<SshSymbol> {
        return when (kex.flowType) {
            KeyExchangeFlowType.DIFFIE_HELLMAN_GROUP_EXCHANGE -> arrayOf(
                DhGexKeyExchangeRequestMessage().toSymbol(),
                DhGexKeyExchangeInitMessage().toSymbol()
            )
            KeyExchangeFlowType.DIFFIE_HELLMAN -> arrayOf(
                DhKeyExchangeInitMessage().toSymbol()
            )
            KeyExchangeFlowType.ECDH -> arrayOf(
                EcdhKeyExchangeInitMessage().toSymbol()
            )
            else -> TODO("Key exchange algorithm flow type ${kex.flowType} is not yet supported by SSH-Attacker")
        }
    }

    /**
     * Constructs a happy flow which, applied on a fresh SUL oracle, lead to a desired output.
     *
     * @param stage The protocol stage to construct a happy flow for.
     * @param kex The selected key exchange method to construct a happy flow for.
     * @return The word representing a happy flow within the provided protocol stage and key exchange algorithm.
     */
    fun constructHappyFlow(stage: ProtocolStage, kex: KeyExchangeAlgorithm): Word<SshSymbol> {
        return when (stage) {
            ProtocolStage.TRANSPORT -> Word.fromSymbols(
                VersionExchangeMessage().toSymbol(),
                KeyExchangeInitMessage().toSymbol(),
                *constructKexFlow(kex),
                NewKeysMessage().toSymbol(),
                ServiceRequestMessage().toSymbol()
            )
            ProtocolStage.AUTHENTICATION -> Word.fromSymbols(
                UserAuthPasswordMessage().toSymbol()
            )
            ProtocolStage.CONNECTION -> Word.fromSymbols(
                ChannelOpenMessage().toSymbol(),
                ChannelRequestExecMessage().toSymbol()
            )
        }
    }
}
