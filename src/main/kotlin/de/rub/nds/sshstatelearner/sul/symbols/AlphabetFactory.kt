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
import de.rub.nds.sshattacker.core.protocol.transport.message.DhGexKeyExchangeInitMessage
import de.rub.nds.sshattacker.core.protocol.transport.message.DhGexKeyExchangeOldRequestMessage
import de.rub.nds.sshattacker.core.protocol.transport.message.DhGexKeyExchangeRequestMessage
import de.rub.nds.sshattacker.core.protocol.transport.message.DhKeyExchangeInitMessage
import de.rub.nds.sshattacker.core.protocol.transport.message.EcdhKeyExchangeInitMessage
import de.rub.nds.sshattacker.core.protocol.transport.message.KeyExchangeInitMessage
import de.rub.nds.sshattacker.core.protocol.transport.message.NewKeysMessage
import de.rub.nds.sshattacker.core.protocol.transport.message.ServiceRequestMessage
import de.rub.nds.sshattacker.core.protocol.transport.message.VersionExchangeMessage
import de.rub.nds.sshstatelearner.exceptions.IllegalKeyExchangeException
import de.rub.nds.sshstatelearner.sul.ProtocolStage
import net.automatalib.words.Alphabet
import net.automatalib.words.impl.ListAlphabet

object AlphabetFactory {
    private fun constructKexSymbols(kex: KeyExchangeAlgorithm, receiveDelay: Long): Array<out SshSymbol> {
        return when (kex.flowType) {
            KeyExchangeFlowType.DIFFIE_HELLMAN_GROUP_EXCHANGE -> arrayOf(
                DhGexKeyExchangeRequestMessage().toSymbol(receiveDelay),
                DhGexKeyExchangeOldRequestMessage().toSymbol(receiveDelay),
                DhGexKeyExchangeInitMessage().toSymbol(receiveDelay)
            )
            KeyExchangeFlowType.DIFFIE_HELLMAN -> arrayOf(
                DhKeyExchangeInitMessage().toSymbol(receiveDelay)
            )
            KeyExchangeFlowType.ECDH -> arrayOf(
                EcdhKeyExchangeInitMessage().toSymbol(receiveDelay)
            )
            KeyExchangeFlowType.ECMQV -> TODO("ECMQV kex algorithm is not yet implemented in SSH-Attacker")
            KeyExchangeFlowType.RSA -> TODO("RSA kex algorithm is not yet implemented in SSH-Attacker")
            null -> throw IllegalKeyExchangeException("Unable to construct kex symbols for extension info - ext-info-s and ext-info-c are no valid kex algorithms")
        }
    }

    fun construct(stage: ProtocolStage = ProtocolStage.TRANSPORT, kex: KeyExchangeAlgorithm = KeyExchangeAlgorithm.DIFFIE_HELLMAN_GROUP_EXCHANGE_SHA256, receiveDelay: Long = SshSymbol.DEFAULT_RECEIVE_DELAY): Alphabet<SshSymbol> {
        return when (stage) {
            // TODO: Define alphabet for transport stage
            ProtocolStage.TRANSPORT -> ListAlphabet(
                listOf(
                    VersionExchangeMessage().toSymbol(receiveDelay),
                    KeyExchangeInitMessage().toSymbol(receiveDelay),
                    *constructKexSymbols(kex, receiveDelay),
                    NewKeysMessage().toSymbol(receiveDelay),
                    ServiceRequestMessage().toSymbol(receiveDelay)
                )
            )
            ProtocolStage.AUTHENTICATION -> ListAlphabet(listOf(
                    // TODO: Define alphabet for authentication stage
                ))
            ProtocolStage.CONNECTION -> ListAlphabet(listOf(
                // TODO: Define alphabet for connection stage
            ))
        }
    }
}
