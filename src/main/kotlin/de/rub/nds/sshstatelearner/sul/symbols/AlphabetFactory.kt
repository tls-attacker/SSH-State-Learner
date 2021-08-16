/*
 * SSH State Learner - A tool for extracting state machines from SSH server implementations
 *
 * Copyright 2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.sshstatelearner.sul.symbols

import de.rub.nds.sshattacker.core.protocol.transport.message.DhGexKeyExchangeInitMessage
import de.rub.nds.sshattacker.core.protocol.transport.message.DhGexKeyExchangeRequestMessage
import de.rub.nds.sshattacker.core.protocol.transport.message.KeyExchangeInitMessage
import de.rub.nds.sshattacker.core.protocol.transport.message.NewKeysMessage
import de.rub.nds.sshattacker.core.protocol.transport.message.ServiceRequestMessage
import de.rub.nds.sshattacker.core.protocol.transport.message.VersionExchangeMessage
import de.rub.nds.sshstatelearner.sul.ProtocolStage
import net.automatalib.words.Alphabet
import net.automatalib.words.impl.ListAlphabet

object AlphabetFactory {
    fun construct(stage: ProtocolStage = ProtocolStage.TRANSPORT, receiveDelay: Long = SshSymbol.DEFAULT_RECEIVE_DELAY): Alphabet<SshSymbol> {
        return when (stage) {
            // TODO: Define alphabet for transport stage
            ProtocolStage.TRANSPORT -> ListAlphabet(listOf(
                VersionExchangeMessage().toSymbol(receiveDelay),
                KeyExchangeInitMessage().toSymbol(receiveDelay),
                DhGexKeyExchangeRequestMessage().toSymbol(receiveDelay),
                DhGexKeyExchangeInitMessage().toSymbol(receiveDelay),
                NewKeysMessage().toSymbol(receiveDelay),
                ServiceRequestMessage().toSymbol(receiveDelay)
            ))
            ProtocolStage.AUTHENTICATION -> ListAlphabet(listOf(
                // TODO: Define alphabet for authentication stage
            ))
            ProtocolStage.CONNECTION -> ListAlphabet(listOf(
                // TODO: Define alphabet for connection stage
            ))
        }
    }
}
