/*
 * SSH State Learner - A tool for extracting state machines from SSH server implementations
 *
 * Copyright 2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.sshstatelearner.algorithms.symbols

import de.rub.nds.sshattacker.core.protocol.common.SshMessage

/**
 * Wraps the SSH message into a message symbol implementation.
 */
fun <T : SshMessage<T>> SshMessage<T>.toSymbol(): AbstractSshSymbol {
    return BppMessageSymbol(this)
}

/**
 * Wraps the SSH message into a message symbol implementation.
 *
 * @param retrieveDelay The delay between sending the message and retrieving the response of the peer.
 */
fun <T : SshMessage<T>> SshMessage<T>.toSymbol(retrieveDelay: Long): AbstractSshSymbol {
    return BppMessageSymbol(this, retrieveDelay)
}
