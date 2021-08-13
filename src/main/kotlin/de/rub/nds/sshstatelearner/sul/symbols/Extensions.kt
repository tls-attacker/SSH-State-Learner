/*
 * SSH State Learner - A tool for extracting state machines from SSH server implementations
 *
 * Copyright 2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.sshstatelearner.sul.symbols

import de.rub.nds.sshattacker.core.protocol.common.Message

fun <T : Message<T>> Message<T>.toSymbol(receiveDelay: Long = SshSymbol.DEFAULT_RECEIVE_DELAY): GenericMessageSymbol {
    return GenericMessageSymbol(this, receiveDelay)
}
