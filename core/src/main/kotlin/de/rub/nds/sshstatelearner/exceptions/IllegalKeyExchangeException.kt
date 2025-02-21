/*
 * SSH State Learner - A tool for extracting state machines from SSH server implementations
 *
 * Copyright 2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.sshstatelearner.exceptions

/**
 * An exception class to signal an invalid key exchange. This exception may be thrown if ext-info-c or ext-info-s
 * is selected as key exchange or the key exchange method in question is not yet implemented.
 *
 * @param message A human-readable message that describes the cause of the exception.
 */
class IllegalKeyExchangeException(message: String?) : Exception(message)
