/*
 * SSH State Learner - A tool for extracting state machines from SSH server implementations
 *
 * Copyright 2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.sshstatelearner.sul

import java.io.ByteArrayInputStream

class RefillableByteArrayInputStream(buf: ByteArray, offset: Int, length: Int) : ByteArrayInputStream(buf, offset, length) {

    constructor(buf: ByteArray) : this(buf, 0, buf.size)

    /**
     * Refill the input stream with bytes. The provided bytes will be appended to the current buffer and
     * outputted after the current buffer has been exhausted.
     *
     * @param refillBuf Array of bytes to append
     */
    fun refill(refillBuf: ByteArray) = refill(refillBuf, 0, refillBuf.size)

    /**
     * Refill the input stream with bytes. The provided bytes will be appended to the current buffer and
     * outputted after the current buffer has been exhausted.
     *
     * @param refillBuf Array of bytes to append
     * @param offset The first index of refillBuf to append to the current buffer
     * @param length Number of bytes to add to the buffer (must be less or equal than refillBuf.size)
     */
    fun refill(refillBuf: ByteArray, offset: Int, length: Int) {
        buf = buf.slice(pos until count).toByteArray() +
            refillBuf.slice(offset until offset + length).toByteArray()
        pos = 0
        count = buf.size
    }
}
