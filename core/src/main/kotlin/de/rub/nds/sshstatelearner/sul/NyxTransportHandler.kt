/*
 * SSH State Learner - A tool for extracting state machines from SSH server implementations
 *
 * Copyright 2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.sshstatelearner.sul

import de.rub.nds.tlsattacker.transport.ConnectionEndType
import de.rub.nds.tlsattacker.transport.TransportHandler
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.io.PushbackInputStream

class NyxTransportHandler(
    timeout: Long,
    type: ConnectionEndType,
    private val inputStream: InputStream,
    private val outputStream: OutputStream
) : TransportHandler(timeout, type) {

    private var closed = false
    private var pushbackInputStream: PushbackInputStream? = null

    override fun preInitialize() { }

    override fun initialize() {
        cachedSocketState = null
        pushbackInputStream = PushbackInputStream(inputStream)
    }

    override fun sendData(data: ByteArray?) {
        if (data != null) {
            outputStream.write(data)
        }
    }

    @Throws(IOException::class)
    override fun fetchData(): ByteArray {
        return if (pushbackInputStream!!.available() > 0) {
            pushbackInputStream?.readAllBytes() ?: throw IOException("PushbackInputStream is null")
        } else {
            ByteArray(0)
        }
    }

    override fun fetchData(amountOfData: Int): ByteArray {
        return pushbackInputStream?.readNBytes(amountOfData) ?: throw IOException("PushbackInputStream is null")
    }

    override fun closeConnection() {
        inputStream.close()
        outputStream.close()
        closed = true
    }

    override fun closeClientConnection() { }

    override fun isClosed() = closed

    override fun setTimeout(timeout: Long) {
        this.timeout = timeout
    }
}
