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
) : TransportHandler(timeout, timeout, type) {

    private var closed = false

    override fun preInitialize() { }

    override fun initialize() {
        cachedSocketState = null
        setStreams(PushbackInputStream(inputStream), outputStream)
    }

    @Throws(IOException::class)
    override fun fetchData(): ByteArray {
        return if (inStream.available() > 0) {
            val data = ByteArray(inStream.available())
            inStream.read(data)
            data
        } else {
            ByteArray(0)
        }
    }

    override fun closeConnection() {
        inputStream.close()
        outputStream.close()
        closed = true
    }

    override fun closeClientConnection() {
        TODO("Not yet implemented")
    }

    override fun isClosed() = closed

    override fun setTimeout(timeout: Long) {
        this.timeout = timeout
    }
}