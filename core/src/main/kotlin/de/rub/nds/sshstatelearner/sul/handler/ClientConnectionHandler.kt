package de.rub.nds.sshstatelearner.sul.handler

/**
 * Interface for initializing and controlling various types of clients.
 */
interface ClientConnectionHandler {

    /**
     * Initialization
     */
    fun init()

    /**
     * Starts a connection attempt
     */
    suspend fun connect()

    /**
     * To terminate all created dependencies.
     */
    fun exit()

    /**
     * Returns the port to which the connection attempt is made.
     */
    val port: Int
}