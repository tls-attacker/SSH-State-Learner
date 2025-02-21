package de.rub.nds.sshstatelearner.sul

/**
 * Interface for initializing and controlling various types of clients.
 */
interface ClientConnectionHandler {

    /**
     * Initialization
     */
    fun init()

    /**
     * To terminate all created dependencies.
     */
    fun exit()

    /**
     * Starts a connection attempt
     */
    suspend fun subscribeForConnection()

    /**
     * Returns the port to which the connection attempt is made.
     */
    fun getPort(): Int
}