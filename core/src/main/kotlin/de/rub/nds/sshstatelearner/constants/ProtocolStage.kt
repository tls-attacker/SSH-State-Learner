/*
 * SSH State Learner - A tool for extracting state machines from SSH server implementations
 *
 * Copyright 2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.sshstatelearner.constants

/**
 * An enumeration representing a protocol "stage" within the SSH protocol.
 */
enum class ProtocolStage {
    /**
     * The SSH transport layer protocol stage (RFC 4253) with completed version exchange.
     */
    TRANSPORT,

    /**
     * The SSH transport layer protocol stage (RFC 4253) with completed version exchange and without service request.
     */
    TRANSPORT_KEX,

    /**
     * The SSH authentication layer protocol stage (RFC 4252)
     */
    AUTHENTICATION,

    /**
     * The SSH connection layer protocol stage (RFC 4254)
     */
    CONNECTION,
    
    UNKNOWN;
}
