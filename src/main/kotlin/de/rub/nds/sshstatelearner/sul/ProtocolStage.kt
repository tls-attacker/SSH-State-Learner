/*
 * SSH State Learner - A tool for extracting state machines from SSH server implementations
 *
 * Copyright 2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.sshstatelearner.sul

/**
 * An enumeration representing a protocol "stage" within the SSH protocol.
 */
enum class ProtocolStage {
    /**
     * The SSH transport layer protocol stage (RFC 4253)
     */
    TRANSPORT,
    /**
     * The SSH transport layer protocol as per RFC 4253 with completed version exchange.
     * This stage may be used if the server accepts arbitrary data prior to version exchange which may
     * result in large and inaccurate state machines (can be observed when using e.g. OpenSSH 7.2p1 or 7.4p1)
     */
    TRANSPORT_VEX_COMPLETE,
    /**
     * The SSH authentication layer protocol stage (RFC 4252)
     */
    AUTHENTICATION,
    /**
     * The SSH connection layer protocol stage (RFC 4254)
     */
    CONNECTION;
}
