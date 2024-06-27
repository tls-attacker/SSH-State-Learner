package de.rub.nds.sshstatelearner.db

import de.rub.nds.tlsattacker.transport.socket.SocketState
import jakarta.persistence.Column
import jakarta.persistence.ElementCollection
import jakarta.persistence.Entity
import jakarta.persistence.EnumType
import jakarta.persistence.Enumerated
import jakarta.persistence.GeneratedValue
import jakarta.persistence.GenerationType
import jakarta.persistence.Id
import jakarta.persistence.JoinColumn
import jakarta.persistence.JoinTable

@Entity(name = "QUERY_RESULT_RESPONSE_FINGERPRINT")
data class QueryResultResponseFingerprint(
    @ElementCollection
    @JoinTable(name = "QUERY_RESULT_RESPONSE_FINGERPRINT_MESSAGES", joinColumns = [JoinColumn(name = "id")])
    @Column(name = "messages", nullable = false)
    @Enumerated(EnumType.STRING)
    val messages: List<String>,
    @Enumerated(EnumType.STRING)
    var socketState: SocketState
) {
    @Id
    @GeneratedValue(strategy = GenerationType.SEQUENCE)
    var id: Int? = null
}