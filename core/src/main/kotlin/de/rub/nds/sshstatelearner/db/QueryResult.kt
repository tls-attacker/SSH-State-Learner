package de.rub.nds.sshstatelearner.db

import de.rub.nds.sshstatelearner.extraction.SshSymbol
import jakarta.persistence.CascadeType
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
import jakarta.persistence.OneToMany

@Entity(name = "QUERY_RESULT")
data class QueryResult(
    @ElementCollection(targetClass = SshSymbol::class)
    @JoinTable(name = "QUERY_RESULT_PREFIX", joinColumns = [JoinColumn(name = "id")])
    @Column(name = "prefix", nullable = false)
    @Enumerated(EnumType.STRING)
    val prefix: MutableList<SshSymbol> = mutableListOf(),

    @ElementCollection(targetClass = SshSymbol::class)
    @JoinTable(name = "QUERY_RESULT_SUFFIX", joinColumns = [JoinColumn(name = "id")])
    @Column(name = "suffix", nullable = false)
    @Enumerated(EnumType.STRING)
    val suffix: List<SshSymbol> = mutableListOf(),

    @OneToMany(cascade = [CascadeType.ALL])
    val responseFingerprints: List<QueryResultResponseFingerprint>,

    @Enumerated(EnumType.STRING)
    val queryTyp: QueryTyp
) {
    @Id
    @GeneratedValue(strategy = GenerationType.SEQUENCE)
    var id: Long? = null

    var count: Int = 1
}