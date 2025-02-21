package de.rub.nds.sshstatelearner.db

import jakarta.persistence.CascadeType
import jakarta.persistence.Column
import jakarta.persistence.Entity
import jakarta.persistence.GeneratedValue
import jakarta.persistence.GenerationType
import jakarta.persistence.Id
import jakarta.persistence.OneToMany
import java.time.Instant

@Entity(name = "STL_INFO")
data class STLInfo(
    @Column(columnDefinition = "json")
    var configJSON: String,
    @OneToMany(cascade = [CascadeType.ALL])
    var queryResult: List<QueryResult>,
    var date: Instant
) {
    @Id
    @GeneratedValue(strategy = GenerationType.SEQUENCE)
    var id: Long? = null
}