package de.rub.nds.sshstatelearner.sul

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.cancel
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlin.time.Duration
import kotlin.time.TimeSource

/**
 * The NetworkSshClientSul pool for the SUL. Tracks idle times, initialization, and work time of SULs.
 */
class SshClientWorker {
    private val scope = CoroutineScope(Dispatchers.IO)
    private val sulToUse = Channel<NetworkSshClientSul>(64)
    private val allSuls = mutableListOf<NetworkSshClientSul>()
    private val map = HashMap<Int, IdleVsWorkTime>()

    /**
     *
     */
    fun init(suls: List<NetworkSshClientSul>) {
        runBlocking {
            for (sul in suls) {
                sul.pre()
                sulToUse.send(sul)
                allSuls.add(sul)

                map[sul.port] = IdleVsWorkTime()
            }
        }
    }

    fun exit() {
        runBlocking {
            // Terminates any remaining running threads
            if (scope.isActive) {
                scope.runCatching { cancel() }
            }
            sulToUse.close()
            allSuls.forEach {
                it.post()
            }
        }
    }

    fun getReadySulToUse(): NetworkSshClientSul = runBlocking {
        val sul = sulToUse.receive()
        val idleVsWorkTime = map[sul.port]

        idleVsWorkTime?.markEndIdleTime()
        idleVsWorkTime?.markStartWorkTime()

        sul
    }

    fun getSulWasUsed(sul: NetworkSshClientSul) {
        scope.launch {
            val idleVsWorkTime = map[sul.port]

            idleVsWorkTime?.markEndWorkTime()
            idleVsWorkTime?.markStartInitTime()

            sul.post()
            sul.pre()

            idleVsWorkTime?.markEndInitTime()
            idleVsWorkTime?.markStartIdleTime()

            sulToUse.send(sul)
        }
    }

    fun getTotalIdleTime(): Duration {
        var totalIdleTime = Duration.ZERO
        map.forEach { entry -> totalIdleTime += entry.value.idleTime }
        return totalIdleTime
    }

    fun getTotalWorkTime(): Duration {
        var totalWorkTime = Duration.ZERO
        map.forEach { entry -> totalWorkTime += entry.value.workTime }
        return totalWorkTime
    }

    fun getTotalInitTime(): Duration {
        var totalInitTime = Duration.ZERO
        map.forEach { entry -> totalInitTime += entry.value.initTime }
        return totalInitTime
    }

    private class IdleVsWorkTime {
        var idleTime = Duration.ZERO
        var startIdleTime: TimeSource.Monotonic.ValueTimeMark? = null
        var workTime = Duration.ZERO
        var startWorkTime: TimeSource.Monotonic.ValueTimeMark? = null
        val timeSource = TimeSource.Monotonic
        var initTime = Duration.ZERO
        var startInitTime: TimeSource.Monotonic.ValueTimeMark? = null

        fun markStartIdleTime() {
            startIdleTime = timeSource.markNow()
        }

        fun markEndIdleTime() {
            idleTime += startIdleTime?.elapsedNow() ?: Duration.ZERO
        }

        fun markStartWorkTime() {
            startWorkTime = timeSource.markNow()
        }

        fun markEndWorkTime() {
            workTime += startWorkTime?.elapsedNow() ?: Duration.ZERO
        }


        fun markStartInitTime() {
            startInitTime = timeSource.markNow()
        }

        fun markEndInitTime() {
            initTime += startInitTime?.elapsedNow() ?: Duration.ZERO
        }

    }

}