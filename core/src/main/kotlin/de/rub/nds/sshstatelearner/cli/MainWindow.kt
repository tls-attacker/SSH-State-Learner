/*
 * SSH State Learner - A tool for extracting state machines from SSH server implementations
 *
 * Copyright 2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.sshstatelearner.cli

import com.googlecode.lanterna.TerminalSize
import com.googlecode.lanterna.bundle.LanternaThemes
import com.googlecode.lanterna.gui2.BasicWindow
import com.googlecode.lanterna.gui2.Borders
import com.googlecode.lanterna.gui2.Button
import com.googlecode.lanterna.gui2.Direction
import com.googlecode.lanterna.gui2.GridLayout
import com.googlecode.lanterna.gui2.Label
import com.googlecode.lanterna.gui2.LinearLayout
import com.googlecode.lanterna.gui2.Panel
import com.googlecode.lanterna.gui2.Separator
import com.googlecode.lanterna.gui2.Window.Hint

object MainWindow : BasicWindow("SSH State Learner") {

    private val contentPanel = Panel()

    val infoServerName = Label("[unknown]")
    val infoExecutor = Label("[unknown]")
    val infoTarget = Label("[unknown]")
    val infoStage = Label("[unknown]")
    val infoKex = Label("[unknown]")
    val infoStrictKex = Label("[unknown]")
    val infoAlphabetSize = Label("[unknown]")
    private val infoPanel = Panel(GridLayout(2)).apply {
        addComponent(
            Label("Info").apply {
                layoutData = GridLayout.createLayoutData(GridLayout.Alignment.FILL, GridLayout.Alignment.BEGINNING, true, false, 4, 1)
            }
        )
        addComponent(
            Separator(Direction.HORIZONTAL).apply {
                layoutData = GridLayout.createLayoutData(GridLayout.Alignment.FILL, GridLayout.Alignment.BEGINNING, true, false, 4, 1)
            }
        )
        addComponent(Label("Server Name:"))
        addComponent(infoServerName)
        addComponent(Label("Executor:"))
        addComponent(infoExecutor)
        addComponent(Label("Target:"))
        addComponent(infoTarget)
        addComponent(Label("Protocol stage:"))
        addComponent(infoStage)
        addComponent(Label("Key Exchange Algorithm:"))
        addComponent(infoKex)
        addComponent(Label("Strict KEX:"))
        addComponent(infoStrictKex)
        addComponent(Label("Alphabet size:"))
        addComponent(infoAlphabetSize)

        layoutData = LinearLayout.createLayoutData(LinearLayout.Alignment.Fill)
    }

    val statLearningPhase = Label("INIT").apply { layoutData = GridLayout.createLayoutData(GridLayout.Alignment.END, GridLayout.Alignment.BEGINNING) }
    val statLearningExecTime = Label("").apply { layoutData = GridLayout.createLayoutData(GridLayout.Alignment.END, GridLayout.Alignment.BEGINNING) }
    val statLearningRound = Label("").apply { layoutData = GridLayout.createLayoutData(GridLayout.Alignment.END, GridLayout.Alignment.BEGINNING) }
    val statLearningSteps = Label("").apply { layoutData = GridLayout.createLayoutData(GridLayout.Alignment.END, GridLayout.Alignment.BEGINNING) }
    val statLearningResets = Label("").apply { layoutData = GridLayout.createLayoutData(GridLayout.Alignment.END, GridLayout.Alignment.BEGINNING) }
    val statLearningCacheInconsistencies = Label("").apply { layoutData = GridLayout.createLayoutData(GridLayout.Alignment.END, GridLayout.Alignment.BEGINNING) }
    val statLearningCacheHitRate = Label("").apply { layoutData = GridLayout.createLayoutData(GridLayout.Alignment.END, GridLayout.Alignment.BEGINNING) }

    private val statPanel = Panel(GridLayout(2)).apply {
        addComponent(
            Label("Stats").apply {
                layoutData = GridLayout.createLayoutData(GridLayout.Alignment.FILL, GridLayout.Alignment.BEGINNING, true, false, 4, 1)
            }
        )
        addComponent(
            Separator(Direction.HORIZONTAL).apply {
                layoutData = GridLayout.createLayoutData(GridLayout.Alignment.FILL, GridLayout.Alignment.BEGINNING, true, false, 4, 1)
            }
        )
        addComponent(Label("Phase:"))
        addComponent(statLearningPhase)
        addComponent(Label("Execution time:"))
        addComponent(statLearningExecTime)
        addComponent(Label("Round:"))
        addComponent(statLearningRound)
        addComponent(Label("Total # Steps:"))
        addComponent(statLearningSteps)
        addComponent(Label("Total # Resets:"))
        addComponent(statLearningResets)
        addComponent(Label("Cache Inconsistencies:"))
        addComponent(statLearningCacheInconsistencies)
        addComponent(Label("Cache Hit Rate:"))
        addComponent(statLearningCacheHitRate)

        layoutData = LinearLayout.createLayoutData(LinearLayout.Alignment.Fill)
    }

    private val exitButton = Button("Abort & Exit").apply {
        addListener { this@MainWindow.close() }
    }
    private val ctrlPanel = Panel(GridLayout(4)).apply {
        addComponent(exitButton)
    }

    init {
        contentPanel.addComponent(infoPanel.withBorder(Borders.singleLine()))
        contentPanel.addComponent(statPanel.withBorder(Borders.singleLine()))
        contentPanel.addComponent(ctrlPanel)
        component = contentPanel
        theme = LanternaThemes.getRegisteredTheme("businessmachine")
    }

    fun computeComponentsSize(terminalSize: TerminalSize) {
        infoPanel.size = TerminalSize(terminalSize.columns / 2, infoPanel.calculatePreferredSize().rows)
        statPanel.size = TerminalSize(terminalSize.columns - infoPanel.size.columns, statPanel.calculatePreferredSize().rows)
    }

    override fun getHints(): MutableSet<Hint> {
        return mutableSetOf(Hint.FULL_SCREEN)
    }
}
