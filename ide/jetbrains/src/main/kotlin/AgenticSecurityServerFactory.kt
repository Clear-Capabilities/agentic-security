package com.clearcapabilities.agenticsec

import com.intellij.openapi.project.Project
import com.redhat.devtools.lsp4ij.server.StreamConnectionProvider
import com.redhat.devtools.lsp4ij.server.ProcessStreamConnectionProvider
import com.redhat.devtools.lsp4ij.LanguageServerFactory

class AgenticSecurityConnectionProvider(commands: List<String>, workingDir: String?)
    : ProcessStreamConnectionProvider(commands, workingDir)

class AgenticSecurityServerFactory : LanguageServerFactory {
    override fun createConnectionProvider(project: Project): StreamConnectionProvider {
        val cmd = System.getProperty("agentic-security.lspCommand")
            ?: "agentic-security-lsp"
        return AgenticSecurityConnectionProvider(listOf(cmd), project.basePath)
    }
}
