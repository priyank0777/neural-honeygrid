class TerminalView {
    constructor() {
        this.termBody = document.getElementById('terminal-body');
        this.termInput = document.getElementById('term-input');
        this.promptLabel = document.getElementById('term-prompt-label');
        this.history = [];
        this.historyIndex = -1;
        this.currentSessionId = 'sandbox-operator-01';

        this._initListeners();
    }

    _initListeners() {
        if (!this.termInput) return;

        this.termInput.addEventListener('keydown', async (e) => {
            if (e.key === 'Enter') {
                const cmd = this.termInput.value.trim();
                if (!cmd) return;

                this.history.push(cmd);
                this.historyIndex = this.history.length;
                this.termInput.value = '';

                // Print command line
                this.appendCommandLine(this.promptLabel.textContent, cmd);

                // Clear command
                if (cmd === 'clear') {
                    this.clear();
                    return;
                }

                // Send to backend
                try {
                    const resp = await fetch('/api/shell/exec', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({
                            session_id: this.currentSessionId,
                            command: cmd
                        })
                    });
                    const data = await resp.json();
                    this.handleCommandResponse(data);
                } catch (err) {
                    this.appendOutputLine(`[Network Error]: ${err.message}`, 'alert');
                }
            } else if (e.key === 'ArrowUp') {
                if (this.historyIndex > 0) {
                    this.historyIndex--;
                    this.termInput.value = this.history[this.historyIndex];
                }
                e.preventDefault();
            } else if (e.key === 'ArrowDown') {
                if (this.historyIndex < this.history.length - 1) {
                    this.historyIndex++;
                    this.termInput.value = this.history[this.historyIndex];
                } else {
                    this.historyIndex = this.history.length;
                    this.termInput.value = '';
                }
                e.preventDefault();
            }
        });
    }

    appendCommandLine(prompt, cmd) {
        const div = document.createElement('div');
        div.className = 'term-line cmd';
        div.textContent = `${prompt} ${cmd}`;
        this.termBody.appendChild(div);
        this.scrollToBottom();
    }

    appendOutputLine(text, type = 'out') {
        if (!text) return;
        const div = document.createElement('div');
        div.className = `term-line ${type}`;
        div.textContent = text;
        this.termBody.appendChild(div);
        this.scrollToBottom();
    }

    handleCommandResponse(data) {
        // Output stdout/stderr
        if (data.stdout) {
            this.appendOutputLine(data.stdout, 'out');
        }
        if (data.stderr) {
            this.appendOutputLine(data.stderr, 'alert');
        }

        // Output MITRE flags if any
        if (data.mitre_matches && data.mitre_matches.length > 0) {
            data.mitre_matches.forEach(m => {
                this.appendOutputLine(`🛡️ [MITRE ATT&CK] ${m.technique_id} - ${m.name} (${m.tactic}) [${m.severity}]`, 'mitre');
            });
        }

        // Output Canary alarm if breached
        if (data.canary_triggered) {
            const c = data.canary_triggered;
            this.appendOutputLine(`🚨 [CRITICAL CANARY BREACH] Honeytoken accessed: ${c.description} at ${c.location_planted}`, 'alert');
        }

        if (data.prompt) {
            this.promptLabel.textContent = data.prompt;
        }

        this.scrollToBottom();
    }

    handleLiveBroadcast(eventData) {
        if (eventData.type === 'COMMAND_EXEC') {
            // If it's another session streaming live
            if (eventData.session_id !== this.currentSessionId) {
                const header = `[LIVE STREAM from ${eventData.remote_ip}] ${eventData.prompt || '$'}`;
                this.appendCommandLine(header, eventData.command);
                if (eventData.stdout) this.appendOutputLine(eventData.stdout, 'out');
                if (eventData.stderr) this.appendOutputLine(eventData.stderr, 'alert');
                if (eventData.mitre_matches && eventData.mitre_matches.length > 0) {
                    eventData.mitre_matches.forEach(m => {
                        this.appendOutputLine(`🛡️ [MITRE ATT&CK] ${m.technique_id} - ${m.name}`, 'mitre');
                    });
                }
                if (eventData.canary_triggered) {
                    this.appendOutputLine(`🚨 [CANARY BREACH] ${eventData.canary_triggered.description}`, 'alert');
                }
            }
        }
    }

    clear() {
        this.termBody.innerHTML = '';
    }

    scrollToBottom() {
        this.termBody.scrollTop = this.termBody.scrollHeight;
    }
}

window.terminalView = new TerminalView();
