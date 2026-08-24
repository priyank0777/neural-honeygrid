class HoneyGridApp {
    constructor() {
        this.selectedSessionId = null;
        this.ws = null;
        this._initTabs();
        this._initWebSocket();
        this._startPolling();
    }

    _initTabs() {
        const tabs = document.querySelectorAll('.nav-tab');
        tabs.forEach(tab => {
            tab.addEventListener('click', () => {
                const target = tab.getAttribute('data-tab');
                this.switchTab(target);
            });
        });
    }

    switchTab(tabId) {
        document.querySelectorAll('.nav-tab').forEach(t => t.classList.remove('active'));
        document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));

        const btn = document.querySelector(`[data-tab="${tabId}"]`);
        const content = document.getElementById(tabId);
        if (btn) btn.classList.add('active');
        if (content) content.classList.add('active');

        // Trigger view refreshes when switching tabs
        if (tabId === 'mitre-tab' && window.mitreView) {
            window.mitreView.refresh();
        } else if (tabId === 'canary-tab') {
            this.refreshCanaryVault();
        } else if (tabId === 'simulator-tab' && window.simulatorView) {
            window.simulatorView.refresh();
        } else if (tabId === 'reports-tab') {
            this.refreshReportsView();
        }
    }

    _initWebSocket() {
        const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
        const wsUrl = `${protocol}//${window.location.host}/ws/live`;
        
        try {
            this.ws = new WebSocket(wsUrl);
            this.ws.onopen = () => {
                console.log('[+] Connected to Neural HoneyGrid WebSocket Stream');
            };
            this.ws.onmessage = (event) => {
                try {
                    const data = JSON.parse(event.data);
                    if (window.terminalView) {
                        window.terminalView.handleLiveBroadcast(data);
                    }
                    this.refreshStatus();
                    this.refreshSessions();
                } catch (e) {
                    console.error('Error parsing WebSocket message', e);
                }
            };
            this.ws.onclose = () => {
                console.warn('WebSocket disconnected. Reconnecting in 3s...');
                setTimeout(() => this._initWebSocket(), 3000);
            };
        } catch (e) {
            console.error('WebSocket connection error:', e);
        }
    }

    _startPolling() {
        this.refreshStatus();
        this.refreshSessions();
        this.refreshCanaryVault();

        setInterval(() => {
            this.refreshStatus();
            this.refreshSessions();
        }, 3000);
    }

    async refreshStatus() {
        try {
            const resp = await fetch('/api/status');
            const data = await resp.json();

            // Update Header & Metrics
            document.getElementById('metric-sessions').textContent = data.stats.active_sessions;
            document.getElementById('metric-commands').textContent = data.stats.total_commands_intercepted;
            document.getElementById('metric-canaries').textContent = data.stats.canary_breaches;
            document.getElementById('metric-threats').textContent = data.stats.critical_threats;

            if (data.stats.canary_breaches > 0) {
                const badge = document.getElementById('canary-alert-pill');
                if (badge) badge.style.display = 'inline-flex';
            }
        } catch (err) {
            console.error('Status fetch error', err);
        }
    }

    async refreshSessions() {
        try {
            const resp = await fetch('/api/sessions');
            const sessions = await resp.json();
            const list = document.getElementById('session-list-container');
            if (!list) return;

            list.innerHTML = '';
            if (sessions.length === 0) {
                list.innerHTML = '<div style="padding:1rem; color:#64748b; font-size:0.8rem; text-align:center;">No active sessions yet. Use the Simulator or Terminal to start.</div>';
                return;
            }

            sessions.forEach(s => {
                const item = document.createElement('div');
                item.className = `session-item ${this.selectedSessionId === s.session_id ? 'selected' : ''}`;
                
                let pillClass = 'pill-low';
                if (s.risk_score >= 75) pillClass = 'pill-crit';
                else if (s.risk_score >= 50) pillClass = 'pill-high';
                else if (s.risk_score >= 25) pillClass = 'pill-med';

                item.innerHTML = `
                    <div class="session-top">
                        <span class="session-ip">${s.remote_ip}</span>
                        <span class="threat-pill ${pillClass}">Score ${s.risk_score}</span>
                    </div>
                    <div style="font-size:0.75rem; color:#cbd5e1; margin-bottom:0.25rem; font-weight:600;">
                        ${s.classification}
                    </div>
                    <div class="session-bottom">
                        <span>${s.command_count} cmds | ${s.canary_count} canaries</span>
                        <span>${s.session_id.substring(0, 10)}</span>
                    </div>
                `;
                item.onclick = () => this.selectSession(s.session_id);
                list.appendChild(item);
            });
        } catch (err) {
            console.error('Sessions fetch error', err);
        }
    }

    selectSession(sessionId) {
        this.selectedSessionId = sessionId;
        if (window.terminalView) {
            window.terminalView.currentSessionId = sessionId;
        }
        this.refreshSessions();
        this.loadSessionReport(sessionId);
    }

    async refreshCanaryVault() {
        try {
            const [tokensResp, alertsResp] = await Promise.all([
                fetch('/api/canary/tokens'),
                fetch('/api/canary/alerts')
            ]);
            const tokens = await tokensResp.json();
            const alerts = await alertsResp.json();

            const grid = document.getElementById('canary-vault-grid');
            if (!grid) return;
            grid.innerHTML = '';

            tokens.forEach(tok => {
                const card = document.createElement('div');
                card.className = `canary-card ${tok.triggered ? 'breached' : ''}`;

                card.innerHTML = `
                    <span class="canary-status-tag ${tok.triggered ? 'tag-breached' : 'tag-armed'}">
                        ${tok.triggered ? '🚨 BREACHED' : 'ARMED & ACTIVE'}
                    </span>
                    <div style="font-size:0.75rem; color:#38bdf8; font-weight:bold; font-family:var(--font-mono); text-transform:uppercase;">
                        ${tok.token_type}
                    </div>
                    <h3 style="font-size:0.95rem; font-weight:700; margin:0.3rem 0;">${tok.description}</h3>
                    <p style="font-size:0.75rem; color:#94a3b8;">Planted at: <code>${tok.location_planted}</code></p>
                    <div class="canary-code">${tok.token_value}</div>
                    ${tok.triggered ? `<p style="font-size:0.75rem; color:#ef4444; margin-top:0.5rem; font-weight:600;">Last triggered: ${tok.trigger_context || 'Access Detected'}</p>` : ''}
                `;
                grid.appendChild(card);
            });
        } catch (err) {
            console.error('Canary vault fetch error', err);
        }
    }

    async refreshReportsView() {
        try {
            const resp = await fetch('/api/sessions');
            const sessions = await resp.json();
            const select = document.getElementById('report-session-select');
            if (!select) return;

            select.innerHTML = '';
            sessions.forEach(s => {
                const opt = document.createElement('option');
                opt.value = s.session_id;
                opt.textContent = `${s.session_id} (${s.remote_ip} - Score: ${s.risk_score} - ${s.classification})`;
                select.appendChild(opt);
            });

            if (sessions.length > 0) {
                const targetId = this.selectedSessionId || sessions[0].session_id;
                select.value = targetId;
                this.loadSessionReport(targetId);
            }
        } catch (err) {
            console.error('Reports refresh error', err);
        }
    }

    async loadSessionReport(sessionId) {
        if (!sessionId) return;
        try {
            const resp = await fetch(`/api/reports/${sessionId}/markdown`);
            if (resp.ok) {
                const md = await resp.text();
                const container = document.getElementById('report-markdown-container');
                if (container) container.textContent = md;
            }
        } catch (err) {
            console.error('Load report error', err);
        }
    }

    async downloadReportStix() {
        const select = document.getElementById('report-session-select');
        const sessionId = select ? select.value : this.selectedSessionId;
        if (!sessionId) {
            alert('Please select a session first.');
            return;
        }
        window.open(`/api/reports/${sessionId}/stix`, '_blank');
    }

    async saveLLMSettings() {
        const provider = document.getElementById('llm-provider-select').value;
        const geminiKey = document.getElementById('llm-gemini-key').value;
        const groqKey = document.getElementById('llm-groq-key').value;
        const openaiKey = document.getElementById('llm-openai-key').value;

        try {
            const resp = await fetch('/api/config/llm', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    provider: provider,
                    gemini_key: geminiKey || null,
                    groq_key: groqKey || null,
                    openai_key: openaiKey || null
                })
            });
            const data = await resp.json();
            if (data.status === 'SUCCESS') {
                alert(`[✓] AI Core Configuration updated to provider: ${data.provider}`);
            }
        } catch (err) {
            alert(`Error updating settings: ${err.message}`);
        }
    }
}

document.addEventListener('DOMContentLoaded', () => {
    window.app = new HoneyGridApp();
});
