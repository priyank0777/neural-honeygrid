class SimulatorView {
    constructor() {
        this.container = document.getElementById('simulator-scenarios-container');
    }

    async refresh() {
        try {
            const resp = await fetch('/api/simulator/scenarios');
            const scenarios = await resp.json();
            this.render(scenarios);
        } catch (err) {
            console.error('Failed to load scenarios', err);
        }
    }

    render(scenarios) {
        if (!this.container) return;
        this.container.innerHTML = '';

        scenarios.forEach(sc => {
            const card = document.createElement('div');
            card.className = 'sim-card';

            card.innerHTML = `
                <div>
                    <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:0.5rem;">
                        <span style="font-size:0.75rem; color:#38bdf8; font-weight:bold; font-family:var(--font-mono);">${sc.actor}</span>
                        <span style="font-size:0.7rem; background:rgba(59,130,246,0.2); color:#60a5fa; padding:2px 8px; border-radius:9999px;">${sc.command_count} Commands</span>
                    </div>
                    <h3 style="font-size:1.05rem; font-weight:700; margin-bottom:0.4rem;">${sc.name}</h3>
                    <p style="font-size:0.8rem; color:#94a3b8; line-height:1.4;">${sc.description}</p>
                </div>
                <button class="btn-launch" onclick="window.simulatorView.launchScenario('${sc.id}')">
                    <span>⚡ Launch Attack Persona</span>
                </button>
            `;
            this.container.appendChild(card);
        });
    }

    async launchScenario(scenarioId) {
        try {
            const resp = await fetch('/api/simulator/launch', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ scenario_id: scenarioId })
            });
            const data = await resp.json();
            if (data.status === 'SUCCESS') {
                // Switch to live terminal tab to watch attack unfold
                if (window.app) {
                    window.app.switchTab('terminal-tab');
                }
                alert(`🚀 Launched adversary scenario '${scenarioId}'! Watch the Live Terminal for real-time actions and MITRE mapping.`);
            }
        } catch (err) {
            alert(`Error launching simulation: ${err.message}`);
        }
    }
}

window.simulatorView = new SimulatorView();
