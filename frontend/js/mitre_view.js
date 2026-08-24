class MitreView {
    constructor() {
        this.container = document.getElementById('mitre-matrix-container');
        this.tactics = [
            { id: "Discovery", name: "Recon & Discovery", color: "#38bdf8" },
            { id: "Credential Access", name: "Credential Access", color: "#f87171" },
            { id: "Execution", name: "Execution", color: "#fbbf24" },
            { id: "Privilege Escalation", name: "Privilege Escalation", color: "#f97316" },
            { id: "Defense Evasion", name: "Defense Evasion", color: "#a855f7" },
            { id: "Persistence", name: "Persistence", color: "#ec4899" },
            { id: "Collection", name: "Collection", color: "#60a5fa" },
            { id: "Exfiltration", name: "Exfiltration", color: "#ef4444" },
            { id: "Impact", name: "Impact / Hijack", color: "#dc2626" }
        ];
    }

    async refresh() {
        try {
            const resp = await fetch('/api/mitre/matrix');
            const data = await resp.json();
            this.render(data);
        } catch (err) {
            console.error('Failed to load MITRE matrix', err);
        }
    }

    render(activeTechniques) {
        if (!this.container) return;
        this.container.innerHTML = '';

        const activeMap = {};
        activeTechniques.forEach(t => {
            activeMap[t.technique_id] = t;
        });

        // Curated reference techniques for each tactic
        const baseTechniqueCatalog = {
            "Discovery": [
                { id: "T1087.001", name: "Account Discovery" },
                { id: "T1082", name: "System Info Discovery" },
                { id: "T1083", name: "File & Directory Discovery" },
                { id: "T1049", name: "Network Connection Discovery" },
                { id: "T1016", name: "Network Config Discovery" },
                { id: "T1057", name: "Process Discovery" },
                { id: "T1046", name: "Network Service Scanning" }
            ],
            "Credential Access": [
                { id: "T1003.008", name: "OS Credential Dumping (/etc/shadow)" },
                { id: "T1552.001", name: "Credentials In Files (.env, AWS)" },
                { id: "T1552.003", name: "Bash History Credentials" },
                { id: "T1110", name: "Brute Force Authentication" }
            ],
            "Execution": [
                { id: "T1059.004", name: "Unix Shell Script Interpreter" },
                { id: "T1203", name: "Remote Script Pipe (curl|bash)" },
                { id: "T1053.003", name: "Cron Scheduled Execution" }
            ],
            "Privilege Escalation": [
                { id: "T1548.003", name: "Sudo / Sudoers Abuse" },
                { id: "T1548.001", name: "Setuid / SUID Exploitation" },
                { id: "T1068", name: "Kernel Exploit / LinPEAS" }
            ],
            "Defense Evasion": [
                { id: "T1070.003", name: "Clear Command History" },
                { id: "T1562.001", name: "Disable Firewall / iptables" },
                { id: "T1027", name: "Obfuscated / Base64 Payload" }
            ],
            "Persistence": [
                { id: "T1136.001", name: "Local Backdoor User Creation" },
                { id: "T1098.004", name: "SSH Authorized Keys Injection" },
                { id: "T1546.004", name: ".bashrc Profile Persistence" }
            ],
            "Collection": [
                { id: "T1560.001", name: "Archive Utility (tar / zip)" }
            ],
            "Exfiltration": [
                { id: "T1048", name: "Exfiltration Over Alt Protocol (nc)" },
                { id: "T1567", name: "Exfiltration to Cloud Storage" }
            ],
            "Impact": [
                { id: "T1496", name: "Resource Hijacking (Cryptominer)" },
                { id: "T1486", name: "Data Encrypted for Impact" }
            ]
        };

        this.tactics.forEach(tactic => {
            const col = document.createElement('div');
            col.className = 'tactic-column';

            const header = document.createElement('div');
            header.className = 'tactic-header';
            header.innerHTML = `<span>${tactic.name}</span>`;
            col.appendChild(header);

            const list = document.createElement('div');
            list.className = 'technique-list';

            const techniques = baseTechniqueCatalog[tactic.id] || [];
            techniques.forEach(tech => {
                const isTriggered = activeMap[tech.id] !== undefined;
                const hitInfo = activeMap[tech.id];

                const card = document.createElement('div');
                card.className = `technique-card ${isTriggered ? 'triggered' : ''}`;
                
                card.innerHTML = `
                    <div style="display:flex; justify-content:space-between; align-items:center;">
                        <span class="tech-id">${tech.id}</span>
                        ${isTriggered ? `<span style="background:#ef4444; color:#fff; font-size:0.65rem; font-weight:800; padding:1px 5px; border-radius:3px;">${hitInfo.hit_count} HITS</span>` : ''}
                    </div>
                    <div class="tech-name">${tech.name}</div>
                `;
                list.appendChild(card);
            });

            col.appendChild(list);
            this.container.appendChild(col);
        });
    }
}

window.mitreView = new MitreView();
