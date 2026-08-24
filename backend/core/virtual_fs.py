import os
import time
from typing import Dict, Optional, List, Tuple
from backend.config import config

class FSNode:
    def __init__(
        self,
        name: str,
        is_directory: bool = False,
        content: str = "",
        owner: str = "root",
        group: str = "root",
        mode: str = "0644",
        parent: Optional['FSNode'] = None
    ):
        self.name = name
        self.is_directory = is_directory
        self.content = content
        self.owner = owner
        self.group = group
        self.mode = "drwxr-xr-x" if is_directory else "-rw-r--r--"
        self.mtime = time.time() - (86400 * 3) # created 3 days ago
        self.parent = parent
        self.children: Dict[str, 'FSNode'] = {} if is_directory else None

    @property
    def size(self) -> int:
        if self.is_directory:
            return 4096
        return len(self.content.encode('utf-8'))

class VirtualFileSystem:
    def __init__(self):
        self.root = FSNode("", is_directory=True, owner="root", group="root")
        self._init_default_tree()

    def _init_default_tree(self):
        # Create standard Linux directories
        dirs = [
            "/bin", "/sbin", "/usr/bin", "/usr/sbin", "/usr/local/bin",
            "/etc", "/etc/nginx", "/etc/ssh", "/etc/cron.d", "/etc/systemd",
            "/home/admin", "/home/admin/.ssh", "/home/admin/.aws",
            "/home/devops", "/home/devops/.ssh",
            "/root", "/root/.ssh",
            "/opt", "/opt/api_gateway", "/opt/backup_scripts",
            "/var/log", "/var/log/nginx", "/var/www/html",
            "/tmp", "/var/tmp",
            "/proc", "/sys", "/dev"
        ]
        for d in dirs:
            self.mkdir_p(d)

        # Seed realistic Linux files
        self.write_file("/etc/os-release", 
            'NAME="Ubuntu"\n'
            'VERSION="22.04.4 LTS (Jammy Jellyfish)"\n'
            'ID=ubuntu\n'
            'ID_LIKE=debian\n'
            'PRETTY_NAME="Ubuntu 22.04.4 LTS"\n'
            'VERSION_ID="22.04"\n'
            'HOME_URL="https://www.ubuntu.com/"\n'
            'SUPPORT_URL="https://help.ubuntu.com/"\n'
            'BUG_REPORT_URL="https://bugs.launchpad.net/ubuntu/"\n'
            'UBUNTU_CODENAME=jammy\n'
        )

        self.write_file("/etc/issue", "Ubuntu 22.04.4 LTS \\n \\l\n")
        self.write_file("/etc/hostname", f"{config.HOSTNAME}\n")
        self.write_file("/etc/hosts", 
            "127.0.0.1 localhost\n"
            f"127.0.1.1 {config.HOSTNAME}\n"
            "10.0.4.10 prod-db-primary.internal\n"
            "10.0.4.12 prod-db-replica.internal\n"
            "10.0.5.50 redis-cache.internal\n"
            "10.0.2.1  gateway.corp.internal\n"
        )
        self.write_file("/etc/resolv.conf", "nameserver 127.0.0.53\noptions edns0 trust-ad\nsearch corp.internal\n")
        
        self.write_file("/etc/passwd",
            "root:x:0:0:root:/root:/bin/bash\n"
            "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
            "bin:x:2:2:bin:/bin:/usr/sbin/nologin\n"
            "sys:x:3:3:sys:/dev:/usr/sbin/nologin\n"
            "sync:x:4:65534:sync:/bin:/bin/sync\n"
            "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n"
            "syslog:x:104:110::/home/syslog:/usr/sbin/nologin\n"
            "systemd-resolve:x:103:108:systemd Resolver,,,:/run/systemd/resolve:/usr/sbin/nologin\n"
            "sshd:x:110:65534::/run/sshd:/usr/sbin/nologin\n"
            "admin:x:1000:1000:Admin User,,,:/home/admin:/bin/bash\n"
            "devops:x:1001:1001:DevOps Automation,,,:/home/devops:/bin/bash\n"
            "postgres:x:112:118:PostgreSQL administrator,,,:/var/lib/postgresql:/bin/bash\n"
        )

        self.write_file("/etc/shadow",
            "root:$6$kL8x94qP$w9x7hF1xL0w7Qo8aMnOpQrStUvWxYzAbCdEfGhIjKlMnOpQrStUvWxYzAbCdEfGhIjKlMnOpQrStUvWxYz0:19820:0:99999:7:::\n"
            "daemon:*:19820:0:99999:7:::\n"
            "admin:$6$9kLmNoPq$RsTuVwXyZ0123456789aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789aBcDeFgHiJkLmNoPqRsTuVwXy:19820:0:99999:7:::\n"
            "devops:$6$zYxWvUtS$fedcba9876543210zyxwvutsrqponmlkjihgfedcba9876543210zyxwvutsrqponmlkjihgfedcba98:19820:0:99999:7:::\n",
            owner="root", group="shadow", mode="-rw-r-----"
        )

        self.write_file("/etc/sudoers",
            "# /etc/sudoers\n"
            "Defaults\tenv_reset\n"
            "Defaults\tmail_badpass\n"
            "Defaults\tsecure_path=\"/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\"\n"
            "root\tALL=(ALL:ALL) ALL\n"
            "%admin ALL=(ALL) NOPASSWD: /usr/bin/systemctl, /usr/bin/docker\n"
            "%sudo\tALL=(ALL:ALL) ALL\n"
        )

        self.write_file("/etc/crontab",
            "# /etc/crontab: system-wide crontab\n"
            "SHELL=/bin/sh\n"
            "PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin\n\n"
            "# m h dom mon dow user\tcommand\n"
            "17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly\n"
            "25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )\n"
            "*/10 *  * * *   root    /opt/backup_scripts/sync_db.sh >/dev/null 2>&1\n"
        )

        # Plant Canary & Bait Files
        self.write_file("/home/admin/.aws/credentials",
            "[default]\n"
            "aws_access_key_id = CANARY_AWS_KEY_BAIT_94X7F\n"
            "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY_BAIT_992\n"
            "region = us-east-1\n",
            owner="admin", group="admin"
        )

        self.write_file("/opt/api_gateway/.env",
            "# Production Environment Configuration - DO NOT COMMIT\n"
            "NODE_ENV=production\n"
            "PORT=3000\n"
            "DATABASE_URL=postgres://superadmin:P@ssw0rd_Canary_2024!@10.0.4.12:5432/core_production\n"
            "REDIS_URL=redis://10.0.5.50:6379/0\n"
            "JWT_SECRET=SUPER_SECRET_INTERNAL_CANARY_JWT_SIGNING_KEY_9921\n"
            "STRIPE_API_KEY=sk_live_51MzCanaryBaitKeyNotRealStripe992817xX\n",
            owner="admin", group="admin"
        )

        self.write_file("/home/admin/.git-credentials",
            "https://devops-bot:CANARY_GH_PAT_CorpDeployKey_99281@github.com\n",
            owner="admin", group="admin"
        )

        self.write_file("/root/.ssh/id_rsa",
            "-----BEGIN OPENSSH PRIVATE KEY-----\n"
            "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn\n"
            "NhAAAAAwEAAQAAAYEAv9CanaryBaitKey9940xRootProdClusterMasterKeyBait==\n"
            "-----END OPENSSH PRIVATE KEY-----\n",
            owner="root", group="root", mode="-rw-------"
        )

        self.write_file("/home/admin/.bash_history",
            "git status\n"
            "cd /opt/api_gateway\n"
            "cat .env\n"
            "docker ps\n"
            "sudo systemctl restart nginx\n"
            "ssh -i ~/.ssh/id_rsa admin@10.0.4.10\n"
            "aws s3 ls s3://corp-db-backups-2024/\n"
            "curl http://10.0.5.50:6379/ping\n"
            "ps aux | grep node\n",
            owner="admin", group="admin"
        )

        self.write_file("/opt/backup_scripts/sync_db.sh",
            "#!/bin/bash\n"
            "# Automated DB backup synchronization script\n"
            "PGPASSWORD='P@ssw0rd_Canary_2024!' pg_dump -h 10.0.4.12 -U superadmin core_production | gzip > /tmp/db_backup_$(date +%Y%m%d).sql.gz\n",
            owner="root", group="root", mode="-rwxr-xr-x"
        )

        self.write_file("/var/log/auth.log",
            "Aug 24 04:12:01 prod-corp-sec-srv01 CRON[12044]: pam_unix(cron:session): session opened for user root(uid=0) by (uid=0)\n"
            "Aug 24 04:12:01 prod-corp-sec-srv01 CRON[12044]: pam_unix(cron:session): session closed for user root\n"
            "Aug 24 07:44:19 prod-corp-sec-srv01 sshd[14299]: Accepted publickey for admin from 192.168.1.55 port 52140 ssh2: RSA SHA256:4x8...\n"
        )

        self.write_file("/proc/version", f"{config.KERNEL_VERSION}\n")
        self.write_file("/proc/cpuinfo", 
            "processor\t: 0\nvendor_id\t: GenuineIntel\ncpu family\t: 6\nmodel name\t: Intel(R) Xeon(R) Platinum 8375C CPU @ 2.90GHz\ncpu MHz\t\t: 2899.998\ncache size\t: 55296 KB\n\n"
            "processor\t: 1\nvendor_id\t: GenuineIntel\ncpu family\t: 6\nmodel name\t: Intel(R) Xeon(R) Platinum 8375C CPU @ 2.90GHz\ncpu MHz\t\t: 2899.998\ncache size\t: 55296 KB\n"
        )
        self.write_file("/proc/meminfo",
            "MemTotal:        8149228 kB\n"
            "MemFree:         4382912 kB\n"
            "MemAvailable:    6241088 kB\n"
            "Buffers:          218400 kB\n"
            "Cached:          1894000 kB\n"
            "SwapTotal:       2097148 kB\n"
            "SwapFree:        2097148 kB\n"
        )

    def _normalize_path(self, path: str, cwd: str = "/") -> List[str]:
        if not path:
            path = cwd
        if not path.startswith("/"):
            path = os.path.normpath(os.path.join(cwd, path)).replace("\\", "/")
        else:
            path = os.path.normpath(path).replace("\\", "/")
        parts = [p for p in path.split("/") if p]
        return parts

    def resolve_path(self, path: str, cwd: str = "/") -> Tuple[Optional[FSNode], str]:
        parts = self._normalize_path(path, cwd)
        curr = self.root
        curr_path = "/"
        for part in parts:
            if not curr.is_directory or part not in curr.children:
                return None, "/" + "/".join(parts)
            curr = curr.children[part]
            curr_path = "/" + "/".join(parts[:parts.index(part)+1])
        return curr, "/" + "/".join(parts)

    def mkdir_p(self, path: str, cwd: str = "/", owner: str = "root", group: str = "root") -> FSNode:
        parts = self._normalize_path(path, cwd)
        curr = self.root
        for part in parts:
            if part not in curr.children:
                new_node = FSNode(part, is_directory=True, owner=owner, group=group, parent=curr)
                curr.children[part] = new_node
            curr = curr.children[part]
        return curr

    def write_file(self, path: str, content: str, cwd: str = "/", owner: str = "root", group: str = "root", mode: str = "-rw-r--r--") -> FSNode:
        parts = self._normalize_path(path, cwd)
        if not parts:
            return self.root
        dir_parts = parts[:-1]
        file_name = parts[-1]
        
        curr = self.root
        for part in dir_parts:
            if part not in curr.children:
                new_node = FSNode(part, is_directory=True, owner=owner, group=group, parent=curr)
                curr.children[part] = new_node
            curr = curr.children[part]
            
        file_node = FSNode(file_name, is_directory=False, content=content, owner=owner, group=group, mode=mode, parent=curr)
        curr.children[file_name] = file_node
        return file_node

    def append_file(self, path: str, content: str, cwd: str = "/") -> bool:
        node, _ = self.resolve_path(path, cwd)
        if node and not node.is_directory:
            node.content += content
            node.mtime = time.time()
            return True
        elif not node:
            self.write_file(path, content, cwd=cwd)
            return True
        return False

    def read_file(self, path: str, cwd: str = "/") -> Optional[str]:
        node, _ = self.resolve_path(path, cwd)
        if node and not node.is_directory:
            return node.content
        return None

    def list_dir(self, path: str, cwd: str = "/") -> Optional[Dict[str, FSNode]]:
        node, _ = self.resolve_path(path, cwd)
        if node and node.is_directory:
            return node.children
        return None

    def remove(self, path: str, cwd: str = "/") -> bool:
        node, _ = self.resolve_path(path, cwd)
        if node and node.parent and node.name in node.parent.children:
            del node.parent.children[node.name]
            return True
        return False

    def exists(self, path: str, cwd: str = "/") -> bool:
        node, _ = self.resolve_path(path, cwd)
        return node is not None

    def is_dir(self, path: str, cwd: str = "/") -> bool:
        node, _ = self.resolve_path(path, cwd)
        return node is not None and node.is_directory
