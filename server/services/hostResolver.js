const dns = require('dns').promises;
const { execFile } = require('child_process');
const util = require('util');
const execFileAsync = util.promisify(execFile);
const os = require('os');

class HostResolver {
    constructor(config) {
        this.config = config;
        this.cache = new Map();
        this.cacheTTL = 30 * 60 * 1000; // 30 minutes
        this.isWindows = process.platform === 'win32';
    }

    async resolveHostname(ip) {
        // Check cache first
        const cached = this.cache.get(ip);
        if (cached && Date.now() < cached.expires) {
            return cached.hostname || ip;  // Return IP if hostname is null
        }

        let hostname = null;

        // Try different resolution methods
        try {
            // Method 1: DNS reverse lookup
            hostname = await this.dnsLookup(ip);

            // Method 2: NetBIOS name (Windows) or mDNS (Linux)
            if (!hostname) {
                hostname = this.isWindows ? 
                    await this.netbiosLookup(ip) :
                    await this.mdnsLookup(ip);
            }

            // Method 3: System-specific commands
            if (!hostname) {
                hostname = await this.systemLookup(ip);
            }

            // Cache the result (even if null)
            this.cache.set(ip, {
                hostname: hostname,
                expires: Date.now() + this.cacheTTL
            });

            return hostname || ip;  // Return IP if no hostname found
        } catch (error) {
            console.debug(`Hostname resolution failed for ${ip}:`, error.message);
            return ip;  // Return IP on error
        }
    }

    async dnsLookup(ip) {
        try {
            const hostnames = await dns.reverse(ip);
            return hostnames[0] || null;
        } catch {
            return null;
        }
    }

    async netbiosLookup(ip) {
        if (!this.isWindows) return null;

        try {
            const { stdout } = await execFileAsync('nbtstat', ['-A', ip]);
            const match = stdout.match(/<00>\s+UNIQUE\s+([^\\]+)/);
            return match ? match[1].trim() : null;
        } catch {
            return null;
        }
    }

    async mdnsLookup(ip) {
        if (this.isWindows) return null;

        try {
            const { stdout } = await execFileAsync('avahi-resolve', ['-a', ip]);
            const match = stdout.match(/^.+?\s+(.+)$/m);
            return match ? match[1].trim() : null;
        } catch {
            return null;
        }
    }

    async systemLookup(ip) {
        try {
            if (this.isWindows) {
                const { stdout } = await execFileAsync('powershell', [
                    '-Command',
                    `[System.Net.Dns]::GetHostEntry('${ip}').HostName`
                ]);
                return stdout.trim() || null;
            } else {
                // Try getent on Linux
                const { stdout } = await execFileAsync('getent', ['hosts', ip]);
                const match = stdout.match(/^\S+\s+(.+)$/);
                return match ? match[1].trim() : null;
            }
        } catch {
            return null;
        }
    }

    clearExpiredCache() {
        const now = Date.now();
        for (const [ip, entry] of this.cache) {
            if (now > entry.expires) {
                this.cache.delete(ip);
            }
        }
    }
}

module.exports = HostResolver;