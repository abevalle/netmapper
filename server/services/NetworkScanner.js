
class NetworkScanner {
    constructor(config, macResolver, systemUtils) {
        this.config = config;
        this.macResolver = macResolver;
        this.systemUtils = systemUtils;
    }

    async scanNetwork(range) {
        // ...existing code...
    }

    async scanSingleHost(ip) {
        const results = {
            ip,
            isAlive: false,
            mac: null,
            manufacturer: null,
            hostname: null,
            ports: []
        };

        try {
            const alive = await this.systemUtils.pingHost(ip);
            if (!alive) return results;

            results.isAlive = true;
            results.mac = await this.macResolver.getMACAddress(ip);
            results.manufacturer = await this.macResolver.getManufacturer(results.mac);
            results.hostname = await this.systemUtils.getHostname(ip);
            results.ports = await this.scanPorts(ip);

            return results;
        } catch (error) {
            console.error(`Error scanning ${ip}:`, error);
            return results;
        }
    }

    // ...existing code...
}

module.exports = NetworkScanner;