class NetworkScanner {
    constructor(config, macResolver, systemUtils) {
        this.config = config;
        this.macResolver = macResolver;
        this.systemUtils = systemUtils;
    }

    async scanNetwork(range) {
        const networkDevices = [];
        
        // Get gateway info first
        const gateway = await this.systemUtils.getGatewayInfo();
        let gatewayNode = null;

        // If we find a gateway, scan it first
        if (gateway && gateway.ip) {
            console.log('Detected gateway:', gateway.ip);
            const gatewayInfo = await this.scanSingleHost(gateway.ip);
            if (gatewayInfo.isAlive) {
                gatewayInfo.isGateway = true;
                gatewayInfo.name = 'Gateway';
                networkDevices.push(gatewayInfo);
                gatewayNode = gatewayInfo;
            }
        }

        // Continue with regular network scan
        // ... scan other devices ...

        // If custom range is used and no gateway was found in our range,
        // don't artificially create a center node
        if (!gatewayNode && networkDevices.length > 0) {
            // Use a distributed graph layout instead of centralized
            // This will be handled by the frontend force layout
        }

        return networkDevices;
    }

    async scanSingleHost(ip) {
        const results = {
            ip,
            isAlive: false,
            mac: 'Unknown',
            manufacturer: null,
            hostname: null,
            ports: []
        };

        try {
            const alive = await this.systemUtils.pingHost(ip);
            if (!alive) return results;

            results.isAlive = true;
            
            // Get MAC address with retries
            for (let i = 0; i < 3; i++) {
                const mac = await this.macResolver.getMACAddress(ip);
                if (mac && mac !== 'Unknown') {
                    results.mac = mac;
                    results.manufacturer = await this.macResolver.getManufacturer(mac);
                    break;
                }
                // Small delay between retries
                await new Promise(resolve => setTimeout(resolve, 500));
            }

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