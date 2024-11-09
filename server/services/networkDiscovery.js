const os = require('os');
const { promisify } = require('util');
const { exec } = require('child_process');
const execAsync = promisify(exec);

class NetworkDiscovery {
    constructor(config) {
        this.config = config;
        this.interfaces = new Map();
        this.routes = new Map();
    }

    async discover() {
        await this.getInterfaces();
        await this.getRoutes();
        await this.identifyGateways();
        await this.detectSubnets();
        return this.buildTopology();
    }

    async getInterfaces() {
        const interfaces = os.networkInterfaces();
        for (const [name, addrs] of Object.entries(interfaces)) {
            const ipv4 = addrs.find(addr => addr.family === 'IPv4' && !addr.internal);
            if (ipv4) {
                this.interfaces.set(name, {
                    name,
                    ip: ipv4.address,
                    netmask: ipv4.netmask,
                    mac: ipv4.mac,
                    cidr: this.calculateCIDR(ipv4.address, ipv4.netmask)
                });
            }
        }
    }

    async getRoutes() {
        try {
            const { stdout } = await execAsync('ip route');
            stdout.split('\n').forEach(line => {
                const match = line.match(/^(\S+)\s+via\s+(\S+)/);
                if (match) {
                    this.routes.set(match[1], { via: match[2] });
                }
            });
        } catch (error) {
            console.warn('Could not get routing info:', error.message);
        }
    }

    async identifyGateways() {
        this.gateways = new Map();
        
        // Method 1: Direct gateway check
        try {
            const { stdout } = await execAsync('ip route show default');
            const matches = stdout.matchAll(/default via ([0-9.]+) dev (\w+)/g);
            for (const match of matches) {
                this.gateways.set(match[1], {
                    interface: match[2],
                    type: 'primary',
                    confidence: 1.0
                });
            }
        } catch (e) {
            console.debug('Failed to get default gateway:', e.message);
        }

        // Method 2: Check for router-like devices
        for (const route of this.routes.values()) {
            if (route.via && !this.gateways.has(route.via)) {
                this.gateways.set(route.via, {
                    type: 'router',
                    confidence: 0.8
                });
            }
        }
    }

    async detectSubnets() {
        this.subnets = new Map();
        
        // Method 1: Interface subnets
        for (const iface of this.interfaces.values()) {
            if (!iface.cidr) continue;
            
            const subnet = {
                cidr: iface.cidr,
                interface: iface.name,
                type: 'local',
                gateway: this.findGatewayForInterface(iface.name)
            };
            
            this.subnets.set(iface.cidr, subnet);
        }

        // Method 2: Route-based subnets
        for (const [dest, route] of this.routes) {
            if (dest.includes('/')) {
                this.subnets.set(dest, {
                    cidr: dest,
                    type: 'remote',
                    gateway: route.via,
                    interface: route.dev
                });
            }
        }
    }

    findGatewayForInterface(ifaceName) {
        for (const [ip, gw] of this.gateways) {
            if (gw.interface === ifaceName) return ip;
        }
        return null;
    }

    calculateCIDR(ip, netmask) {
        const maskBits = netmask.split('.')
            .map(octet => Number(octet).toString(2).padStart(8, '0'))
            .join('')
            .split('0')[0].length;
        return `${ip}/${maskBits}`;
    }

    async buildTopology() {
        return {
            interfaces: Array.from(this.interfaces.values()),
            gateways: Array.from(this.gateways.entries()).map(([ip, info]) => ({
                ip,
                ...info
            })),
            subnets: Array.from(this.subnets.values()),
            routes: Array.from(this.routes.entries()).map(([dest, route]) => ({
                destination: dest,
                ...route
            }))
        };
    }

    async detectSegments() {
        const segments = [];
        for (const iface of this.interfaces.values()) {
            segments.push({
                cidr: iface.cidr,
                interface: iface.name,
                connected: Array.from(this.routes.entries())
                    .filter(([dest]) => this.isInSubnet(dest, iface.ip, iface.netmask))
                    .map(([dest]) => dest)
            });
        }
        return segments;
    }

    isInSubnet(ip, networkIp, netmask) {
        const ipParts = ip.split('.').map(Number);
        const networkParts = networkIp.split('.').map(Number);
        const maskParts = netmask.split('.').map(Number);
        
        return ipParts.every((octet, i) => 
            (octet & maskParts[i]) === (networkParts[i] & maskParts[i])
        );
    }
}

module.exports = NetworkDiscovery;