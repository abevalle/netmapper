const os = require('os');
const { promisify } = require('util');
const { exec } = require('child_process');
const execAsync = promisify(exec);
const MDNSDiscovery = require('./mdnsDiscovery');

class NetworkDiscovery {
    constructor(config) {
        this.config = config;
        this.interfaces = new Map();
        this.routes = new Map();
        this.mdnsDiscovery = new MDNSDiscovery();
    }

    async discover() {
        await this.getInterfaces();
        await this.getRoutes();
        await this.identifyGateways();
        await this.detectSubnets();

        // Add mDNS discovery
        if (this.config.discovery.mdns.enabled) {
            await this.discoverMDNS();
        }

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
            if (process.platform === 'win32') {
                const { stdout } = await execAsync('route print -4');
                const routes = stdout.split('\n')
                    .filter(line => line.match(/^\s+\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/))
                    .map(line => {
                        const parts = line.trim().split(/\s+/);
                        return {
                            destination: parts[0],
                            via: parts[2] !== '0.0.0.0' ? parts[2] : null
                        };
                    });
                
                routes.forEach(route => {
                    this.routes.set(route.destination, { via: route.via });
                });
            } else {
                // Existing Linux code
                const { stdout } = await execAsync('ip route');
                stdout.split('\n').forEach(line => {
                    const match = line.match(/^(\S+)\s+via\s+(\S+)/);
                    if (match) {
                        this.routes.set(match[1], { via: match[2] });
                    }
                });
            }
        } catch (error) {
            console.warn('Could not get routing info:', error.message);
        }
    }

    async identifyGateways() {
        this.gateways = new Map();
        
        try {
            if (process.platform === 'win32') {
                // Method 1: Default route from routing table
                const { stdout } = await execAsync('route print 0.0.0.0');
                const match = stdout.match(/0\.0\.0\.0\s+0\.0\.0\.0\s+(\d+\.\d+\.\d+\.\d+)/);
                if (match) {
                    this.gateways.set(match[1], {
                        type: 'primary',
                        confidence: 1.0
                    });
                }

                // Method 2: ipconfig
                const { stdout: ipconfigOutput } = await execAsync('ipconfig');
                const gatewayMatches = ipconfigOutput.matchAll(/Default Gateway[.\s]+: ([0-9.]+)/g);
                for (const match of gatewayMatches) {
                    this.gateways.set(match[1], {
                        type: 'primary',
                        confidence: 0.9
                    });
                }
            } else {
                // Existing Linux code for gateway detection
                const { stdout } = await execAsync('ip route show default');
                const matches = stdout.matchAll(/default via ([0-9.]+) dev (\w+)/g);
                for (const match of matches) {
                    this.gateways.set(match[1], {
                        interface: match[2],
                        type: 'primary',
                        confidence: 1.0
                    });
                }
            }
        } catch (e) {
            console.debug('Failed to get default gateway:', e.message);
        }

        // Method 2: Check for router-like devices (works for both platforms)
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

    isInSubnet(ip, networkIpOrCidr, netmask = null) {
        if (!ip || !networkIpOrCidr) return false;

        let networkIp, maskBits;

        // Handle CIDR notation (e.g. "192.168.1.0/24")
        if (networkIpOrCidr.includes('/')) {
            [networkIp, maskBits] = networkIpOrCidr.split('/');
            maskBits = parseInt(maskBits);
            
            // Convert mask bits to IP format
            const mask = new Array(4).fill(0);
            for (let i = 0; i < Math.floor(maskBits / 8); i++) {
                mask[i] = 255;
            }
            if (maskBits % 8) {
                mask[Math.floor(maskBits / 8)] = 256 - Math.pow(2, 8 - (maskBits % 8));
            }
            netmask = mask.join('.');
        } else {
            networkIp = networkIpOrCidr;
            // If no netmask provided and not CIDR, assume /24
            if (!netmask) {
                netmask = '255.255.255.0';
            }
        }

        try {
            const ipParts = ip.split('.').map(Number);
            const networkParts = networkIp.split('.').map(Number);
            const maskParts = netmask.split('.').map(Number);

            return ipParts.every((octet, i) => 
                (octet & maskParts[i]) === (networkParts[i] & maskParts[i])
            );
        } catch (error) {
            console.debug(`Subnet check failed for ${ip} in ${networkIpOrCidr}: ${error.message}`);
            return false;
        }
    }

    isLocalSubnet(ip) {
        if (!ip) return false;
        
        for (const [_, iface] of this.interfaces) {
            if (iface.cidr && this.isInSubnet(ip, iface.cidr)) {
                return true;
            }
        }
        return false;
    }

    async discoverMDNS() {
        return new Promise((resolve) => {
            const timeout = this.config.discovery.mdns.timeout || 5000;
            const mdnsDevices = new Map();

            this.mdnsDiscovery.start((device) => {
                mdnsDevices.set(device.id, device);
                
                // Add to interfaces if it's a local device
                if (this.isLocalSubnet(device.ip)) {
                    this.interfaces.set(device.name, {
                        name: device.name,
                        ip: device.ip,
                        type: 'mdns',
                        services: device.services
                    });
                }
            });

            // Stop discovery after timeout
            setTimeout(() => {
                this.mdnsDiscovery.stop();
                resolve(mdnsDevices);
            }, timeout);
        });
    }

    isLocalSubnet(ip) {
        for (const [_, iface] of this.interfaces) {
            if (iface.cidr && this.isInSubnet(ip, iface.cidr)) {
                return true;
            }
        }
        return false;
    }
}

module.exports = NetworkDiscovery;