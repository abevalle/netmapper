const express = require('express');
const network = require('network');
const ping = require('ping');
const arp = require('node-arp');
const { execSync, spawn } = require('child_process');
const app = express();
const dns = require('dns').promises;
const net = require('net');
const fs = require('fs').promises;
const path = require('path');
const NetworkDiscovery = require('./server/services/networkDiscovery');
const config = require('./server/config/config');
const MACResolver = require('./server/services/macResolver');
const macResolver = new MACResolver(config);
const os = require('os');  // Add this import
const powerShell = require('node-powershell'); // Add this for better PowerShell support
const { Client: SSDPClient } = require('node-ssdp');  // Replace upnp dependency
const wmi = require('node-wmi');  // Update wmi import

// Add platform detection
const isWindows = process.platform === 'win32';
const isLinux = process.platform === 'linux';

// Add OS check function
function checkOSSupport() {
    if (!isWindows && !isLinux) {
        console.warn('Warning: Unsupported operating system. Some features may not work correctly.');
    }
    console.log(`Running on ${process.platform} platform`);
}

// Update CIDR parsing function
function parseCIDR(cidr) {
    if (!cidr) return null;
    
    const [ip, bits] = cidr.split('/');
    const mask = bits ? parseInt(bits) : 24;
    
    if (mask < 16 || mask > 32) {
        throw new Error('Subnet mask must be between 16 and 32 for safety');
    }

    // Split IP into octets and convert to numbers
    const ipParts = ip.split('.').map(Number);
    
    // Calculate the number of host bits
    const hostBits = 32 - mask;
    
    // Calculate total number of hosts
    const totalHosts = Math.pow(2, hostBits);
    
    // Calculate the network address (zero out host bits)
    const networkMask = ~((1 << hostBits) - 1);
    const networkStart = (ipParts[0] << 24) + (ipParts[1] << 16) + (ipParts[2] << 8) + ipParts[3];
    const networkStartMasked = networkStart & networkMask;
    
    // Calculate first and last hosts
    const firstHost = networkStartMasked + 1;
    const lastHost = networkStartMasked + totalHosts - 2; // -2 to exclude network and broadcast
    
    // Convert back to octets
    const startIP = {
        octet1: (firstHost >> 24) & 255,
        octet2: (firstHost >> 16) & 255,
        octet3: (firstHost >> 8) & 255,
        octet4: firstHost & 255
    };
    
    const endIP = {
        octet1: (lastHost >> 24) & 255,
        octet2: (lastHost >> 16) & 255,
        octet3: (lastHost >> 8) & 255,
        octet4: lastHost & 255
    };

    return {
        networkSize: totalHosts,
        startAddress: `${startIP.octet1}.${startIP.octet2}.${startIP.octet3}.${startIP.octet4}`,
        endAddress: `${endIP.octet1}.${endIP.octet2}.${endIP.octet3}.${endIP.octet4}`
    };
}

// Update executeCommand to handle promises
function executeCommand(command, args = []) {
    return new Promise((resolve, reject) => {
        try {
            const output = execSync(command, { encoding: 'utf8', windowsHide: true });
            resolve(output);
        } catch (error) {
            reject(error);
        }
    });
}

// Add new network utilities
const snmp = require('net-snmp');  // Add this dependency

// Update Windows MAC resolution function
async function getWindowsMAC(ip) {
    try {
        // First attempt: Direct ARP after ping
        const macFromArp = await tryArpResolution(ip);
        if (macFromArp && macFromArp !== 'Unknown') {
            return macFromArp;
        }

        // Second attempt: SNMP query if device supports it
        const macFromSnmp = await trySnmpResolution(ip);
        if (macFromSnmp) {
            return macFromSnmp;
        }

        // Third attempt: WMI query for Windows devices
        const macFromWmi = await tryWmiResolution(ip);
        if (macFromWmi) {
            return macFromWmi;
        }

        // Fourth attempt: UPnP discovery
        const macFromUpnp = await tryUpnpResolution(ip);
        if (macFromUpnp) {
            return macFromUpnp;
        }

        return 'Unknown';
    } catch (error) {
        console.error(`Failed to get MAC for ${ip}:`, error.message);
        return 'Unknown';
    }
}

// Update tryArpResolution function to handle Windows differently
async function tryArpResolution(ip) {
    try {
        // Get all network interfaces
        const interfaces = os.networkInterfaces();
        
        // Try ping through each interface
        for (const [name, addrs] of Object.entries(interfaces)) {
            const ipv4 = addrs.find(addr => addr.family === 'IPv4' && !addr.internal);
            if (ipv4) {
                try {
                    // Windows doesn't support -S flag, use different format
                    const pingCmd = isWindows 
                        ? `ping -n 1 -w 500 ${ip}`
                        : `ping -c 1 -W 500 -I ${ipv4.address} ${ip}`;
                    
                    await executeCommand(pingCmd);
                    await new Promise(resolve => setTimeout(resolve, 100));
                } catch (e) {
                    console.debug(`Ping failed through interface ${name}`);
                }
            }
        }

        // Check ARP table after all pings
        const output = await executeCommand('arp -a');
        const lines = output.split('\n');
        for (const line of lines) {
            // Adjust regex for Windows ARP output format
            const matches = line.match(new RegExp(`${ip}\\s+([0-9a-fA-F-]{17})`));
            if (matches && matches[1]) {
                const mac = matches[1].replace(/-/g, ':');
                console.debug(`Found MAC for ${ip} using ARP: ${mac}`);
                return mac;
            }
        }
    } catch (e) {
        console.debug(`ARP resolution failed for ${ip}: ${e.message}`);
    }
    return null;
}

async function trySnmpResolution(ip) {
    return new Promise((resolve) => {
        let isResolved = false;
        let session = null;
        
        try {
            session = snmp.createSession(ip, 'public', {
                timeout: 1000,
                retries: 0,
                transport: 'udp4'
            });
            
            const oid = '1.3.6.1.2.1.2.2.1.6.2'; // MAC address OID

            session.get([oid], (error, varbinds) => {
                if (isResolved) return;
                isResolved = true;
                
                try {
                    if (session) {
                        session.close();
                        session = null;
                    }
                } catch (closeError) {
                    console.debug(`SNMP session close error for ${ip}: ${closeError.message}`);
                }
                
                if (error) {
                    console.debug(`SNMP failed for ${ip}: ${error.message}`);
                    resolve(null);
                } else {
                    try {
                        const mac = varbinds[0]?.value?.toString('hex')
                            .match(/.{1,2}/g)?.join(':');
                        if (mac) {
                            console.debug(`Found MAC for ${ip} using SNMP: ${mac}`);
                            resolve(mac);
                        } else {
                            resolve(null);
                        }
                    } catch (parseError) {
                        console.debug(`SNMP parse error for ${ip}: ${parseError.message}`);
                        resolve(null);
                    }
                }
            });

            // Set timeout
            setTimeout(() => {
                if (!isResolved) {
                    isResolved = true;
                    try {
                        if (session) {
                            session.close();
                            session = null;
                        }
                    } catch (closeError) {
                        console.debug(`SNMP timeout session close error for ${ip}: ${closeError.message}`);
                    }
                    resolve(null);
                }
            }, 1000);

            // Handle session errors
            session.on('error', (err) => {
                if (!isResolved) {
                    isResolved = true;
                    console.debug(`SNMP session error for ${ip}: ${err.message}`);
                    try {
                        if (session) {
                            session.close();
                            session = null;
                        }
                    } catch (closeError) {
                        console.debug(`SNMP error handler close error for ${ip}: ${closeError.message}`);
                    }
                    resolve(null);
                }
            });

        } catch (initError) {
            console.debug(`SNMP initialization error for ${ip}: ${initError.message}`);
            if (session) {
                try {
                    session.close();
                } catch (closeError) {
                    console.debug(`SNMP init error close error for ${ip}: ${closeError.message}`);
                }
            }
            resolve(null);
        }
    });
}

// Replace WMI with direct PowerShell commands
async function tryWmiResolution(ip) {
    if (!isWindows) return null;

    return new Promise((resolve) => {
        try {
            // Create a valid WQL query for network adapters
            const wqlQuery = {
                class: 'Win32_NetworkAdapterConfiguration',
                properties: ['MacAddress', 'IPAddress'],
                namespace: 'root\\CIMV2',
                // Using a proper WQL WHERE clause
                where: `IPEnabled = true AND IPAddress IS NOT NULL`
            };

            wmi.Query(wqlQuery, (err, results) => {
                if (err) {
                    console.debug(`WMI query failed for ${ip}: ${err.message}`);
                    resolve(null);
                    return;
                }

                // Look through results for matching IP
                for (const adapter of results || []) {
                    if (adapter.IPAddress && Array.isArray(adapter.IPAddress)) {
                        // IPAddress is an array in WMI
                        if (adapter.IPAddress.includes(ip) && adapter.MacAddress) {
                            const mac = adapter.MacAddress.toUpperCase();
                            console.debug(`Found MAC for ${ip} using WMI: ${mac}`);
                            resolve(mac);
                            return;
                        }
                    }
                }

                console.debug(`No matching WMI results for ${ip}`);
                resolve(null);
            });
        } catch (error) {
            console.debug(`WMI initialization failed for ${ip}: ${error.message}`);
            resolve(null);
        }
    });
}

// Update tryUpnpResolution function with node-ssdp
async function tryUpnpResolution(ip) {
    return new Promise((resolve) => {
        const client = new SSDPClient({
            explicitSocketBind: true,  // Help with multiple NICs
            reuseAddr: true
        });
        let found = false;

        client.on('response', (headers, statusCode, rinfo) => {
            if (rinfo.address === ip) {
                // Try to extract MAC from device info
                const location = headers.LOCATION;
                const usn = headers.USN;
                
                // Try to find MAC in USN or device description
                const macMatch = usn && usn.match(/uuid:[^:]*?([a-fA-F0-9]{12})|MAC=([a-fA-F0-9]{12})/i);
                if (macMatch) {
                    const mac = (macMatch[1] || macMatch[2])
                        .match(/.{2}/g)
                        .join(':')
                        .toLowerCase();
                    console.debug(`Found MAC for ${ip} using SSDP USN: ${mac}`);
                    found = true;
                    client.stop();
                    resolve(mac);
                }
            }
        });

        // Search for all SSDP devices
        client.search('ssdp:all');

        // Set timeout and cleanup
        setTimeout(() => {
            if (!found) {
                try {
                    client.stop();
                } catch (e) {
                    console.debug(`SSDP client stop error: ${e.message}`);
                }
                resolve(null);
            }
        }, 5000);  // Give more time for SSDP responses

        // Handle errors
        client.on('error', (err) => {
            console.debug(`SSDP error for ${ip}: ${err.message}`);
            if (!found) {
                try {
                    client.stop();
                } catch (e) {
                    console.debug(`SSDP client stop error: ${e.message}`);
                }
                resolve(null);
            }
        });
    });
}

// Add command availability check
function isCommandAvailable(command) {
    try {
        execSync(`which ${command}`, { encoding: 'utf8' });
        return true;
    } catch (error) {
        return false;
    }
}

// Update Linux MAC resolution function
async function getLinuxMAC(ip, interfaceName) {
    let mac = 'Unknown';
    
    // Try arp-scan first (most reliable)
    if (isCommandAvailable('arp-scan')) {
        try {
            const output = await executeCommand([
                'sudo', 'arp-scan',
                `--interface=${interfaceName}`,
                '--quiet',
                '--ignoredups',
                '--retry=1',
                '--timeout=500',
                ip
            ].join(' '));
            
            // Look for MAC address in output
            const match = output.match(/([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}/);
            if (match) {
                mac = match[0];
                console.debug(`Found MAC for ${ip} using arp-scan: ${mac}`);
                return mac;
            }
        } catch (e) {
            console.debug(`arp-scan failed for ${ip}: ${e.message}`);
        }
    }

    // Try ip neighbor show as second option
    try {
        const output = await executeCommand(`ip neighbor show ${ip}`);
        const match = output.match(/([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}/);
        if (match) {
            mac = match[0];
            console.debug(`Found MAC for ${ip} using ip neighbor: ${mac}`);
            return mac;
        }
    } catch (e) {
        console.debug(`ip neighbor failed for ${ip}`);
    }

    // Try node-arp as last resort
    try {
        const arpMac = await new Promise((resolve) => {
            arp.getMAC(ip, (err, mac) => {
                if (err) {
                    console.debug(`node-arp error for ${ip}: ${err.message}`);
                    resolve(null);
                } else {
                    resolve(mac);
                }
            });
        });
        if (arpMac) {
            console.debug(`Found MAC for ${ip} using node-arp: ${arpMac}`);
            return arpMac;
        }
    } catch (e) {
        console.debug(`node-arp failed for ${ip}`);
    }

    console.debug(`Could not resolve MAC for ${ip}`);
    return 'Unknown';
}

// Update getMACAddress function
async function getMACAddress(ip) {
    if (!isWindows && !isLinux) {
        console.warn(`MAC address resolution not implemented for ${process.platform}`);
        return {
            address: 'Unknown',
            vendor: 'Unknown',
            countryCode: 'N/A'
        };
    }

    let mac = 'Unknown';
    try {
        if (isLinux) {
            const interfaceName = activeInterface ? activeInterface.name : 'eth0';
            mac = await getLinuxMAC(ip, interfaceName);
        } else {
            mac = await getWindowsMAC(ip);
        }
        
        return await macResolver.getVendorInfo(mac, ip);
    } catch (error) {
        console.error(`MAC resolution failed for ${ip}:`, error);
        return {
            address: 'Unknown',
            vendor: 'Unknown',
            countryCode: 'N/A'
        };
    }
}

// Serve static files
app.use(express.static('public'));

const deviceConnections = new Map();

// Modify traffic monitoring function
function startTrafficMonitoring() {
    if (isWindows) {
        console.log('Traffic monitoring is not supported on Windows');
        return null;
    }

    if (!isLinux) {
        console.log('Traffic monitoring is only supported on Linux');
        return null;
    }

    try {
        // Check if tcpdump is available
        execSync('which tcpdump');
        
        const tcpdump = spawn('tcpdump', ['-n', '-q', '-l'], {
            shell: true,
            stdio: ['ignore', 'pipe', 'pipe']
        });
        
        tcpdump.stdout.on('data', (data) => {
            const lines = data.toString().split('\n');
            lines.forEach(line => {
                const match = line.match(/(\d+\.\d+\.\d+\.\d+).*? > (\d+\.\d+\.\d+\.\d+)/);
                if (match) {
                    const [_, source, dest] = match;
                    const key = `${source}-${dest}`;
                    const count = deviceConnections.get(key) || 0;
                    deviceConnections.set(key, count + 1);
                }
            });
        });

        tcpdump.stderr.on('data', (data) => {
            console.error('tcpdump error:', data.toString());
        });

        return tcpdump;
    } catch (error) {
        console.log('Traffic monitoring disabled: tcpdump not available');
        return null;
    }
}

// Ensure activeInterface is accessible
let activeInterface = null;

// Add new functions before the API endpoints
async function getHostname(ip) {
    try {
        const hostnames = await dns.reverse(ip);
        return hostnames[0] || null;
    } catch {
        return null;
    }
}

async function scanPorts(ip) {
    const commonPorts = [21, 22, 23, 25, 53, 80, 443, 445, 3306, 3389, 5432, 8080];
    const openPorts = [];
    
    await Promise.all(commonPorts.map(port => {
        return new Promise(resolve => {
            const socket = new net.Socket();
            socket.setTimeout(500);  // 500ms timeout
            
            socket.on('connect', () => {
                openPorts.push(port);
                socket.destroy();
                resolve();
            });
            
            socket.on('error', () => {
                socket.destroy();
                resolve();
            });
            
            socket.on('timeout', () => {
                socket.destroy();
                resolve();
            });
            
            socket.connect(port, ip);
        });
    }));
    
    return openPorts;
}

// Add MAC database loading and lookup functionality
let macDatabase = null;

async function loadMACDatabase() {
    try {
        const data = await fs.readFile(path.join(__dirname, 'macdb.json'), 'utf8');
        macDatabase = JSON.parse(data);
        console.log(`Loaded ${macDatabase.length} MAC address entries`);
    } catch (error) {
        console.error('Failed to load MAC database:', error.message);
        macDatabase = [];
    }
}

function lookupOUI(mac) {
    if (!mac || mac === 'Unknown' || !macDatabase) return null;
    
    // Normalize MAC address format (remove colons/hyphens, uppercase)
    const normalizedMAC = mac.replace(/[:\-]/g, '').toUpperCase();
    
    // Get first 7 characters for OUI lookup
    const oui = normalizedMAC.substring(0, 7);
    
    return macDatabase.find(entry => entry.oui.replace(/[:\-]/g, '').toUpperCase() === oui) || null;
}

// Add discovery endpoint before other routes
app.get('/api/network/topology', async (req, res) => {
    try {
        const discovery = new NetworkDiscovery(config);
        const topology = await discovery.discover();
        res.json(topology);
    } catch (error) {
        console.error('Topology error:', error);
        res.status(500).json({ error: error.message });
    }
});

// Update the /api/scan endpoint to use the new CIDR parsing
function chunkArray(array, chunkSize) {
    const chunks = [];
    for (let i = 0; i < array.length; i += chunkSize) {
        chunks.push(array.slice(i, i + chunkSize));
    }
    return chunks;
}

async function scanChunk(ipList, options = {}) {
    const startTime = Date.now();
    const { chunkNum, totalChunks } = options;
    const scanProgress = {
        currentChunk: chunkNum,
        totalChunks: totalChunks,
        chunkStart: ipList[0],
        chunkEnd: ipList[ipList.length - 1],
        totalHosts: ipList.length
    };

    const networkDevices = [];
    const scanPromises = [];

    for (const ip of ipList) {
        // Skip if scanning local network and IP matches local device or gateway
        if (options.activeInterface && 
            (ip === options.activeInterface.ip_address || ip === options.activeInterface.gateway_ip)) {
            continue;
        }

        scanPromises.push(
            ping.promise.probe(ip, {
                timeout: 1,
                min_reply: 1
            }).then(async (res) => {
                if (res.alive) {
                    const macInfo = await getMACAddress(ip);
                    const hostname = await getHostname(ip);
                    const openPorts = await scanPorts(ip);
                    networkDevices.push({
                        ip: ip,         // Ensure IP is set
                        id: ip,         // Set ID to match IP for D3
                        mac: macInfo.address,
                        manufacturer: {
                            companyName: macInfo.vendor || 'Unknown',
                            countryCode: macInfo.countryCode || 'N/A'
                        },
                        name: hostname || ip,  // Use IP instead of "Device N"
                        hostname,
                        ports: openPorts,
                        isAlive: true
                    });
                }
            }).catch(err => {
                console.warn(`Error scanning ${ip}:`, err.message);
            })
        );
    }

    await Promise.all(scanPromises);

    const endTime = Date.now();
    const duration = ((endTime - startTime) / 1000).toFixed(1);
    console.log(`Chunk ${chunkNum}/${totalChunks} completed in ${duration}s: ${ipList[0]} to ${ipList[ipList.length - 1]}`);

    return {
        devices: networkDevices,
        progress: scanProgress,
        duration: duration
    };
}

// Update /api/scan endpoint
async function analyzeConnections(devices, topology) {
    const connections = new Map();
    
    // Group devices by subnet
    const subnetGroups = new Map();
    for (const device of devices) {
        const subnet = topology.subnets.find(s => isInSubnet(device.ip, s.cidr));
        if (subnet) {
            if (!subnetGroups.has(subnet.cidr)) {
                subnetGroups.set(subnet.cidr, []);
            }
            subnetGroups.get(subnet.cidr).push(device);
        }
    }

    // Create connections based on network topology
    for (const [cidr, subnetDevices] of subnetGroups) {
        const subnet = topology.subnets.find(s => s.cidr === cidr);
        const gateway = topology.gateways.find(g => g.ip === subnet.gateway);
        
        if (gateway) {
            // Connect devices to their subnet gateway
            subnetDevices.forEach(device => {
                if (device.ip !== gateway.ip) {
                    connections.set(`${device.ip}-${gateway.ip}`, {
                        type: 'subnet',
                        strength: 1
                    });
                }
            });
        }
    }

    // Connect gateways to each other based on routes
    topology.routes.forEach(route => {
        if (route.via) {
            connections.set(`${route.destination}-${route.via}`, {
                type: 'route',
                strength: 0.5
            });
        }
    });

    return Array.from(connections.entries()).map(([key, value]) => {
        const [source, target] = key.split('-');
        return { source, target, ...value };
    });
}

// Modify /api/scan endpoint
app.get('/api/scan', async (req, res) => {
    try {
        const customRange = req.query.range;
        let scanRange;

        if (customRange) {
            const parsedRange = parseCIDR(customRange);
            if (!parsedRange) {
                throw new Error('Invalid IP range');
            }

            if (parsedRange.networkSize > config.scanner.maxTotalSize) {
                throw new Error(`Network size too large. Maximum allowed is ${config.scanner.maxTotalSize} hosts.`);
            }

            // Generate list of IPs to scan
            scanRange = {
                startIP: parsedRange.startAddress,
                endIP: parsedRange.endAddress,
                ipList: []
            };

            // Generate complete IP list
            const [startIP1, startIP2, startIP3, startIP4] = parsedRange.startAddress.split('.').map(Number);
            const [endIP1, endIP2, endIP3, endIP4] = parsedRange.endAddress.split('.').map(Number);
            
            for (let i1 = startIP1; i1 <= endIP1; i1++) {
                for (let i2 = (i1 === startIP1 ? startIP2 : 0); i2 <= (i1 === endIP1 ? endIP2 : 255); i2++) {
                    for (let i3 = (i1 === startIP1 && i2 === startIP2 ? startIP3 : 0); 
                         i3 <= (i1 === endIP1 && i2 === endIP2 ? endIP3 : 255); i3++) {
                        for (let i4 = (i1 === startIP1 && i2 === startIP2 && i3 === startIP3 ? startIP4 : 1);
                             i4 <= (i1 === endIP1 && i2 === endIP2 && i3 === endIP3 ? endIP4 : 254); i4++) {
                            scanRange.ipList.push(`${i1}.${i2}.${i3}.${i4}`);
                        }
                    }
                }
            }
            
            // Split IPs into chunks
            const chunks = chunkArray(scanRange.ipList, config.scanner.maxChunkSize);
            const allDevices = [];
            let lastProgress = null;
            
            // Process each chunk
            for (let i = 0; i < chunks.length; i++) {
                const chunkResult = await scanChunk(chunks[i], { 
                    activeInterface,
                    chunkNum: i + 1,
                    totalChunks: chunks.length
                });
                
                allDevices.push(...chunkResult.devices);
                lastProgress = chunkResult.progress;
                
                // Add delay between chunks except for the last one
                if (i < chunks.length - 1) {
                    await new Promise(resolve => setTimeout(resolve, config.scanner.chunkDelay));
                }
            }

            // Create graph data structure
            const nodes = allDevices.map(device => ({
                id: device.ip,
                mac: device.mac || 'Unknown',
                name: device.name || 'Unknown Device',
                isGateway: device.isGateway || false,
                isLocal: device.isLocal || false,
                manufacturer: device.manufacturer,
                ports: device.ports || [],
                hostname: device.hostname
            }));

            // Create links - use first device as central node for custom ranges
            const centralNode = activeInterface ? activeInterface.gateway_ip : nodes[0].id;
            const links = nodes
                .filter(node => node.id !== centralNode)
                .map(node => ({
                    source: node.id,
                    target: centralNode,
                    value: 1
                }));

            // Add network topology data
            const discovery = new NetworkDiscovery(config);
            const topology = await discovery.discover();
            const connections = await analyzeConnections(allDevices, topology);

            // Update node data with subnet information
            const updatedNodes = allDevices.map(device => {
                const subnet = topology.subnets.find(s => isInSubnet(device.ip, s.cidr));
                return {
                    ...device,
                    subnet: subnet ? subnet.cidr : null,
                    isGateway: topology.gateways.some(g => g.ip === device.ip)
                };
            });

            res.json({ 
                nodes: updatedNodes,
                links: connections,
                topology,
                scanRange,
                scanProgress: lastProgress
            });
        } else {
            // Get local network interface info and set up local scan
            const interfaces = await new Promise((resolve, reject) => {
                network.get_interfaces_list((err, interfaces) => {
                    if (err) reject(err);
                    else resolve(interfaces);
                });
            });

            activeInterface = interfaces.find(i => i.ip_address && (i.type === 'Wired' || i.type === 'Wireless'));
            if (!activeInterface) {
                throw new Error('No active network interface found');
            }

            // Log interface info for debugging
            console.log('Active interface:', {
                type: activeInterface.type,
                ip: activeInterface.ip_address,
                gateway: activeInterface.gateway_ip,
                mac: activeInterface.mac_address
            });

            if (!activeInterface.gateway_ip) {
                throw new Error('No gateway IP found');
            }

            const baseIP = activeInterface.ip_address.split('.');
            scanRange = {
                baseIP: baseIP.slice(0, 3).join('.'),
                startHost: 1,
                endHost: 254
            };

            const networkDevices = [];
            const scanPromises = [];

            // Scan the specified range
            for (let i = scanRange.startHost; i <= scanRange.endHost; i++) {
                const ip = `${scanRange.baseIP}.${i}`;
                
                // Skip if scanning local network and IP matches local device or gateway
                if (activeInterface && (ip === activeInterface.ip_address || ip === activeInterface.gateway_ip)) {
                    continue;
                }

                scanPromises.push(
                    ping.promise.probe(ip, {
                        timeout: 1,
                        min_reply: 1
                    }).then(async (res) => {
                        if (res.alive) {
                            const macInfo = await getMACAddress(ip);
                            const hostname = await getHostname(ip);
                            const openPorts = await scanPorts(ip);
                            networkDevices.push({
                                ip: ip,         // Ensure IP is set
                                id: ip,         // Set ID to match IP for D3
                                mac: macInfo.address,
                                manufacturer: {
                                    companyName: macInfo.vendor || 'Unknown',
                                    countryCode: macInfo.countryCode || 'N/A'
                                },
                                name: hostname || ip,  // Use IP instead of "Device N"
                                hostname,
                                ports: openPorts,
                                isAlive: true
                            });
                        }
                    })
                );
            }

            await Promise.all(scanPromises);

            // Ensure we have at least one device before creating the graph
            if (networkDevices.length === 0) {
                res.json({
                    nodes: [],
                    links: [],
                    scanRange: {
                        start: scanRange.startIP || `${scanRange.baseIP}.${scanRange.startHost}`,
                        end: scanRange.endIP || `${scanRange.baseIP}.${scanRange.endHost}`,
                        total: scanRange.ipList ? scanRange.ipList.length : (scanRange.endHost - scanRange.startHost + 1)
                    }
                });
                return;
            }

            // Create graph data structure
            const nodes = networkDevices.map(device => ({
                id: device.ip,
                mac: device.mac || 'Unknown',
                name: device.name || 'Unknown Device',
                isGateway: device.isGateway || false,
                isLocal: device.isLocal || false,
                manufacturer: device.manufacturer,
                ports: device.ports || [],
                hostname: device.hostname
            }));

            // Create links - use first device as central node for custom ranges
            const centralNode = activeInterface ? activeInterface.gateway_ip : nodes[0].id;
            const links = nodes
                .filter(node => node.id !== centralNode)
                .map(node => ({
                    source: node.id,
                    target: centralNode,
                    value: 1
                }));

            // Add network topology data
            const discovery = new NetworkDiscovery(config);
            const topology = await discovery.discover();
            const connections = await analyzeConnections(networkDevices, topology);

            // Update node data with subnet information
            const updatedNodes = networkDevices.map(device => {
                const subnet = topology.subnets.find(s => isInSubnet(device.ip, s.cidr));
                return {
                    ...device,
                    subnet: subnet ? subnet.cidr : null,
                    isGateway: topology.gateways.some(g => g.ip === device.ip)
                };
            });

            res.json({ 
                nodes: updatedNodes,
                links: connections,
                topology,
                scanRange
            });
        }
    } catch (error) {
        console.error('Scan error:', error);
        res.status(500).json({ 
            error: error.message, 
            stack: error.stack,
            nodes: [],
            links: []
        });
    }
});

app.get('/api/connections', (req, res) => {
    if (process.platform === 'win32' || !deviceConnections.size) {
        res.json([]);
        return;
    }
    
    const connections = [];
    deviceConnections.forEach((count, key) => {
        const [source, target] = key.split('-');
        connections.push({ source, target, count });
    });
    res.json(connections);
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, async () => {
    console.log(`Server running on port ${PORT}`);
    await macResolver.initialize();
    checkOSSupport();
    checkRequiredTools();
    const monitor = startTrafficMonitoring();
    if (!monitor) {
        console.log(`Note: Network traffic monitoring is disabled on ${process.platform}`);
    }
});

// Add check and install suggestion at server startup
function checkRequiredTools() {
    if (isLinux) {
        const tools = ['arp-scan', 'ip'];
        const missing = tools.filter(tool => !isCommandAvailable(tool));
        if (missing.length > 0) {
            console.warn(`Missing recommended tools: ${missing.join(', ')}`);
            console.warn('To install on Ubuntu/Debian: sudo apt-get install -y ' + missing.join(' '));
            console.warn('To install on RHEL/CentOS: sudo yum install -y ' + missing.join(' '));
        }
    }
}

// Add subnet membership check function
function isInSubnet(ip, cidr) {
    if (!ip || !cidr) return false;
    
    const [networkAddress, bits] = cidr.split('/');
    const mask = Number(bits);
    
    const ipBinary = ip.split('.')
        .map(octet => Number(octet).toString(2).padStart(8, '0'))
        .join('');
    
    const networkBinary = networkAddress.split('.')
        .map(octet => Number(octet).toString(2).padStart(8, '0'))
        .join('');
        return ipBinary.substring(0, mask) === networkBinary.substring(0, mask);}

// Add new helper function for better PowerShell execution
async function executePowerShell(command) {
    const { PowerShell } = require('node-powershell');
    
    let ps = null;
    try {
        ps = new PowerShell();  // Initialize without options first
        
        // Configure PowerShell instance
        await ps.configuration({
            executionPolicy: 'Bypass',
            noProfile: true,
            inputEncoding: 'utf8',
            outputEncoding: 'utf8'
        });

        // Add and execute command
        await ps.addCommand(command);
        const result = await ps.invoke();
        return result;
    } catch (error) {
        console.debug(`PowerShell execution failed: ${error.message}`);
        return null;
    } finally {
        if (ps) {
            try {
                await ps.dispose();
            } catch (e) {
                console.debug(`PowerShell dispose error: ${e.message}`);
            }
        }
    }
}