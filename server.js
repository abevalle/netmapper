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

// Update Windows MAC resolution function
async function getWindowsMAC(ip) {
    try {
        // Try using ARP first
        const arpOutput = executeCommand('arp -a ' + ip);
        if (arpOutput) {
            const lines = arpOutput.split('\n');
            for (const line of lines) {
                if (line.includes(ip)) {
                    const match = line.match(/([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})/);
                    if (match) return match[0];
                }
            }
        }

        // Try using ipconfig as fallback
        const ipconfigOutput = executeCommand('ipconfig /all');
        if (ipconfigOutput) {
            const lines = ipconfigOutput.split('\n');
            for (let i = 0; i < lines.length; i++) {
                if (lines[i].includes(ip)) {
                    // Look for Physical Address in nearby lines
                    for (let j = i - 5; j < i + 5; j++) {
                        if (lines[j] && lines[j].includes('Physical Address')) {
                            const match = lines[j].match(/([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})/);
                            if (match) return match[0];
                        }
                    }
                }
            }
        }

        return 'Unknown';
    } catch (error) {
        console.error(`Failed to get MAC for ${ip} using Windows commands:`, error.message);
        return 'Unknown';
    }
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
    // Try arp-scan first (most reliable according to man page)
    if (isCommandAvailable('arp-scan')) {
        try {
            // Using documented options from man page:
            // --interface: specify network interface
            // --quiet: minimal output
            // --ignoredups: ignore duplicate packets
            // --retry=1: single retry (faster)
            // --timeout=500: 500ms timeout (good balance)
            // Target specific IP instead of --localnet for accuracy
            const output = await executeCommand([
                'sudo', 'arp-scan',
                `--interface=${interfaceName}`,
                '--quiet',
                '--ignoredups',
                '--retry=1',
                '--timeout=500',
                ip
            ].join(' '));
            
            if (output) {
                const match = output.match(/([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}/);
                if (match) return match[0];
            }
        } catch (e) {
            console.debug(`arp-scan failed for ${ip}: ${e.message}`);
        }
    }

    // Try node-arp as fallback
    try {
        const mac = await new Promise((resolve) => {
            arp.getMAC(ip, (err, mac) => {
                if (mac) {
                    resolve(mac);
                } else {
                    resolve(null);
                }
            });
        });
        if (mac) return mac;
    } catch (e) {
        console.debug(`node-arp failed for ${ip}`);
    }

    // Try ip neighbor as last resort
    try {
        const output = await executeCommand(`ip neighbor show ${ip}`);
        if (output) {
            const match = output.match(/([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}/);
            if (match) return match[0];
        }
    } catch (e) {
        console.debug(`ip neighbor failed for ${ip}`);
    }

    return 'Unknown';
}

// Modify getMACAddress function
async function getMACAddress(ip) {
    if (!isWindows && !isLinux) {
        console.warn(`MAC address resolution not implemented for ${process.platform}`);
        return 'Unknown';
    }

    if (isLinux) {
        const interfaceName = activeInterface ? activeInterface.name : 'eth0';
        const mac = await getLinuxMAC(ip, interfaceName);
        const ouiInfo = lookupOUI(mac);
        return {
            address: mac,
            vendor: ouiInfo ? ouiInfo.companyName : 'Unknown',
            countryCode: ouiInfo ? ouiInfo.countryCode : null
        };
    } else {
        const mac = await getWindowsMAC(ip);
        const ouiInfo = lookupOUI(mac);
        return {
            address: mac,
            vendor: ouiInfo ? ouiInfo.companyName : 'Unknown',
            countryCode: ouiInfo ? ouiInfo.countryCode : null
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

// Update the /api/scan endpoint to use the new CIDR parsing
app.get('/api/scan', async (req, res) => {
    try {
        const customRange = req.query.range;
        let scanRange;

        if (customRange) {
            const parsedRange = parseCIDR(customRange);
            if (!parsedRange) {
                throw new Error('Invalid IP range');
            }
            
            // Get start and end components
            const [startIP1, startIP2, startIP3, startIP4] = parsedRange.startAddress.split('.').map(Number);
            const [endIP1, endIP2, endIP3, endIP4] = parsedRange.endAddress.split('.').map(Number);
            
            console.log(`Scanning range from ${parsedRange.startAddress} to ${parsedRange.endAddress}`);
            
            if (parsedRange.networkSize > 1000) {
                throw new Error('Network size too large. Please use a smaller range for scanning.');
            }

            scanRange = {
                startIP: parsedRange.startAddress,
                endIP: parsedRange.endAddress,
                ipList: [] // Will be populated with all IPs to scan
            };

            // Generate list of IPs to scan
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
        }

        const networkDevices = [];
        const scanPromises = [];

        // Create a central node for custom range scans if no gateway is available
        if (customRange && !activeInterface) {
            networkDevices.push({
                ip: scanRange.ipList[0],
                mac: 'Unknown',
                manufacturer: {
                    companyName: 'Unknown',
                    companyAddress: 'N/A',
                    countryCode: 'N/A',
                    oui: 'Unknown'
                },
                isLocal: true,
                name: 'Network Center'
            });
        }

        // Update scanning logic to use ipList when available
        if (scanRange.ipList) {
            // Use the generated IP list for custom ranges
            for (const ip of scanRange.ipList) {
                scanPromises.push(
                    ping.promise.probe(ip, {
                        timeout: 1,
                        min_reply: 1
                    }).then(async (res) => {
                        if (res.alive) {
                            const macInfo = await getMACAddress(ip);
                            const hostname = await getHostname(ip);
                            const openPorts = await scanPorts(ip);
                            const manufacturer = lookupOUI(macInfo.address) || {
                                companyName: 'Unknown',
                                companyAddress: 'N/A',
                                countryCode: 'N/A',
                                oui: 'Unknown'
                            };

                            networkDevices.push({
                                ip,
                                mac: macInfo.address,
                                manufacturer,
                                name: hostname || `Device ${networkDevices.length + 1}`,
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
        } else {
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
                                ip,
                                mac: macInfo.address,
                                manufacturer: lookupOUI(macInfo.address) || {
                                    companyName: 'Unknown',
                                    companyAddress: 'N/A',
                                    countryCode: 'N/A',
                                    oui: 'Unknown'
                                },
                                name: hostname || `Device ${networkDevices.length + 1}`,
                                hostname,
                                ports: openPorts,
                                isAlive: true
                            });
                        }
                    })
                );
            }
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

        res.json({ 
            nodes, 
            links,
            scanRange: {
                start: scanRange.startIP || `${scanRange.baseIP}.${scanRange.startHost}`,
                end: scanRange.endIP || `${scanRange.baseIP}.${scanRange.endHost}`,
                total: scanRange.ipList ? scanRange.ipList.length : (scanRange.endHost - scanRange.startHost + 1)
            }
        });

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
    await loadMACDatabase();
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