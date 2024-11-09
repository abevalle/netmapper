const { execSync } = require('child_process');
const os = require('os');

const isWindows = process.platform === 'win32';
const isLinux = process.platform === 'linux';
const isWSL = isLinux && os.release().toLowerCase().includes('microsoft');

function checkOSSupport() {
    if (!isWindows && !isLinux) {
        console.warn('Warning: Unsupported operating system. Some features may not work correctly.');
    }
    console.log(`Running on ${process.platform} platform`);
}

function isCommandAvailable(command) {
    try {
        if (isWindows || isWSL) {
            // For Windows/WSL, check using where or PowerShell
            try {
                execSync(`where ${command}`, { encoding: 'utf8' });
                return true;
            } catch {
                try {
                    execSync(`powershell -Command "Get-Command ${command} -ErrorAction Stop"`, { encoding: 'utf8' });
                    return true;
                } catch {
                    return false;
                }
            }
        } else {
            execSync(`which ${command}`, { encoding: 'utf8' });
            return true;
        }
    } catch (error) {
        return false;
    }
}

function checkRequiredTools() {
    if (isLinux) {
        const tools = ['arp-scan', 'ip'];
        const missing = tools.filter(tool => !isCommandAvailable(tool));
        if (missing.length > 0) {
            console.warn(`Missing recommended tools: ${missing.join(', ')}`);
            console.warn('To install on Ubuntu/Debian: sudo apt-get install -y ' + missing.join(' '));
            console.warn('To install on RHEL/CentOS: sudo yum install -y ' + missing.join(' '));
        }
    } else if (isWindows) {
        const tools = ['netstat', 'arp', 'ping'];
        const missing = tools.filter(tool => !isCommandAvailable(tool));
        if (missing.length > 0) {
            console.warn(`Missing recommended Windows tools: ${missing.join(', ')}`);
        }

        // Check PowerShell availability
        try {
            execSync('powershell -Command "Get-Host"', { encoding: 'utf8' });
        } catch (error) {
            console.warn('PowerShell is not available. Some features may be limited.');
        }
    }
}

async function getGatewayInfo() {
    try {
        let gateway = null;
        
        if (isWindows || isWSL) {
            // For Windows and WSL, try multiple methods
            const methods = [
                // Method 1: PowerShell
                async () => {
                    const output = execSync(
                        'powershell -Command "Get-NetRoute -DestinationPrefix 0.0.0.0/0 | Select-Object -ExpandProperty NextHop"',
                        { encoding: 'utf8' }
                    );
                    return output.trim();
                },
                // Method 2: route print
                async () => {
                    const output = execSync('route print -4 0.0.0.0', { encoding: 'utf8' });
                    const match = output.match(/0\.0\.0\.0\s+0\.0\.0\.0\s+(\d+\.\d+\.\d+\.\d+)/);
                    return match ? match[1] : null;
                },
                // Method 3: ipconfig
                async () => {
                    const output = execSync('ipconfig', { encoding: 'utf8' });
                    const match = output.match(/Default Gateway[.\s]+: ([0-9.]+)/);
                    return match ? match[1] : null;
                }
            ];

            // Try each method until one works
            for (const method of methods) {
                try {
                    gateway = await method();
                    if (gateway) break;
                } catch (e) {
                    console.debug('Gateway detection method failed:', e.message);
                }
            }
        } else if (isLinux) {
            // Try multiple methods to find gateway
            try {
                // Method 1: ip route
                const output = execSync("ip route | grep default", { encoding: 'utf8' });
                const match = output.match(/default via ([0-9.]+)/);
                if (match) gateway = match[1];
            } catch (e) {
                try {
                    // Method 2: route -n
                    const output = execSync("route -n | grep '^0.0.0.0'", { encoding: 'utf8' });
                    const match = output.match(/\s+([0-9.]+)\s+/);
                    if (match) gateway = match[1];
                } catch (e2) {
                    // Method 3: netstat
                    try {
                        const output = execSync("netstat -rn | grep '^0.0.0.0'", { encoding: 'utf8' });
                        const match = output.match(/\s+([0-9.]+)\s+/);
                        if (match) gateway = match[1];
                    } catch (e3) {
                        console.warn('All gateway detection methods failed');
                    }
                }
            }
        }
        
        return gateway ? { ip: gateway } : null;
    } catch (error) {
        console.warn('Failed to get gateway info:', error.message);
        return null;
    }
}

async function getWindowsMAC(ip) {
    try {
        // Try PowerShell ARP command first
        try {
            // Use PowerShell to get ARP table
            const cmd = `powershell -Command "Get-NetNeighbor -IPAddress ${ip} | Select-Object -ExpandProperty LinkLayerAddress"`;
            const mac = execSync(cmd, { encoding: 'utf8' }).trim();
            
            if (mac && mac.length > 0 && /^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$/.test(mac)) {
                console.debug(`Found MAC for ${ip} using PowerShell Get-NetNeighbor: ${mac}`);
                return mac;
            }
        } catch (e) {
            console.debug(`PowerShell Get-NetNeighbor failed for ${ip}, trying ARP command`);
        }

        // Try standard ARP command as fallback
        try {
            const cmd = `arp -a ${ip}`;
            const output = execSync(cmd, { encoding: 'utf8' });
            const lines = output.split('\n');
            
            for (const line of lines) {
                // Match IP and MAC address pattern in ARP output
                const match = line.match(new RegExp(`${ip}\\s+([-0-9a-fA-F]{17})`));
                if (match && match[1]) {
                    const mac = match[1].replace(/-/g, ':');
                    console.debug(`Found MAC for ${ip} using ARP command: ${mac}`);
                    return mac;
                }
            }
        } catch (e) {
            console.debug(`ARP command failed for ${ip}: ${e.message}`);
        }

        // Try netsh as last resort
        try {
            const cmd = `netsh interface ipv4 show neighbors "${ip}"`;
            const output = execSync(cmd, { encoding: 'utf8' });
            const match = output.match(/([0-9a-fA-F]{2}-){5}[0-9a-fA-F]{2}/i);
            if (match) {
                const mac = match[0].replace(/-/g, ':');
                console.debug(`Found MAC for ${ip} using netsh: ${mac}`);
                return mac;
            }
        } catch (e) {
            console.debug(`netsh command failed for ${ip}: ${e.message}`);
        }

        console.debug(`Could not resolve MAC for ${ip} using any method`);
        return 'Unknown';
    } catch (error) {
        console.error(`Failed to get MAC for ${ip}:`, error.message);
        return 'Unknown';
    }
}

module.exports = {
    isWindows,
    isLinux,
    isWSL,
    checkOSSupport,
    isCommandAvailable,
    checkRequiredTools,
    getGatewayInfo
};