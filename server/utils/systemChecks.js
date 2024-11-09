
const { execSync } = require('child_process');

const isWindows = process.platform === 'win32';
const isLinux = process.platform === 'linux';

function checkOSSupport() {
    if (!isWindows && !isLinux) {
        console.warn('Warning: Unsupported operating system. Some features may not work correctly.');
    }
    console.log(`Running on ${process.platform} platform`);
}

function isCommandAvailable(command) {
    try {
        execSync(`which ${command}`, { encoding: 'utf8' });
        return true;
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
    }
}

module.exports = {
    isWindows,
    isLinux,
    checkOSSupport,
    isCommandAvailable,
    checkRequiredTools
};