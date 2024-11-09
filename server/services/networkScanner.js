
const ping = require('ping');
const dns = require('dns').promises;
const net = require('net');
const { getMACAddress } = require('./macResolver');
const { parseCIDR } = require('../utils/ipUtils');
const { lookupOUI } = require('./macDatabase');

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
            socket.setTimeout(500);
            
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

// ... add more scanning related functions

module.exports = {
    getHostname,
    scanPorts,
    // ... export other functions
};