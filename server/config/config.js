module.exports = {
    server: {
        port: process.env.PORT || 3000,
        host: process.env.HOST || 'localhost'
    },
    scanner: {
        defaultTimeout: 1000,
        maxNetworkSize: 1000,
        portScanTimeout: 500,
        commonPorts: [21, 22, 23, 25, 53, 80, 443, 445, 3306, 3389, 5432, 8080],
        maxChunkSize: 256, // Max IPs to scan at once
        chunkDelay: 1000, // Delay between chunks in ms
        maxTotalSize: 65536 // Maximum total IPs allowed in scan
    },
    database: {
        macDbPath: './server/macdb.json'  // Updated path to server directory
    },
    monitoring: {
        enabled: true,
        updateInterval: 5000
    },
    discovery: {
        enabled: true,
        scanInterval: 300000, // 5 minutes
        includeRoutes: true,
        maxSegments: 50,
        mdns: {
            enabled: true,
            timeout: 5000,  // 5 seconds timeout for mDNS discovery
            services: [
                '_http._tcp.local',
                '_https._tcp.local',
                '_workstation._tcp.local',
                '_printer._tcp.local',
                '_ipp._tcp.local',
                '_smb._tcp.local'
            ]
        }
    }
};