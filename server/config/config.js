
module.exports = {
    server: {
        port: process.env.PORT || 3000,
        host: process.env.HOST || 'localhost'
    },
    scanner: {
        defaultTimeout: 1000,
        maxNetworkSize: 1000,
        portScanTimeout: 500,
        commonPorts: [21, 22, 23, 25, 53, 80, 443, 445, 3306, 3389, 5432, 8080]
    },
    database: {
        macDbPath: './data/macdb.json'
    },
    monitoring: {
        enabled: true,
        updateInterval: 5000
    }
};