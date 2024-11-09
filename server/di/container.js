
class Container {
    constructor(config) {
        this.config = config;
        this.services = new Map();
    }

    async initialize() {
        // Initialize core services
        this.services.set('systemUtils', new SystemUtils(this.config));
        this.services.set('macResolver', new MACResolver(this.config));
        this.services.set('networkScanner', new NetworkScanner(
            this.config,
            this.get('macResolver'),
            this.get('systemUtils')
        ));
        
        // Initialize optional services
        if (this.config.monitoring.enabled) {
            this.services.set('trafficMonitor', new TrafficMonitor(this.config));
            await this.get('trafficMonitor').start();
        }
    }

    get(serviceName) {
        if (!this.services.has(serviceName)) {
            throw new Error(`Service ${serviceName} not found`);
        }
        return this.services.get(serviceName);
    }

    getScanRouter() {
        const controller = new ScanController(
            this.get('networkScanner'),
            this.get('graphBuilder')
        );
        return setupScanRoutes(controller);
    }

    // ...additional methods...
}

module.exports = Container;