
const mdns = require('multicast-dns')();

class MDNSDiscovery {
    constructor() {
        this.devices = new Map();
        this.onDeviceFound = null;
    }

    start(callback) {
        this.onDeviceFound = callback;

        mdns.on('response', (response) => {
            const device = this.parseResponse(response);
            if (device) {
                this.devices.set(device.id, device);
                if (this.onDeviceFound) {
                    this.onDeviceFound(device);
                }
            }
        });

        // Query for common service types
        this.query('_http._tcp.local');
        this.query('_https._tcp.local');
        this.query('_workstation._tcp.local');
        this.query('_printer._tcp.local');
        this.query('_ipp._tcp.local');
        this.query('_smb._tcp.local');
    }

    stop() {
        mdns.removeAllListeners('response');
        mdns.destroy();
    }

    query(serviceType) {
        mdns.query({
            questions: [{
                name: serviceType,
                type: 'PTR'
            }]
        });
    }

    parseResponse(response) {
        const answers = [...response.answers, ...response.additionals];
        let device = null;

        // Look for A records (IPv4 addresses)
        const aRecord = answers.find(a => a.type === 'A');
        if (aRecord) {
            device = {
                id: aRecord.data,
                ip: aRecord.data,
                name: aRecord.name,
                type: 'mdns',
                services: new Set()
            };

            // Look for PTR records (services)
            answers
                .filter(a => a.type === 'PTR')
                .forEach(ptr => {
                    device.services.add(ptr.name.split('._')[0].slice(1));
                });

            // Look for TXT records (additional info)
            const txtRecord = answers.find(a => a.type === 'TXT');
            if (txtRecord) {
                device.txtRecord = txtRecord.data.map(buf => buf.toString());
            }

            // Convert services Set to Array for JSON serialization
            device.services = Array.from(device.services);
        }

        return device;
    }
}

module.exports = MDNSDiscovery;