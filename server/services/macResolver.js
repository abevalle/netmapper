const fs = require('fs').promises;

class MACResolver {
    constructor(config) {
        this.config = config;
        this.macDatabase = null;
        this.macCache = new Map();
        this.cacheTTL = 5 * 60 * 1000; // 5 minutes
        this.lastRequestTime = 0;
        this.minRequestInterval = 100; // ms between requests
    }

    async initialize() {
        try {
            const data = await fs.readFile(this.config.database.macDbPath, 'utf8');
            this.macDatabase = JSON.parse(data);
            console.log(`Loaded ${this.macDatabase.length} MAC address entries`);
        } catch (error) {
            console.error('Failed to load MAC database:', error.message);
            this.macDatabase = [];
        }
    }

    normalizeMACAddress(mac) {
        if (!mac || mac === 'Unknown') return null;
        
        // Remove special characters and convert to uppercase
        const normalized = mac.replace(/[^A-Fa-f0-9]/g, '').toUpperCase();
        
        // Ensure we have at least 6 characters (3 bytes) for OUI
        if (normalized.length < 6) return null;
        
        // Format as XX:XX:XX for OUI lookup
        return normalized.slice(0, 6).match(/.{1,2}/g).join(':');
    }

    lookupOUI(mac) {
        const normalizedMAC = this.normalizeMACAddress(mac);
        if (!normalizedMAC) return null;

        // Check cache first
        if (this.macCache.has(normalizedMAC)) {
            return this.macCache.get(normalizedMAC);
        }

        // Search database
        const info = this.macDatabase.find(entry => {
            const entryOUI = entry.oui.replace(/[^A-Fa-f0-9]/g, '').toUpperCase().slice(0, 6);
            const checkOUI = normalizedMAC.replace(/[^A-Fa-f0-9]/g, '').slice(0, 6);
            return entryOUI === checkOUI;
        });

        // Cache result (including null results to avoid repeated lookups)
        this.macCache.set(normalizedMAC, info || null);
        return info;
    }

    async getVendorInfo(mac, ip) {
        // Clear expired cache entries
        this.clearExpiredCache();

        // Check cache first
        const cacheKey = `${ip}-${mac}`;
        const cached = this.macCache.get(cacheKey);
        if (cached && Date.now() < cached.expires) {
            return cached.data;
        }

        // Rate limiting
        const now = Date.now();
        const timeSinceLastRequest = now - this.lastRequestTime;
        if (timeSinceLastRequest < this.minRequestInterval) {
            await new Promise(resolve => 
                setTimeout(resolve, this.minRequestInterval - timeSinceLastRequest)
            );
        }
        this.lastRequestTime = Date.now();

        // Lookup info
        const info = this.lookupOUI(mac);
        const vendorInfo = {
            address: mac || 'Unknown',
            vendor: info ? info.companyName : 'Unknown',
            countryCode: info ? info.countryCode : null,
            isPrivate: info ? info.isPrivate : null,
            blockType: info ? info.assignmentBlockSize : null
        };

        // Cache the result
        this.macCache.set(cacheKey, {
            data: vendorInfo,
            expires: Date.now() + this.cacheTTL
        });

        return vendorInfo;
    }

    clearExpiredCache() {
        const now = Date.now();
        for (const [key, value] of this.macCache) {
            if (now > value.expires) {
                this.macCache.delete(key);
            }
        }
    }
}

module.exports = MACResolver;