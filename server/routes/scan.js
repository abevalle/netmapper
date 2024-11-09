
const express = require('express');
const router = express.Router();

class ScanController {
    constructor(networkScanner, graphBuilder) {
        this.networkScanner = networkScanner;
        this.graphBuilder = graphBuilder;
    }

    async handleScan(req, res) {
        try {
            const range = req.query.range;
            const scanResults = await this.networkScanner.scanNetwork(range);
            const graph = this.graphBuilder.buildNetworkGraph(scanResults);
            
            res.json({
                nodes: graph.nodes,
                links: graph.links,
                scanRange: scanResults.range
            });
        } catch (error) {
            res.status(500).json({
                error: error.message,
                nodes: [],
                links: []
            });
        }
    }
}

module.exports = {
    ScanController,
    router
};