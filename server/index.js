const express = require('express');
const config = require('./config/config');
const Container = require('./di/container');

async function startServer() {
    const app = express();
    const container = new Container(config);

    // Initialize services
    await container.initialize();

    // Setup routes
    app.use(express.static('public'));
    app.use('/api/scan', container.getScanRouter());
    app.use('/api/connections', container.getConnectionsRouter());

    // Error handling middleware
    app.use((err, req, res, next) => {
        console.error(err.stack);
        res.status(500).json({ error: err.message });
    });

    app.listen(config.server.port, () => {
        console.log(`Server running on port ${config.server.port}`);
    });
}

startServer().catch(console.error);