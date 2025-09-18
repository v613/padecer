const express = require('express');
const fs = require('fs').promises;
const path = require('path');

const app = express();
const PORT = 3000;
const ALERTS_FILE = path.join(__dirname, 'alerts.json');

app.use(express.json());
app.use(express.static(__dirname));

async function loadAlerts() {
    try {
        const data = await fs.readFile(ALERTS_FILE, 'utf8');
        return JSON.parse(data);
    } catch (error) {
        return [];
    }
}

async function saveAlerts(alerts) {
    try {
        await fs.writeFile(ALERTS_FILE, JSON.stringify(alerts, null, 2));
    } catch (error) {
        console.error('Failed to save alerts:', error);
    }
}

// Endpoint to receive alerts from padecer
app.post('/alerts', async (req, res) => {
    try {
        const alertPayload = req.body;
        
        // Validate required fields
        if (!alertPayload.host || !alertPayload.path || !alertPayload.expirationDate) {
            return res.status(400).json({ error: 'Missing required fields' });
        }

        const alerts = await loadAlerts();
        
        // Add timestamp if not present
        if (!alertPayload.timestamp) {
            alertPayload.timestamp = new Date().toISOString();
        }
        
        // Check for duplicate alerts (same host + path)
        const existingIndex = alerts.findIndex(a => 
            a.host === alertPayload.host && a.path === alertPayload.path
        );
        
        if (existingIndex >= 0) {
            // Update existing alert
            alerts[existingIndex] = alertPayload;
        } else {
            // Add new alert
            alerts.push(alertPayload);
        }
        
        await saveAlerts(alerts);
        
        console.log(`Alert received: ${alertPayload.host}::${alertPayload.path} => ${alertPayload.expirationDate}`);
        res.status(200).json({ message: 'Alert received successfully' });
        
    } catch (error) {
        console.error('Error processing alert:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Endpoint to get all alerts for the dashboard
app.get('/api/alerts', async (req, res) => {
    try {
        const alerts = await loadAlerts();
        res.json(alerts);
    } catch (error) {
        console.error('Error loading alerts:', error);
        res.status(500).json({ error: 'Failed to load alerts' });
    }
});

// Endpoint to clear all alerts
app.delete('/api/alerts', async (req, res) => {
    try {
        await saveAlerts([]);
        res.json({ message: 'All alerts cleared' });
    } catch (error) {
        console.error('Error clearing alerts:', error);
        res.status(500).json({ error: 'Failed to clear alerts' });
    }
});

// Serve the dashboard at root
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

app.listen(PORT, () => {
    console.log(`Certificate Dashboard running at http://localhost:${PORT}`);
    console.log(`Alert endpoint: http://localhost:${PORT}/alerts`);
    console.log(`Configure padecer with: --send-to="http://localhost:${PORT}/alerts"`);
});