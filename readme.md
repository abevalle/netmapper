# Network Device Scanner & Visualizer

An interactive network device discovery and visualization tool that creates real-time visual maps of your local network topology.

## Features

- **Network Discovery**
  - Automatic scanning of local networks
  - Custom IP range scanning support (CIDR notation)
  - Port scanning for common services
  - Device fingerprinting with MAC vendor lookup
  - Hostname resolution
  - Gateway detection

- **Interactive Visualization**
  - Force-directed graph layout
  - Subnet grouping and visualization
  - Node categorization (gateway, local devices)
  - Device relationship mapping
  - Zoom and pan controls
  - Drag-and-drop node positioning

- **Real-time Information**
  - Device status monitoring
  - Network traffic visualization (Linux only)
  - Port and service information
  - Manufacturer details
  - Interactive tooltips

## Prerequisites

- Node.js (v14 or higher)
- For Linux systems (enhanced functionality):
  - `arp-scan`
  - `ip` command
