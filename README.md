# Trendify Nexus TCP Relay

## Required Railway variables
- PORT=443
- RELAY_SECRET: use the value returned by the Installer.

## Deployment
1. Deploy this repository to Railway.
2. Set PORT=443 and RELAY_SECRET in Railway variables.
3. Create a Railway TCP Proxy targeting internal port 443.
4. Copy the public TCP hostname and port.
5. Configure RELAY_HOST and RELAY_PORT in the Gateway Worker.

Never publish RELAY_SECRET.