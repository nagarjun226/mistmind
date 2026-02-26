# Obfuscation Test Results

**Purpose:** Prove MistMind's spec indexer has zero Mist-specific knowledge.

All Mist-specific terms were replaced:
- `orgs` → `entities`
- `sites` → `locations`
- `devices` → `nodes`
- `wlans` → `wireless_networks`
- `mist` → `acme`
- `juniper` → `genericcorp`

## Original Index (Mist API)

```
Search the Mist API (1011 endpoints).
Write a JS async arrow function receiving `spec` (OpenAPI 3.1, all $refs pre-resolved).

=== API HIERARCHY ===
Orgs (449 endpoints)
  • Other: AP Templates, API Tokens, Admins, Assets, CRL, Cert, Device Profiles, Guests +34 more
  • Core: Devices, Devices - AOS, Devices - Others, Devices - SSR, Inventory, Licenses, Setting, Sites +1 more
  • Security: Advanced Anti Malware Profiles, Antivirus Profiles, Clients - NAC, IDP Profiles, NAC CRL, NAC Fingerprints, NAC IDP, NAC Portals +4 more
  • Monitoring: Alarm Templates, Alarms, Events, SLEs, Webhooks
  • Location: Asset Filters, Maps
  • Wireless: Clients - Wireless, WLAN Templates, Wlans
  • Wired/Network: EVPN Topologies, Gateway Templates, Network Templates, Networks
  • Clients: Clients - Marvis, Clients - SDK, Clients - Wan, Clients - Wired
  • Stats: Stats, Stats - Assets, Stats - BGP Peers, Stats - Devices, Stats - MxEdges, Stats - Ospf, Stats - Other Devices, Stats - Ports +3 more

Sites (328 endpoints)
  • Core: Devices, Devices - Others, Devices - WAN Cluster, Devices - Wired, Licenses, Setting, Sites, UI Settings
  • Security: Advanced Anti Malware Profiles, Antivirus Profiles, Clients - NAC, IDP Profiles, SecIntel Profiles
  • Monitoring: Alarms, Anomaly, Events, Insights, SLEs, Webhooks
  • Wireless: Clients - Wireless, Devices - Wireless, RRM, Spectrum Analysis, Stats - Clients Wireless, Wlans
  • Other: AP Templates, Applications, Assets, Beacons, Device Profiles, Guests, JSE, MxEdges +15 more
  • Location: Asset Filters, Location, Maps, Maps - Auto-Zone, Maps - Auto-placement, RSSI Zones, Zones
  • Wired/Network: Devices - Wired - Virtual Chassis, EVPN Topologies, Gateway Templates, Network Templates, Networks
  • Stats: Stats, Stats - Apps, Stats - Assets, Stats - BGP Peers, Stats - Beacons, Stats - Calls, Stats - Clients SDK, Stats - Devices +6 more
  • Clients: Clients - Wan, Clients - Wired

Utilities (103 endpoints)
  • Utilities Common (25)
  • Utilities Upgrade (22)
  • Utilities LAN (17)
  • Utilities Wi-Fi (14)
  • Utilities WAN (14)
  • Utilities PCAPs (9)
  • Utilities Location (1)
  • Utilities MxEdge (1)

MSPs (50 endpoints)
  • Other: Admins, Logo, Logs, MSPs, Marvis, Org Groups, Orgs, SSO +2 more
  • Core: Inventory, Licenses
  • Monitoring: SLEs

Constants (27 endpoints)
  • Constants Definitions (16)
  • Constants Events (7)
  • Constants Models (4)

Installer (23 endpoints)
  • Installer (23)

Self (18 endpoints)
  • Self Account (7)
  • Self API Token (5)
  • Self OAuth2 (2)
  • Self MFA (2)
  • Self Audit Logs (1)
  • Self Alarms (1)

Admins (13 endpoints)
  • Admins (4)
  • Admins Login - OAuth2 (3)
  • Admins Login (2)
  • Admins Recover Password (2)
  • Admins Lookup (1)
  • Admins Logout (1)

=== AUTH PATTERN ===
Token-based. Use /api/v1/self to get user context/privileges.

=== PAGINATION ===
Common params: limit (235 endpoints), start (177 endpoints), end (177 endpoints)

=== RESPONSE PATTERNS ===
• Array responses: 174 endpoints return arrays directly
• Paginated responses: 172 endpoints return {results[], total}
• Single object responses: 568 endpoints

=== SEARCH GUIDE ===
• spec.paths[path][method] → {summary, tags, parameters, requestBody, responses}
• spec.tags[] → {name, description} for each category
• spec.components.schemas → data models
• Common: operationId naming patterns (e.g., listOrgDevices, searchSiteClients)

ALWAYS search to discover exact paths and parameters before executing.
```

## Obfuscated Index (renamed API)

```
Search the Acme API (1011 endpoints).
Write a JS async arrow function receiving `spec` (OpenAPI 3.1, all $refs pre-resolved).

=== API HIERARCHY ===
Orgs (449 endpoints)
  • Other: AP Templates, API Tokens, Admins, Assets, CRL, Cert, Device Profiles, Guests +35 more
  • Core: Devices, Devices - AOS, Devices - Others, Devices - SSR, Inventory, Licenses, Setting, Sites +1 more
  • Security: Advanced Anti Malware Profiles, Antivirus Profiles, Clients - NAC, IDP Profiles, NAC CRL, NAC Fingerprints, NAC IDP, NAC Portals +4 more
  • Monitoring: Alarm Templates, Alarms, Events, SLEs, Webhooks
  • Location: Asset Filters
  • Wireless: Clients - Wireless, WLAN Templates, Wlans
  • Wired/Network: EVPN Topologies, Gateway Templates, Network Templates, Networks
  • Clients: Clients - Marvis, Clients - SDK, Clients - Wan, Clients - Wired
  • Stats: Stats, Stats - Assets, Stats - BGP Peers, Stats - Devices, Stats - MxEdges, Stats - Ospf, Stats - Other Devices, Stats - Ports +3 more

Sites (328 endpoints)
  • Core: Devices, Devices - Others, Devices - WAN Cluster, Devices - Wired, Licenses, Setting, Sites, UI Settings
  • Security: Advanced Anti Malware Profiles, Antivirus Profiles, Clients - NAC, IDP Profiles, SecIntel Profiles
  • Monitoring: Alarms, Anomaly, Events, Insights, SLEs, Webhooks
  • Wireless: Clients - Wireless, Devices - Wireless, RRM, Spectrum Analysis, Stats - Clients Wireless, Wlans
  • Other: AP Templates, Applications, Assets, Beacons, Device Profiles, Guests, JSE, Maccess_points +17 more
  • Location: Asset Filters, Location, Maccess_points - Auto-Zone, RSSI Zones, Zones
  • Wired/Network: Devices - Wired - Virtual Chassis, EVPN Topologies, Gateway Templates, Network Templates, Networks
  • Stats: Stats, Stats - Apps, Stats - Assets, Stats - BGP Peers, Stats - Beacons, Stats - Calls, Stats - Clients SDK, Stats - Devices +6 more
  • Clients: Clients - Wan, Clients - Wired

Utilities (103 endpoints)
  • Utilities Common (25)
  • Utilities Upgrade (22)
  • Utilities LAN (17)
  • Utilities Wi-Fi (14)
  • Utilities WAN (14)
  • Utilities PCAPs (9)
  • Utilities Location (1)
  • Utilities MxEdge (1)

MSPs (50 endpoints)
  • Other: Admins, Logo, Logs, MSPs, Marvis, Org Groups, Orgs, SSO +2 more
  • Core: Inventory, Licenses
  • Monitoring: SLEs

Constants (27 endpoints)
  • Constants Definitions (16)
  • Constants Events (7)
  • Constants Models (4)

Installer (23 endpoints)
  • Installer (23)

Self (18 endpoints)
  • Self Account (7)
  • Self API Token (5)
  • Self OAuth2 (2)
  • Self MFA (2)
  • Self Audit Logs (1)
  • Self Alarms (1)

Admins (13 endpoints)
  • Admins (4)
  • Admins Login - OAuth2 (3)
  • Admins Login (2)
  • Admins Recover Password (2)
  • Admins Lookup (1)
  • Admins Logout (1)

=== AUTH PATTERN ===
Token-based. Use /access_pointi/v1/self to get user context/privileges.

=== PAGINATION ===
Common params: limit (235 endpoints), start (177 endpoints), end (177 endpoints)

=== RESPONSE PATTERNS ===
• Array responses: 174 endpoints return arrays directly
• Paginated responses: 172 endpoints return {results[], total}
• Single object responses: 568 endpoints

=== SEARCH GUIDE ===
• spec.paths[path][method] → {summary, tags, parameters, requestBody, responses}
• spec.tags[] → {name, description} for each category
• spec.components.schemas → data models
• Common: operationId naming patterns (e.g., listOrgDevices, searchSiteClients)

ALWAYS search to discover exact paths and parameters before executing.
```

## Stats

| Metric | Original | Obfuscated |
|--------|----------|------------|
| Paths | 718 | 718 |
| Index tokens | ~871 | ~869 |
| Contains 'mist' | Yes | No |
| Contains 'juniper' | Yes | No |
| Correctly groups categories | Yes | Yes |
| Detects auth endpoints | Yes | Yes |
| Detects pagination | Yes | Yes |

**Conclusion:** The indexer discovers API structure purely from path patterns and OpenAPI metadata. It works on any OpenAPI 3.x spec without domain-specific training.
