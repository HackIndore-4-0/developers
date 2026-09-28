# developers

HackIndore 4.0 team repository.

## Projects

### Dronikastra Dashboard

React + Vite security scanning dashboard that integrates with the Acunetix API.

- `src/pages/` - application pages (Scans, Targets, Vulnerabilities, Reports, WAFs, Workers, etc.)
- `src/components/layout/` - Layout, Sidebar, Topbar
- `src/context/` - Api, Auth, Theme providers
- `src/api/client.js` - Acunetix API client
- `src/utils/twilioAlert.js` - Twilio voice alert for critical findings
- `server.js` - Express proxy server

#### Setup

```bash
npm install
cp .env.example .env   # fill in Twilio credentials
npm run dev
```

#### Environment variables

| Variable | Purpose |
| --- | --- |
| `VITE_TWILIO_ACCOUNT_SID` | Twilio account SID |
| `VITE_TWILIO_AUTH_TOKEN` | Twilio auth token |
| `VITE_TWILIO_TO_NUMBER` | Alert recipient number |
| `VITE_TWILIO_FROM_NUMBER` | Twilio caller number |

`.env` is gitignored and must never be committed.

## Challenges

- [Challenge 1](Challenges/Challenge1.md)
- [Challenge 2](Challenge2.md)
