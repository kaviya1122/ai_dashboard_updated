# Launch this dashboard on Vercel

## Deploy the updated frontend

1. Copy this project into the GitHub repository connected to your Vercel project and commit/push the changes.
2. In Vercel, use the project root as the Root Directory, `npm install` as the Install Command, `npm run build` as the Build Command, and `dist` as the Output Directory.
3. Deploy. The included `vercel.json` routes direct page links through the React app.

## Current capabilities and limits

- Seeded alerts and scanner results are sample records and are labeled that way.
- The global intelligence view and status bar read the public CISA Known Exploited Vulnerabilities catalog through `/api/threat-intel`. It checks again every 15 minutes and caches upstream responses at Vercel for 15 minutes. No API key or database account is required for this public catalog.
- CISA KEV is a catalog of vulnerabilities exploited in the wild. It is not a stream of attacks against this app, and it is not a device/network sensor. The app has no inventory to determine whether your devices run affected products.
- Uploaded files are analyzed locally in the browser. They are not uploaded to Google Cloud Storage and do not persist across a page reload.
- File analysis uses heuristics; it is not a full antivirus or sandbox verdict. Reports show this source and start with containment marked **Not performed**. Response status can be recorded manually in a report and is not verified by the dashboard.
- Device protection and quarantine commands are not connected. The device page stays empty until an authorized device source is integrated.
- AI can help review data submitted in the dashboard. It does not monitor your network or create human analyst performance metrics by itself.

For monitoring your own devices, connect an authorized security data source to a persistent backend and add authenticated ingestion plus response-status evidence. Public vulnerability intelligence alone cannot discover devices or collect network telemetry. Do not expose provider API keys in `VITE_*` browser variables.
