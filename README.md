# CyberPulse Stream

**CyberPulse Stream** is a specialized Security Operations Center (SOC) dashboard designed to run on a dedicated wall monitor or secondary display. It provides a continuous, auto-scrolling stream of real-time threat intelligence.

## 🚀 Features

### 1. Unified Intelligence Stream
Combines three critical data sources into a single, high-visibility feed:
-   **Security News**: Latest headlines from major cybersecurity outlets (Hacker News, BleepingComputer, dark Reading, etc.).
-   **Data Breaches**: Real-time alerts on new data leaks and breaches.
-   **Vulnerabilities (CVEs)**: Critical and high-severity vulnerability disclosures from the National Vulnerability Database (NVD).

### 2. Smart Time Window & Fallback Logic
To ensure the dashboard is never empty, the app employs a progressive search strategy:
-   **Primary (Last 24 Hours)**: Initially attempts to fetch only the freshest data from the last day.
-   **Fallback 1 (Last 72 Hours)**: If the 24h window yields zero results, it automatically extends the scope to 3 days.
-   **Fallback 2 (Last 7 Days)**: If there is still no activity, it performs a deep search of the last week.

### 3. "SOC Wall" Optimized UI
-   **Dark Mode**: High-contrast "Cyberpunk/Terminal" aesthetic designed for readability at a distance.
-   **Auto-Scroll**: The feed automatically scrolls continuously, creating a "ticker" effect.
-   **Color Coding**:
    -   🔵 **Blue**: General Intelligence & News
    -   🔴 **Red**: Data Breaches & Critical Alerts
    -   🟠 **Orange**: Vulnerabilities (CVEs)

### 4. Technical Highlights
-   **No Backend Required**: Runs entirely in the browser using public APIs (RSS to JSON, NVD API).
-   **Auto-Refresh**: Automatically refreshes data every 10 minutes.
-   **Resilience**: Built-in timeouts and error handling prevent the dashboard from hanging on "Initializing".

## 🛠️ Installation & Usage

### Method 1: Instant Launch (Windows)
Double-click the included batch file:
`run_stream.bat`

### Method 2: Manual
Open `index.html` in any modern web browser.

### Recommended Display Settings
For the full SOC experience:
1.  Open the app.
2.  Press **F11** to enter Full Screen mode.
3.  Leave running on a secondary monitor.

## ⚙️ Configuration

The feed sources and API endpoints are configurable in `main.js`:

```javascript
// Add or remove RSS feeds here
const NEWS_FEEDS = [
    { name: 'The Hacker News', url: '...' },
    { name: 'Bleeping Computer', url: '...' },
    // ...
];
```

## ⚠️ API Note
The app uses the **NVD Public API** for CVEs, which has rate limits. If the CVE section takes longer to load, it is likely due to API throttling. The app handles this gracefully by attempting to fall back or load available data.
