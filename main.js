const START_TIME = Date.now();
const ONE_DAY_MS = 24 * 60 * 60 * 1000;

// Configs
const NEWS_FEEDS = [
    { name: 'The Hacker News', url: 'https://feeds.feedburner.com/TheHackersNews' },
    { name: 'Bleeping Computer', url: 'https://www.bleepingcomputer.com/feed/' },
    { name: 'Dark Reading', url: 'https://www.darkreading.com/rss.xml' },
    { name: 'CyberScoop', url: 'https://cyberscoop.com/feed/' },
    { name: 'SecurityWeek', url: 'https://www.securityweek.com/feed/' },
    { name: 'ZDNet', url: 'https://www.zdnet.com/topic/security/rss.xml' },
    { name: 'Krebs on Security', url: 'https://krebsonsecurity.com/feed/' },
    { name: 'The Record', url: 'https://therecord.media/feed' },
    { name: 'Help Net Security', url: 'https://www.helpnetsecurity.com/feed/' },
    { name: 'CISA Alerts', url: 'https://www.cisa.gov/news-events/cybersecurity-advisories/rss.xml' }
];

const BREACH_FEEDS = [
    { name: 'DataBreaches.net', url: 'https://www.databreaches.net/feed/' },
    { name: 'Bleeping (Breach)', url: 'https://www.bleepingcomputer.com/news/security/breach/feed/' }
];

// NVD CVE API 2.0
const CVE_API = "https://services.nvd.nist.gov/rest/json/cves/2.0";

// rss2json endpoint + optional key support
const RSS2JSON_BASE = "https://api.rss2json.com/v1/api.json";
const RSS2JSON_API_KEY = ""; // optional: rss2json api_key param (per docs) [1](https://github.com/wazuh/wazuh/issues/17055)

// optional: NVD apiKey header support (per NVD 2.0 guidance) [2](https://groups.google.com/a/list.nist.gov/g/nvd-news/c/sV8WN_fdRBw)
const NVD_API_KEY = "";

// ---------------- DOM ----------------

const elCVE = document.getElementById("cveFeed");
const elClock = document.getElementById("wallClock");

// unified stream container
const mainFeedEl = document.getElementById("mainFeed");

// ---------------- Utils ----------------

function updateClock() {
    const now = new Date();
    elClock.textContent = now.toISOString().split("T")[1].split(".")[0] + " UTC";
}
setInterval(updateClock, 1000);
updateClock();

function cleanText(text, limit = 1200) {
    const div = document.createElement("div");
    div.innerHTML = text ?? "";
    let clean = div.textContent || div.innerText || "";
    if (clean.length > limit) clean = clean.substring(0, limit) + "...";
    return clean;
}

function rss2jsonUrl(feedUrl) {
    const u = new URL(RSS2JSON_BASE);
    u.searchParams.set("rss_url", feedUrl);
    if (RSS2JSON_API_KEY) u.searchParams.set("api_key", RSS2JSON_API_KEY);
    return u.toString();
}

async function fetchWithTimeout(url, timeout = 8000, options = {}) {
    const controller = new AbortController();
    const id = setTimeout(() => controller.abort(), timeout);

    try {
        const res = await fetch(url, { ...options, signal: controller.signal });
        clearTimeout(id);
        return res;
    } catch (e) {
        clearTimeout(id);
        throw e;
    }
}

// ---------------- Unified Stream State ----------------

let allItems = [];

function addToStream(newItems, type) {
    // Tag items with type
    const tagged = newItems.map(i => ({ ...i, type }));
    allItems.push(...tagged);

    // Deduplicate by (id || guid || link || title+source)
    const seen = new Set();
    allItems = allItems.filter(item => {
        const key =
            item.id ||
            item.guid ||
            item.link ||
            `${item.title || "untitled"}::${item.source || "unknown"}`;
        if (seen.has(key)) return false;
        seen.add(key);
        return true;
    });

    // Sort newest first
    allItems.sort((a, b) => {
        const ta = new Date(a.pubDate || a.published || 0).getTime();
        const tb = new Date(b.pubDate || b.published || 0).getTime();
        return tb - ta;
    });

    renderUnifiedStream();
}

function renderEmpty(container, message) {
    container.innerHTML = `<div style="padding: 2rem; text-align: center; color: #666;">${message}</div>`;
}

function renderUnifiedStream() {
    const container = mainFeedEl;
    container.innerHTML = "";

    if (!allItems.length) {
        renderEmpty(container, "Scanning all frequencies... No recent traffic.");
        return;
    }

    // Duplicate items for continuous scroll
    const displayItems = [...allItems, ...allItems];
    if (allItems.length < 5) displayItems.push(...allItems);

    displayItems.forEach(item => {
        const card = document.createElement("div");
        const time = new Date(item.pubDate || item.published).toLocaleTimeString([], {
            hour: "2-digit",
            minute: "2-digit"
        });

        if (item.type === "cve") {
            const severity = item.score >= 9 ? "CRITICAL" : item.score >= 7 ? "HIGH" : "MEDIUM";
            const color = item.score >= 9 ? "#ff4757" : item.score >= 7 ? "#ffa502" : "#eccc68";

            card.className = "feed-item type-cve";
            card.innerHTML = `
        <div class="item-header">
          <div>
            <span class="item-badge badge-cve">CVE</span>
            <span class="item-source">NVD ALERT</span>
          </div>
          <span class="item-time">${time}</span>
        </div>
        <div class="software-family" style="color: ${color}">
          SEVERITY: ${severity} (CVSS ${item.score})
        </div>
        <div class="item-title">${item.id}</div>
        <div class="item-desc">${cleanText(item.description, 1200)}</div>
        <div class="item-desc"><a href="${item.link}" target="_blank" rel="noopener">View on NVD</a></div>
      `;
        } else if (item.type === "breach") {
            card.className = "feed-item type-breach";
            card.innerHTML = `
        <div class="item-header">
          <div>
            <span class="item-badge badge-breach">LEAK</span>
            <span class="item-source">${item.source}</span>
          </div>
          <span class="item-time">${time}</span>
        </div>
        <div class="item-title">${item.title}</div>
        <div class="item-desc">${cleanText(item.content || item.description, 1200)}</div>
        ${item.link ? `<div class="item-desc"><a href="${item.link}" target="_blank" rel="noopener">Read more</a></div>` : ""}
      `;
        } else {
            // news
            card.className = "feed-item type-news";
            card.innerHTML = `
        <div class="item-header">
          <div>
            <span class="item-badge badge-news">INTEL</span>
            <span class="item-source">${item.source}</span>
          </div>
          <span class="item-time">${time}</span>
        </div>
        <div class="item-title">${item.title}</div>
        <div class="item-desc">${cleanText(item.content || item.description, 1200)}</div>
        ${item.link ? `<div class="item-desc"><a href="${item.link}" target="_blank" rel="noopener">Read more</a></div>` : ""}
      `;
        }

        container.appendChild(card);
    });

    setupAutoScroll(container);
}

function setupAutoScroll(element) {
    const wrapper = element;
    const scrollHeight = wrapper.scrollHeight;

    // Stop any previous animation if content changed
    wrapper.style.animation = "none";
    // Force reflow to restart animation reliably
    void wrapper.offsetHeight;

    if (scrollHeight <= wrapper.parentElement.clientHeight) return;

    // Duration scales with height (lower = faster)
    const duration = Math.max(20, scrollHeight / 50);
    wrapper.style.animation = `autoScroll ${duration}s linear infinite`;
}

// ---------------- Fetchers ----------------

async function fetchRSS(feeds, windowDays, type) {
    const cutoff = Date.now() - windowDays * ONE_DAY_MS;

    const promises = feeds.map(async feed => {
        const url = rss2jsonUrl(feed.url);

        try {
            const res = await fetchWithTimeout(url, 10000);

            // rss2json sometimes returns 422 with a JSON body; surface it
            if (!res.ok) {
                let body = "";
                try { body = await res.text(); } catch { }
                console.warn(`[RSS ${type}] ${feed.name} failed: HTTP ${res.status}`, body);
                return [];
            }

            const data = await res.json();

            if (data.status !== "ok") {
                // rss2json documented behavior: "Feed could not be converted..." etc. [3](https://www.reddit.com/r/cybersecurity/comments/18c9h38/nvd_api_v2_problems_timeouts_403_503/)
                console.warn(`[RSS ${type}] ${feed.name} conversion error:`, data.message || data);
                return [];
            }

            const items = (data.items || []).map(i => ({ ...i, source: feed.name }));

            return items.filter(i => {
                const t = new Date(i.pubDate).getTime();
                return Number.isFinite(t) && t > cutoff;
            });
        } catch (e) {
            console.warn(`[RSS ${type}] ${feed.name} fetch exception`, e);
            return [];
        }
    });

    const recentItems = (await Promise.all(promises)).flat();
    addToStream(recentItems, type);
}

function processCVE(cve) {
    const metrics =
        cve.metrics?.cvssMetricV31?.[0] ||
        cve.metrics?.cvssMetricV30?.[0] ||
        cve.metrics?.cvssMetricV2?.[0];

    const score = metrics?.cvssData?.baseScore || 0;

    // Extract vendor/product from first CPE match if available
    let software = "Unknown Software";

    if (Array.isArray(cve.configurations)) {
        for (const config of cve.configurations) {
            for (const node of (config.nodes || [])) {
                for (const match of (node.cpeMatch || [])) {
                    if (match.criteria) {
                        const parts = match.criteria.split(":");
                        if (parts.length >= 5) {
                            software = `${parts[3]} ${parts[4]}`.toUpperCase().replace(/_/g, " ");
                            break;
                        }
                    }
                }
                if (software !== "Unknown Software") break;
            }
            if (software !== "Unknown Software") break;
        }
    }

    return {
        id: cve.id,
        description: cve.descriptions?.[0]?.value || "No description provided",
        score,
        software,
        published: cve.published,
        link: `https://nvd.nist.gov/vuln/detail/${cve.id}`
    };
}

async function fetchCVEs(windowDays) {
    const now = new Date();
    const startDate = new Date(now.getTime() - windowDays * ONE_DAY_MS);

    // NVD expects date-times in ISO-like format; your prior code removed 'Z' which you kept.
    const pubStartDate = startDate.toISOString().replace("Z", "");
    const pubEndDate = now.toISOString().replace("Z", "");

    const url = `${CVE_API}?pubStartDate=${pubStartDate}&pubEndDate=${pubEndDate}`;

    try {
        const headers = {};
        // NVD 2.0 guidance: api key passed via request header "apiKey" [2](https://groups.google.com/a/list.nist.gov/g/nvd-news/c/sV8WN_fdRBw)
        if (NVD_API_KEY) headers.apiKey = NVD_API_KEY;

        const res = await fetchWithTimeout(url, 15000, { headers });

        if (!res.ok) {
            const body = await res.text().catch(() => "");
            console.warn(`[CVE] NVD failed: HTTP ${res.status}`, body);
            return;
        }

        const data = await res.json();

        if (Array.isArray(data.vulnerabilities) && data.vulnerabilities.length) {
            const cves = data.vulnerabilities.map(v => processCVE(v.cve));
            addToStream(cves, "cve");
        }
    } catch (e) {
        console.error("CVE Fetch failed", e);
    }
}

// ---------------- Orchestrator ----------------

async function fetchAllData(windowDays) {
    console.log(`Attempting fetch with ${windowDays} day window...`);
    allItems = []; // Clear items for this attempt (keeps your “window fallback” behavior)

    const timeLabel = document.querySelector(".time-window");
    if (timeLabel) timeLabel.textContent = windowDays === 1 ? "LAST 24H" : `LAST ${windowDays} DAYS`;

    try {
        await Promise.all([
            fetchRSS(NEWS_FEEDS, windowDays, "news"),
            fetchRSS(BREACH_FEEDS, windowDays, "breach"),
            fetchCVEs(windowDays)
        ]);

        return allItems.length;
    } catch (e) {
        console.error("Fetch cycle failed:", e);
        return 0;
    }
}

async function init() {
    if (!mainFeedEl) return;

    let count = await fetchAllData(1);

    if (count === 0) {
        console.log("24h window empty. extending to 72h...");
        count = await fetchAllData(3);
    }

    if (count === 0) {
        console.log("72h window empty. extending to 7 days...");
        count = await fetchAllData(7);
    }

    if (count === 0) {
        renderEmpty(mainFeedEl, "No recent intelligence found (Last 7 Days).");
    }

    // Refresh loop
    setInterval(async () => {
        console.log("Refreshing feeds...");
        let c = await fetchAllData(1);
        if (c === 0) c = await fetchAllData(3);
        if (c === 0) c = await fetchAllData(7);

        if (c === 0) {
            renderEmpty(mainFeedEl, "No recent intelligence found (Last 7 Days).");
        }
    }, 10 * 60 * 1000);
}

init();
