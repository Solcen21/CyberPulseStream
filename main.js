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


// ✅ Replace with your Worker:
// Example: "https://rss-proxy.yourname.workers.dev/rss?url="
const RSS_PROXY_BASE = "https://rss-proxy.solcen21.workers.dev/rss?url=";

// Optional: NVD api key header (recommended for stability with NVD v2)
const NVD_API_KEY = ""; // leave blank if you don't have one

// ---------------- DOM ----------------

const elClock = document.getElementById("wallClock");
const mainFeedEl = document.getElementById("mainFeed");

// ---------------- Clock ----------------

function updateClock() {
    const now = new Date();
    elClock.textContent = now.toISOString().split("T")[1].split(".")[0] + " UTC";
}
setInterval(updateClock, 1000);
updateClock();

// ---------------- Utilities ----------------

function cleanText(text, limit = 1200) {
    const div = document.createElement("div");
    div.innerHTML = text ?? "";
    let clean = div.textContent || div.innerText || "";
    if (clean.length > limit) clean = clean.substring(0, limit) + "...";
    return clean;
}

async function fetchWithTimeout(url, timeout = 12000, options = {}) {
    const controller = new AbortController();
    const id = setTimeout(() => controller.abort(), timeout);
    try {
        const res = await fetch(url, { ...options, signal: controller.signal });
        clearTimeout(id);
        return res;
    } finally {
        clearTimeout(id);
    }
}

function safeDateMs(dateStr) {
    const t = new Date(dateStr).getTime();
    return Number.isFinite(t) ? t : 0;
}

// ---------------- Unified Stream ----------------

let allItems = [];

function dedupeKey(item) {
    return item.id || item.guid || item.link || `${item.title || "untitled"}::${item.source || "unknown"}::${item.type}`;
}

function addToStream(newItems, type) {
    const tagged = newItems.map(i => ({ ...i, type }));
    allItems.push(...tagged);

    // de-dupe
    const seen = new Set();
    allItems = allItems.filter(it => {
        const k = dedupeKey(it);
        if (seen.has(k)) return false;
        seen.add(k);
        return true;
    });

    // sort newest first
    allItems.sort((a, b) => {
        const ta = safeDateMs(a.pubDate || a.published || 0);
        const tb = safeDateMs(b.pubDate || b.published || 0);
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

    const displayItems = [...allItems, ...allItems];
    if (allItems.length < 5) displayItems.push(...allItems);

    for (const item of displayItems) {
        const card = document.createElement("div");
        const time = new Date(item.pubDate || item.published).toLocaleTimeString([], {
            hour: "2-digit", minute: "2-digit"
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
        <div class="software-family" style="color:${color}">
          SEVERITY: ${severity} (CVSS ${item.score})
        </div>
        <div class="item-title">${item.id}</div>
        <div class="item-desc">${cleanText(item.description, 1200)}</div>
        <div class="item-desc">
          <a href="${item.link}" target="_blank" rel="noopener">View on NVD</a>
        </div>
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
        <div class="item-title">${item.title || "Untitled"}</div>
        <div class="item-desc">${cleanText(item.description, 1200)}</div>
        ${item.link ? `<div class="item-desc"><a href="${item.link}" target="_blank" rel="noopener">Read more</a></div>` : ""}
      `;
        } else {
            card.className = "feed-item type-news";
            card.innerHTML = `
        <div class="item-header">
          <div>
            <span class="item-badge badge-news">INTEL</span>
            <span class="item-source">${item.source}</span>
          </div>
          <span class="item-time">${time}</span>
        </div>
        <div class="item-title">${item.title || "Untitled"}</div>
        <div class="item-desc">${cleanText(item.description, 1200)}</div>
        ${item.link ? `<div class="item-desc"><a href="${item.link}" target="_blank" rel="noopener">Read more</a></div>` : ""}
      `;
        }

        container.appendChild(card);
    }

    setupAutoScroll(container);
}

function setupAutoScroll(element) {
    element.style.animation = "none";
    void element.offsetHeight;

    const scrollHeight = element.scrollHeight;
    if (scrollHeight <= element.parentElement.clientHeight) return;

    const duration = Math.max(20, scrollHeight / 50);
    element.style.animation = `autoScroll ${duration}s linear infinite`;
}

// ---------------- Fetch RSS via Worker ----------------

function proxyUrl(feedUrl) {
    // you can add &cache=600 if you want: `${RSS_PROXY_BASE}${encodeURIComponent(feedUrl)}&cache=600`
    return `${RSS_PROXY_BASE}${encodeURIComponent(feedUrl)}&cache=600`;
}

async function fetchRSS(feeds, windowDays, type) {
    const cutoff = Date.now() - windowDays * ONE_DAY_MS;

    const promises = feeds.map(async feed => {
        try {
            const res = await fetchWithTimeout(proxyUrl(feed.url), 12000);

            if (!res.ok) {
                const body = await res.text().catch(() => "");
                console.warn(`[RSS ${type}] ${feed.name} failed: HTTP ${res.status}`, body);
                return [];
            }

            const data = await res.json();
            if (data.status !== "ok") {
                console.warn(`[RSS ${type}] ${feed.name} parse error`, data);
                return [];
            }

            const items = (data.items || []).map(i => ({
                title: i.title,
                link: i.link,
                pubDate: i.pubDate,
                description: i.description,
                source: feed.name
            }));

            return items.filter(i => safeDateMs(i.pubDate) > cutoff);
        } catch (e) {
            console.warn(`[RSS ${type}] ${feed.name} exception`, e);
            return [];
        }
    });

    const recent = (await Promise.all(promises)).flat();
    addToStream(recent, type);
}

// ---------------- Fetch CVEs ----------------

function processCVE(cve) {
    const metrics =
        cve.metrics?.cvssMetricV31?.[0] ||
        cve.metrics?.cvssMetricV30?.[0] ||
        cve.metrics?.cvssMetricV2?.[0];

    const score = metrics?.cvssData?.baseScore || 0;

    let software = "Unknown Software";
    if (Array.isArray(cve.configurations)) {
        for (const config of cve.configurations) {
            for (const node of (config.nodes || [])) {
                for (const match of (node.cpeMatch || [])) {
                    const criteria = match.criteria;
                    if (criteria) {
                        const parts = criteria.split(":");
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

    const pubStartDate = startDate.toISOString().replace("Z", "");
    const pubEndDate = now.toISOString().replace("Z", "");

    const url = `${CVE_API}?pubStartDate=${pubStartDate}&pubEndDate=${pubEndDate}`;

    try {
        const headers = {};
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
    allItems = [];

    const timeLabel = document.querySelector(".time-window");
    if (timeLabel) timeLabel.textContent = windowDays === 1 ? "LAST 24H" : `LAST ${windowDays} DAYS`;

    await Promise.all([
        fetchRSS(NEWS_FEEDS, windowDays, "news"),
        fetchRSS(BREACH_FEEDS, windowDays, "breach"),
        fetchCVEs(windowDays)
    ]);

    return allItems.length;
}

async function init() {
    if (!mainFeedEl) return;

    let count = await fetchAllData(1);
    if (count === 0) count = await fetchAllData(3);
    if (count === 0) count = await fetchAllData(7);

    if (count === 0) {
        renderEmpty(mainFeedEl, "No recent intelligence found (Last 7 Days).");
    }

    setInterval(async () => {
        console.log("Refreshing feeds...");
        let c = await fetchAllData(1);
        if (c === 0) c = await fetchAllData(3);
        if (c === 0) c = await fetchAllData(7);

        if (c === 0) renderEmpty(mainFeedEl, "No recent intelligence found (Last 7 Days).");
    }, 10 * 60 * 1000);
}

init();
