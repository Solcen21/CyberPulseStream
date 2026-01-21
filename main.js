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

const CVE_API = 'https://services.nvd.nist.gov/rest/json/cves/2.0';
const RSS_TO_JSON = 'https://api.rss2json.com/v1/api.json?rss_url=';

// DOM Elements
const elBreach = document.getElementById('breachFeed');
const elNews = document.getElementById('newsFeed');
const elCVE = document.getElementById('cveFeed');
const elClock = document.getElementById('wallClock');

// --- Utils ---

function updateClock() {
    const now = new Date();
    elClock.textContent = now.toISOString().split('T')[1].split('.')[0] + " UTC";
}
setInterval(updateClock, 1000);
updateClock();

function isRecent(dateString) {
    const pubDate = new Date(dateString);
    // Strict 24h check
    return (Date.now() - pubDate.getTime()) < ONE_DAY_MS;
}

function cleanText(text, limit = 1200) {
    const div = document.createElement('div');
    div.innerHTML = text;
    let clean = div.textContent || div.innerText || '';
    if (clean.length > limit) clean = clean.substring(0, limit) + '...';
    return clean;
}

// --- Data Fetching ---

async function fetchWithTimeout(url, timeout = 5000) {
    const controller = new AbortController();
    const id = setTimeout(() => controller.abort(), timeout);
    try {
        const response = await fetch(url, { signal: controller.signal });
        clearTimeout(id);
        return response;
    } catch (e) {
        clearTimeout(id);
        throw e;
    }
}

async function fetchRSS(feeds, targetElement, type) {
    let items = [];
    const promises = feeds.map(feed =>
        fetchWithTimeout(`${RSS_TO_JSON}${encodeURIComponent(feed.url)}`)
            .then(r => r.json())
            .then(data => {
                if (data.status === 'ok') {
                    return data.items.map(i => ({ ...i, source: feed.name }));
                }
                return [];
            })
            .catch(() => [])
    );

    const results = await Promise.all(promises);
    items = results.flat();

    // Filter for last 24h
    const recentItems = items.filter(i => isRecent(i.pubDate))
        .sort((a, b) => new Date(b.pubDate) - new Date(a.pubDate));

    renderStream(targetElement, recentItems, type);
}

async function fetchCVEs() {
    // Calculate 24h window for NVD
    // Note: NVD can be slow to index. If 24h returns 0, we might strictly show 0 as per user request, 
    // but usually there's something.
    const now = new Date();
    const yesterday = new Date(now.getTime() - ONE_DAY_MS);

    const formatDate = (d) => d.toISOString().replace('Z', ''); // NVD requires no 'Z'

    const pubStartDate = formatDate(yesterday);
    const pubEndDate = formatDate(now);

    const url = `${CVE_API}?pubStartDate=${pubStartDate}&pubEndDate=${pubEndDate}`;

    try {
        const res = await fetchWithTimeout(url, 15000); // NVD is slow
        const data = await res.json();

        if (data.vulnerabilities) {
            const cves = data.vulnerabilities.map(v => processCVE(v.cve));
            renderStream(elCVE, cves, 'cve');
        } else {
            renderEmpty(elCVE, "No CVEs published in last 24h");
        }
    } catch (e) {
        console.error("CVE Fetch failed", e);
        renderEmpty(elCVE, "CVE Stream Offline");
    }
}

function processCVE(cve) {
    const metrics = cve.metrics?.cvssMetricV31?.[0] || cve.metrics?.cvssMetricV30?.[0] || cve.metrics?.cvssMetricV2?.[0];
    const score = metrics?.cvssData?.baseScore || 0;

    // Attempt to extract software family
    // CPE format: cpe:2.3:a:vendor:product:version...
    let software = "Unknown Software";

    if (cve.configurations) {
        // Broad search for a CPE string
        for (const config of cve.configurations) {
            for (const node of config.nodes || []) {
                for (const match of node.cpeMatch || []) {
                    if (match.criteria) {
                        const parts = match.criteria.split(':');
                        if (parts.length >= 5) {
                            // Vendor + Product (e.g., microsoft:windows)
                            software = `${parts[3]} ${parts[4]}`.toUpperCase().replace(/_/g, ' ');
                            break;
                        }
                    }
                }
                if (software !== "Unknown Software") break;
            }
            if (software !== "Unknown Software") break;
        }
    }

    // If no CPE, try description
    if (software === "Unknown Software") {
        const desc = cve.descriptions[0]?.value || "";
        // Simple heuristic: First 3 words might be relevant if no CPE
        // software = desc.split(' ').slice(0, 3).join(' '); 
    }

    return {
        id: cve.id,
        description: cve.descriptions?.[0]?.value || "No description provided",
        score: score,
        software: software,
        published: cve.published,
        link: `https://nvd.nist.gov/vuln/detail/${cve.id}`
    };
}

// --- Rendering ---

let allItems = [];

function addToStream(newItems, type) {
    // Add type to items
    const taggedItems = newItems.map(i => ({ ...i, type }));
    allItems.push(...taggedItems);

    // Sort combined stream
    allItems.sort((a, b) => new Date(b.pubDate || b.published) - new Date(a.pubDate || a.published));

    // De-duplicate by ID or Title to prevent flicker on re-fetch
    const seen = new Set();
    const uniqueItems = allItems.filter(item => {
        const key = item.id || item.title;
        const duplicate = seen.has(key);
        seen.add(key);
        return !duplicate;
    });

    allItems = uniqueItems;
    renderUnifiedStream();
}

function renderUnifiedStream() {
    const container = document.getElementById('mainFeed');
    container.innerHTML = '';

    if (allItems.length === 0) {
        renderEmpty(container, "Scanning all frequencies... No recent traffic.");
        return;
    }

    // Double for scrolling
    const displayItems = [...allItems, ...allItems];
    // If very few, triple
    if (allItems.length < 5) displayItems.push(...allItems);

    displayItems.forEach(item => {
        const card = document.createElement('div');
        const time = new Date(item.pubDate || item.published).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });

        if (item.type === 'cve') {
            const severity = item.score >= 9 ? 'CRITICAL' : (item.score >= 7 ? 'HIGH' : 'MEDIUM');
            const color = item.score >= 9 ? '#ff4757' : (item.score >= 7 ? '#ffa502' : '#eccc68');

            card.className = `feed-item type-cve`;
            card.innerHTML = `
                <div class="item-header">
                    <div>
                        <span class="item-badge badge-cve">CVE</span>
                        <span class="item-source">NVD ALERT</span>
                    </div>
                    <span class="item-time">${time}</span>
                </div>
                <div class="software-family" style="color: ${color}">SEVERITY: ${severity} (CVSS ${item.score})</div>
                <div class="item-title">${item.id}</div>
                <div class="item-desc">${cleanText(item.description, 1200)}</div>
            `;
        } else if (item.type === 'breach') {
            card.className = `feed-item type-breach`;
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
            `;
        } else {
            // News
            card.className = `feed-item type-news`;
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
            `;
        }

        container.appendChild(card);
    });

    setupAutoScroll(container);
}

function renderEmpty(container, message) {
    container.innerHTML = `<div style="padding: 2rem; text-align: center; color: #666;">${message}</div>`;
}

function setupAutoScroll(element) {
    // We need to animate the container.
    // The content is already duplicated. 
    // We'll use CSS animation on the container itself or a wrapper

    // We need to calculate the height of one 'set' of items to know how far to scroll
    // But since we just want a continuous flow, we can use a simpler approach:
    // Append the SAME content again, and scroll from 0 to 50% height.

    const wrapper = element; // The .scroll-content div
    const scrollHeight = wrapper.scrollHeight;

    // If content is shorter than container, no need to scroll
    if (scrollHeight <= wrapper.parentElement.clientHeight) return;

    // Set animation duration based on height (slower for longer content)
    // Approx 50px per second ? 
    const duration = scrollHeight / 50;

    wrapper.style.animation = `autoScroll ${duration}s linear infinite`;
}

// --- Init & Smart Fetch ---

async function fetchAllData(windowDays) {
    console.log(`Attempting fetch with ${windowDays} day window...`);
    allItems = []; // Clear current items for this attempt

    // Update time window display
    const timeLabel = document.querySelector('.time-window');
    if (timeLabel) timeLabel.textContent = windowDays === 1 ? "LAST 24H" : `LAST ${windowDays} DAYS`;

    try {
        await Promise.all([
            fetchRSS(NEWS_FEEDS, windowDays, 'news'),
            fetchRSS(BREACH_FEEDS, windowDays, 'breach'),
            fetchCVEs(windowDays)
        ]);
        return allItems.length;
    } catch (e) {
        console.error("Fetch cycle failed:", e);
        return 0;
    }
}

async function init() {
    const container = document.getElementById('mainFeed');

    // Initial fetch cycle with fallbacks
    let count = await fetchAllData(1); // Try 24h

    if (count === 0) {
        console.log("24h window empty. extending to 72h...");
        count = await fetchAllData(3); // Try 3 days
    }

    if (count === 0) {
        console.log("72h window empty. extending to 7 days...");
        count = await fetchAllData(7); // Try 7 days
    }

    if (count === 0) {
        renderEmpty(container, "No recent intelligence found (Last 7 Days).");
    }

    // Refresh loop (stick to the determined window or reset to 1? 
    // Let's reset to 1 to prefer fresh data, and let logic cascade again if needed)
    setInterval(async () => {
        console.log("Refreshing feeds...");
        count = await fetchAllData(1);
        if (count === 0) count = await fetchAllData(3);
        if (count === 0) count = await fetchAllData(7);

        if (count === 0) {
            renderEmpty(container, "No recent intelligence found (Last 7 Days).");
        }
    }, 10 * 60 * 1000);
}

// Updated Fetchers to accept windowDays

async function fetchRSS(feeds, windowDays, type) {
    const promises = feeds.map(feed =>
        fetchWithTimeout(`${RSS_TO_JSON}${encodeURIComponent(feed.url)}`)
            .then(r => r.json())
            .then(data => {
                if (data.status === 'ok') {
                    return data.items.map(i => ({ ...i, source: feed.name }));
                }
                return [];
            })
            .catch(() => [])
    );

    const results = await Promise.all(promises);
    const flattened = results.flat();

    // Filter by window
    const cutoff = Date.now() - (windowDays * ONE_DAY_MS);
    const recentItems = flattened.filter(i => new Date(i.pubDate).getTime() > cutoff);

    addToStream(recentItems, type);
}

async function fetchCVEs(windowDays) {
    const now = new Date();
    const startDate = new Date(now.getTime() - (windowDays * ONE_DAY_MS));

    const formatDate = (d) => d.toISOString().replace('Z', '');
    const pubStartDate = formatDate(startDate);
    const pubEndDate = formatDate(now);

    const url = `${CVE_API}?pubStartDate=${pubStartDate}&pubEndDate=${pubEndDate}`;

    try {
        const res = await fetchWithTimeout(url, 15000);
        const data = await res.json();

        if (data.vulnerabilities) {
            const cves = data.vulnerabilities.map(v => processCVE(v.cve));
            addToStream(cves, 'cve');
        }
    } catch (e) {
        console.error("CVE Fetch failed", e);
    }
}

init();
