export default {
    async fetch(request, env, ctx) {
        const url = new URL(request.url);

        // --- CORS preflight ---
        if (request.method === "OPTIONS") {
            return new Response(null, { status: 204, headers: corsHeaders() });
        }

        // Basic routes
        if (url.pathname === "/health") {
            return withCors(json({ ok: true, name: "rss-proxy" }));
        }

        if (url.pathname !== "/rss") {
            return withCors(new Response("Not found", { status: 404 }));
        }

        const feedUrl = url.searchParams.get("url");
        if (!feedUrl) {
            return withCors(json({ error: "Missing url parameter" }, 400));
        }

        // Optional: cache seconds (default 10 minutes)
        const cacheSeconds = clampInt(url.searchParams.get("cache"), 600, 60, 3600);

        // --- Cache lookup ---
        const cacheKey = new Request(url.toString(), request);
        const cache = caches.default;
        const cached = await cache.match(cacheKey);
        if (cached) return withCors(cached);

        try {
            // Server-side fetch avoids browser CORS issues [3](https://dev.to/keploy/understanding-the-http-422-unprocessable-entity-error-causes-solutions-and-prevention-nj0)[4](https://www.beanstalkconsulting.co/playbooks/422-error-code-resolution)
            const upstream = await fetch(feedUrl, {
                headers: {
                    "User-Agent": "Mozilla/5.0 (compatible; RSSProxy/1.0)",
                    "Accept": "application/rss+xml, application/atom+xml, application/xml;q=0.9, text/xml;q=0.8, */*;q=0.7"
                },
                redirect: "follow"
            });

            if (!upstream.ok) {
                const body = await safeText(upstream);
                const resp = json(
                    { error: "Upstream fetch failed", status: upstream.status, body: body.slice(0, 500) },
                    502
                );
                return withCors(resp);
            }

            const xml = await upstream.text();
            const parsed = parseFeed(xml);

            const resp = json({ status: "ok", ...parsed }, 200, {
                "Cache-Control": `public, max-age=${cacheSeconds}`,
            });

            // Store in cache
            ctx.waitUntil(cache.put(cacheKey, resp.clone()));
            return withCors(resp);
        } catch (e) {
            return withCors(json({ error: "Worker exception", message: String(e) }, 500));
        }
    }
};

// ---------- Helpers ----------
function corsHeaders() {
    return {
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods": "GET, OPTIONS",
        "Access-Control-Allow-Headers": "*",
        "Access-Control-Max-Age": "86400"
    };
}

function withCors(response) {
    const h = new Headers(response.headers);
    for (const [k, v] of Object.entries(corsHeaders())) h.set(k, v);
    return new Response(response.body, { status: response.status, headers: h });
}

function json(obj, status = 200, headers = {}) {
    return new Response(JSON.stringify(obj), {
        status,
        headers: {
            "Content-Type": "application/json; charset=utf-8",
            ...headers
        }
    });
}

function clampInt(value, fallback, min, max) {
    const n = parseInt(value ?? "", 10);
    if (!Number.isFinite(n)) return fallback;
    return Math.min(max, Math.max(min, n));
}

async function safeText(res) {
    try { return await res.text(); } catch { return ""; }
}

// ---------- RSS/Atom parsing (DOMParser) ----------
function parseFeed(xml) {
    const doc = new DOMParser().parseFromString(xml, "text/xml");

    // Atom?
    const atomEntries = [...doc.getElementsByTagName("entry")];
    if (atomEntries.length) {
        const items = atomEntries.map(e => ({
            title: text(e, "title"),
            link: atomLink(e),
            pubDate: text(e, "updated") || text(e, "published"),
            description: text(e, "summary") || text(e, "content")
        })).filter(i => i.title || i.link);

        return { format: "atom", items };
    }

// RSS?
