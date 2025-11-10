// app.js
// Frontend JS for AI SQLi Detector
// - Supports index.html (query check) and admin.html (stats)
// - Update API_BASE if your backend runs on a different host/port
const API_BASE = "http://127.0.0.1:5000"; // change if necessary
const FETCH_TIMEOUT_MS = 8000; // 8s timeout for API calls

/* ---------- Helpers ---------- */
function el(id) { return document.getElementById(id); }

function withTimeout(fetchPromise, timeout = FETCH_TIMEOUT_MS) {
    const controller = new AbortController();
    const id = setTimeout(() => controller.abort(), timeout);
    return fetchPromise({ signal: controller.signal }).finally(() => clearTimeout(id));
}

function safeJson(resp) {
    return resp.json().catch(() => ({}));
}

function setResult(message, type = "info") {
    // type: 'info' | 'safe' | 'sqli' | 'error'
    const resultEl = el("result") || el("resultLabel") || null;
    if (!resultEl) return;
    resultEl.innerHTML = message;
    resultEl.style.color = {
        safe: "#22c55e",
        sqli: "#ef4444",
        error: "#f59e0b",
        info: "#fff"
    }[type] || "#fff";
}

/* ---------- Query Check (index.html) ---------- */
async function checkQuery() {
    const queryInput = el("queryInput") || el("sqlQuery") || el("queryInputText") || null;
    const checkBtn = el("checkBtn") || el("checkQueryBtn") || null;
    if (!queryInput) return alert("Query input not found on page.");

    const query = queryInput.value.trim();
    if (!query) {
        setResult("Please enter a SQL query.", "error");
        return;
    }

    if (checkBtn) {
        checkBtn.disabled = true;
        checkBtn.innerText = "Checking...";
    }

    try {
        const resp = await withTimeout((opts) => fetch(`${API_BASE}/check`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ query }),
            signal: opts.signal
        }), FETCH_TIMEOUT_MS);

        if (!resp.ok) {
            // try to read JSON error or show generic
            const err = await safeJson(resp);
            const msg = err.message || `Server returned ${resp.status}`;
            setResult(`Server Error: ${msg}`, "error");
        } else {
            const data = await safeJson(resp);
            handleCheckResult(data);
            // refresh stats after each check (if admin / stats area present)
            await fetchStats();
        }
    } catch (e) {
        console.error("checkQuery error:", e);
        if (e.name === "AbortError") {
            setResult("Request timed out. Backend may be slow or unreachable.", "error");
        } else {
            setResult("Backend not reachable. Start server and try again.", "error");
        }
    } finally {
        if (checkBtn) {
            checkBtn.disabled = false;
            checkBtn.innerText = "Check Query";
        }
    }
}

function handleCheckResult(data) {
    // Expected shape from backend: { label: "sqli"|"safe", confidence: 0.9|null, reason: "rule:..."/"ml"/... }
    if (!data || !data.label) {
        setResult("Invalid response from server.", "error");
        return;
    }

    const label = String(data.label).toLowerCase();
    const reason = data.reason ? String(data.reason) : "No reason provided";
    const conf = (data.confidence !== undefined && data.confidence !== null) ? ` (conf: ${(data.confidence*100).toFixed(1)}%)` : "";

    if (label === "sqli" || label === "malicious") {
        setResult(`🚫 Unsafe Query Detected${conf}<br><small>Reason: ${reason}</small>`, "sqli");
    } else if (label === "safe" || label === "benign") {
        setResult(`✅ Safe Query${conf}<br><small>Reason: ${reason}</small>`, "safe");
    } else {
        setResult(`${label.toUpperCase()} - ${reason}`, "info");
    }
}

/* ---------- Stats (admin.html and index.html optional) ---------- */
async function fetchStats() {
    const totalEl = el("total") || el("totalQueries") || el("totalQueriesSpan");
    const safeEl  = el("safe")  || el("safeQueries")  || el("safeQueriesSpan");
    const attacksEl = el("attacks") || el("sqliQueries") || el("blockedQueries");

    const refreshBtn = el("refreshStats") || el("refreshBtn") || null;
    if (refreshBtn) {
        refreshBtn.disabled = true;
        refreshBtn.innerText = "Loading...";
    }

    try {
        const resp = await withTimeout((opts) => fetch(API_BASE + "/stats", { signal: opts.signal }), FETCH_TIMEOUT_MS);
        if (!resp.ok) {
            console.error("Stats fetch failed", resp.status);
            return;
        }
        const stats = await safeJson(resp);
        if (totalEl) totalEl.innerText = stats.total ?? 0;
        if (safeEl) safeEl.innerText = stats.safe ?? 0;
        if (attacksEl) attacksEl.innerText = stats.attacks ?? 0;
    } catch (e) {
        console.error("fetchStats error:", e);
        // silently fail (keep previous numbers), but log to console
    } finally {
        if (refreshBtn) {
            refreshBtn.disabled = false;
            refreshBtn.innerText = "Refresh Stats";
        }
    }
}

/* ---------- Auto-refresh on admin page ---------- */
let statsInterval = null;
function startAutoRefresh() {
    // only start if admin page is present
    if (!el("statsSection") && !el("stats") && !el("total")) return;
    // fetch immediately then every 5s
    fetchStats();
    if (!statsInterval) statsInterval = setInterval(fetchStats, 5000);
}
function stopAutoRefresh() {
    if (statsInterval) {
        clearInterval(statsInterval);
        statsInterval = null;
    }
}

/* ---------- Wire UI elements on load ---------- */
window.addEventListener("DOMContentLoaded", () => {
    // Query check bindings
    const checkBtn = el("checkBtn") || el("checkQueryBtn") || null;
    const queryInput = el("queryInput") || el("sqlQuery") || null;

    if (checkBtn && queryInput) {
        checkBtn.addEventListener("click", checkQuery);
        // allow Ctrl+Enter to submit
        queryInput.addEventListener("keydown", (e) => {
            if ((e.ctrlKey || e.metaKey) && e.key === "Enter") checkQuery();
        });
    }

    // Stats bindings
    const refreshBtn = el("refreshStats") || el("refreshBtn") || null;
    if (refreshBtn) refreshBtn.addEventListener("click", fetchStats);

    // Auto refresh on admin page
    startAutoRefresh();
});

/* ---------- Expose for debugging (optional) ---------- */
window.__sqlidetector = {
    checkQuery,
    fetchStats,
    startAutoRefresh,
    stopAutoRefresh,
    setResult
};