/* app.js - frontend logic used by both index.html & admin.html
   Important: set window.APP_CONFIG.BACKEND_URL in index/admin HTML before this script
*/

const CONFIG = window.APP_CONFIG || {};
const BACKEND = CONFIG.BACKEND_URL || "http://127.0.0.1:5000";

function el(id){ return document.getElementById(id) }

// --- Index page logic ---
async function checkQueryHandler(){
  const ta = el("sqlQuery");
  const resultBox = el("resultBox");
  const resultLabel = el("resultLabel");
  const resultMeta = el("resultMeta");

  if(!ta) return;
  const q = ta.value.trim();
  resultBox.classList.remove("hidden");
  resultLabel.textContent = "Checking...";
  resultMeta.textContent = "";

  if(!q){ resultLabel.textContent = "Please enter a query."; resultLabel.style.color = "#f59e0b"; return; }

  try {
    const resp = await fetch(${BACKEND}/check, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ query: q })
    });
    if(!resp.ok) throw new Error("backend error");
    const data = await resp.json();
    // format
    if(data.label === "sqli"){
      resultLabel.textContent = "🚫 SQL Injection Detected";
      resultLabel.style.color = "#ff6b6b";
      resultMeta.textContent = Reason: ${data.reason || "ml/rule"}  •  Confidence: ${typeof data.confidence !== "undefined" ? data.confidence : "N/A"};
    } else if(data.label === "safe"){
      resultLabel.textContent = "✅ Query looks safe";
      resultLabel.style.color = "#6ee7b7";
      resultMeta.textContent = Reason: ${data.reason || "ml"}  •  Confidence: ${typeof data.confidence !== "undefined" ? data.confidence : "N/A"};
    } else {
      resultLabel.textContent = ⚠ ${data.label};
      resultLabel.style.color = "#f59e0b";
      resultMeta.textContent = String(data.reason || "");
    }
    // refresh stats after each check (if admin page open)
    await fetchStats();
  } catch(err){
    resultLabel.textContent = "❌ Backend not reachable";
    resultLabel.style.color = "#ff6b6b";
    resultMeta.textContent = String(err);
    console.error(err);
  }
}

// clear textarea
function clearQuery(){
  const ta = el("sqlQuery");
  if(ta) ta.value = "";
  const rb = el("resultBox");
  if(rb) rb.classList.add("hidden");
}

// --- Admin page logic ---
async function fetchStats(){
  try {
    const resp = await fetch(${BACKEND}/stats);
    if(!resp.ok) throw new Error("stats error");
    const data = await resp.json();
    if(el("totalQueries")) el("totalQueries").textContent = data.total ?? 0;
    if(el("safeQueries")) el("safeQueries").textContent = data.safe ?? 0;
    if(el("sqliQueries")) el("sqliQueries").textContent = data.attacks ?? 0;
    if(el("statsMsg")) el("statsMsg").textContent = "";
  } catch(err){
    console.error("fetchStats:", err);
    if(el("statsMsg")) el("statsMsg").textContent = "Could not load stats — backend unreachable";
  }
}

// export csv (basic)
async function exportCSV(){
  try {
    const resp = await fetch(${BACKEND}/export_logs); // optional endpoint in backend (see server instructions)
    if(!resp.ok) throw new Error("export failed");
    const text = await resp.text();
    const blob = new Blob([text], {type: "text/csv"});
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = "logs.csv";
    a.click();
  } catch(err){
    console.error("export error:", err);
    if(el("statsMsg")) el("statsMsg").textContent = "Export failed (server must implement /export_logs)";
  }
}

// attach listeners if DOM elements exist
document.addEventListener("DOMContentLoaded", () => {
  const checkBtn = el("checkBtn");
  if(checkBtn) checkBtn.addEventListener("click", checkQueryHandler);
  const clearBtn = el("clearBtn");
  if(clearBtn) clearBtn.addEventListener("click", clearQuery);
  const refreshBtn = el("refreshBtn");
  if(refreshBtn) refreshBtn.addEventListener("click", fetchStats);
  const exportBtn = el("exportBtn");
  if(exportBtn) exportBtn.addEventListener("click", exportCSV);

  // auto-load stats on admin page
  if(el("totalQueries")) fetchStats();
});
