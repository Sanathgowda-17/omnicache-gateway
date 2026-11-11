/**
 * app.js — OmniCache & Guard Client Controller
 * Handles real-time telemetry streaming, interactive playground queries, and metric updates.
 */

document.addEventListener("DOMContentLoaded", () => {
  // DOM Elements
  const chatForm = document.getElementById("chatForm");
  const promptInput = document.getElementById("promptInput");
  const bypassCacheToggle = document.getElementById("bypassCacheToggle");
  const thresholdSlider = document.getElementById("thresholdSlider");
  const thresholdVal = document.getElementById("thresholdVal");
  const submitBtn = document.getElementById("submitBtn");
  const btnText = document.getElementById("btnText");
  const btnSpinner = document.getElementById("btnSpinner");

  const responseContainer = document.getElementById("responseContainer");
  const cacheBadge = document.getElementById("cacheBadge");
  const latencyBadge = document.getElementById("latencyBadge");
  const providerBadge = document.getElementById("providerBadge");
  const simScoreVal = document.getElementById("simScoreVal");
  const piiAlertBar = document.getElementById("piiAlertBar");
  const piiAlertText = document.getElementById("piiAlertText");
  const responseContent = document.getElementById("responseContent");
  const matchedBox = document.getElementById("matchedBox");
  const matchedPromptText = document.getElementById("matchedPromptText");

  // Metrics Elements
  const metricHitRatio = document.getElementById("metricHitRatio");
  const metricHitCount = document.getElementById("metricHitCount");
  const metricLatencySaved = document.getElementById("metricLatencySaved");
  const metricTokensSaved = document.getElementById("metricTokensSaved");
  const metricCostSaved = document.getElementById("metricCostSaved");
  const metricPiiCount = document.getElementById("metricPiiCount");

  // Telemetry Table & Actions
  const logsTableBody = document.getElementById("logsTableBody");
  const refreshLogsBtn = document.getElementById("refreshLogsBtn");
  const seedBtn = document.getElementById("seedBtn");
  const clearCacheBtn = document.getElementById("clearCacheBtn");

  // Threshold slider live label
  thresholdSlider.addEventListener("input", (e) => {
    thresholdVal.textContent = e.target.value;
  });

  // Preset chips click handler
  document.querySelectorAll(".preset-chip").forEach(chip => {
    chip.addEventListener("click", () => {
      promptInput.value = chip.getAttribute("data-prompt");
      promptInput.focus();
    });
  });

  // Fetch metrics summary
  async function fetchMetrics() {
    try {
      const res = await fetch("/api/metrics");
      if (!res.ok) return;
      const data = await res.json();

      metricHitRatio.textContent = `${data.hit_ratio_percent}%`;
      metricHitCount.textContent = `${data.cache_hits} hits / ${data.total_requests} total`;
      metricLatencySaved.textContent = `${data.total_latency_saved_ms.toLocaleString()} ms`;
      metricTokensSaved.textContent = data.total_tokens_saved.toLocaleString();
      metricCostSaved.textContent = `$${data.estimated_cost_saved_usd.toFixed(4)}`;
      metricPiiCount.textContent = data.total_pii_redacted.toLocaleString();
    } catch (err) {
      console.error("Failed to fetch metrics:", err);
    }
  }

  // Fetch telemetry logs
  async function fetchLogs() {
    try {
      const res = await fetch("/api/logs?limit=15");
      if (!res.ok) return;
      const logs = await res.json();

      if (!logs || logs.length === 0) {
        logsTableBody.innerHTML = `<tr><td colspan="5" class="empty-state">No requests dispatched yet. Click a quick test above!</td></tr>`;
        return;
      }

      logsTableBody.innerHTML = logs.map(log => {
        const isHit = log.cache_status === "HIT";
        const badgeClass = isHit ? "badge hit" : "badge miss";
        const simDisplay = log.similarity_score ? log.similarity_score.toFixed(3) : "—";
        const latencyDisplay = `${log.latency_ms.toFixed(1)} ms`;

        return `
          <tr>
            <td><span class="${badgeClass}">${log.cache_status}</span></td>
            <td class="prompt-truncate" title="${escapeHtml(log.sanitized_prompt)}">${escapeHtml(log.sanitized_prompt)}</td>
            <td><code>${simDisplay}</code></td>
            <td><strong>${latencyDisplay}</strong></td>
            <td><span style="font-size:0.75rem; color:#9ca3af;">${escapeHtml(log.provider)}</span></td>
          </tr>
        `;
      }).join("");
    } catch (err) {
      console.error("Failed to fetch logs:", err);
    }
  }

  // Form Submission
  chatForm.addEventListener("submit", async (e) => {
    e.preventDefault();
    const prompt = promptInput.value.trim();
    if (!prompt) return;

    // Loading State
    submitBtn.disabled = true;
    btnText.textContent = "Processing via Gateway...";
    btnSpinner.classList.remove("hidden");

    try {
      const payload = {
        prompt: prompt,
        bypass_cache: bypassCacheToggle.checked,
        similarity_threshold: parseFloat(thresholdSlider.value)
      };

      const res = await fetch("/api/chat", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload)
      });

      if (!res.ok) {
        const err = await res.json();
        throw new Error(err.detail || "Gateway error");
      }

      const data = await res.json();

      // Display results
      responseContainer.classList.remove("hidden");

      // Cache Badge
      const isHit = data.cache_status === "HIT";
      cacheBadge.textContent = isHit ? "CACHE HIT" : "CACHE MISS";
      cacheBadge.className = `badge ${isHit ? "hit" : "miss"}`;

      // Latency & Provider Badges
      latencyBadge.textContent = `${data.latency_ms} ms`;
      providerBadge.textContent = data.provider;

      // Cosine Similarity
      simScoreVal.textContent = data.similarity_score.toFixed(3);

      // PII Alert
      if (data.pii_redacted && data.pii_redacted.length > 0) {
        const types = data.pii_redacted.map(p => `${p.count} ${p.entity_type}`).join(", ");
        piiAlertText.textContent = `Security Guard: Automatically redacted ${types} before forwarding.`;
        piiAlertBar.classList.remove("hidden");
      } else {
        piiAlertBar.classList.add("hidden");
      }

      // Response text
      responseContent.textContent = data.response;

      // Matched Memory Box
      if (isHit && data.matched_prompt) {
        matchedPromptText.textContent = `"${data.matched_prompt}"`;
        matchedBox.classList.remove("hidden");
      } else {
        matchedBox.classList.add("hidden");
      }

      // Refresh metrics and logs
      fetchMetrics();
      fetchLogs();

    } catch (err) {
      alert(`Error from Gateway: ${err.message}`);
    } finally {
      submitBtn.disabled = false;
      btnText.textContent = "Dispatch Through Gateway";
      btnSpinner.classList.add("hidden");
    }
  });

  // Seed Demo Knowledge
  seedBtn.addEventListener("click", async () => {
    seedBtn.disabled = true;
    seedBtn.textContent = "Seeding...";
    try {
      const res = await fetch("/api/cache/seed", { method: "POST" });
      const data = await res.json();
      alert(`✅ ${data.message}\nTry typing 'I forgot my password' to test instant sub-15ms semantic matching!`);
      fetchMetrics();
      fetchLogs();
    } catch (err) {
      alert(`Error seeding: ${err.message}`);
    } finally {
      seedBtn.disabled = false;
      seedBtn.textContent = "⚡ Seed Knowledge";
    }
  });

  // Clear Cache
  clearCacheBtn.addEventListener("click", async () => {
    if (!confirm("Are you sure you want to clear the in-memory semantic cache?")) return;
    try {
      await fetch("/api/cache/clear", { method: "POST" });
      alert("🗑️ Semantic cache cleared.");
      responseContainer.classList.add("hidden");
      fetchMetrics();
      fetchLogs();
    } catch (err) {
      alert(`Error clearing cache: ${err.message}`);
    }
  });

  // Manual Refresh
  refreshLogsBtn.addEventListener("click", () => {
    fetchMetrics();
    fetchLogs();
  });

  // Helper
  function escapeHtml(str) {
    if (!str) return "";
    return str
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#039;");
  }

  // Initial Load
  fetchMetrics();
  fetchLogs();
});
