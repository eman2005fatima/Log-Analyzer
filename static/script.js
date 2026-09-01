const state = {
  analysisId: document.body.dataset.initialAnalysisId || "",
  stats: null,
  anomalies: [],
  entries: [],
  anomalyPage: 1,
  entryPage: 1,
  anomalySort: { key: "severity", direction: "asc" },
  entrySort: { key: "timestamp", direction: "desc" },
};

const pageSize = 10;
const uploadForm = document.querySelector("#upload-form");
const fileInput = document.querySelector("#log-file");
const fileLabel = document.querySelector("#file-label");
const dropZone = document.querySelector("#drop-zone");
const statusMessage = document.querySelector("#status-message");
const loadSampleButton = document.querySelector("#load-sample");
const exportJson = document.querySelector("#export-json");
const exportCsv = document.querySelector("#export-csv");

uploadForm.addEventListener("submit", uploadFile);
loadSampleButton.addEventListener("click", loadSample);
fileInput.addEventListener("change", () => {
  fileLabel.textContent = fileInput.files[0]?.name || "Choose or drop a log file";
});

["dragenter", "dragover"].forEach((eventName) => {
  dropZone.addEventListener(eventName, (event) => {
    event.preventDefault();
    dropZone.classList.add("dragging");
  });
});

["dragleave", "drop"].forEach((eventName) => {
  dropZone.addEventListener(eventName, (event) => {
    event.preventDefault();
    dropZone.classList.remove("dragging");
  });
});

dropZone.addEventListener("drop", (event) => {
  if (event.dataTransfer.files.length > 0) {
    fileInput.files = event.dataTransfer.files;
    fileLabel.textContent = fileInput.files[0].name;
  }
});

document.querySelector("#anomaly-search").addEventListener("input", () => {
  state.anomalyPage = 1;
  renderAnomalyTable();
});

["#entry-ip", "#entry-level", "#entry-keyword", "#entry-start", "#entry-end"].forEach((selector) => {
  document.querySelector(selector).addEventListener("input", () => {
    state.entryPage = 1;
    renderEntryTable();
  });
});

document.querySelectorAll("[data-sort-anomaly]").forEach((header) => {
  header.addEventListener("click", () => {
    updateSort(state.anomalySort, header.dataset.sortAnomaly);
    renderAnomalyTable();
  });
});

document.querySelectorAll("[data-sort-entry]").forEach((header) => {
  header.addEventListener("click", () => {
    updateSort(state.entrySort, header.dataset.sortEntry);
    renderEntryTable();
  });
});

document.querySelector("#anomaly-prev").addEventListener("click", () => {
  state.anomalyPage = Math.max(1, state.anomalyPage - 1);
  renderAnomalyTable();
});

document.querySelector("#anomaly-next").addEventListener("click", () => {
  state.anomalyPage += 1;
  renderAnomalyTable();
});

document.querySelector("#entry-prev").addEventListener("click", () => {
  state.entryPage = Math.max(1, state.entryPage - 1);
  renderEntryTable();
});

document.querySelector("#entry-next").addEventListener("click", () => {
  state.entryPage += 1;
  renderEntryTable();
});

if (state.analysisId) {
  loadAnalysis(state.analysisId);
}

async function uploadFile(event) {
  event.preventDefault();
  if (!fileInput.files.length) {
    setStatus("Please choose a log file first.", true);
    return;
  }

  const formData = new FormData();
  formData.append("file", fileInput.files[0]);
  await sendAnalysisRequest("/upload", { method: "POST", body: formData });
}

async function loadSample() {
  await sendAnalysisRequest("/sample", { method: "POST" });
}

async function sendAnalysisRequest(url, options) {
  setLoading(true);
  try {
    const response = await fetch(url, options);
    const data = await response.json();
    if (!response.ok) {
      throw new Error(data.error || "Analysis request failed.");
    }
    state.analysisId = data.analysis_id;
    await loadAnalysis(state.analysisId);
    setStatus(buildAnalysisMessage(data.filename, data.warnings), false);
  } catch (error) {
    setStatus(error.message, true);
  } finally {
    setLoading(false);
  }
}

async function loadAnalysis(analysisId) {
  const [statsResponse, anomaliesResponse] = await Promise.all([
    fetch(`/stats/${analysisId}`),
    fetch(`/anomalies/${analysisId}`),
  ]);
  const statsData = await statsResponse.json();
  const anomalyData = await anomaliesResponse.json();

  state.stats = statsData.statistics;
  state.entries = statsData.entries;
  state.anomalies = anomalyData;
  state.anomalyPage = 1;
  state.entryPage = 1;

  renderSummary();
  renderCharts();
  renderAnomalyTable();
  renderEntryTable();
  updateExports();
}

function renderSummary() {
  document.querySelector("#total-lines").textContent = state.stats.total_lines;
  document.querySelector("#parsed-percent").textContent = `${state.stats.parsed_percent}%`;
  document.querySelector("#unique-ips").textContent = state.stats.unique_ips;
  document.querySelector("#anomaly-count").textContent = state.stats.anomaly_count;
}

function buildAnalysisMessage(filename, warnings = {}) {
  const notes = [];
  if (warnings.unparseable_lines) {
    notes.push(`${warnings.unparseable_lines} unmatched lines preserved`);
  }
  if (warnings.empty_lines_skipped) {
    notes.push(`${warnings.empty_lines_skipped} empty lines skipped`);
  }
  if (state.stats && state.entries.length > 0) {
    if (state.stats.requests_per_hour.length === 0) {
      notes.push("no timestamps found for timeline");
    }
    if (state.stats.top_ips.length === 0) {
      notes.push("no IP addresses found for IP chart");
    }
    const statusTotal = Object.values(state.stats.status_codes.classes).reduce((sum, count) => sum + count, 0);
    if (statusTotal === 0) {
      notes.push("no HTTP status codes found");
    }
  }
  return notes.length ? `Analyzed ${filename}. ${notes.join("; ")}.` : `Analyzed ${filename}.`;
}

function renderCharts() {
  drawLineChart(
    "timeline-chart",
    state.stats.requests_per_hour.map((item) => item.hour),
    state.stats.requests_per_hour.map((item) => item.count),
  );

  drawHorizontalBarChart(
    "top-ip-chart",
    state.stats.top_ips.map((item) => item.ip),
    state.stats.top_ips.map((item) => item.count),
    "#1c6b75",
  );

  drawDonutChart(
    "status-chart",
    Object.keys(state.stats.status_codes.classes),
    Object.values(state.stats.status_codes.classes),
    ["#2f855a", "#4c78a8", "#c05621", "#b42318", "#98a2b3"],
  );

  drawBarChart(
    "level-chart",
    Object.keys(state.stats.log_levels),
    Object.values(state.stats.log_levels),
    "#475467",
  );
}

function setupCanvas(canvasId) {
  const canvas = document.querySelector(`#${canvasId}`);
  const rect = canvas.parentElement.getBoundingClientRect();
  const ratio = window.devicePixelRatio || 1;
  const width = Math.max(280, Math.floor(rect.width - 36));
  const height = 240;
  canvas.width = width * ratio;
  canvas.height = height * ratio;
  canvas.style.width = `${width}px`;
  canvas.style.height = `${height}px`;
  const context = canvas.getContext("2d");
  context.setTransform(ratio, 0, 0, ratio, 0, 0);
  context.clearRect(0, 0, width, height);
  context.font = "12px system-ui, sans-serif";
  context.fillStyle = "#667085";
  return { canvas, context, width, height };
}

function drawLineChart(canvasId, labels, values) {
  const { context, width, height } = setupCanvas(canvasId);
  const padding = { top: 18, right: 18, bottom: 42, left: 42 };
  const chartWidth = width - padding.left - padding.right;
  const chartHeight = height - padding.top - padding.bottom;
  const max = Math.max(1, ...values);

  drawAxes(context, padding, width, height);
  if (!values.length) {
    drawEmptyChart(context, width, height);
    return;
  }

  const points = values.map((value, index) => {
    const x = padding.left + (labels.length === 1 ? chartWidth / 2 : (index / (labels.length - 1)) * chartWidth);
    const y = padding.top + chartHeight - (value / max) * chartHeight;
    return { x, y };
  });

  context.beginPath();
  context.strokeStyle = "#1c6b75";
  context.lineWidth = 3;
  points.forEach((point, index) => {
    if (index === 0) context.moveTo(point.x, point.y);
    else context.lineTo(point.x, point.y);
  });
  context.stroke();

  context.fillStyle = "#1c6b75";
  points.forEach((point) => {
    context.beginPath();
    context.arc(point.x, point.y, 4, 0, Math.PI * 2);
    context.fill();
  });

  drawLabel(context, labels[0] || "", padding.left, height - 14, "left");
  drawLabel(context, labels[labels.length - 1] || "", width - padding.right, height - 14, "right");
}

function drawBarChart(canvasId, labels, values, color) {
  const { context, width, height } = setupCanvas(canvasId);
  const padding = { top: 18, right: 18, bottom: 54, left: 42 };
  const chartWidth = width - padding.left - padding.right;
  const chartHeight = height - padding.top - padding.bottom;
  const max = Math.max(1, ...values);

  drawAxes(context, padding, width, height);
  if (!values.length) {
    drawEmptyChart(context, width, height);
    return;
  }

  const gap = 8;
  const barWidth = Math.max(12, (chartWidth - gap * (values.length - 1)) / values.length);
  values.forEach((value, index) => {
    const barHeight = (value / max) * chartHeight;
    const x = padding.left + index * (barWidth + gap);
    const y = padding.top + chartHeight - barHeight;
    context.fillStyle = color;
    context.fillRect(x, y, barWidth, barHeight);
    drawLabel(context, String(value), x + barWidth / 2, y - 5, "center");
    drawLabel(context, truncate(labels[index], 10), x + barWidth / 2, height - 18, "center");
  });
}

function drawHorizontalBarChart(canvasId, labels, values, color) {
  const { context, width, height } = setupCanvas(canvasId);
  const padding = { top: 12, right: 34, bottom: 20, left: 92 };
  const chartWidth = width - padding.left - padding.right;
  const rowHeight = Math.max(16, (height - padding.top - padding.bottom) / Math.max(values.length, 1));
  const max = Math.max(1, ...values);

  if (!values.length) {
    drawEmptyChart(context, width, height);
    return;
  }

  values.forEach((value, index) => {
    const y = padding.top + index * rowHeight + 4;
    const barHeight = Math.max(8, rowHeight - 9);
    const barWidth = (value / max) * chartWidth;
    drawLabel(context, truncate(labels[index], 14), padding.left - 8, y + barHeight - 2, "right");
    context.fillStyle = "#edf2f7";
    context.fillRect(padding.left, y, chartWidth, barHeight);
    context.fillStyle = color;
    context.fillRect(padding.left, y, barWidth, barHeight);
    drawLabel(context, String(value), padding.left + barWidth + 6, y + barHeight - 2, "left");
  });
}

function drawDonutChart(canvasId, labels, values, colors) {
  const { context, width, height } = setupCanvas(canvasId);
  const total = values.reduce((sum, value) => sum + value, 0);
  const centerX = width * 0.36;
  const centerY = height / 2;
  const radius = Math.min(width, height) * 0.32;
  let start = -Math.PI / 2;

  if (!total) {
    drawEmptyChart(context, width, height);
    return;
  }

  values.forEach((value, index) => {
    const angle = (value / total) * Math.PI * 2;
    context.beginPath();
    context.moveTo(centerX, centerY);
    context.arc(centerX, centerY, radius, start, start + angle);
    context.closePath();
    context.fillStyle = colors[index % colors.length];
    context.fill();
    start += angle;
  });

  context.beginPath();
  context.fillStyle = "#ffffff";
  context.arc(centerX, centerY, radius * 0.55, 0, Math.PI * 2);
  context.fill();

  labels.forEach((label, index) => {
    const x = width * 0.68;
    const y = 54 + index * 26;
    context.fillStyle = colors[index % colors.length];
    context.fillRect(x, y - 10, 12, 12);
    context.fillStyle = "#354052";
    context.textAlign = "left";
    context.fillText(`${label}: ${values[index]}`, x + 18, y);
  });
}

function drawAxes(context, padding, width, height) {
  context.strokeStyle = "#d7dde6";
  context.lineWidth = 1;
  context.beginPath();
  context.moveTo(padding.left, padding.top);
  context.lineTo(padding.left, height - padding.bottom);
  context.lineTo(width - padding.right, height - padding.bottom);
  context.stroke();
}

function drawEmptyChart(context, width, height) {
  context.fillStyle = "#667085";
  context.textAlign = "center";
  context.fillText("No chart data yet", width / 2, height / 2);
}

function drawLabel(context, text, x, y, align) {
  context.fillStyle = "#667085";
  context.textAlign = align;
  context.fillText(text, x, y);
}

function truncate(value, length) {
  const text = String(value);
  return text.length > length ? `${text.slice(0, length - 1)}...` : text;
}

function renderAnomalyTable() {
  const search = document.querySelector("#anomaly-search").value.toLowerCase();
  const filtered = state.anomalies.filter((item) => JSON.stringify(item).toLowerCase().includes(search));
  const sorted = sortItems(filtered, state.anomalySort);
  const page = paginate(sorted, state.anomalyPage);
  const tbody = document.querySelector("#anomaly-table");

  tbody.innerHTML = page.items.map((item) => `
    <tr>
      <td>${escapeHtml(item.ip)}</td>
      <td>${escapeHtml(item.type.replaceAll("_", " "))}</td>
      <td><span class="badge severity-${item.severity}">${escapeHtml(item.severity)}</span></td>
      <td>${item.count}</td>
      <td class="message">${escapeHtml(item.description)}</td>
    </tr>
  `).join("") || `<tr><td colspan="5">No anomalies match the current filters.</td></tr>`;

  updatePager("anomaly", page);
}

function renderEntryTable() {
  const ip = document.querySelector("#entry-ip").value.toLowerCase();
  const level = document.querySelector("#entry-level").value.toLowerCase();
  const keyword = document.querySelector("#entry-keyword").value.toLowerCase();
  const start = document.querySelector("#entry-start").value;
  const end = document.querySelector("#entry-end").value;

  const filtered = state.entries.filter((entry) => {
    const timestamp = entry.timestamp || "";
    return (!ip || (entry.ip_address || "").toLowerCase().includes(ip))
      && (!level || (entry.log_level || "").toLowerCase().includes(level))
      && (!keyword || (`${entry.message} ${entry.raw_line}`).toLowerCase().includes(keyword))
      && (!start || timestamp >= start)
      && (!end || timestamp <= end);
  });

  const sorted = sortItems(filtered, state.entrySort);
  const page = paginate(sorted, state.entryPage);
  const tbody = document.querySelector("#entry-table");

  tbody.innerHTML = page.items.map((entry) => `
    <tr>
      <td>${escapeHtml(entry.timestamp || "n/a")}</td>
      <td>${escapeHtml(entry.ip_address || "n/a")}</td>
      <td class="level-${escapeHtml(entry.log_level)}">${escapeHtml(entry.log_level)}</td>
      <td>${escapeHtml(entry.status_code || "")}</td>
      <td>${escapeHtml(entry.source_format)}</td>
      <td class="message">${escapeHtml(entry.message)}</td>
    </tr>
  `).join("") || `<tr><td colspan="6">No log entries match the current filters.</td></tr>`;

  updatePager("entry", page);
}

function sortItems(items, sortState) {
  const severityRank = { high: 1, medium: 2, low: 3 };
  return [...items].sort((a, b) => {
    const left = sortState.key === "severity" ? severityRank[a[sortState.key]] : a[sortState.key];
    const right = sortState.key === "severity" ? severityRank[b[sortState.key]] : b[sortState.key];
    if (left === right) return 0;
    const result = left > right ? 1 : -1;
    return sortState.direction === "asc" ? result : -result;
  });
}

function updateSort(sortState, key) {
  if (sortState.key === key) {
    sortState.direction = sortState.direction === "asc" ? "desc" : "asc";
    return;
  }
  sortState.key = key;
  sortState.direction = "asc";
}

function paginate(items, currentPage) {
  const totalPages = Math.max(1, Math.ceil(items.length / pageSize));
  const safePage = Math.min(currentPage, totalPages);
  const start = (safePage - 1) * pageSize;
  return { items: items.slice(start, start + pageSize), page: safePage, totalPages };
}

function updatePager(prefix, page) {
  state[`${prefix}Page`] = page.page;
  document.querySelector(`#${prefix}-page`).textContent = `Page ${page.page} of ${page.totalPages}`;
  document.querySelector(`#${prefix}-prev`).disabled = page.page <= 1;
  document.querySelector(`#${prefix}-next`).disabled = page.page >= page.totalPages;
}

function updateExports() {
  exportJson.href = `/export/${state.analysisId}?format=json`;
  exportCsv.href = `/export/${state.analysisId}?format=csv`;
  exportJson.classList.remove("disabled");
  exportCsv.classList.remove("disabled");
}

function setLoading(isLoading) {
  uploadForm.querySelector("button").disabled = isLoading;
  loadSampleButton.disabled = isLoading;
  if (isLoading) {
    setStatus("Uploading and parsing log data...", false);
  }
}

function setStatus(message, isError) {
  statusMessage.textContent = message;
  statusMessage.style.color = isError ? "#b42318" : "#667085";
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}
