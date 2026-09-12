"use strict";

const fileInput = document.querySelector("#log-file");
const dropZone = document.querySelector("#drop-zone");
const selectedFile = document.querySelector("#selected-file");

function showFilename() {
  if (fileInput?.files.length) selectedFile.textContent = fileInput.files[0].name;
}

fileInput?.addEventListener("change", showFilename);
dropZone?.addEventListener("dragover", (event) => {
  event.preventDefault();
  dropZone.classList.add("dragging");
});
dropZone?.addEventListener("dragleave", () => dropZone.classList.remove("dragging"));
dropZone?.addEventListener("drop", (event) => {
  event.preventDefault();
  dropZone.classList.remove("dragging");
  if (event.dataTransfer.files.length) {
    fileInput.files = event.dataTransfer.files;
    showFilename();
  }
});

const staticToggle = document.querySelector("#show-static");
const queryToggle = document.querySelector("#hide-queries");
const pathFilter = document.querySelector("#path-filter");
const filterButtons = [...document.querySelectorAll(".filter-button")];
let activeFilter = "all";

function applyFilters() {
  const needle = (pathFilter?.value || "").trim().toLowerCase();
  document.body.classList.toggle("show-static", Boolean(staticToggle?.checked));
  document.body.classList.toggle("hide-queries", Boolean(queryToggle?.checked));

  document.querySelectorAll(".session").forEach((session) => {
    let visible = 0;
    session.querySelectorAll(".request-row").forEach((row) => {
      const isStatic = row.classList.contains("static-request");
      const statusIsError = Number(row.dataset.status) >= 400;
      const staticAllowed = statusIsError || staticToggle.checked || !isStatic;
      const typeAllowed = activeFilter === "all" || row.dataset.method === activeFilter || row.dataset.statusGroup === activeFilter;
      const pathAllowed = !needle || row.dataset.path.includes(needle);
      const show = staticAllowed && typeAllowed && pathAllowed;
      row.hidden = !show;
      if (show) visible += 1;
    });
    const message = session.querySelector(".empty-filter-message");
    if (message) message.hidden = visible !== 0;
  });
}

staticToggle?.addEventListener("change", applyFilters);
queryToggle?.addEventListener("change", applyFilters);
pathFilter?.addEventListener("input", applyFilters);
filterButtons.forEach((button) => button.addEventListener("click", () => {
  activeFilter = button.dataset.filter;
  filterButtons.forEach((item) => item.classList.toggle("active", item === button));
  applyFilters();
}));
if (staticToggle) applyFilters();

const compareLeft = document.querySelector("#compare-left");
const compareRight = document.querySelector("#compare-right");
const hideCommonPrefix = document.querySelector("#hide-common-prefix");
const journeyData = new Map(
  [...document.querySelectorAll("#journey-data [data-session]")].map((node) => [
    node.dataset.session,
    JSON.parse(node.dataset.requests),
  ]),
);

function commonPrefixLength(left, right) {
  let length = 0;
  while (
    length < left.length &&
    length < right.length &&
    left[length].method === right[length].method &&
    left[length].path === right[length].path
  ) {
    length += 1;
  }
  return length;
}

function makeCompareCell(request, sessionNumber, onlyInSession) {
  const cell = document.createElement("div");
  cell.className = "compare-cell";
  cell.dataset.sessionLabel = `Session #${sessionNumber}`;
  if (!request) {
    cell.classList.add("empty-compare-cell");
    cell.setAttribute("aria-hidden", "true");
    return cell;
  }

  const sequence = document.createElement("span");
  sequence.className = "compare-sequence";
  sequence.textContent = `#${String(request.sequence).padStart(2, "0")}`;

  const timestamp = document.createElement("time");
  timestamp.textContent = request.timestamp;

  const method = document.createElement("span");
  method.className = `method method-${request.method.toLowerCase()}`;
  method.textContent = request.method;

  const path = document.createElement("span");
  path.className = "compare-path";
  path.textContent = request.path;
  path.title = request.path;

  const status = document.createElement("span");
  status.className = `status status-${Math.floor(request.status / 100)}xx`;
  status.textContent = String(request.status);

  cell.append(sequence, timestamp, method, path, status);
  if (onlyInSession) {
    const only = document.createElement("span");
    only.className = "only-in-session";
    only.textContent = `Only in Session #${sessionNumber}`;
    cell.append(only);
  }
  return cell;
}

function renderComparison() {
  const target = document.querySelector("#compare-rows");
  if (!target || !compareLeft || !compareRight) return;

  const left = journeyData.get(compareLeft.value) || [];
  const right = journeyData.get(compareRight.value) || [];
  const prefixLength = commonPrefixLength(left, right);
  const rowCount = Math.max(left.length, right.length);
  const start = hideCommonPrefix?.checked ? prefixLength : 0;
  const rows = [];

  document.querySelector("#left-session-heading").textContent = `Session #${compareLeft.value}`;
  document.querySelector("#right-session-heading").textContent = `Session #${compareRight.value}`;

  const hiddenNote = document.querySelector("#common-hidden-note");
  hiddenNote.hidden = !hideCommonPrefix?.checked || prefixLength === 0;
  hiddenNote.textContent = `${prefixLength} common ${prefixLength === 1 ? "request" : "requests"} hidden`;

  for (let index = start; index < rowCount; index += 1) {
    const leftRequest = left[index];
    const rightRequest = right[index];
    const different = !leftRequest || !rightRequest ||
      leftRequest.method !== rightRequest.method || leftRequest.path !== rightRequest.path;

    if (index === prefixLength && different) {
      const marker = document.createElement("div");
      marker.className = "divergence-marker";
      marker.textContent = "First divergence";
      rows.push(marker);
    }

    const pair = document.createElement("div");
    pair.className = `compare-pair ${different ? "different" : "common"}`;
    pair.append(
      makeCompareCell(leftRequest, compareLeft.value, Boolean(leftRequest && !rightRequest)),
      makeCompareCell(rightRequest, compareRight.value, Boolean(rightRequest && !leftRequest)),
    );
    rows.push(pair);
  }

  if (prefixLength === rowCount) {
    const same = document.createElement("p");
    same.className = "same-journey-note";
    same.textContent = "No positional differences in these application requests.";
    rows.push(same);
  }
  target.replaceChildren(...rows);
}

function keepSessionsDifferent(changed, other) {
  if (changed.value !== other.value) return;
  const alternative = [...other.options].find((option) => option.value !== changed.value);
  if (alternative) other.value = alternative.value;
}

compareLeft?.addEventListener("change", () => {
  keepSessionsDifferent(compareLeft, compareRight);
  renderComparison();
});
compareRight?.addEventListener("change", () => {
  keepSessionsDifferent(compareRight, compareLeft);
  renderComparison();
});
hideCommonPrefix?.addEventListener("change", renderComparison);
renderComparison();
