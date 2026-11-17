const form = document.getElementById("scan-form");
const urlInput = document.getElementById("url-input");
const scanButton = document.getElementById("scan-button");
const errorMessage = document.getElementById("error-message");
const resultPanel = document.getElementById("result-panel");
const historyBody = document.getElementById("history-body");

function makeElement(tag, className, text) {
    const element = document.createElement(tag);
    if (className) element.className = className;
    if (text !== undefined) element.textContent = text;
    return element;
}

function riskClass(level) {
    if (level === "Cao") return "risk-high";
    if (level === "Trung bình") return "risk-medium";
    return "risk-low";
}

function showError(message) {
    errorMessage.textContent = message;
    errorMessage.hidden = false;
}

function hideError() {
    errorMessage.textContent = "";
    errorMessage.hidden = true;
}

form.addEventListener("submit", async (event) => {
    event.preventDefault();
    hideError();
    resultPanel.hidden = true;

    scanButton.disabled = true;
    scanButton.textContent = "ĐANG PHÂN TÍCH...";

    try {
        const response = await fetch("/api/scan", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ url: urlInput.value })
        });
        const data = await response.json();

        if (!response.ok) {
            throw new Error(data.error || "Không thể phân tích đường dẫn.");
        }

        renderResult(data);
        await loadHistory();
    } catch (error) {
        showError(error.message || "Không thể kết nối đến máy chủ.");
    } finally {
        scanButton.disabled = false;
        scanButton.innerHTML = "<span>⌕</span> PHÂN TÍCH";
    }
});

function renderResult(data) {
    document.getElementById("result-title").textContent = "Đã hoàn tất phân tích";
    document.getElementById("risk-badge").textContent = `RỦI RO ${data.level.toUpperCase()}`;
    document.getElementById("risk-badge").className = `risk-badge ${riskClass(data.level)}`;
    document.getElementById("risk-score").textContent = data.score;
    document.getElementById("score-circle").style.borderColor =
        data.level === "Cao" ? "#e66d78" : data.level === "Trung bình" ? "#d7ad50" : "#36b99a";
    document.getElementById("result-domain").textContent = data.domain;
    document.getElementById("result-scheme").textContent = data.scheme;
    document.getElementById("result-time").textContent = data.checked_at;
    document.getElementById("result-advice").textContent = data.advice;

    const list = document.getElementById("reasons-list");
    list.replaceChildren();
    data.reasons.forEach((reason) => list.append(makeElement("li", "", reason)));

    resultPanel.hidden = false;
    resultPanel.scrollIntoView({ behavior: "smooth", block: "nearest" });
}

async function loadHistory() {
    try {
        const response = await fetch("/api/history");
        if (!response.ok) throw new Error("Không tải được lịch sử.");
        const items = await response.json();
        renderHistory(items);
        updateStats(items);
    } catch (error) {
        historyBody.replaceChildren();
        const row = makeElement("tr");
        const cell = makeElement("td", "empty-state", error.message);
        cell.colSpan = 6;
        row.append(cell);
        historyBody.append(row);
    }
}

function updateStats(items) {
    document.getElementById("total-scans").textContent = items.length;
    document.getElementById("high-scans").textContent = items.filter(x => x.level === "Cao").length;
    document.getElementById("medium-scans").textContent = items.filter(x => x.level === "Trung bình").length;
    document.getElementById("low-scans").textContent = items.filter(x => x.level === "Thấp").length;
}

function renderHistory(items) {
    historyBody.replaceChildren();
    if (!items.length) {
        const row = makeElement("tr");
        const cell = makeElement("td", "empty-state", "Chưa có dữ liệu kiểm tra.");
        cell.colSpan = 6;
        row.append(cell);
        historyBody.append(row);
        return;
    }

    items.forEach((item) => {
        const row = makeElement("tr");
        row.append(makeElement("td", "", item.url));
        row.append(makeElement("td", "", item.domain));
        row.append(makeElement("td", "", `${item.score}/100`));

        const levelCell = makeElement("td");
        levelCell.append(makeElement("span", `table-risk ${riskClass(item.level)}`, item.level));
        row.append(levelCell);

        row.append(makeElement("td", "", item.created_at));

        const actionCell = makeElement("td");
        const button = makeElement("button", "detail-button", "Chi tiết");
        button.type = "button";
        button.addEventListener("click", () => showDetail(item.id));
        actionCell.append(button);
        row.append(actionCell);

        historyBody.append(row);
    });
}

async function showDetail(id) {
    try {
        const response = await fetch(`/api/history/${id}`);
        const data = await response.json();
        if (!response.ok) throw new Error(data.error || "Không tải được chi tiết.");

        const container = document.getElementById("modal-content");
        container.replaceChildren();

        const fields = [
            ["Đường dẫn", data.url],
            ["Tên miền", data.domain],
            ["Giao thức", data.scheme],
            ["Điểm rủi ro", `${data.score}/100`],
            ["Mức độ", data.level],
            ["Thời gian", data.created_at]
        ];

        fields.forEach(([label, value]) => {
            const paragraph = makeElement("p");
            const strong = makeElement("strong", "", `${label}: `);
            paragraph.append(strong, document.createTextNode(value));
            container.append(paragraph);
        });

        container.append(makeElement("h3", "", "Dấu hiệu phát hiện"));
        const list = makeElement("ul");
        data.reasons.forEach(reason => list.append(makeElement("li", "", reason)));
        container.append(list);

        document.getElementById("detail-modal").hidden = false;
    } catch (error) {
        alert(error.message);
    }
}

document.getElementById("clear-history").addEventListener("click", async () => {
    const confirmed = window.confirm("Bạn có chắc muốn xóa toàn bộ lịch sử kiểm tra?");
    if (!confirmed) return;

    try {
        const response = await fetch("/api/history", { method: "DELETE" });
        const data = await response.json();
        if (!response.ok) throw new Error(data.error || "Không thể xóa lịch sử.");
        await loadHistory();
        resultPanel.hidden = true;
        hideError();
    } catch (error) {
        showError(error.message);
    }
});

document.querySelectorAll("[data-close-modal]").forEach(element => {
    element.addEventListener("click", () => {
        document.getElementById("detail-modal").hidden = true;
    });
});

document.addEventListener("keydown", (event) => {
    if (event.key === "Escape") {
        document.getElementById("detail-modal").hidden = true;
    }
});

loadHistory();
