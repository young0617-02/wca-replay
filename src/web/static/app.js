// 界面只用原生 fetch：没有前端框架、没有构建流水线（需求 §6.2 / NFR-07）。
// 每个动作都是"调服务端的一个接口"，服务端再调用与脚本同一个函数。

function wcaCsrfToken() {
  const meta = document.querySelector('meta[name="csrf-token"]');
  return meta ? meta.content : "";
}

async function wcaPost(path, body) {
  const headers = { "Content-Type": "application/json" };
  const token = wcaCsrfToken();
  if (token) headers["X-CSRF-Token"] = token;
  const res = await fetch(path, {
    method: "POST",
    headers,
    credentials: "same-origin",
    body: JSON.stringify(body || {}),
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.detail || (path + " → HTTP " + res.status));
  return data;
}

function wcaBindImport() {
  const btn = document.getElementById("doImport");
  const msg = document.getElementById("importMsg");
  if (!btn) return;
  btn.addEventListener("click", async () => {
    const input = document.getElementById("csv");
    const file = input && input.files && input.files[0];
    if (!file) { msg.textContent = "先选一个 .csv 文件"; return; }
    msg.textContent = "导入中…";
    try {
      const content = await file.text();
      const r = await wcaPost("/api/import", { filename: file.name, content });
      msg.textContent = `已导入 ${r.kind}：看到 ${r.rows_seen} 行 / 入库 ${r.rows_accepted} / `
        + `拒收 ${r.rows_rejected} / 质量问题 ${r.issue_count} / sha256 ${(r.sha256 || "").slice(0, 12)}…`;
    } catch (e) { msg.textContent = "导入失败：" + e.message; }
  });
}

function wcaBindCheck() {
  const btn = document.getElementById("doCheck");
  const msg = document.getElementById("checkMsg");
  if (!btn) return;
  btn.addEventListener("click", async () => {
    const body = {
      region_code: document.getElementById("region").value,
      start: document.getElementById("start").value,
      end: document.getElementById("end").value,
    };
    msg.textContent = "校验中…";
    try {
      const r = await wcaPost("/api/check", body);
      const c = r.counts || {};
      msg.textContent = `${r.region_label}（${r.region_code}）规则包 ${r.rule_pack}：`
        + `员工 ${r.employees} / 事实 ${r.days} / 结论 ${r.findings}｜`
        + `违规 ${c.VIOLATION || 0} 需复核 ${c.REVIEW || 0} 可申辩 ${c.DEFENSIBLE || 0}`
        + `｜摘要 ${(r.triple || {}).conclusion_digest?.slice(0, 12) || "—"}…｜${r.elapsed_ms} ms`;
    } catch (e) { msg.textContent = "校验失败：" + e.message; }
  });
}

function wcaBindApprovalForm(mode, docNo) {
  const form = document.getElementById("approvalForm");
  if (!form) return;
  const msg = document.getElementById("approvalMsg");
  form.addEventListener("submit", async (ev) => {
    ev.preventDefault();
    msg.textContent = "保存中…";
    const data = Object.fromEntries(new FormData(form).entries());
    const path = mode === "new" ? "/api/approvals/draft"
      : `/api/approvals/${encodeURIComponent(docNo)}/edit`;
    try {
      const r = await wcaPost(path, data);
      msg.textContent = `已保存 ${r.doc_no} v${r.version_no}（审计链已记录）`;
      if (mode === "new") location.href = `/approvals/${encodeURIComponent(r.doc_no)}`;
    } catch (e) { msg.textContent = "保存失败：" + e.message; }
  });
}

function wcaBindApprovalPublish() {
  document.querySelectorAll("button[data-doc][data-version]").forEach((btn) => {
    btn.addEventListener("click", async () => {
      const doc = btn.dataset.doc;
      const version = btn.dataset.version;
      const out = document.getElementById("pub-" + version);
      if (out) out.textContent = "发布中…";
      try {
        const r = await wcaPost(`/api/approvals/${encodeURIComponent(doc)}/publish`,
                                { version_no: Number(version) });
        if (out) out.textContent = `已发布 v${r.version_no}，覆盖员工 ${r.coverage_employees}`;
        location.reload();
      } catch (e) {
        if (out) out.textContent = "发布失败：" + e.message;
      }
    });
  });
}

function wcaBindApprovalImport(maxBytes, maxRows) {
  const btn = document.getElementById("doApprovalImport");
  const msg = document.getElementById("approvalImportMsg");
  if (!btn) return;
  btn.addEventListener("click", async () => {
    const input = document.getElementById("approvalCsv");
    const file = input && input.files && input.files[0];
    if (!file) { msg.textContent = "先选一个 .csv 文件"; return; }
    if (file.size > maxBytes) { msg.textContent = `文件超过 ${maxBytes} 字节上限，拒绝导入`; return; }
    const content = await file.text();
    const rows = content.split(/\r?\n/).filter((x) => x.trim()).length - 1;
    if (rows > maxRows) { msg.textContent = `数据行 ${rows} 超过 ${maxRows} 行上限，拒绝导入`; return; }
    msg.textContent = "导入中…";
    try {
      const r = await wcaPost("/api/approvals/import", { filename: file.name, content });
      msg.textContent = `已导入 ${r.docs} 个批文 / ${r.versions} 个版本 / ${r.rows} 行`;
      setTimeout(() => location.reload(), 800);
    } catch (e) { msg.textContent = "导入失败：" + e.message; }
  });
}

function wcaBindReview() {
  document.querySelectorAll("button[data-rid]").forEach((btn) => {
    btn.addEventListener("click", async () => {
      const rid = btn.dataset.rid;
      const out = document.getElementById("r" + rid);
      const raw = document.getElementById("a" + rid).value.trim();
      const amount = raw === "" ? null : Number(raw);
      if (amount !== null && (!Number.isInteger(amount) || amount < 0)) {
        out.textContent = "金额必须是≥0 的整数分"; return;
      }
      out.textContent = "登记中…";
      try {
        const r = await wcaPost(`/api/review/${rid}/decision`, {
          decision: document.getElementById("d" + rid).value,
          note: document.getElementById("n" + rid).value,
          amount_cents: amount,
        });
        out.textContent = `已登记 ${r.decision}（审计序号 ${r.audit_seq}，摘要 ${r.entry_hash?.slice(0, 10)}…）`;
      } catch (e) { out.textContent = "登记失败：" + e.message; }
    });
  });

  const exp = document.getElementById("doExport");
  if (!exp) return;
  exp.addEventListener("click", async () => {
    const msg = document.getElementById("exportMsg");
    msg.textContent = "导出中…";
    try {
      const r = await wcaPost("/api/export", {});
      const delivery = r.delivery_event_recorded
        ? " / 已登记交付事件（非密码学签名）"
        : " / 未登记交付事件";
      const signed = r.signed
        ? ` / 包已签名（${r.signature_key_id || "key_id 未知"}）`
        : " / 包未签名（v2）";
      msg.textContent = `举证包 ${(r.package_zip || "").split(/[\\/]/).pop()}：`
        + `结论 ${r.counts.findings} 条 / 审计链 ${r.chain_ok ? "完整" : "已断"} / `
        + `manifest ${(r.manifest_sha256 || "").slice(0, 12)}…${signed}${delivery}`;
    } catch (e) { msg.textContent = "导出失败：" + e.message; }
  });
}
