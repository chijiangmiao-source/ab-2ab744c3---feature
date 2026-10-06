/* 机载维护镜像 · 链接闭合审计前端 */

const MAX_ROWS = 12;
const rowsEl = document.getElementById('rows');
const verdictEl = document.getElementById('verdict');
const errEl = document.getElementById('requestError');
const hintEl = document.getElementById('loadHint');
const submitBtn = document.getElementById('submitBtn');
const auditIdEl = document.getElementById('auditId');

let seq = 0;

function addRow({ name = '', group = '', data = '' } = {}) {
  if (rowsEl.children.length >= MAX_ROWS) return;
  seq += 1;
  const pos = rowsEl.children.length + 1;
  const row = document.createElement('div');
  row.className = 'row';
  row.innerHTML = `
    <div class="pos">#${pos}</div>
    <div class="flds">
      <input type="text" class="r-name" placeholder="对象或归档文件名（如 main.o / libx.a）"
             value="${escapeAttr(name)}" autocomplete="off" spellcheck="false" />
      <div class="data-row">
        <textarea class="r-data" placeholder="粘贴 Base64（ELF64 ET_REL 或 GNU ar），或用右侧按钮选择文件"
                  spellcheck="false">${escapeAttr(data)}</textarea>
        <label class="file-btn" title="从本地文件读取并编码为 Base64">📄
          <input type="file" class="r-file" hidden />
        </label>
      </div>
    </div>
    <div class="flds2">
      <input type="text" class="r-group" placeholder="组标签"
             value="${escapeAttr(group)}" autocomplete="off" spellcheck="false"
             title="相同组标签且连续的输入按 --start-group 语义反复扫描" />
    </div>
    <button class="del" type="button" title="删除此行">✕</button>`;
  row.querySelector('.del').addEventListener('click', () => {
    row.remove();
    renumber();
  });
  row.querySelector('.r-file').addEventListener('change', (ev) => {
    const file = ev.target.files?.[0];
    if (!file) return;
    const nameInput = row.querySelector('.r-name');
    if (!nameInput.value.trim()) nameInput.value = file.name;
    const reader = new FileReader();
    reader.onload = () => {
      const b64Text = String(reader.result).split(',')[1] ?? '';
      row.querySelector('.r-data').value = b64Text;
    };
    reader.readAsDataURL(file);
  });
  rowsEl.appendChild(row);
  renumber();
}

function renumber() {
  [...rowsEl.children].forEach((r, i) => {
    r.querySelector('.pos').textContent = `#${i + 1}`;
  });
}

function escapeAttr(s) {
  return String(s).replace(/&/g, '&amp;').replace(/"/g, '&quot;')
    .replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

function collect() {
  const inputs = [...rowsEl.children].map((r) => ({
    name: r.querySelector('.r-name').value.trim(),
    group: (r.querySelector('.r-group').value.trim() || null),
    data_b64: r.querySelector('.r-data').value.replace(/\s+/g, ''),
  }));
  return {
    audit_id: auditIdEl.value.trim(),
    audit_type: 'link_closure',
    inputs,
  };
}

function showRequestError(msg) {
  errEl.hidden = false;
  errEl.textContent = msg;
}
function clearRequestError() {
  errEl.hidden = true;
  errEl.textContent = '';
}

function setBusy(on, hint = '') {
  submitBtn.disabled = on;
  hintEl.textContent = hint;
}

// --------------------------------------------------------------------------- //
async function submitAudit() {
  clearRequestError();
  verdictEl.innerHTML = '<div class="empty">裁决计算中…</div>';
  const payload = collect();
  let basicErr = null;
  if (!/^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/.test(payload.audit_id)) {
    basicErr = '审计标识不合法：须为 1-64 位字母数字及 ._-，以字母数字开头。';
  } else if (payload.inputs.length === 0) {
    basicErr = '请至少填写一个输入。';
  } else if (payload.inputs.some((i) => !i.name || !i.data_b64)) {
    basicErr = '每行都需要文件名与 Base64 数据。';
  }
  if (basicErr) {
    showRequestError(basicErr);
    verdictEl.innerHTML = '<div class="empty">尚未提交</div>';
    return;
  }
  setBusy(true, 'POST /api/audits …');
  try {
    const res = await fetch('/api/audits', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    const body = await res.json();
    if (res.status >= 400 && body.status === undefined) {
      showRequestError(`${body.error?.code ?? 'ERROR'}: ${body.error?.message ?? res.statusText}`);
      verdictEl.innerHTML = '<div class="empty">请求被拒绝，未产生冻结结论</div>';
      return;
    }
    renderVerdict(body, { frozen: res.status === 409 });
  } catch (e) {
    showRequestError(`网络错误：${e.message}`);
    verdictEl.innerHTML = '<div class="empty">后端不可达</div>';
  } finally {
    setBusy(false);
  }
}

async function reopenAudit() {
  clearRequestError();
  const id = auditIdEl.value.trim();
  if (!/^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/.test(id)) {
    showRequestError('请先填写合法的稳定审计标识。');
    return;
  }
  setBusy(true, `GET /api/audits/${id} …`);
  verdictEl.innerHTML = '<div class="empty">读取冻结结论…</div>';
  try {
    const res = await fetch(`/api/audits/${encodeURIComponent(id)}`);
    const body = await res.json();
    if (res.status === 404) {
      verdictEl.innerHTML = `<div class="empty">${escapeHtml(body.error?.message ?? '无冻结结论')}</div>`;
      return;
    }
    renderVerdict(body, { frozen: true, reopened: true });
  } catch (e) {
    showRequestError(`网络错误：${e.message}`);
  } finally {
    setBusy(false);
  }
}

async function fillDemo() {
  clearRequestError();
  setBusy(true, 'GET /api/demo/cycle …');
  try {
    const res = await fetch('/api/demo/cycle');
    const demo = await res.json();
    auditIdEl.value = demo.audit_id;
    rowsEl.innerHTML = '';
    demo.inputs.forEach((i) => addRow({ name: i.name, group: i.group ?? '', data: i.data_b64 }));
    verdictEl.innerHTML = `<div class="empty">已填充${demo.inputs.length}个真实合成输入（${escapeHtml(demo.explanation)}）。点击「提交审计」查看裁决。</div>`;
  } catch (e) {
    showRequestError(`示例加载失败：${e.message}`);
  } finally {
    setBusy(false);
  }
}

// --------------------------------------------------------------------------- //
function escapeHtml(s) {
  return String(s ?? '').replace(/[&<>"']/g, (c) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
  }[c]));
}

function tag(text, cls = '') {
  return `<span class="tag ${cls}">${escapeHtml(text)}</span>`;
}

function renderVerdict(v, { frozen = false, reopened = false } = {}) {
  const accepted = v.status === 'accepted';
  const banner = accepted
    ? `<div class="banner accepted"><span class="dot">✔</span> 链接闭包通过 · 审计标识 ${escapeHtml(v.audit_id)}</div>`
    : `<div class="banner rejected"><span class="dot">✖</span> 审计拒绝 · ${escapeHtml(v.error?.code ?? '')} · 审计标识 ${escapeHtml(v.audit_id)}</div>`;

  let html = banner;
  if (frozen) {
    html += `<div class="frozen-note">❄ ${reopened ? '重开的' : '返回的'}是按稳定标识冻结的既有结论（HTTP ${reopened ? '200' : '409'}），不会被本次提交覆盖。</div>`;
  }

  html += `<div class="meta-grid">
    <div class="meta-item"><div class="k">状态</div><div class="v">${escapeHtml(v.status)}</div></div>
    <div class="meta-item"><div class="k">输入数</div><div class="v">${(v.inputs ?? []).length}</div></div>
    <div class="meta-item"><div class="k">抽取成员</div><div class="v">${(v.extraction_order ?? []).length}</div></div>
    <div class="meta-item"><div class="k">扫描轮次</div><div class="v">${(v.rounds ?? []).length}</div></div>
  </div>`;

  if (!accepted && v.error) {
    html += `<h3>首次触发位置</h3>
      <div class="loc">${escapeHtml(v.error.location)}</div>
      <div style="font-size:.82rem;margin-top:4px">${escapeHtml(v.error.message)}</div>`;
    const ev = v.error.evidence ?? {};
    if (ev.undefined) {
      html += `<h3>最终未定义集合</h3><div class="undef-set">${ev.undefined.map(escapeHtml).join(', ') || '（空）'}</div>`;
    }
    if (ev.first_definition) {
      html += `<h3>强定义冲突证据</h3>
        <table><tr><th>先定义</th><td class="mono">${escapeHtml(ev.first_definition)}</td></tr>
        <tr><th>冲突定义</th><td class="mono">${escapeHtml(ev.conflicting_definition ?? '')}</td></tr></table>`;
    }
    // 修复建议入口：仅基于原冻结输入枚举相邻未分组归档段重裁
    html += `<div class="fix-entry">
      <button id="fixBtn" class="btn small" type="button">🛠 分析相邻归档成组修复建议</button>
      <span class="fix-note">只读分析：仅基于原冻结输入重放，不改写冻结结论</span>
      <div id="fixResult"></div>
    </div>`;
  }

  html += renderInputs(v.inputs ?? []);
  html += renderExtraction(v.extraction_order ?? []);
  html += renderRounds(v.rounds ?? []);
  html += renderDefinitions(v.definitions ?? {});
  if ((v.weak_unresolved ?? []).length) {
    html += `<h3>弱未定义（不判错）</h3><div class="undef-set">${v.weak_unresolved.map(escapeHtml).join(', ')}</div>`;
  }
  verdictEl.innerHTML = html;
  const fixBtn = document.getElementById('fixBtn');
  if (fixBtn) {
    fixBtn.addEventListener('click', () => loadFixSuggestion(v.audit_id));
  }
}

// --------------------------------------------------------------------------- //
// 修复建议：枚举相邻未分组归档段，按既有成组语义重裁（只读，不改写冻结结论）
// --------------------------------------------------------------------------- //
async function loadFixSuggestion(auditId) {
  const box = document.getElementById('fixResult');
  const btn = document.getElementById('fixBtn');
  if (!box) return;
  if (btn) btn.disabled = true;
  box.innerHTML = '<div class="empty">正在基于原冻结输入枚举候选段并重裁…</div>';
  try {
    const res = await fetch(`/api/audits/${encodeURIComponent(auditId)}/fix-suggestion`);
    const body = await res.json();
    box.innerHTML = renderFixSuggestion(body, res.status);
  } catch (e) {
    box.innerHTML = `<div class="fix-panel fail">网络错误：${escapeHtml(e.message)}</div>`;
  } finally {
    if (btn) btn.disabled = false;
  }
}

function renderFixSuggestion(body, httpStatus) {
  if (httpStatus === 200 && body.status === 'suggested') {
    const s = body.suggestion;
    const seg = s.segment;
    const names = (seg.archives ?? []).map((a) => `#${a.position} ${escapeHtml(a.name)}`).join('、');
    let html = `<div class="fix-panel ok">
      <div class="fix-title">✔ 唯一最短修复段：将连续 ${seg.length} 个未分组归档置入同一链接组即可闭合</div>
      <table>
        <tr><th>段首尾</th><td class="mono">输入 #${seg.start_position} → #${seg.end_position}</td></tr>
        <tr><th>段内归档</th><td class="mono">${names}</td></tr>
        <tr><th>建议组标签</th><td class="mono">${tag('组 ' + s.group)}</td></tr>
        <tr><th>消失的未定义集合</th><td class="undef-set">{${(s.resolved_undefined ?? []).map(escapeHtml).join(', ')}} → ∅</td></tr>
      </table>
      <h3>成组重裁后的归档成员抽取顺序</h3>
      ${renderExtraction(s.extraction_order ?? [])}
      ${renderRounds(s.rounds ?? [])}
      <div class="fix-note">已按 (段长, 起始位置) 稳定选择最短段，共检查 ${body.candidates_checked} 个候选；原冻结结论与输入顺序未被改写。</div>
    </div>`;
    return html;
  }

  const reason = body.reason ?? {};
  const candidates = body.candidates ?? [];
  let html = `<div class="fix-panel fail">
    <div class="fix-title">✖ 无可行成组修复段 · ${escapeHtml(reason.code ?? `HTTP ${httpStatus}`)}</div>
    <div style="font-size:.8rem">${escapeHtml(reason.message ?? '未知原因')}</div>`;
  if (candidates.length) {
    const rows = candidates.map((c) => `<tr>
      <td class="mono">#${c.segment.start_position} → #${c.segment.end_position}</td>
      <td class="mono">${(c.segment.archives ?? []).map((a) => escapeHtml(a.name)).join(', ')}</td>
      <td>${tag(c.error?.code ?? '', 'err')}</td>
      <td class="mono" style="font-size:.7rem">${escapeHtml(c.error?.location ?? '')}</td>
    </tr>`).join('');
    html += `<h3>候选段重放结果（${candidates.length}）</h3>
      <div class="scroll"><table>
        <tr><th>段首尾</th><th>段内归档</th><th>重放拒绝码</th><th>首触发位置</th></tr>${rows}
      </table></div>`;
  }
  html += `<div class="fix-note">原冻结结论、输入顺序与既有重开结果均未被改写。</div></div>`;
  return html;
}

function renderInputs(inputs) {
  if (!inputs.length) return '';
  const rows = inputs.map((i) => `
    <tr>
      <td class="mono">#${i.position}</td>
      <td class="mono">${escapeHtml(i.name)}</td>
      <td>${i.kind === 'ar' ? tag('GNU ar', 'ar') : tag('ELF REL', 'obj')}</td>
      <td class="mono">${i.group ? tag('组 ' + i.group) : '—'}</td>
      <td class="mono">${i.bytes} B${i.members ? ` · ${i.members.length} 成员 · 索引 ${i.index_symbols} 符号` : ''}</td>
    </tr>`).join('');
  return `<h3>输入（命令行顺序）</h3><div class="scroll"><table>
    <tr><th>位置</th><th>名称</th><th>类型</th><th>成组</th><th>规模</th></tr>${rows}
  </table></div>`;
}

function renderExtraction(orders) {
  if (!orders.length) return '<h3>归档成员抽取顺序</h3><div class="empty">无归档成员被抽取</div>';
  const rows = orders.map((e) => `
    <tr>
      <td class="mono">${e.seq}</td>
      <td class="mono">#${e.input_position} ${escapeHtml(e.archive)}</td>
      <td class="mono">${escapeHtml(e.member)}</td>
      <td class="mono">${(e.matched_index_symbols ?? []).map(escapeHtml).join(', ')}</td>
      <td class="mono pill">${e.context ?? ''}${e.pass_or_round ? '#' + e.pass_or_round : ''}</td>
      <td class="undef-set">{${(e.undefined_before ?? []).join(', ')}}</td>
      <td class="undef-set">{${(e.undefined_after ?? []).join(', ')}}</td>
    </tr>`).join('');
  return `<h3>归档成员抽取顺序（含匹配索引符号与每轮未定义集合）</h3>
  <div class="scroll"><table>
    <tr><th>#</th><th>归档</th><th>成员</th><th>命中索引符号</th><th>上下文/轮次</th><th>抽取前未定义</th><th>抽取后未定义</th></tr>
    ${rows}
  </table></div>`;
}

function renderRounds(rounds) {
  if (!rounds.length) return '';
  const rows = rounds.map((r) => {
    const scope = r.scope === 'group'
      ? `组 ${r.group} · 第 ${r.round} 轮`
      : `归档 ${r.archive} · 第 ${r.pass} 趟`;
    const extracted = r.scope === 'group'
      ? (r.scans ?? []).map((s) => `${s.name}:[${(s.extracted ?? []).join(', ')}]`).join(' ｜ ')
      : (r.extracted ?? []).join(', ');
    return `<tr>
      <td class="mono">${scope}</td>
      <td class="mono">${escapeHtml(extracted || '—')}</td>
      <td>${r.changed ? tag('有新增', 'err') : tag('收敛', 'ok')}</td>
      <td class="undef-set">{${(r.undefined_before ?? []).join(', ')}}</td>
      <td class="undef-set">{${(r.undefined_after ?? []).join(', ')}}</td>
    </tr>`;
  }).join('');
  return `<details open><summary>逐趟/逐轮扫描证据（${rounds.length}）</summary>
  <div class="scroll"><table>
    <tr><th>范围</th><th>本轮抽取</th><th>未定义集合变化</th><th>轮前</th><th>轮后</th></tr>
    ${rows}
  </table></div></details>`;
}

function renderDefinitions(defs) {
  const names = Object.keys(defs);
  if (!names.length) return '';
  const rows = names.map((n) => {
    const d = defs[n];
    const cls = d.binding === 'strong' ? 'strong' : d.binding === 'weak' ? 'weak' : 'common';
    return `<tr><td class="mono">${escapeHtml(n)}</td>
      <td>${tag(d.binding, cls)}</td>
      <td class="mono" style="font-size:.7rem">${escapeHtml(d.source)}</td></tr>`;
  }).join('');
  return `<details><summary>外部符号裁决表（${names.length}）</summary>
  <div class="scroll"><table>
    <tr><th>符号</th><th>裁决绑定</th><th>满足位置</th></tr>${rows}
  </table></div></details>`;
}

// --------------------------------------------------------------------------- //
document.getElementById('submitBtn').addEventListener('click', submitAudit);
document.getElementById('reopenBtn').addEventListener('click', reopenAudit);
document.getElementById('addRow').addEventListener('click', () => addRow());
document.getElementById('addDemo').addEventListener('click', fillDemo);

addRow();
verdictEl.innerHTML = '<div class="empty">填写标识与输入，或点击「填充循环依赖示例」</div>';
