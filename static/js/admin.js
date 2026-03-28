// ── Sidebar: sync active state with Bootstrap tab events ──────────────────
document.querySelectorAll('.sidebar-item[data-bs-toggle="tab"]').forEach(btn => {
  btn.addEventListener('shown.bs.tab', () => {
    document.querySelectorAll('.sidebar-item').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
  });
});

// ── Open correct tab from URL hash ────────────────────────────────────────
const hashTabMap = {
  '#users':     'tab-users-btn',
  '#settings':  'tab-settings-btn',
  '#logs':      'tab-logs-btn',
  '#sso':       'tab-sso-btn',
  '#s3':        'tab-s3-btn',
  '#legal':     'tab-legal-btn',
  '#analytics': 'tab-analytics-btn',
};
const targetBtn = hashTabMap[window.location.hash];
if (targetBtn) bootstrap.Tab.getOrCreateInstance(document.getElementById(targetBtn)).show();

// ── SSO: show/hide "Force SSO" toggle ────────────────────────────────────
const ssoEnabledSwitch = document.getElementById('ssoEnabled');
const ssoForceWrapper  = document.getElementById('ssoForceWrapper');
const ssoForceSwitch   = document.getElementById('ssoForce');

function updateSsoForceVisibility() {
  if (!ssoEnabledSwitch || !ssoForceWrapper) return;
  ssoForceWrapper.style.display = ssoEnabledSwitch.checked ? '' : 'none';
  if (!ssoEnabledSwitch.checked && ssoForceSwitch) ssoForceSwitch.checked = false;
}
if (ssoEnabledSwitch) {
  updateSsoForceVisibility();
  ssoEnabledSwitch.addEventListener('change', updateSsoForceVisibility);
}

// ── Storage: show/hide S3 fields ──────────────────────────────────────────
const storageBackendSelect = document.getElementById('storageBackend');
const s3Fields             = document.getElementById('s3Fields');

function updateS3Fields() {
  if (storageBackendSelect && s3Fields) {
    s3Fields.style.display = storageBackendSelect.value === 's3' ? '' : 'none';
  }
}
if (storageBackendSelect) {
  storageBackendSelect.addEventListener('change', updateS3Fields);
}

// ── S3 connection test button ─────────────────────────────────────────────
const btnTestS3    = document.getElementById('btnTestS3');
const s3TestResult = document.getElementById('s3TestResult');

if (btnTestS3) {
  btnTestS3.addEventListener('click', async () => {
    const form = btnTestS3.closest('form');
    const payload = {
      s3_bucket:       form.querySelector('[name="s3_bucket"]')?.value.trim()       || '',
      s3_region:       form.querySelector('[name="s3_region"]')?.value.trim()       || '',
      s3_endpoint_url: form.querySelector('[name="s3_endpoint_url"]')?.value.trim() || '',
      s3_access_key:   form.querySelector('[name="s3_access_key"]')?.value.trim()   || '',
      s3_secret_key:   form.querySelector('[name="s3_secret_key"]')?.value.trim()   || '',
    };
    btnTestS3.disabled = true;
    btnTestS3.innerHTML = '<span class="spinner-border spinner-border-sm me-2"></span>Test…';
    s3TestResult.style.display = 'none';
    try {
      const resp = await fetch(window.ADMIN_S3_TEST_URL, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-CSRFToken': document.querySelector('input[name="csrf_token"]')?.value || '',
        },
        body: JSON.stringify(payload),
      });
      const data = await resp.json();
      s3TestResult.textContent = data.message;
      s3TestResult.className   = 'small fw-semibold ' + (data.ok ? 'text-success' : 'text-danger');
      s3TestResult.style.display = '';
    } catch {
      s3TestResult.textContent = 'Erreur réseau.';
      s3TestResult.className   = 'small fw-semibold text-danger';
      s3TestResult.style.display = '';
    } finally {
      btnTestS3.disabled = false;
      btnTestS3.innerHTML = '<i class="fas fa-plug me-2"></i>Tester la connexion';
    }
  });
}

// ── Audit log: client-side filter ─────────────────────────────────────────
const filterSel   = document.getElementById('log-filter');
const searchInput = document.getElementById('log-search');

function filterLogs() {
  const action  = filterSel.value.toLowerCase();
  const keyword = searchInput.value.toLowerCase().trim();
  document.querySelectorAll('#log-table .log-row').forEach(row => {
    const matchAction  = !action  || row.dataset.action === action;
    const matchKeyword = !keyword || row.dataset.search.includes(keyword);
    row.style.display  = (matchAction && matchKeyword) ? '' : 'none';
  });
}
if (filterSel)   filterSel.addEventListener('change', filterLogs);
if (searchInput) searchInput.addEventListener('input', filterLogs);

// ── Color picker (accent color swatches) ──────────────────────────────────
const accentInput    = document.getElementById('accentColorInput');
const customPicker   = document.getElementById('customColorPicker');
const customLabel    = document.querySelector('.swatch-custom');
const presetSwatches = document.querySelectorAll('.color-swatch-btn:not(.swatch-custom)');

function setActive(color) {
  if (!accentInput) return;
  accentInput.value = color;
  presetSwatches.forEach(s => s.classList.toggle('swatch-active', s.dataset.color === color));
  const isPreset = [...presetSwatches].some(s => s.dataset.color === color);
  if (customLabel) {
    customLabel.classList.toggle('swatch-active', !isPreset);
    customLabel.style.background = isPreset ? '' : color;
    const icon = customLabel.querySelector('i');
    if (icon) icon.style.display = isPreset ? '' : 'none';
  }
}
presetSwatches.forEach(s => s.addEventListener('click', () => setActive(s.dataset.color)));
if (customPicker) {
  customPicker.addEventListener('input',  e => setActive(e.target.value));
  customPicker.addEventListener('change', e => setActive(e.target.value));
}
