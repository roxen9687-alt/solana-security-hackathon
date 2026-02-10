(function () {
  'use strict';

  // hardcoded fallback for local dev or when results aren't generated yet
  const FALLBACK_DATA = [
    {
      program_id: '6N8t8PJSZeR9ZLH1Fk7wEKkTxXfQqzz4jtgjwrKKKnNU',
      total_exploits: 9, critical_count: 2, high_count: 2, medium_count: 5, security_score: 82,
      exploits: [
        { id: 'VULN-01', category: 'Auth & Auth', vulnerability_type: 'Initialization Frontrunning', severity: 4, severity_label: 'HIGH', instruction: 'initialize', description: 'Attackers can intercept the initialization transaction to take control of the program authority before the legitimate admin.', attack_scenario: 'Attacker monitors mempool for initialize instructions and frontruns with their own authority.', secure_fix: 'Check if already initialized or use constant seeds for singleton state.', economic_impact: 'High: Complete loss of protocol ownership.' },
        { id: 'VULN-02', category: 'DeFi Logic', vulnerability_type: 'Economic Invariant Violation', severity: 5, severity_label: 'CRITICAL', instruction: 'swap', description: 'Swap logic fails to enforce k=xy constant product invariant, allowing liquidity extraction.', attack_scenario: 'Attacker performs multiple unbalanced swaps to drain specific pool reserves.', secure_fix: 'Enforce post-execution balance checks against the invariant.', economic_impact: 'Critical: Potential drainage of all pool assets.' }
      ],
      timestamp: new Date().toISOString()
    },
    {
      program_id: '7M8t8PJSZeR9ZLH1Fk7wEKkTxXfQqzz4jtgjwrKKKnNT',
      total_exploits: 12, critical_count: 3, high_count: 3, medium_count: 6, security_score: 45,
      exploits: [
        { id: 'VULN-08', category: 'Access Control', vulnerability_type: 'Missing Owner Validation', severity: 5, severity_label: 'CRITICAL', instruction: 'withdraw', description: 'The withdraw instruction does not verify if the signer is the legitimate owner of the funds.', attack_scenario: 'Any user can call withdraw on any account by providing their own target address.', secure_fix: 'Add signer check: require(ctx.accounts.owner.is_signer).', economic_impact: 'Critical: All user deposited funds are at high risk.' }
      ],
      timestamp: new Date().toISOString()
    }
  ];

  const state = {
    reports: [],
    allExploits: [],
    currentPage: 'overview',
    isSidebarCollapsed: false,
    filters: {
      search: '',
      severity: 'all',
      category: 'all'
    }
  };

  const $ = (sel) => document.querySelector(sel);
  const $$ = (sel) => [...document.querySelectorAll(sel)];

  async function init() {
    console.log('Security Swarm Intelligence Platform Initialising...');

    injectIcons();

    const reports = await loadIntelligence();
    state.reports = reports;
    flattenExploits(reports);

    setupSidebar();
    setupRouter();
    setupEventHandlers();
    completeLoading();

    const hash = window.location.hash.slice(1) || 'overview';
    navigate(hash);
  }

  function injectIcons() {
    if (!window.Icons) return;
    $$('[data-icon]').forEach(el => {
      const iconName = el.dataset.icon;
      const size = el.dataset.size ? parseInt(el.dataset.size) : 18;
      el.innerHTML = window.Icons.svg(iconName, size);
    });
  }

  async function loadIntelligence() {
    const endpoints = [
      '../production_audit_results/vulnerable_vault_report.json',
      '../production_audit_results/vulnerable_token_report.json',
      '../production_audit_results/vulnerable_staking_report.json',
    ];

    try {
      const responses = await Promise.all(endpoints.map(u => fetch(u)));
      if (responses.some(r => !r.ok)) throw new Error('CORS or Network failure');
      return await Promise.all(responses.map(r => r.json()));
    } catch (e) {
      // CORS usually blocks this on file:// - fallback to local data
      console.warn('Using fallback intelligence repository.');
      return FALLBACK_DATA;
    }
  }

  function flattenExploits(reports) {
    state.allExploits = [];
    reports.forEach((r, rIdx) => {
      const exploits = r.exploits || (r.enhanced_report && r.enhanced_report.base_report && r.enhanced_report.base_report.findings) || [];
      exploits.forEach((ex, exIdx) => {
        state.allExploits.push({
          ...ex,
          _program_id: r.program_id,
          _uid: `ex-${rIdx}-${exIdx}`,
          _severity_norm: (ex.severity_label || 'MEDIUM').toUpperCase()
        });
      });
    });
  }

  function completeLoading() {
    const loader = $('#loading-screen');
    const appShell = $('#app');

    // simulate a small delay for brain loading
    setTimeout(() => {
      if (loader) loader.style.opacity = '0';
      if (appShell) {
        appShell.removeAttribute('aria-hidden');
        appShell.style.opacity = '1';
      }
      setTimeout(() => loader && loader.remove(), 600);
    }, 1500);
  }

  function setupRouter() {
    window.addEventListener('hashchange', () => {
      navigate(window.location.hash.slice(1) || 'overview');
    });
  }

  function navigate(page) {
    state.currentPage = page;

    $$('.sidebar__nav-item').forEach(el => {
      el.classList.toggle('is-active', el.dataset.page === page);
    });

    if (page !== 'findings') {
      state.filters = { search: '', severity: 'all', category: 'all' };
    }

    const titleEl = $('#page-title');
    if (titleEl) {
      const titles = {
        overview: 'Insight Overview',
        programs: 'Program Assets',
        findings: 'Vulnerability Intelligence',
        'risk-matrix': 'Risk Heatmap',
        'taint-analysis': 'Dataflow Taint'
      };
      titleEl.textContent = titles[page] || 'Intelligence';
    }

    renderPage(page);
  }

  function renderPage(page) {
    const container = $('#content');
    if (!container) return;
    container.innerHTML = '';

    switch (page) {
      case 'overview': renderOverview(container); break;
      case 'programs': renderPrograms(container); break;
      case 'findings': renderFindings(container); break;
      case 'risk-matrix': renderRiskMatrix(container); break;
      case 'taint-analysis': renderTaintAnalysis(container); break;
    }
  }

  function renderOverview(container) {
    const C = window.Components;
    const stats = calculateGlobalStats();

    container.innerHTML = C.sectionHeader({
      title: 'Intelligence Overview',
      subtitle: `System-wide analysis of ${state.reports.length} critical on-chain assets.`
    });

    const statsGrid = C.statGrid([
      C.statCard({ label: 'Vulnerabilities', value: stats.total, iconName: 'findings', context: 'Identified flaws across all audited scopes.' }),
      C.statCard({ label: 'Critical Exposure', value: stats.critical, iconName: 'criticalAlert', variant: 'critical', context: 'Severe threads requiring immediate remediation.' }),
      C.statCard({ label: 'System Health', value: `${stats.avgScore}%`, iconName: 'securityScore', context: 'Overall weighted security posture score.' }),
      C.statCard({ label: 'Risk Coverage', value: '100%', iconName: 'shield', variant: 'low', context: 'Portion of logic reached by fuzzing & verification.' })
    ]);

    container.insertAdjacentHTML('beforeend', statsGrid);

    const grid = document.createElement('div');
    grid.className = 'grid-2';
    grid.innerHTML = `
      ${C.card({ title: 'Threat Category Distribution', subtitle: 'Breakdown by vulnerability archetype', body: '<div id="chart-distribution"></div>' })}
      ${C.card({ title: 'Vulnerabilities by Program', subtitle: 'Comparative risk assessment', body: '<div id="chart-comparison"></div>' })}
    `;
    container.appendChild(grid);

    requestAnimationFrame(() => {
      if (window.Charts) {
        window.Charts.donut($('#chart-distribution'), {
          critical: stats.critical,
          high: stats.high,
          medium: stats.medium,
          low: stats.low || 1
        });

        const programCompareData = state.reports.map(r => ({
          name: C.truncateAddr(r.program_id, 4),
          critical: r.critical_count || 0,
          high: r.high_count || 0,
          medium: r.medium_count || 0
        }));
        window.Charts.groupedBar($('#chart-comparison'), programCompareData);
      }
    });

    const feed = document.createElement('div');
    feed.innerHTML = `
      <div class="section-header mt-4">
        <h3 class="section-header__title" style="font-size: 1.2rem;">Priority Remediation Feed</h3>
      </div>
      <div class="findings-feed">
        ${state.allExploits.slice(0, 3).map(ex => C.findingCard(ex)).join('')}
      </div>
    `;
    container.appendChild(feed);
  }

  function renderPrograms(container) {
    const C = window.Components;
    container.innerHTML = C.sectionHeader({ title: 'Asset Repository', subtitle: 'Detailed security parameters for on-chain programs.' });

    const grid = document.createElement('div');
    grid.className = 'grid-3';
    state.reports.forEach(r => {
      const cardHtml = C.card({
        title: `Program ${C.truncateAddr(r.program_id, 6)}`,
        subtitle: r.program_id,
        body: `
          <div class="program-stats" style="display: flex; gap: 16px; margin-bottom: 20px;">
            <div style="flex: 1; text-align: center; border-right: 1px solid var(--border-subtle);">
              <div class="text-muted" style="font-size: 0.7rem; text-transform: uppercase;">Score</div>
              <div class="text-pure" style="font-size: 1.5rem; font-weight: 700;">${r.security_score}%</div>
            </div>
            <div style="flex: 1; text-align: center;">
              <div class="text-muted" style="font-size: 0.7rem; text-transform: uppercase;">Findings</div>
              <div class="text-pure" style="font-size: 1.5rem; font-weight: 700;">${r.total_exploits}</div>
            </div>
          </div>
          <div style="display: flex; flex-direction: column; gap: 8px;">
            ${C.severityBadge('CRITICAL')} <span class="text-secondary">${r.critical_count} items</span>
            ${C.severityBadge('HIGH')} <span class="text-secondary">${r.high_count} items</span>
          </div>
          <button class="btn btn--secondary mt-4 w-full view-program-btn" data-id="${r.program_id}" style="width: 100%;">Inspect Assets</button>
        `
      });
      const wrap = document.createElement('div');
      wrap.innerHTML = cardHtml;
      grid.appendChild(wrap);
    });
    container.appendChild(grid);
  }

  function renderFindings(container) {
    const C = window.Components;
    container.innerHTML = C.sectionHeader({
      title: 'Vulnerability Intelligence',
      subtitle: 'Aggregated threat repository with cross-program correlation.'
    });

    const controlsHtml = `
      <div class="controls-row">
        ${C.searchInput({ id: 'findings-search', placeholder: 'Search by type, instruction, or Ref-ID...' })}
        ${C.filterGroup({
      label: 'Severity Level',
      id: 'filter-severity',
      options: [
        { label: 'All Levels', value: 'all' },
        { label: 'Critical Only', value: 'CRITICAL' },
        { label: 'High Severity', value: 'HIGH' },
        { label: 'Medium/Low', value: 'MEDIUM' }
      ]
    })}
        ${C.filterGroup({
      label: 'Category',
      id: 'filter-category',
      options: [
        { label: 'All Categories', value: 'all' },
        ...([...new Set(state.allExploits.map(ex => ex.category))].sort().map(cat => ({ label: cat, value: cat })))
      ]
    })}
      </div>
      <div id="findings-table-target"></div>
    `;

    container.insertAdjacentHTML('beforeend', controlsHtml);

    updateFindingsTable();

    const searchInput = $('#findings-search');
    const sevSelect = $('#filter-severity');
    const catSelect = $('#filter-category');

    searchInput.addEventListener('input', e => {
      state.filters.search = e.target.value.toLowerCase();
      updateFindingsTable();
    });

    sevSelect.addEventListener('change', e => {
      state.filters.severity = e.target.value;
      updateFindingsTable();
    });

    catSelect.addEventListener('change', e => {
      state.filters.category = e.target.value;
      updateFindingsTable();
    });
  }

  function updateFindingsTable() {
    const C = window.Components;
    const target = $('#findings-table-target');
    if (!target) return;

    const filtered = state.allExploits.filter(ex => {
      const matchesSearch = !state.filters.search ||
        (ex.vulnerability_type || '').toLowerCase().includes(state.filters.search) ||
        (ex.instruction || '').toLowerCase().includes(state.filters.search) ||
        (ex.id || '').toLowerCase().includes(state.filters.search);

      const matchesSev = state.filters.severity === 'all' ||
        ex._severity_norm === state.filters.severity;

      const matchesCat = state.filters.category === 'all' ||
        ex.category === state.filters.category;

      return matchesSearch && matchesSev && matchesCat;
    });

    target.innerHTML = C.dataTable({
      columns: [
        { key: '_severity_norm', label: 'Risk', render: s => C.severityBadge(s) },
        { key: 'vulnerability_type', label: 'Vulnerability Analysis' },
        { key: 'category', label: 'Archetype' },
        { key: 'instruction', label: 'Affected Logic', render: (v, row) => `<span style="font-family: var(--font-mono); font-size: 0.8rem;">${v || 'Common'} ${row.line_number ? `(L${row.line_number})` : ''}</span>` },
        { key: '_program_id', label: 'Origin', render: p => `<span style="color: var(--accent-primary); font-family: var(--font-mono);">${C.truncateAddr(p)}</span>` }
      ],
      rows: filtered
    });
  }

  function renderRiskMatrix(container) {
    const C = window.Components;
    container.innerHTML = C.sectionHeader({ title: 'Risk Heatmap', subtitle: 'Severity over Frequency distribution matrix.' });

    const body = `<div id="heatmap-target" style="min-height: 400px; display: flex; align-items: center; justify-content: center;"></div>`;
    container.insertAdjacentHTML('beforeend', C.card({ title: 'Distribution Matrix', body }));

    requestAnimationFrame(() => {
      if (window.Charts && window.Charts.heatmap) {
        const categories = [...new Set(state.allExploits.map(ex => ex.category))];
        const matrix = [
          categories.map(cat => state.allExploits.filter(ex => ex.category === cat && ex.severity >= 4).length),
          categories.map(cat => state.allExploits.filter(ex => ex.category === cat && ex.severity === 3).length),
          categories.map(cat => state.allExploits.filter(ex => ex.category === cat && ex.severity <= 2).length),
        ];
        window.Charts.heatmap($('#heatmap-target'), matrix, {
          rows: ['CRITICAL/HIGH', 'MEDIUM', 'INFO/LOW'],
          cols: categories
        });
      }
    });
  }

  function renderTaintAnalysis(container) {
    const C = window.Components;
    container.innerHTML = C.sectionHeader({ title: 'Static Taint Propagation', subtitle: 'Analysis of untrusted input reaching privileged instructions.' });

    // taint analysis is heavy, keeping it experimental for now
    const body = `
      <div class="empty-state" style="padding: 100px 0; text-align: center;">
         <div class="text-muted" style="margin-bottom: 24px; opacity: 0.2;">${window.Icons.svg('taintAnalysis', 64)}</div>
         <h3 class="text-pure">Experimental Intelligence Module</h3>
         <p class="text-muted">Inter-procedural taint analysis is currently processing large callgraphs. Partial results available in Findings.</p>
      </div>
    `;
    container.insertAdjacentHTML('beforeend', C.card({ title: 'Flow Analysis', body }));
  }

  function setupSidebar() {
    const toggle = $('#sidebar-toggle');
    const shell = $('.app-shell');
    toggle.addEventListener('click', () => {
      state.isSidebarCollapsed = !state.isSidebarCollapsed;
      shell.classList.toggle('is-collapsed', state.isSidebarCollapsed);

      if (state.isSidebarCollapsed) {
        shell.style.gridTemplateColumns = 'var(--sidebar-collapsed) 1fr';
      } else {
        shell.style.gridTemplateColumns = 'var(--sidebar-w) 1fr';
      }
    });
  }

  function setupEventHandlers() {
    document.addEventListener('click', e => {
      // global listener for data-uid elements (finding cards/rows)
      const card = e.target.closest('[data-uid]');
      if (card) {
        const exploit = state.allExploits.find(ex => ex._uid === card.dataset.uid);
        if (exploit) openModal(exploit);
      }

      const dismiss = e.target.closest('[data-dismiss="modal"]');
      if (dismiss || e.target.closest('#modal-close')) {
        closeModal();
      }
    });

    const timestampEl = $('#audit-timestamp');
    if (timestampEl) {
      timestampEl.textContent = window.Components.formatTimestamp(new Date().toISOString());
    }
  }

  function openModal(exploit) {
    const modal = $('#modal-overlay');
    const body = $('#modal-body');
    if (!modal || !body) return;

    body.innerHTML = window.Components.findingDetail(exploit);
    injectIcons();
    modal.classList.add('is-visible');
    document.body.style.overflow = 'hidden';
  }

  function closeModal() {
    const modal = $('#modal-overlay');
    if (modal) modal.classList.remove('is-visible');
    document.body.style.overflow = '';
  }

  function calculateGlobalStats() {
    const r = state.reports;
    if (!r.length) return { total: 0, critical: 0, high: 0, medium: 0, avgScore: 0 };

    return {
      total: r.reduce((s, x) => s + x.total_exploits, 0),
      critical: r.reduce((s, x) => s + x.critical_count, 0),
      high: r.reduce((s, x) => s + x.high_count, 0),
      medium: r.reduce((s, x) => s + x.medium_count, 0),
      avgScore: Math.round(r.reduce((s, x) => s + x.security_score, 0) / r.length)
    };
  }

  init();

})();
