(function () {
  'use strict';

  function escapeHtml(str) {
    if (str == null) return '';
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }

  function truncateAddr(addr, len = 6) {
    if (!addr) return '—';
    if (addr.length <= len * 2 + 1) return escapeHtml(addr);
    return escapeHtml(addr.slice(0, len)) + '…' + escapeHtml(addr.slice(-len));
  }

  function getSeverityLabel(s) {
    if (typeof s === 'string') return s.toUpperCase();
    switch (s) {
      case 5: return 'CRITICAL';
      case 4: return 'HIGH';
      case 3: return 'MEDIUM';
      case 2: return 'LOW';
      default: return 'INFO';
    }
  }

  function searchInput(opts = {}) {
    const placeholder = opts.placeholder || 'Filter intelligence...';
    const id = opts.id || 'search-input';
    const icon = window.Icons ? window.Icons.svg('search', 16) : '';

    return `
      <div class="search-field">
        <span class="search-field__icon">${icon}</span>
        <input type="text" id="${id}" class="search-field__input" placeholder="${escapeHtml(placeholder)}" aria-label="Search findings" />
      </div>
    `;
  }

  function filterGroup(opts = {}) {
    const { label, id, options } = opts;
    return `
      <div class="filter-group">
        <label for="${id}" class="filter-group__label">${escapeHtml(label)}</label>
        <select id="${id}" class="filter-group__select">
          ${options.map(opt => `<option value="${opt.value}">${escapeHtml(opt.label)}</option>`).join('')}
        </select>
      </div>
    `;
  }

  function statCard(opts) {
    const iconName = opts.iconName || 'activity';
    const value = opts.value != null ? opts.value : '—';
    const label = opts.label || '';
    const variant = opts.variant || 'default';
    const trend = opts.trend || '';
    const context = opts.context || '';

    let trendHtml = '';
    if (trend) {
      const isUp = trend.startsWith('+');
      const cls = isUp ? 'stat-card__trend--up' : 'stat-card__trend--down';
      trendHtml = `<span class="stat-card__trend ${cls}">${escapeHtml(trend)}</span>`;
    }

    const iconHtml = window.Icons ? window.Icons.svg(iconName, 24) : '';

    return `
      <div class="stat-card stat-card--${variant}">
        <div class="stat-card__icon">${iconHtml}</div>
        <div class="stat-card__body">
          <div class="stat-card__value">
            ${escapeHtml(String(value))}
            ${trendHtml}
          </div>
          <div class="stat-card__label">${escapeHtml(label)}</div>
          ${context ? `<p class="stat-card__context text-muted mt-4" style="font-size: 0.75rem;">${escapeHtml(context)}</p>` : ''}
        </div>
      </div>
    `;
  }

  function statGrid(cards) {
    return `<div class="stat-grid">${(cards || []).join('')}</div>`;
  }

  function severityBadge(severity) {
    const label = getSeverityLabel(severity);
    const cls = label.toLowerCase();
    return `
      <span class="severity-badge severity-badge--${cls}" aria-label="Severity: ${label}">
        <span class="severity-badge__dot"></span>
        ${label}
      </span>
    `;
  }

  function riskBadge(passed) {
    const label = passed ? 'SECURE' : 'VULNERABLE';
    const variant = passed ? 'low' : 'critical';
    return `
      <span class="severity-badge severity-badge--${variant}" style="border-radius: 4px;">
        ${label}
      </span>
    `;
  }

  function card(opts) {
    const title = opts.title || '';
    const subtitle = opts.subtitle || '';
    const body = opts.body || '';
    const headerRight = opts.headerRight || '';
    const className = opts.className || '';

    return `
      <div class="card ${className}">
        <div class="card__header">
          <div class="card__header-left">
            <h3 class="card__title">${escapeHtml(title)}</h3>
            <p class="card__subtitle">${escapeHtml(subtitle)}</p>
          </div>
          <div class="card__header-right">${headerRight}</div>
        </div>
        <div class="card__body">${body}</div>
      </div>
    `;
  }

  function findingCard(exploit) {
    if (!exploit) return '';

    const label = getSeverityLabel(exploit.severity_label || exploit.severity);
    const category = exploit.category || 'General';
    const instruction = exploit.instruction || 'N/A';

    // truncate description for the card view
    const description = exploit.description || 'No detailed description provided.';
    const shortDesc = description.length > 140 ? description.slice(0, 137) + '…' : description;

    const iconFolder = window.Icons ? window.Icons.svg('folder', 14) : '';
    const iconPin = window.Icons ? window.Icons.svg('mapPin', 14) : '';

    return `
      <article class="finding-card finding-card--${label.toLowerCase()}" data-uid="${exploit._uid || ''}">
        <div class="finding-card__header">
          ${severityBadge(label)}
          ${exploit.cwe ? `<span class="text-muted" style="font-size: 0.7rem; font-family: var(--font-mono);">${escapeHtml(exploit.cwe)}</span>` : ''}
        </div>
        <h4 class="finding-card__title">${escapeHtml(exploit.vulnerability_type || 'Unspecified Vulnerability')}</h4>
        <div class="finding-card__meta">
          <span title="Security Category">${iconFolder} ${escapeHtml(category)}</span>
          <span title="Affected Instruction">${iconPin} ${escapeHtml(instruction)}${exploit.line_number ? ` : L${exploit.line_number}` : ''}</span>
        </div>
        <p class="finding-card__desc">${escapeHtml(shortDesc)}</p>
      </article>
    `;
  }

  function findingDetail(exploit) {
    if (!exploit) return '<p class="text-muted">No assessment data available for this finding.</p>';

    const sections = [];

    sections.push(`
      <div class="finding-detail__summary mb-4">
        <div class="finding-detail__header" style="display: flex; align-items: center; gap: 12px; margin-bottom: 16px;">
          ${severityBadge(exploit.severity_label || exploit.severity)}
          <span class="text-muted" style="font-family: var(--font-mono); font-size: 0.8rem;">REF-ID: ${escapeHtml(exploit.id || 'N/A')}</span>
        </div>
        <h1 style="font-size: 1.5rem; color: var(--text-pure); margin-bottom: 12px;">${escapeHtml(exploit.vulnerability_type || 'Vulnerability Analysis')}</h1>
        <p class="text-secondary" style="font-size: 1rem; line-height: 1.6;">${escapeHtml(exploit.description || '')}</p>
      </div>
    `);

    sections.push(detailSection('Technical Context', `
      <div class="grid-2" style="margin-bottom: 0;">
        <div>
          <label class="text-muted" style="font-size: 0.7rem; text-transform: uppercase;">Affected Instruction</label>
          <div class="text-pure" style="font-family: var(--font-mono);">${escapeHtml(exploit.instruction || 'Common Utility')}</div>
        </div>
        <div>
          <label class="text-muted" style="font-size: 0.7rem; text-transform: uppercase;">Security Category</label>
          <div class="text-pure">${escapeHtml(exploit.category || 'General')}</div>
        </div>
      </div>
    `, 'code'));

    if (exploit.attack_scenario) {
      sections.push(detailSection('Threat Assessment & Proof of Concept', `
        <p class="mb-4">${escapeHtml(exploit.attack_scenario)}</p>
        ${exploit.economic_impact ? `<div style="background: var(--bg-surface); padding: 12px; border-radius: 4px; border-left: 3px solid var(--accent-secondary);">
          <strong class="text-pure" style="font-size: 0.8rem; display: block; margin-bottom: 4px;">Potential Economic Impact</strong>
          <span style="font-size: 0.9rem;">${escapeHtml(exploit.economic_impact)}</span>
        </div>` : ''}
      `, 'sword'));
    }

    if (exploit.secure_fix || exploit.fix_suggestion_enhanced) {
      const code = exploit.secure_fix || exploit.fix_suggestion_enhanced;
      sections.push(detailSection('Strategic Remediation', `
        <p class="mb-4">${escapeHtml(exploit.prevention || 'Implementation of proper authority checks and state validation.')}</p>
        <div class="code-block">
          <pre><code>${escapeHtml(code)}</code></pre>
        </div>
      `, 'shield'));
    }

    if (exploit.ai_explanation) {
      sections.push(detailSection('Agentic Insight', `
        <p style="font-style: italic; border-left: 2px solid var(--accent-primary); padding-left: 16px;">${escapeHtml(exploit.ai_explanation)}</p>
      `, 'brain'));
    }

    return `<div class="finding-detail">${sections.join('')}</div>`;
  }

  function detailSection(title, contentHtml, iconName) {
    const iconHtml = window.Icons && iconName ? window.Icons.svg(iconName, 16) : '';
    return `
      <section class="finding-detail__section">
        <h3 class="finding-detail__section-title">
          ${iconHtml} ${escapeHtml(title)}
        </h3>
        <div class="finding-detail__section-body">${contentHtml}</div>
      </section>
    `;
  }

  function sectionHeader(opts) {
    return `
      <div class="section-header">
        <h2 class="section-header__title">${escapeHtml(opts.title)}</h2>
        <p class="section-header__subtitle">${escapeHtml(opts.subtitle)}</p>
      </div>
    `;
  }

  function dataTable(opts) {
    const columns = opts.columns || [];
    const rows = opts.rows || [];
    const emptyText = opts.emptyText || 'No intelligence data retrieved for this query.';

    if (rows.length === 0) {
      return `
        <div class="empty-state" style="padding: 64px 0; text-align: center;">
          <div class="text-muted mb-4" style="opacity: 0.3;">${window.Icons ? window.Icons.svg('search', 48) : ''}</div>
          <p class="text-muted">${escapeHtml(emptyText)}</p>
        </div>
      `;
    }

    const ths = columns.map(col => `<th class="data-table__th">${escapeHtml(col.label)}</th>`).join('');
    const trs = rows.map((row) => {
      const tds = columns.map(col => {
        const raw = row[col.key];
        const val = col.render ? col.render(raw, row) : escapeHtml(raw != null ? String(raw) : '—');
        return `<td class="data-table__td">${val}</td>`;
      }).join('');
      return `<tr class="data-table__tr" data-uid="${row._uid || ''}">${tds}</tr>`;
    }).join('');

    return `
      <div class="data-table-wrapper">
        <table class="data-table">
          <thead><tr>${ths}</tr></thead>
          <tbody>${trs}</tbody>
        </table>
      </div>
    `;
  }

  window.Components = {
    statCard,
    statGrid,
    severityBadge,
    riskBadge,
    card,
    findingCard,
    findingDetail,
    sectionHeader,
    dataTable,
    searchInput,
    filterGroup,
    truncateAddr,
    formatTimestamp: (iso) => {
      if (!iso) return 'NEVER';
      const d = new Date(iso);
      return d.toLocaleString('en-US', { hour12: false, month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' }).toUpperCase();
    }
  };

})();
