(function () {
  'use strict';

  function open(s, className) {
    const cls = className ? ` class="${className}"` : '';
    return `<svg width="${s}" height="${s}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"${cls}>`;
  }

  const C = '</svg>';

  const lib = {
    overview: (size = 20) => open(size) +
      '<rect x="3" y="3" width="7" height="7" rx="1"/>' +
      '<rect x="14" y="3" width="7" height="7" rx="1"/>' +
      '<rect x="3" y="14" width="7" height="7" rx="1"/>' +
      '<rect x="14" y="14" width="7" height="7" rx="1"/>' + C,

    programs: (size = 20) => open(size) +
      '<path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z"/>' +
      '<polyline points="3.27 6.96 12 12.01 20.73 6.96"/>' +
      '<line x1="12" y1="22.08" x2="12" y2="12"/>' + C,

    findings: (size = 20) => open(size) +
      '<circle cx="12" cy="12" r="10"/>' +
      '<circle cx="12" cy="12" r="6"/>' +
      '<circle cx="12" cy="12" r="2"/>' +
      '<line x1="12" y1="2" x2="12" y2="4"/>' +
      '<line x1="12" y1="20" x2="12" y2="22"/>' +
      '<line x1="2" y1="12" x2="4" y2="12"/>' +
      '<line x1="20" y1="12" x2="22" y2="12"/>' + C,

    'risk-matrix': (size = 20) => open(size) +
      '<rect x="3" y="3" width="18" height="18" rx="2"/>' +
      '<line x1="3" y1="9" x2="21" y2="9"/>' +
      '<line x1="3" y1="15" x2="21" y2="15"/>' +
      '<line x1="9" y1="3" x2="9" y2="21"/>' +
      '<line x1="15" y1="3" x2="15" y2="21"/>' +
      '<line x1="3" y1="21" x2="21" y2="3"/>' + C,

    'taint-analysis': (size = 20) => open(size) +
      '<line x1="6" y1="3" x2="6" y2="15"/>' +
      '<circle cx="18" cy="6" r="3"/>' +
      '<circle cx="6" cy="18" r="3"/>' +
      '<path d="M6 6a9 9 0 0 0 9 9"/>' + C,

    critical: (size = 6) => `<svg width="${size}" height="${size}" viewBox="0 0 10 10" fill="currentColor"><circle cx="5" cy="5" r="5"/></svg>`,

    criticalAlert: (size = 20) => open(size) +
      '<polygon points="7.86 2 16.14 2 22 7.86 22 16.14 16.14 22 7.86 22 2 16.14 2 7.86 7.86 2"/>' +
      '<line x1="12" y1="8" x2="12" y2="12"/>' +
      '<line x1="12" y1="16" x2="12.01" y2="16"/>' + C,

    securityScore: (size = 20) => open(size) +
      '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>' +
      '<polyline points="9 12 11 14 15 10"/>' + C,

    shield: (size = 20) => open(size) +
      '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>' + C,

    search: (size = 20) => open(size) +
      '<circle cx="11" cy="11" r="8"/>' +
      '<line x1="21" y1="21" x2="16.65" y2="16.65"/>' + C,

    bell: (size = 20) => open(size) +
      '<path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9"/>' +
      '<path d="M13.73 21a2 2 0 0 1-3.46 0"/>' + C,

    account: (size = 20) => open(size) +
      '<path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/>' +
      '<circle cx="12" cy="7" r="4"/>' + C,

    x: (size = 20) => open(size) +
      '<line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/>' + C,

    code: (size = 16) => open(size) +
      '<polyline points="16 18 22 12 16 6"/><polyline points="8 6 2 12 8 18"/>' + C,

    brain: (size = 16) => open(size) +
      '<path d="M12 2a5 5 0 0 1 4.9 4 4.5 4.5 0 0 1 2.1 3.8 4.5 4.5 0 0 1-1.8 3.6A4 4 0 0 1 14 18h-4a4 4 0 0 1-3.2-4.6A4.5 4.5 0 0 1 5 9.8 4.5 4.5 0 0 1 7.1 6 5 5 0 0 1 12 2z"/>' +
      '<path d="M12 2v20"/><path d="M8 8c1.5 0 3 1 4 2"/><path d="M16 8c-1.5 0-3 1-4 2"/><path d="M8 14c1.5 0 3-1 4-2"/><path d="M16 14c-1.5 0-3-1-4-2"/>' + C,

    sword: (size = 16) => open(size) +
      '<line x1="4" y1="4" x2="18" y2="18"/><polyline points="15 4 18 4 18 7"/><line x1="20" y1="4" x2="4" y2="20"/><polyline points="9 4 6 4 6 7"/><polyline points="15 20 18 20 18 17"/><polyline points="9 20 6 20 6 17"/>' + C,

    folder: (size = 14) => open(size) +
      '<path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"/>' + C,

    mapPin: (size = 14) => open(size) +
      '<path d="M21 10c0 7-9 13-9 13s-9-6-9-13a9 9 0 0 1 18 0z"/><circle cx="12" cy="10" r="3"/>' + C,

    activity: (size = 20) => open(size) +
      '<polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/>' + C
  };

  window.Icons = {
    svg: (name, size, className) => {
      const fn = lib[name];
      if (!fn) return '';
      let res = fn(size);
      if (className) res = res.replace('<svg ', `<svg class="${className}" `);
      return res;
    }
  };

})();
