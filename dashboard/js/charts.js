(function () {
  'use strict';

  const NS = 'http://www.w3.org/2000/svg';
  const COLORS = {
    critical: '#ff3355',
    high: '#ff8833',
    medium: '#ffcc33',
    low: '#33dd99',
    accent: '#14f195',
    grid: 'rgba(255, 255, 255, 0.05)',
    text: '#a0a0a0'
  };

  function createEl(tag, attrs = {}) {
    const el = document.createElementNS(NS, tag);
    for (const [k, v] of Object.entries(attrs)) el.setAttribute(k, v);
    return el;
  }

  function clear(container) {
    if (typeof container === 'string') container = document.querySelector(container);
    if (container) container.innerHTML = '';
    return container;
  }

  function donut(container, data, size = 200) {
    const el = clear(container);
    if (!el) return;

    const svg = createEl('svg', {
      width: '100%', height: size,
      viewBox: `0 0 ${size} ${size}`,
      style: 'max-width: 100%;'
    });

    const cx = size / 2;
    const cy = size / 2;
    const r = (size * 0.4);
    const strokeWidth = size * 0.12;
    const circumference = 2 * Math.PI * r;

    let offset = 0;
    const total = Object.values(data).reduce((s, v) => s + v, 0);
    const sortedKeys = ['critical', 'high', 'medium', 'low'];

    sortedKeys.forEach(key => {
      const val = data[key] || 0;
      if (val === 0) return;

      const percentage = val / total;
      const sliceLen = percentage * circumference;

      const circle = createEl('circle', {
        cx, cy, r,
        fill: 'none',
        stroke: COLORS[key],
        'stroke-width': strokeWidth,
        'stroke-dasharray': `${sliceLen} ${circumference}`,
        'stroke-dashoffset': -offset,
        'stroke-linecap': 'butt',
        transform: `rotate(-90 ${cx} ${cy})`,
        style: 'transition: stroke-dasharray 0.8s ease-out;'
      });

      circle.addEventListener('mouseenter', () => {
        circle.setAttribute('stroke-width', strokeWidth * 1.2);
        circle.style.filter = 'drop-shadow(0 0 8px ' + COLORS[key] + ')';
      });
      circle.addEventListener('mouseleave', () => {
        circle.setAttribute('stroke-width', strokeWidth);
        circle.style.filter = 'none';
      });

      svg.appendChild(circle);
      offset += sliceLen;
    });

    const textGroup = createEl('g', { transform: `translate(${cx}, ${cy})` });
    const countText = createEl('text', {
      'text-anchor': 'middle',
      'dominant-baseline': 'middle',
      fill: '#ffffff',
      'font-size': size * 0.15,
      'font-weight': '700'
    });
    countText.textContent = total;
    textGroup.appendChild(countText);

    const labelText = createEl('text', {
      y: size * 0.1,
      'text-anchor': 'middle',
      fill: COLORS.text,
      'font-size': size * 0.06,
      'text-transform': 'uppercase',
      'letter-spacing': '0.1em'
    });
    labelText.textContent = 'Results';
    textGroup.appendChild(labelText);

    svg.appendChild(textGroup);
    el.appendChild(svg);
  }

  function groupedBar(container, programs, height = 240) {
    const el = clear(container);
    if (!el || programs.length === 0) return;

    const width = el.clientWidth || 500;
    const svg = createEl('svg', {
      width: '100%', height,
      viewBox: `0 0 ${width} ${height}`
    });

    const padL = 40;
    const padB = 40;
    const chartW = width - padL - 20;
    const chartH = height - padB - 20;

    const maxVal = Math.max(...programs.map(p => Math.max(p.critical, p.high, p.medium)), 1);

    // grid background
    for (let i = 0; i <= 4; i++) {
      const y = 20 + chartH - (i * chartH / 4);
      const line = createEl('line', {
        x1: padL, y1: y, x2: width - 20, y2: y,
        stroke: COLORS.grid, 'stroke-width': 1
      });
      svg.appendChild(line);
    }

    const groupW = chartW / programs.length;
    const barW = Math.max(groupW * 0.15, 8);

    programs.forEach((p, i) => {
      const gx = padL + (i * groupW) + (groupW * 0.1);

      ['critical', 'high', 'medium'].forEach((sev, si) => {
        const val = p[sev] || 0;
        const bH = (val / maxVal) * chartH;
        const x = gx + (si * barW * 1.5);
        const y = 20 + chartH - bH;

        const rect = createEl('rect', {
          x, y, width: barW, height: bH,
          fill: COLORS[sev],
          rx: 2
        });
        svg.appendChild(rect);
      });

      const label = createEl('text', {
        x: gx + groupW * 0.2,
        y: height - 15,
        fill: COLORS.text,
        'font-size': 10,
        'text-anchor': 'middle'
      });
      label.textContent = p.name;
      svg.appendChild(label);
    });

    el.appendChild(svg);
  }

  function heatmap(container, matrix, opts) {
    const el = clear(container);
    if (!el) return;

    const rows = opts.rows || [];
    const cols = opts.cols || [];
    const cellS = 40;
    const padL = 120;
    const padT = 50;

    const svg = createEl('svg', {
      width: '100%', height: padT + (rows.length * cellS) + 20,
      viewBox: `0 0 ${padL + (cols.length * cellS) + 20} ${padT + (rows.length * cellS) + 20}`
    });

    cols.forEach((col, ci) => {
      const t = createEl('text', {
        x: padL + (ci * cellS) + cellS / 2,
        y: padT - 15,
        fill: COLORS.text,
        'font-size': 9,
        'text-anchor': 'middle'
      });
      t.textContent = col.length > 12 ? col.slice(0, 10) + '..' : col;
      svg.appendChild(t);
    });

    rows.forEach((row, ri) => {
      const rt = createEl('text', {
        x: padL - 15,
        y: padT + (ri * cellS) + cellS / 2,
        fill: COLORS.text,
        'font-size': 10,
        'text-anchor': 'end',
        'dominant-baseline': 'middle'
      });
      rt.textContent = row;
      svg.appendChild(rt);

      cols.forEach((col, ci) => {
        const val = matrix[ri][ci] || 0;
        const max = Math.max(...matrix.flat(), 1);
        const opacity = 0.1 + (val / max) * 0.9;
        const fill = val > 0 ? COLORS.accent : 'rgba(255,255,255,0.02)';

        const rect = createEl('rect', {
          x: padL + (ci * cellS) + 2,
          y: padT + (ri * cellS) + 2,
          width: cellS - 4,
          height: cellS - 4,
          fill: fill,
          opacity: opacity,
          rx: 4
        });
        svg.appendChild(rect);

        if (val > 0) {
          const vt = createEl('text', {
            x: padL + (ci * cellS) + cellS / 2,
            y: padT + (ri * cellS) + cellS / 2,
            fill: '#fff',
            'font-size': 10,
            'font-weight': '700',
            'text-anchor': 'middle',
            'dominant-baseline': 'middle'
          });
          vt.textContent = val;
          svg.appendChild(vt);
        }
      });
    });

    el.appendChild(svg);
  }

  window.Charts = {
    donut,
    groupedBar,
    heatmap,
    gauge: (container, val) => {
      const el = clear(container);
      el.innerHTML = `<div style="color:var(--accent-primary); font-size: 1.5rem; font-weight:700;">${val}%</div>`;
    }
  };

})();
