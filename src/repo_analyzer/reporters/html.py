"""HTML reporter: the polished, shareable dashboard (and the Pages demo artifact).

Self-contained dark dashboard (no external CDN/fonts/network): inline CSS, inline
SVG charts, a tiny vanilla-JS tab + severity filter. Palette mirrors the author's
portfolio (arthurbernard.dev). Rendered with Jinja2 autoescaping ON, and
reference URLs are scheme-checked (``safe_url``), so repo/tool-controlled strings
cannot inject markup or active links.
"""

from __future__ import annotations

from urllib.parse import urlsplit

from jinja2 import Environment

from ..report import Report
from ._common import build_context


def _safe_url(value: object) -> str | None:
    """Return the URL only if it uses an http(s) scheme (blocks javascript:/data:)."""
    try:
        return str(value) if urlsplit(str(value)).scheme in ("http", "https") else None
    except ValueError:
        return None


_ENV = Environment(trim_blocks=True, lstrip_blocks=True, autoescape=True)
_ENV.filters["safe_url"] = _safe_url

_TEMPLATE = _ENV.from_string(
    """
{%- macro card(f) -%}
      <div class="finding" data-sev="{{ f.sev }}" data-dom="{{ f.domain }}">
        <div class="cardtop">
          <span class="sevbadge" style="background: {{ f.color }}">{{ f.sev_label }}</span>
          <span class="domtag">{{ f.domain }}</span>
        </div>
        <div class="title">{{ f.title }}</div>
        {% if f.file %}<div class="row"><span class="lbl">where</span><span class="loc mono">{{ f.file }}{% if f.line %}:{{ f.line }}{% endif %}{% if f.resource %} · {{ f.resource }}{% endif %}</span></div>{% endif %}
        {% if f.message %}<div class="msg">{{ f.message }}</div>{% endif %}
        <div class="row"><span class="lbl">fix</span><span class="fix">{{ f.action }}</span></div>
        <div class="prov">
          <span class="pill">{{ f.tool }}</span>
          <span class="pill mono">{{ f.rule_id }}</span>
          {% set ref = (f.references[0] | safe_url) if f.references else None %}
          {% if ref %}<a class="pill dig" href="{{ ref }}" rel="noopener noreferrer">dig ↗</a>{% endif %}
        </div>
      </div>
{%- endmacro -%}
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>repo-analyzer · {{ repo_name }}</title>
<style>
  :root {
    --bg: #121212; --hero: #0a0a0a; --card: #141414; --card-2: #1a1a1a;
    --border: rgba(140,150,255,.10); --border-2: rgba(255,255,255,.08);
    --text: #e2e8f0; --muted: #94a3b8; --faint: #64748b;
    --accent: #8c96ff; --accent-hover: #7c8aff; --track: #262626;
    --radius: 14px; --shadow: 0 8px 24px -4px rgba(0,0,0,.35);
  }
  * { box-sizing: border-box; }
  html { -webkit-font-smoothing: antialiased; }
  body {
    margin: 0; background: var(--bg); color: var(--text);
    font-family: "DM Sans", -apple-system, BlinkMacSystemFont, "Segoe UI", system-ui, sans-serif;
    font-size: 14px; line-height: 1.55;
    background-image: radial-gradient(820px 360px at 82% -8%, rgba(140,150,255,.10), transparent 62%);
  }
  .wrap { max-width: 1040px; margin: 0 auto; padding: 26px 24px 80px; }
  a { color: var(--accent); text-decoration: none; }
  a:hover { color: var(--accent-hover); }
  .mono { font-family: ui-monospace, "SF Mono", "JetBrains Mono", Menlo, monospace; }

  .topbar { display: flex; align-items: center; justify-content: space-between; margin-bottom: 26px; }
  .brand { display: flex; align-items: center; gap: 9px; font-weight: 600; letter-spacing: -.01em; }
  .brand .dot { width: 11px; height: 11px; border-radius: 3px; background: var(--accent);
                box-shadow: 0 0 16px rgba(140,150,255,.7); }
  .gate { font-size: 12px; font-weight: 600; padding: 6px 13px; border-radius: 999px; border: 1px solid var(--border-2); }
  .gate.pass { color: #2fdca5; background: rgba(47,220,165,.12); border-color: rgba(47,220,165,.35); }
  .gate.fail { color: #fb2e6b; background: rgba(251,46,107,.12); border-color: rgba(251,46,107,.35); }
  .badges { display: flex; align-items: center; gap: 9px; }
  .scbadge { font-size: 12px; font-weight: 600; padding: 6px 13px; border-radius: 999px;
             border: 1px solid var(--border-2); background: var(--card); }

  .hero { display: grid; grid-template-columns: auto 1fr auto; gap: 28px; align-items: center;
          background: linear-gradient(180deg, var(--card-2), var(--hero)); border: 1px solid var(--border);
          border-radius: var(--radius); padding: 26px 30px; box-shadow: var(--shadow); }
  .gauge { position: relative; width: 140px; height: 140px; }
  .gauge .center { position: absolute; inset: 0; display: flex; flex-direction: column; align-items: center; justify-content: center; }
  .gauge .grade { font-size: 38px; font-weight: 700; letter-spacing: -.02em; line-height: 1; }
  .gauge .score { font-size: 12px; color: var(--muted); margin-top: 3px; }
  .hero h1 { margin: 0 0 4px; font-size: 23px; font-weight: 650; letter-spacing: -.02em; }
  .hero .sub { color: var(--muted); font-size: 13px; }
  .meta { margin-top: 15px; display: grid; gap: 5px; font-size: 12.5px; }
  .meta div { display: flex; gap: 8px; }
  .meta .k { color: var(--faint); min-width: 76px; }
  .meta .v { color: var(--muted); word-break: break-all; }

  .donut-wrap { display: flex; flex-direction: column; align-items: center; gap: 10px; }
  .legend { display: grid; grid-template-columns: 1fr 1fr; gap: 3px 14px; font-size: 12px; }
  .legend span { display: flex; align-items: center; gap: 6px; color: var(--muted); }
  .legend i { width: 8px; height: 8px; border-radius: 2px; display: inline-block; }
  .legend b { color: var(--text); font-weight: 600; }

  .tabs { display: flex; gap: 4px; margin: 30px 0 0; border-bottom: 1px solid var(--border-2); }
  .tab { cursor: pointer; user-select: none; font-size: 13.5px; font-weight: 500; padding: 11px 16px;
         color: var(--muted); border-bottom: 2px solid transparent; margin-bottom: -1px; }
  .tab:hover { color: var(--text); }
  .tab.active { color: var(--text); border-bottom-color: var(--accent); }
  .tab .n { font-size: 11px; color: var(--faint); margin-left: 6px; }

  section h2 { font-size: 12px; font-weight: 600; text-transform: uppercase; letter-spacing: .08em;
               color: var(--faint); margin: 26px 0 13px; }
  .note { font-size: 12.5px; color: var(--faint); margin: 12px 0 0; }
  .note b { color: var(--muted); }

  .verdict { font-size: 13.5px; font-weight: 600; margin: 3px 0 4px; }
  .h2note { text-transform: none; letter-spacing: 0; color: var(--faint); font-weight: 400; }
  .domgrid { display: grid; grid-template-columns: repeat(auto-fit, minmax(124px, 1fr)); gap: 10px; }
  .domcard { cursor: pointer; border: 1px solid var(--border-2); border-radius: 12px; padding: 13px 15px;
             background: var(--card); transition: .12s; }
  .domcard:hover { border-color: var(--border); }
  .domcard.active { border-color: var(--accent); background: rgba(140,150,255,.07); }
  .dc-label { font-size: 11px; color: var(--muted); text-transform: uppercase; letter-spacing: .05em;
              margin-bottom: 7px; display: flex; align-items: center; gap: 6px; }
  .dc-score { font-size: 27px; font-weight: 700; letter-spacing: -.02em; line-height: 1; }
  .dc-of { font-size: 13px; color: var(--faint); font-weight: 500; }
  .dc-sub { font-size: 11.5px; color: var(--faint); margin-top: 5px; }

  .chips { display: flex; flex-wrap: wrap; gap: 8px; }
  .chip { cursor: pointer; user-select: none; font-size: 12.5px; font-weight: 500; padding: 7px 13px;
          border-radius: 999px; border: 1px solid var(--border-2); background: var(--card); color: var(--muted); transition: .12s; }
  .chip:hover { border-color: var(--border); color: var(--text); }
  .chip.active { background: var(--text); color: #121212; border-color: var(--text); }
  .chip i { width: 7px; height: 7px; border-radius: 2px; display: inline-block; margin-right: 6px; }

  .finding { border: 1px solid var(--border-2); border-radius: 12px; padding: 16px 18px;
             margin-bottom: 12px; background: var(--card); }
  .finding:hover { border-color: var(--border); }
  .cardtop { display: flex; gap: 8px; align-items: center; margin-bottom: 9px; }
  .sevbadge { font-size: 10.5px; font-weight: 700; letter-spacing: .05em; text-transform: uppercase;
              color: #121212; padding: 3px 11px; border-radius: 999px; }
  .domtag { font-size: 10.5px; font-weight: 600; letter-spacing: .04em; text-transform: uppercase;
            color: var(--muted); border: 1px solid var(--border-2); padding: 2px 10px; border-radius: 999px; }
  .finding .title { font-size: 15px; font-weight: 650; line-height: 1.4; letter-spacing: -.01em; }
  .finding .row { display: flex; gap: 10px; align-items: baseline; margin-top: 9px; font-size: 12.5px; }
  .lbl { flex: 0 0 36px; font-size: 10px; font-weight: 700; text-transform: uppercase; letter-spacing: .06em; color: var(--faint); }
  .finding .loc { color: var(--accent); word-break: break-all; }
  .finding .msg { color: #c2c2cc; font-size: 13px; margin-top: 9px; line-height: 1.5; }
  .finding .fix { color: var(--text); }
  .prov { margin-top: 12px; display: flex; gap: 7px; flex-wrap: wrap; align-items: center; }
  .pill { font-size: 11px; color: var(--muted); border: 1px solid var(--border-2); padding: 2px 9px; border-radius: 999px; }
  .pill.dig { color: var(--accent); border-color: var(--border); }
  .gradetag { font-size: 10px; font-weight: 700; color: var(--accent); border: 1px solid var(--border); padding: 1px 6px; border-radius: 5px; }

  .empty { text-align: center; padding: 52px 18px; color: var(--muted); }
  .empty .big { font-size: 17px; color: var(--text); margin-bottom: 6px; }
  .empty.clean .big { color: #8cffa0; }
  .rawbox { margin-top: 40px; border: 1px solid var(--border); border-radius: var(--radius);
            background: linear-gradient(180deg, var(--card-2), var(--card)); padding: 18px 20px;
            display: flex; align-items: center; justify-content: space-between; gap: 18px; flex-wrap: wrap; }
  .rawbox-title { font-size: 13px; font-weight: 650; letter-spacing: -.01em; }
  .rawbox-desc { font-size: 12px; color: var(--faint); margin-top: 3px; max-width: 560px; }
  .rawbox-links { display: flex; gap: 8px; flex-wrap: wrap; }
  .rawlink { font-size: 11.5px; color: var(--muted); border: 1px solid var(--border-2); background: var(--card);
             padding: 6px 13px; border-radius: 999px; transition: .12s; }
  .rawlink:hover { border-color: var(--accent); color: var(--accent); }

  footer { margin-top: 40px; padding-top: 18px; border-top: 1px solid var(--border-2);
           color: var(--faint); font-size: 12px; display: flex; justify-content: space-between; flex-wrap: wrap; gap: 8px; }

  @media (max-width: 720px) {
    .hero { grid-template-columns: 1fr; text-align: center; justify-items: center; }
  }
</style>
</head>
<body>
<main class="wrap">
  <div class="topbar">
    <div class="brand"><span class="dot"></span> repo-analyzer</div>
    <div class="badges">
      {% if supply_chain %}<div class="scbadge" style="border-color: {{ supply_chain.color }}; color: {{ supply_chain.color }}" title="OpenSSF Scorecard posture (advisory, excluded from the grade)">Supply chain {{ supply_chain.grade }} · {{ supply_chain.score }}/100</div>{% endif %}
      <div class="gate {{ 'pass' if passed else 'fail' }}">Gate {{ gate_status }}</div>
    </div>
  </div>

  <div class="hero">
    <div class="gauge">
      <svg width="140" height="140" viewBox="0 0 140 140">
        <circle cx="70" cy="70" r="{{ ring.radius }}" fill="none" stroke="var(--track)" stroke-width="11"/>
        <circle cx="70" cy="70" r="{{ ring.radius }}" fill="none" stroke="{{ grade_color }}" stroke-width="11"
                stroke-linecap="round" stroke-dasharray="{{ ring.dash }} {{ ring.circ }}" transform="rotate(-90 70 70)"/>
      </svg>
      <div class="center">
        <div class="grade" style="color: {{ grade_color }}">{{ grade }}</div>
        <div class="score">{{ total }}/100</div>
      </div>
    </div>

    <div>
      <h1>{{ repo_name }}</h1>
      <div class="verdict" style="color: {{ grade_color }}">Security grade {{ grade }} · {{ grade_caption }}</div>
      <div class="sub">{{ total_findings }} finding{{ '' if total_findings == 1 else 's' }} · scanned by {{ tools }}</div>
      <div class="meta">
        <div><span class="k">Target</span><span class="v mono">{{ target }}</span></div>
        <div><span class="k">Generated</span><span class="v">{{ generated_at }}</span></div>
        <div><span class="k">Fails on</span><span class="v">{{ fail_on }}</span></div>
        {% if duplicates_removed %}
        <div><span class="k">Deduped</span><span class="v">{{ duplicates_removed }} cross-tool duplicate(s)</span></div>
        {% endif %}
      </div>
    </div>

    <div class="donut-wrap">
      <svg width="160" height="160" viewBox="0 0 160 160">
        <circle cx="80" cy="80" r="{{ donut.radius }}" fill="none" stroke="var(--track)" stroke-width="16"/>
        {% for seg in donut.segments %}
        <circle cx="80" cy="80" r="{{ donut.radius }}" fill="none" stroke="{{ seg.color }}" stroke-width="16"
                stroke-dasharray="{{ seg.dash }} {{ seg.gap }}" stroke-dashoffset="{{ seg.offset }}" transform="rotate(-90 80 80)"/>
        {% endfor %}
        <text x="80" y="75" text-anchor="middle" fill="var(--text)" font-size="26" font-weight="700">{{ total_findings }}</text>
        <text x="80" y="94" text-anchor="middle" fill="var(--muted)" font-size="11">findings</text>
      </svg>
      <div class="legend">
        {% for c in counts %}{% if c.count %}
        <span><i style="background: {{ c.color }}"></i>{{ c.label }} <b>{{ c.count }}</b></span>
        {% endif %}{% endfor %}
      </div>
    </div>
  </div>

  <div class="tabs">
    <div class="tab active" data-tab="project">App &amp; Infra<span class="n">{{ project_cards | length }}</span></div>
    <div class="tab" data-tab="ci">CI/CD<span class="n">{{ ci_cards | length }}</span></div>
    <div class="tab" data-tab="repo">Supply chain<span class="n">{{ (repo_cards | length) if supply_chain else 'n/a' }}</span></div>
  </div>

  <section data-panel="project">
    {% if domains %}
    <h2>Domains <span class="h2note">(click a domain to filter)</span></h2>
    <div class="domgrid">
      <div class="domcard active" data-domfilter="all">
        <div class="dc-label">All</div>
        <div class="dc-score">{{ project_cards | length }}</div>
        <div class="dc-sub">findings</div>
      </div>
      {% for d in domains %}
      <div class="domcard" data-domfilter="{{ d.label }}">
        <div class="dc-label">{{ d.label }}</div>
        <div class="dc-score" style="color: {{ d.color }}">{{ d.score }}<span class="dc-of">/100</span></div>
        <div class="dc-sub">{{ d.findings }} finding{{ '' if d.findings == 1 else 's' }}</div>
      </div>
      {% endfor %}
    </div>
    {% endif %}
    {% if not_assessed %}
    <p class="note">Not assessed (no relevant files found): <b>{{ not_assessed | join(', ') }}</b></p>
    {% endif %}

    {% if project_cards %}
    <h2>Findings</h2>
    <div class="chips">
      <span class="chip active" data-sevfilter="all">All severities</span>
      {% for c in counts %}{% if c.count %}
      <span class="chip" data-sevfilter="{{ c.value }}"><i style="background: {{ c.color }}"></i>{{ c.label }} {{ c.count }}</span>
      {% endif %}{% endfor %}
    </div>
    <div style="margin-top: 14px">
      {% for f in project_cards %}{{ card(f) }}{% endfor %}
    </div>
    {% else %}
    <div class="empty clean"><div class="big">✓ No findings</div>Clean across the assessed project domains.</div>
    {% endif %}
  </section>

  <section data-panel="ci" style="display:none">
    {% if ci_cards %}
    <div style="margin-top: 18px">{% for f in ci_cards %}{{ card(f) }}{% endfor %}</div>
    {% else %}
    <div class="empty clean"><div class="big">✓ No pipeline findings</div>GitHub Actions workflows scanned by zizmor + actionlint.</div>
    {% endif %}
  </section>

  <section data-panel="repo" style="display:none">
    {% if repo_cards %}
    <div style="margin-top: 18px">{% for f in repo_cards %}{{ card(f) }}{% endfor %}</div>
    {% else %}
    <div class="empty"><div class="big">Supply-chain posture</div>OpenSSF Scorecard scores the repo's governance &amp; supply chain (branch protection, signed releases, pinned dependencies, token permissions...). It inspects the remote GitHub repo, so it runs in CI on a GitHub repository and is not assessed for a local folder scan. Advisory: shown as a header badge, excluded from the grade.</div>
    {% endif %}
  </section>

  {% if raw_tools %}
  <section class="rawbox">
    <div>
      <div class="rawbox-title">Raw scanner output</div>
      <div class="rawbox-desc">Untouched JSON straight from each tool, to audit or dig deeper. gitleaks is excluded on purpose (its raw report would expose the matched secret).</div>
    </div>
    <div class="rawbox-links">
      {% for t in raw_tools %}<a class="rawlink mono" href="raw/{{ t }}.json">{{ t }}.json</a>{% endfor %}
    </div>
  </section>
  {% endif %}

  <footer>
    <span>Generated by <a href="https://github.com/TuroTheReal/repo-analyzer">repo-analyzer</a></span>
    <span>Grade computed only over assessed domains</span>
  </footer>
</main>
<script>
  (function () {
    var tabs = document.querySelectorAll('[data-tab]');
    var panels = document.querySelectorAll('[data-panel]');
    tabs.forEach(function (t) {
      t.addEventListener('click', function () {
        tabs.forEach(function (x) { x.classList.remove('active'); });
        t.classList.add('active');
        var name = t.getAttribute('data-tab');
        panels.forEach(function (p) { p.style.display = (p.getAttribute('data-panel') === name) ? '' : 'none'; });
      });
    });
    var cards = document.querySelectorAll('[data-panel="project"] .finding');
    var domcards = document.querySelectorAll('[data-domfilter]');
    var chips = document.querySelectorAll('[data-sevfilter]');
    var activeDom = 'all', activeSev = 'all';
    function applyFilters() {
      cards.forEach(function (card) {
        var okDom = activeDom === 'all' || card.getAttribute('data-dom') === activeDom;
        var okSev = activeSev === 'all' || card.getAttribute('data-sev') === activeSev;
        card.style.display = (okDom && okSev) ? '' : 'none';
      });
    }
    domcards.forEach(function (d) {
      d.addEventListener('click', function () {
        domcards.forEach(function (x) { x.classList.remove('active'); });
        d.classList.add('active');
        activeDom = d.getAttribute('data-domfilter');
        applyFilters();
      });
    });
    chips.forEach(function (c) {
      c.addEventListener('click', function () {
        chips.forEach(function (x) { x.classList.remove('active'); });
        c.classList.add('active');
        activeSev = c.getAttribute('data-sevfilter');
        applyFilters();
      });
    });
  })();
</script>
</body>
</html>
"""
)


def render(report: Report) -> str:
    """Render the report as a self-contained dark HTML dashboard."""
    return _TEMPLATE.render(**build_context(report))
