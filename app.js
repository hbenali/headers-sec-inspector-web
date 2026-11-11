/* Security Headers Grader: paste HTTP response headers, get a heuristic grade, per-header findings and fix hints,
   and generate a recommended header set for nginx, Apache, Caddy and a _headers file.
   Everything runs locally: no network calls (CSP connect-src 'none'). No dependencies, no inline code. */
(function () {
  'use strict';

  var $ = function (id) { return document.getElementById(id); };

  // ====================================================================
  // Parsing a pasted header dump (HTTP/1.1 or HTTP/2, curl -sI/-sIL/-v, dev tools)
  // ====================================================================
  var STATUS_RE = /^HTTP\/(?:[0-9](?:\.[0-9])?)\s+([0-9]{3})(?:\s.*)?$/i;
  var REQUEST_RE = /^[A-Z]{3,10}\s+\S+\s+HTTP\/[0-9.]+\s*$/;
  var HEADER_RE = /^([!#$%&'*+.^_`|~0-9A-Za-z-]+):[ \t]*(.*)$/;

  function parseHeaders(text) {
    var lines = String(text || '').replace(/\r\n?/g, '\n').split('\n');
    var blocks = [];
    var cur = { status: null, headers: [] };
    var bad = [];
    var ignored = 0;
    var lastHeader = null;

    function pushCur() {
      if (cur.status !== null || cur.headers.length) blocks.push(cur);
      cur = { status: null, headers: [] };
      lastHeader = null;
    }

    lines.forEach(function (raw) {
      var line = raw;
      if (/^\s*$/.test(line)) { lastHeader = null; return; }
      // curl -v style: "> " request lines and "* " info lines are skipped, "< " is stripped.
      if (/^>\s/.test(line) || /^\*\s/.test(line)) { ignored++; return; }
      line = line.replace(/^<\s?/, '');
      if (/^\s*$/.test(line)) return;
      var sm = line.trim().match(STATUS_RE);
      if (sm) {
        pushCur();
        cur.status = parseInt(sm[1], 10);
        return;
      }
      if (REQUEST_RE.test(line.trim())) { ignored++; return; }
      if (/^[ \t]/.test(line)) {
        // obsolete line folding: continuation of the previous header value
        if (lastHeader) {
          lastHeader.value = (lastHeader.value + ' ' + line.trim()).trim();
        } else {
          bad.push(line);
        }
        return;
      }
      var pm = line.match(/^:status:\s*([0-9]{3})/i);
      if (pm) { cur.status = parseInt(pm[1], 10); return; }
      if (/^:[a-z-]+:/i.test(line)) { ignored++; return; } // other HTTP/2 pseudo-headers
      var hm = line.match(HEADER_RE);
      if (!hm) { bad.push(line); lastHeader = null; return; }
      lastHeader = { name: hm[1].toLowerCase(), value: hm[2].trim() };
      cur.headers.push(lastHeader);
    });
    pushCur();

    var chosen = null;
    for (var i = blocks.length - 1; i >= 0; i--) {
      if (blocks[i].status === null || blocks[i].status >= 200) { chosen = blocks[i]; break; }
    }
    if (!chosen && blocks.length) chosen = blocks[blocks.length - 1];
    return {
      status: chosen ? chosen.status : null,
      headers: chosen ? chosen.headers : [],
      responses: blocks.length,
      bad: bad,
      ignored: ignored
    };
  }

  function indexHeaders(headers) {
    var map = Object.create(null);
    headers.forEach(function (h) { (map[h.name] = map[h.name] || []).push(h.value); });
    return map;
  }

  // ====================================================================
  // Content-Security-Policy
  // ====================================================================
  function parseCsp(value) {
    var directives = Object.create(null);
    var order = [];
    String(value).split(';').forEach(function (part) {
      var toks = part.trim().split(/\s+/).filter(Boolean);
      if (!toks.length) return;
      var name = toks.shift().toLowerCase();
      if (directives[name]) return; // the first occurrence wins, later duplicates are ignored by browsers
      directives[name] = toks;
      order.push(name);
    });
    return { directives: directives, order: order };
  }

  function has(list, token) {
    return list.some(function (t) { return t.toLowerCase() === token; });
  }

  // Returns { score 0..1, findings [{level,text}], frameAncestors, scriptUnsafe }
  function analyzeCsp(value, opts) {
    opts = opts || {};
    var p = parseCsp(value);
    var d = p.directives;
    var findings = [];
    var score = 1;
    var scriptUnsafe = false;
    function note(level, text, cost) { findings.push({ level: level, text: text }); score -= cost || 0; }

    if (!p.order.length) {
      return { score: 0, findings: [{ level: 'fail', text: 'The policy is empty.' }], parsed: p, scriptUnsafe: true, frameAncestors: null };
    }

    var script = d['script-src'] || d['default-src'];
    var scriptName = d['script-src'] ? 'script-src' : 'default-src';
    if (!script) {
      note('fail', 'No script-src and no default-src: scripts can load from anywhere.', 0.5);
      scriptUnsafe = true;
    } else {
      var mitigated = has(script, "'strict-dynamic'") || script.some(function (t) { return /^'(nonce-|sha(256|384|512)-)/i.test(t); });
      if (has(script, "'unsafe-inline'")) {
        if (mitigated) {
          note('info', scriptName + " lists 'unsafe-inline' but a nonce, hash or 'strict-dynamic' makes modern browsers ignore it.", 0);
        } else {
          note('fail', scriptName + " allows 'unsafe-inline': injected inline scripts will run, which defeats most of the CSP.", 0.35);
          scriptUnsafe = true;
        }
      }
      if (has(script, "'unsafe-eval'")) note('warn', scriptName + " allows 'unsafe-eval' (eval, new Function): a common XSS gadget.", 0.1);
      script.forEach(function (t) {
        var tl = t.toLowerCase();
        if (tl === '*') { note('fail', scriptName + ' contains the wildcard *: any host can serve scripts.', 0.5); scriptUnsafe = true; }
        else if (tl === 'https:' || tl === 'http:' || tl === 'data:' || tl === 'blob:' || tl === 'filesystem:') {
          if (!mitigated || tl === 'http:' || tl === 'data:') {
            note('fail', scriptName + ' allows the whole ' + tl + ' scheme: any such source can serve scripts.', tl === 'https:' ? 0.15 : 0.25);
            scriptUnsafe = true;
          }
        } else if (/^(https?:\/\/)?\*\./i.test(tl)) {
          note('warn', scriptName + ' uses a wildcard host (' + t + '): every subdomain is trusted.', 0.05);
        } else if (/^http:\/\//i.test(tl)) {
          note('warn', scriptName + ' allows a plain http:// source (' + t + ').', 0.05);
        }
      });
    }

    var style = d['style-src'] || d['default-src'];
    if (style && has(style, "'unsafe-inline'") && !style.some(function (t) { return /^'(nonce-|sha(256|384|512)-)/i.test(t); })) {
      note('warn', (d['style-src'] ? 'style-src' : 'default-src') + " allows 'unsafe-inline' styles (weaker, but lower risk than scripts).", 0.03);
    }

    if (!d['default-src']) note('warn', 'No default-src fallback: any fetch directive you did not list is unrestricted.', 0.05);
    var obj = d['object-src'] || d['default-src'];
    if (!obj) note('fail', "No object-src and no default-src: plugins (<object>, <embed>) are not restricted. Use object-src 'none'.", 0.1);
    else if (!has(obj, "'none'")) note('warn', "object-src is not 'none' (it falls back to " + (d['object-src'] ? 'itself' : 'default-src') + "). Set object-src 'none'.", 0.05);
    if (!d['base-uri']) note('warn', "No base-uri: an injected <base> tag can redirect relative URLs. Set base-uri 'none' or 'self'.", 0.1);

    var fa = d['frame-ancestors'];
    if (!fa) {
      note('warn', 'No frame-ancestors: framing is not restricted by this CSP (X-Frame-Options may cover it). frame-ancestors cannot be set in a <meta> tag.', opts.hasXfo ? 0 : 0.05);
    } else if (fa.some(function (t) { return t === '*' || /^https?:$/i.test(t); })) {
      note('warn', 'frame-ancestors allows any site to frame the page.', 0.1);
    }
    if (!d['form-action']) note('info', "No form-action: forms may post to any origin. Consider form-action 'self'.", 0);
    if (!d['upgrade-insecure-requests'] && !d['block-all-mixed-content']) note('info', 'No upgrade-insecure-requests (helpful when migrating mixed content).', 0);
    if (d['report-uri'] || d['report-to']) note('info', 'Violation reporting is configured.', 0);

    return { score: Math.max(0, Math.min(1, score)), findings: findings, parsed: p, scriptUnsafe: scriptUnsafe, frameAncestors: fa || null };
  }

  // ====================================================================
  // Other header parsers
  // ====================================================================
  function parseHsts(value) {
    var out = { maxAge: null, includeSubDomains: false, preload: false, unknown: [] };
    value.split(';').forEach(function (part) {
      var kv = part.trim();
      if (!kv) return;
      var eq = kv.indexOf('=');
      var k = (eq === -1 ? kv : kv.slice(0, eq)).trim().toLowerCase();
      var v = eq === -1 ? '' : kv.slice(eq + 1).trim().replace(/^"|"$/g, '');
      if (k === 'max-age') { if (/^[0-9]+$/.test(v)) out.maxAge = parseInt(v, 10); }
      else if (k === 'includesubdomains') out.includeSubDomains = true;
      else if (k === 'preload') out.preload = true;
      else out.unknown.push(k);
    });
    return out;
  }

  function splitTopLevel(s) {
    var out = [], depth = 0, cur = '';
    for (var i = 0; i < s.length; i++) {
      var c = s[i];
      if (c === '(') depth++;
      if (c === ')') depth = Math.max(0, depth - 1);
      if (c === ',' && depth === 0) { out.push(cur); cur = ''; } else cur += c;
    }
    out.push(cur);
    return out.map(function (x) { return x.trim(); }).filter(Boolean);
  }

  function parseCookie(line) {
    var parts = line.split(';');
    var first = parts.shift();
    var eq = first.indexOf('=');
    var c = { name: (eq === -1 ? '' : first.slice(0, eq)).trim(), hasValue: eq !== -1, attrs: Object.create(null), raw: line };
    parts.forEach(function (a) {
      var t = a.trim();
      if (!t) return;
      var e = t.indexOf('=');
      var k = (e === -1 ? t : t.slice(0, e)).trim().toLowerCase();
      var v = e === -1 ? '' : t.slice(e + 1).trim();
      if (!(k in c.attrs)) c.attrs[k] = v;
    });
    return c;
  }

  function lvl(score) { return score >= 0.9 ? 'pass' : score >= 0.5 ? 'warn' : 'fail'; }
  function fmtList(arr) { return arr.join(', '); }

  // ====================================================================
  // Grading
  // ====================================================================
  function grade(parsed, opts) {
    opts = opts || {};
    var map = indexHeaders(parsed.headers);
    var items = [];
    var caps = [];
    var observations = [];

    function get(name) { return map[name] || null; }
    function first(name) { var v = get(name); return v ? v[0] : null; }
    function add(it) {
      if (it.score === null || it.score === undefined) it.level = it.level || 'na';
      else { it.score = Math.max(0, Math.min(1, it.score)); it.level = lvl(it.score); }
      it.findings = it.findings || [];
      items.push(it);
      return it;
    }

    var xfoVal = first('x-frame-options');

    // ---- Content-Security-Policy ----
    var csp = get('content-security-policy');
    var cspRo = get('content-security-policy-report-only');
    var cspItem = { id: 'csp', title: 'Content-Security-Policy', weight: 25, value: csp || cspRo || null, findings: [] };
    var enforcedFA = null;
    if (!csp) {
      cspItem.score = 0;
      cspItem.findings.push({ level: 'fail', text: cspRo ? 'Only Content-Security-Policy-Report-Only is set. Report-only policies log violations but block nothing, so they give no protection.' : 'Header not set. A CSP is the main defence against cross-site scripting (XSS) and data injection.' });
      cspItem.fix = "Start with: Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'" + (cspRo ? '. Once the report-only policy is clean, send it as Content-Security-Policy.' : '. Run it as Report-Only first if you are unsure what it will break.');
      if (cspRo) {
        var ra = analyzeCsp(cspRo[0], { hasXfo: !!xfoVal });
        ra.findings.forEach(function (f) { cspItem.findings.push({ level: f.level === 'fail' ? 'warn' : f.level, text: '(report-only policy) ' + f.text }); });
      }
      caps.push({ max: 'B', reason: 'No enforced Content-Security-Policy.' });
    } else {
      var worst = null;
      csp.forEach(function (v) {
        var a = analyzeCsp(v, { hasXfo: !!xfoVal });
        if (!worst || a.score < worst.score) worst = a;
        if (a.frameAncestors) enforcedFA = a.frameAncestors;
      });
      cspItem.score = worst.score;
      cspItem.findings = worst.findings.slice();
      if (csp.length > 1) cspItem.findings.unshift({ level: 'info', text: csp.length + ' CSP headers are present; browsers enforce all of them (the strictest result applies). The weakest policy is graded here.' });
      if (worst.scriptUnsafe) caps.push({ max: 'B', reason: 'The CSP does not effectively restrict scripts (unsafe-inline, wildcard or missing script-src).' });
      var needFix = worst.findings.filter(function (f) { return f.level === 'fail' || f.level === 'warn'; });
      if (needFix.length) cspItem.fix = "Avoid 'unsafe-inline' and 'unsafe-eval' (use nonces or hashes), replace wildcards with exact hosts, and add object-src 'none'; base-uri 'none'; frame-ancestors 'none' (or 'self').";
      if (cspRo) cspItem.findings.push({ level: 'info', text: 'A Report-Only policy is also set; it is not counted.' });
    }
    add(cspItem);

    // ---- HSTS ----
    var hsts = get('strict-transport-security');
    var h = { id: 'hsts', title: 'Strict-Transport-Security', weight: 15, value: hsts, findings: [] };
    var hstsStrong = false;
    if (!hsts) {
      h.score = 0;
      h.findings.push({ level: 'fail', text: 'Header not set. Browsers will keep trying plain HTTP first and are open to SSL-stripping.' });
      h.fix = 'Strict-Transport-Security: max-age=31536000; includeSubDomains (only send it over HTTPS).';
      caps.push({ max: 'B', reason: 'No HSTS.' });
    } else {
      var ph = parseHsts(hsts[0]);
      if (hsts.length > 1) h.findings.push({ level: 'warn', text: 'Sent ' + hsts.length + ' times; browsers use only the first.' });
      if (ph.maxAge === null) { h.score = 0.1; h.findings.push({ level: 'fail', text: 'No valid max-age: the header is ignored by browsers.' }); }
      else if (ph.maxAge === 0) { h.score = 0; h.findings.push({ level: 'fail', text: 'max-age=0 tells browsers to forget the HSTS policy.' }); }
      else if (ph.maxAge < 15768000) { h.score = 0.4; h.findings.push({ level: 'warn', text: 'max-age=' + ph.maxAge + ' is under 6 months; use at least 31536000 (1 year).' }); }
      else if (ph.maxAge < 31536000) { h.score = 0.6; h.findings.push({ level: 'warn', text: 'max-age=' + ph.maxAge + ' is under 1 year; the preload list requires at least 31536000.' }); }
      else {
        h.score = 0.8;
        h.findings.push({ level: 'pass', text: 'max-age=' + ph.maxAge + ' is at least one year.' });
        if (ph.includeSubDomains) h.score += 0.1; else h.findings.push({ level: 'warn', text: 'No includeSubDomains: subdomains stay downgradable (only add it once every subdomain serves HTTPS).' });
        if (ph.preload) {
          if (ph.includeSubDomains) { h.score += 0.1; h.findings.push({ level: 'pass', text: 'preload is set (eligible for the browser preload list; submitting is a long-term commitment).' }); }
          else h.findings.push({ level: 'warn', text: 'preload requires includeSubDomains, so this will be rejected by the preload list.' });
        } else h.findings.push({ level: 'info', text: 'No preload directive (optional; it is a long-term commitment, see hstspreload.org).' });
        hstsStrong = h.score >= 0.9;
      }
      if (ph.unknown.length) h.findings.push({ level: 'info', text: 'Unknown directives ignored: ' + fmtList(ph.unknown) + '.' });
      if (h.score < 0.9) h.fix = 'Strict-Transport-Security: max-age=31536000; includeSubDomains' + (ph.maxAge ? '' : ' (max-age is required)');
      if (h.score < 0.5) caps.push({ max: 'B', reason: 'HSTS is missing or ineffective.' });
    }
    add(h);

    // ---- X-Content-Type-Options ----
    var xcto = get('x-content-type-options');
    var x = { id: 'xcto', title: 'X-Content-Type-Options', weight: 5, value: xcto, findings: [] };
    if (!xcto) { x.score = 0; x.findings.push({ level: 'fail', text: 'Header not set: browsers may MIME-sniff responses and run uploaded content as script.' }); x.fix = 'X-Content-Type-Options: nosniff'; }
    else if (xcto[0].split(',')[0].trim().toLowerCase() === 'nosniff') { x.score = xcto.length > 1 ? 0.9 : 1; x.findings.push({ level: 'pass', text: 'nosniff is set.' }); if (xcto.length > 1) x.findings.push({ level: 'warn', text: 'Header is duplicated; send it once.' }); }
    else { x.score = 0.2; x.findings.push({ level: 'fail', text: 'Value "' + xcto[0] + '" is not valid; the only defined value is nosniff.' }); x.fix = 'X-Content-Type-Options: nosniff'; }
    add(x);

    // ---- Referrer-Policy ----
    var rp = get('referrer-policy');
    var r = { id: 'referrer', title: 'Referrer-Policy', weight: 5, value: rp, findings: [] };
    var RP = { 'no-referrer': 1, 'same-origin': 1, 'strict-origin': 1, 'strict-origin-when-cross-origin': 1, 'origin': 0.75, 'origin-when-cross-origin': 0.7, 'no-referrer-when-downgrade': 0.4, 'unsafe-url': 0 };
    if (!rp) {
      r.score = 0.6;
      r.findings.push({ level: 'warn', text: 'Header not set. Current browsers default to strict-origin-when-cross-origin, but older ones leak the full URL; set it explicitly.' });
      r.fix = 'Referrer-Policy: strict-origin-when-cross-origin (or no-referrer).';
    } else {
      var toks = rp.join(',').split(',').map(function (t) { return t.trim().toLowerCase(); }).filter(Boolean);
      var valid = toks.filter(function (t) { return t in RP; });
      var invalid = toks.filter(function (t) { return !(t in RP); });
      if (invalid.length) r.findings.push({ level: 'warn', text: 'Unknown values ignored: ' + fmtList(invalid) + '.' });
      if (!valid.length) { r.score = 0.4; r.findings.push({ level: 'fail', text: 'No valid policy token; the header has no effect.' }); r.fix = 'Referrer-Policy: strict-origin-when-cross-origin'; }
      else {
        var eff = valid[valid.length - 1];
        r.score = RP[eff];
        r.findings.push({ level: lvl(r.score), text: 'Effective policy (last valid token): ' + eff + '.' });
        if (eff === 'unsafe-url') r.findings.push({ level: 'fail', text: 'unsafe-url sends the full URL (path and query) to every site, including over HTTP.' });
        if (eff === 'no-referrer-when-downgrade') r.findings.push({ level: 'warn', text: 'Leaks the full URL to other HTTPS sites.' });
        if (r.score < 0.9) r.fix = 'Referrer-Policy: strict-origin-when-cross-origin';
      }
    }
    add(r);

    // ---- Permissions-Policy ----
    var pp = get('permissions-policy');
    var fp = get('feature-policy');
    var pItem = { id: 'permissions', title: 'Permissions-Policy', weight: 5, value: pp, findings: [] };
    if (!pp) {
      pItem.score = 0;
      pItem.findings.push({ level: 'warn', text: fp ? 'Only the deprecated Feature-Policy header is set; browsers are moving to Permissions-Policy.' : 'Header not set: powerful features (camera, microphone, geolocation) are not explicitly disabled for the page and its iframes.' });
      pItem.fix = 'Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=(), usb=()';
    } else {
      var feats = splitTopLevel(pp.join(','));
      var seen = {};
      var starred = [];
      var malformed = 0;
      feats.forEach(function (f) {
        var m = f.match(/^([a-z0-9-]+)\s*=\s*(.*)$/i);
        if (!m) { malformed++; return; }
        var name = m[1].toLowerCase();
        seen[name] = m[2].trim();
        if (m[2].trim() === '*' || /^\(\s*\*\s*\)$/.test(m[2].trim())) starred.push(name);
      });
      var n = Object.keys(seen).length;
      if (!n) { pItem.score = 0.2; pItem.findings.push({ level: 'fail', text: 'No parsable feature=allowlist entries. Syntax: camera=(), geolocation=(self).' }); }
      else {
        var core = ['camera', 'microphone', 'geolocation'].filter(function (k) { return k in seen; });
        pItem.score = 0.7 + (core.length === 3 ? 0.3 : 0);
        pItem.findings.push({ level: 'pass', text: n + ' feature' + (n === 1 ? '' : 's') + ' configured: ' + fmtList(Object.keys(seen).slice(0, 12)) + (n > 12 ? ', ...' : '') + '.' });
        if (core.length < 3) pItem.findings.push({ level: 'warn', text: 'Not set: ' + fmtList(['camera', 'microphone', 'geolocation'].filter(function (k) { return !(k in seen); })) + '. Disable what you do not use.' });
        var power = starred.filter(function (k) { return ['camera', 'microphone', 'geolocation', 'payment', 'usb', 'display-capture'].indexOf(k) !== -1; });
        if (power.length) { pItem.score -= 0.4; pItem.findings.push({ level: 'fail', text: 'Powerful feature(s) allowed for every origin with *: ' + fmtList(power) + '.' }); }
        if (malformed) { pItem.score -= 0.1; pItem.findings.push({ level: 'warn', text: malformed + ' entr' + (malformed === 1 ? 'y' : 'ies') + ' could not be parsed and will be ignored.' }); }
      }
      if (pItem.score < 0.9) pItem.fix = 'Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=(), usb=()';
    }
    add(pItem);

    // ---- COOP / COEP / CORP ----
    var coop = first('cross-origin-opener-policy');
    var c1 = { id: 'coop', title: 'Cross-Origin-Opener-Policy', weight: 4, value: get('cross-origin-opener-policy'), findings: [] };
    if (!coop) { c1.score = 0; c1.findings.push({ level: 'warn', text: 'Header not set: pop-ups you open (or that open you) keep a window reference, which enables cross-window leaks.' }); c1.fix = 'Cross-Origin-Opener-Policy: same-origin (use same-origin-allow-popups if you rely on OAuth or payment pop-ups).'; }
    else {
      var cv = coop.split(';')[0].trim().toLowerCase();
      if (cv === 'same-origin') { c1.score = 1; c1.findings.push({ level: 'pass', text: 'same-origin isolates the browsing context group.' }); }
      else if (cv === 'same-origin-allow-popups') { c1.score = 0.8; c1.findings.push({ level: 'pass', text: 'same-origin-allow-popups keeps isolation but lets your pop-ups keep a reference.' }); }
      else if (cv === 'unsafe-none') { c1.score = 0.2; c1.findings.push({ level: 'warn', text: 'unsafe-none is the default and gives no isolation.' }); c1.fix = 'Cross-Origin-Opener-Policy: same-origin'; }
      else { c1.score = 0.2; c1.findings.push({ level: 'fail', text: 'Unknown value "' + coop + '".' }); c1.fix = 'Cross-Origin-Opener-Policy: same-origin'; }
    }
    add(c1);

    var coep = first('cross-origin-embedder-policy');
    var c2 = { id: 'coep', title: 'Cross-Origin-Embedder-Policy', weight: 2, value: get('cross-origin-embedder-policy'), findings: [] };
    if (!coep) { c2.score = 0.25; c2.findings.push({ level: 'info', text: 'Header not set. Optional: only needed for cross-origin isolation (SharedArrayBuffer, high-resolution timers). It breaks cross-origin embeds that lack CORS/CORP, so test first.' }); c2.fix = 'Cross-Origin-Embedder-Policy: require-corp (or credentialless).'; }
    else {
      var ev = coep.split(';')[0].trim().toLowerCase();
      if (ev === 'require-corp' || ev === 'credentialless') { c2.score = 1; c2.findings.push({ level: 'pass', text: ev + ' enabled.' }); }
      else if (ev === 'unsafe-none') { c2.score = 0.25; c2.findings.push({ level: 'info', text: 'unsafe-none is the default.' }); }
      else { c2.score = 0.25; c2.findings.push({ level: 'fail', text: 'Unknown value "' + coep + '".' }); }
    }
    add(c2);

    var corp = first('cross-origin-resource-policy');
    var c3 = { id: 'corp', title: 'Cross-Origin-Resource-Policy', weight: 2, value: get('cross-origin-resource-policy'), findings: [] };
    if (!corp) { c3.score = 0.25; c3.findings.push({ level: 'info', text: 'Header not set. It stops other sites loading your resources cross-origin (Spectre-style leaks). Set it on responses that are not meant to be embedded.' }); c3.fix = 'Cross-Origin-Resource-Policy: same-origin (same-site if your subdomains share it).'; }
    else {
      var pv = corp.trim().toLowerCase();
      if (pv === 'same-origin' || pv === 'same-site') { c3.score = 1; c3.findings.push({ level: 'pass', text: pv + ' restricts who can load this resource.' }); }
      else if (pv === 'cross-origin') { c3.score = 0.5; c3.findings.push({ level: 'info', text: 'cross-origin is correct only for resources meant to be embedded by anyone (CDN assets, public images).' }); }
      else { c3.score = 0.2; c3.findings.push({ level: 'fail', text: 'Unknown value "' + corp + '".' }); c3.fix = 'Cross-Origin-Resource-Policy: same-origin'; }
    }
    add(c3);

    // ---- Framing: X-Frame-Options vs CSP frame-ancestors ----
    var xfo = get('x-frame-options');
    var f = { id: 'framing', title: 'Clickjacking: X-Frame-Options / frame-ancestors', weight: 7, value: xfo, findings: [] };
    if (enforcedFA) {
      var open = enforcedFA.some(function (t) { return t === '*' || /^https?:$/i.test(t); });
      if (open) { f.score = 0.2; f.findings.push({ level: 'fail', text: 'frame-ancestors allows any site to frame the page.' }); f.fix = "frame-ancestors 'none' (or 'self') inside the CSP."; }
      else { f.score = 1; f.findings.push({ level: 'pass', text: 'CSP frame-ancestors ' + fmtList(enforcedFA) + ' controls framing (this is the modern mechanism).' }); }
      if (xfo) {
        var xv = xfo[0].trim().toUpperCase();
        var faNone = enforcedFA.length === 1 && enforcedFA[0].toLowerCase() === "'none'";
        if (xv === 'DENY' && !faNone && !open) f.findings.push({ level: 'warn', text: 'X-Frame-Options DENY conflicts with the frame-ancestors allow-list; browsers that support CSP follow frame-ancestors and ignore X-Frame-Options, so legacy browsers will be stricter.' });
        else f.findings.push({ level: 'info', text: 'X-Frame-Options is also sent (fine as a fallback for old browsers).' });
      }
    } else if (xfo) {
      var xv2 = xfo[0].trim().toUpperCase();
      if (xfo.length > 1 || xfo[0].indexOf(',') !== -1) { f.score = 0.3; f.findings.push({ level: 'fail', text: 'Multiple or comma-separated X-Frame-Options values are treated as invalid by browsers, so framing is allowed.' }); f.fix = 'X-Frame-Options: DENY, plus frame-ancestors in the CSP.'; }
      else if (xv2 === 'DENY' || xv2 === 'SAMEORIGIN') { f.score = 0.85; f.findings.push({ level: 'pass', text: 'X-Frame-Options: ' + xv2 + ' blocks framing by other sites.' }); f.findings.push({ level: 'info', text: 'Also add CSP frame-ancestors: it is the standard replacement and also supports allow-lists.' }); f.fix = "Add frame-ancestors 'none' (or 'self') to the CSP."; }
      else if (xv2.indexOf('ALLOW-FROM') === 0) { f.score = 0.2; f.findings.push({ level: 'fail', text: 'ALLOW-FROM is obsolete and ignored by current browsers, so the page can be framed.' }); f.fix = 'Use CSP frame-ancestors with the allowed origins.'; }
      else { f.score = 0.1; f.findings.push({ level: 'fail', text: 'Invalid value "' + xfo[0] + '"; only DENY and SAMEORIGIN are valid.' }); f.fix = 'X-Frame-Options: DENY'; }
    } else {
      f.score = 0;
      f.findings.push({ level: 'fail', text: 'Neither X-Frame-Options nor a CSP frame-ancestors directive: the page can be framed by any site (clickjacking).' });
      f.fix = "Content-Security-Policy: frame-ancestors 'none' (and optionally X-Frame-Options: DENY for old browsers).";
    }
    add(f);

    // ---- Cache-Control ----
    var cc = get('cache-control');
    var cookies = get('set-cookie') || [];
    var cItem = { id: 'cache', title: 'Cache-Control', weight: opts.sensitive ? 5 : 0, value: cc, findings: [] };
    var ccv = cc ? cc.join(',').toLowerCase() : '';
    var shared = /(^|[ ,])public([ ,=]|$)|s-maxage/.test(ccv);
    if (opts.sensitive) {
      if (!cc) { cItem.score = 0; cItem.findings.push({ level: 'fail', text: 'No Cache-Control on a page marked sensitive: shared caches and the browser back button may expose it.' }); cItem.fix = 'Cache-Control: no-store'; }
      else if (/(^|[ ,])no-store([ ,]|$)/.test(ccv)) { cItem.score = 1; cItem.findings.push({ level: 'pass', text: 'no-store keeps the response out of every cache.' }); }
      else if (/(^|[ ,])private([ ,]|$)/.test(ccv) && /no-cache|max-age=0/.test(ccv)) { cItem.score = 0.6; cItem.findings.push({ level: 'warn', text: 'private + no-cache avoids shared caches but the browser still stores the page; prefer no-store for sensitive content.' }); cItem.fix = 'Cache-Control: no-store'; }
      else { cItem.score = shared || /max-age=[1-9]/.test(ccv) ? 0 : 0.3; cItem.findings.push({ level: 'fail', text: 'These directives allow storing the response: ' + cc.join(', ') + '.' }); cItem.fix = 'Cache-Control: no-store'; }
      if (shared && cookies.length) cItem.findings.push({ level: 'fail', text: 'The response sets a cookie while being cacheable by shared caches.' });
    } else {
      cItem.score = null;
      cItem.level = 'info';
      cItem.findings.push({ level: 'info', text: 'Not graded because the page is not marked sensitive. Tick "sensitive page" above if this response holds personal or session data; then no-store is required. Static assets can and should be cached.' });
      if (shared && cookies.length) cItem.findings.push({ level: 'warn', text: 'The response sets a cookie and is marked public/s-maxage: a shared cache could store and replay the cookie.' });
    }
    add(cItem);

    // ---- Cookies ----
    var ck = { id: 'cookies', title: 'Set-Cookie', weight: 10, value: cookies.length ? cookies : null, findings: [] };
    if (!cookies.length) {
      ck.score = null; ck.level = 'na';
      ck.findings.push({ level: 'info', text: 'No Set-Cookie header in this response; nothing to grade.' });
    } else {
      var total = 0;
      var cookieNotes = [];
      cookies.forEach(function (line) {
        var c = parseCookie(line);
        var nm = c.name || '(unnamed)';
        var s = 0;
        var sensitiveName = /sess|sid|auth|token|jwt|login/i.test(nm);
        var secure = 'secure' in c.attrs, httpOnly = 'httponly' in c.attrs;
        var ss = 'samesite' in c.attrs ? c.attrs.samesite.toLowerCase() : null;
        var local = [];
        if (!c.hasValue || !c.name) local.push({ level: 'fail', text: 'Malformed cookie (no name=value pair).' });
        if (secure) s += 0.4; else local.push({ level: 'fail', text: 'Missing Secure: the cookie is also sent over plain HTTP.' });
        if (httpOnly) s += 0.3; else local.push({ level: sensitiveName ? 'fail' : 'warn', text: 'Missing HttpOnly: JavaScript (and any XSS) can read it.' + (sensitiveName ? '' : ' Acceptable only if scripts must read this cookie.') });
        if (ss === 'strict' || ss === 'lax') s += 0.3;
        else if (ss === 'none') { if (secure) { s += 0.15; local.push({ level: 'warn', text: 'SameSite=None sends the cookie cross-site; keep it only for real third-party use.' }); } else local.push({ level: 'fail', text: 'SameSite=None requires Secure; browsers reject this cookie.' }); }
        else if (ss === null) { s += 0.1; local.push({ level: 'warn', text: 'No SameSite: browsers default to Lax, but older ones do not. Set it explicitly.' }); }
        else local.push({ level: 'warn', text: 'Unknown SameSite value "' + c.attrs.samesite + '" (ignored or treated as Lax).' });
        var lname = nm.toLowerCase();
        if (lname.indexOf('__host-') === 0) {
          var okHost = secure && c.attrs.path === '/' && !('domain' in c.attrs);
          if (okHost) local.push({ level: 'pass', text: '__Host- prefix rules satisfied (Secure, Path=/, no Domain).' });
          else { s = Math.min(s, 0.2); local.push({ level: 'fail', text: '__Host- prefix requires Secure, Path=/ and no Domain attribute; browsers will reject this cookie.' }); }
        } else if (lname.indexOf('__secure-') === 0) {
          if (secure) local.push({ level: 'pass', text: '__Secure- prefix rules satisfied.' });
          else { s = Math.min(s, 0.2); local.push({ level: 'fail', text: '__Secure- prefix requires the Secure attribute; browsers will reject this cookie.' }); }
        } else if (sensitiveName && !('domain' in c.attrs)) {
          local.push({ level: 'info', text: 'Consider the __Host- prefix for this cookie (host-only, Secure, Path=/).' });
        }
        if ('domain' in c.attrs && lname.indexOf('__host-') !== 0) local.push({ level: 'info', text: 'Domain=' + c.attrs.domain + ' shares the cookie with all subdomains.' });
        total += s;
        cookieNotes.push({ name: nm, findings: local });
      });
      ck.score = total / cookies.length;
      ck.cookies = cookieNotes;
      if (ck.score < 0.9) ck.fix = 'Set-Cookie: __Host-session=...; Path=/; Secure; HttpOnly; SameSite=Lax';
    }
    add(ck);

    // ---- Information leaks ----
    var server = first('server');
    var leakItem = { id: 'leaks', title: 'Information leaks', weight: 5, value: null, findings: [] };
    var shown = [];
    var leakScore = 1;
    if (server) {
      shown.push('Server: ' + server);
      if (/[\/ ]v?[0-9]+(\.[0-9]+)*/.test(server)) { leakScore -= 0.6; leakItem.findings.push({ level: 'fail', text: 'Server discloses a version (' + server + '): it helps attackers match known vulnerabilities.' }); }
      else leakItem.findings.push({ level: 'pass', text: 'Server (' + server + ') names the software but no version.' });
    }
    [['x-powered-by', 'X-Powered-By'], ['x-aspnet-version', 'X-AspNet-Version'], ['x-aspnetmvc-version', 'X-AspNetMvc-Version'], ['x-generator', 'X-Generator']].forEach(function (p) {
      var v = first(p[0]);
      if (v) { shown.push(p[1] + ': ' + v); leakScore -= 0.3; leakItem.findings.push({ level: 'warn', text: p[1] + ' reveals the technology stack (' + v + ').' }); }
    });
    leakItem.value = shown.length ? shown : null;
    if (!shown.length) leakItem.findings.push({ level: 'pass', text: 'No Server, X-Powered-By or X-AspNet-Version header present.' });
    leakItem.score = leakScore;
    if (leakScore < 0.9) leakItem.fix = 'nginx: server_tokens off; Apache: ServerTokens Prod; PHP: expose_php=Off; Express: app.disable("x-powered-by"); ASP.NET: enableVersionHeader="false" and remove the X-Powered-By custom header.';
    add(leakItem);

    // ---- Other observations (not scored) ----
    var xxp = first('x-xss-protection');
    if (xxp) observations.push({ level: 'info', text: 'X-XSS-Protection: ' + xxp + ' is obsolete; the browser XSS auditor was removed and the header can introduce bugs. Omit it or send 0, and rely on CSP.' });
    if (get('expect-ct')) observations.push({ level: 'info', text: 'Expect-CT is obsolete (Certificate Transparency is enforced by browsers); you can drop it.' });
    if (get('public-key-pins') || get('public-key-pins-report-only')) observations.push({ level: 'warn', text: 'Public-Key-Pins (HPKP) was removed from browsers and is dangerous to keep; delete it.' });
    var acao = first('access-control-allow-origin');
    if (acao === '*') {
      var acac = first('access-control-allow-credentials');
      var credsOn = !!acac && acac.toLowerCase() === 'true';
      observations.push({ level: credsOn ? 'fail' : 'info', text: credsOn ? 'Access-Control-Allow-Origin: * together with Allow-Credentials: true is invalid and refused by browsers; echo a specific allowed origin instead.' : 'Access-Control-Allow-Origin: * lets any site read this response. Fine for public data, not for anything personal.' });
    }
    if (parsed.status && parsed.status >= 300 && parsed.status < 400) observations.push({ level: 'info', text: 'This is a ' + parsed.status + ' redirect. Security headers matter on the final page too: use curl -sIL to capture the whole chain (the last response is graded).' });
    if (parsed.responses > 1) observations.push({ level: 'info', text: parsed.responses + ' responses were found (a redirect chain). Only the last one is graded.' });

    // ---- Score and grade ----
    var wsum = 0, ssum = 0;
    items.forEach(function (it) {
      if (it.score === null || it.score === undefined || !it.weight) return;
      wsum += it.weight; ssum += it.weight * it.score;
    });
    var pct = wsum ? Math.round((ssum / wsum) * 100) : 0;
    var g = pct >= 95 ? 'A+' : pct >= 85 ? 'A' : pct >= 70 ? 'B' : pct >= 55 ? 'C' : pct >= 40 ? 'D' : pct >= 25 ? 'E' : 'F';
    var cspOk = !!csp && cspItem.score >= 0.9;
    if (g === 'A+' && !(cspOk && hstsStrong)) caps.push({ max: 'A', reason: 'A+ needs an enforced, clean CSP and an HSTS policy of at least one year with includeSubDomains.' });
    var rank = ['F', 'E', 'D', 'C', 'B', 'A', 'A+'];
    var applied = [];
    caps.forEach(function (c) {
      if (rank.indexOf(g) > rank.indexOf(c.max)) { g = c.max; applied.push(c.reason); }
    });
    return { grade: g, score: pct, items: items, capReasons: applied, observations: observations, status: parsed.status, count: parsed.headers.length };
  }

  // ====================================================================
  // Recommended header set generator
  // ====================================================================
  var DEFAULT_CSP = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'; upgrade-insecure-requests";
  var PERMISSIONS = 'camera=(), microphone=(), geolocation=(), payment=(), usb=(), accelerometer=(), gyroscope=(), magnetometer=()';

  function safeValue(v) {
    // Values end up inside quoted config strings: plain printable ASCII, no quoting or expansion characters.
    return /^[\x20-\x7e]*$/.test(v) && !/["\\$`{}]/.test(v);
  }

  function buildHeaders(o) {
    var list = [];
    list.push(['Content-Security-Policy', o.csp]);
    var hsts = 'max-age=' + o.hstsAge;
    if (o.includeSub) hsts += '; includeSubDomains';
    if (o.preload) hsts += '; preload';
    list.push(['Strict-Transport-Security', hsts]);
    list.push(['X-Content-Type-Options', 'nosniff']);
    list.push(['Referrer-Policy', o.referrer]);
    list.push(['Permissions-Policy', PERMISSIONS]);
    list.push(['Cross-Origin-Opener-Policy', 'same-origin']);
    if (o.corp) list.push(['Cross-Origin-Resource-Policy', o.corp]);
    if (o.coep) list.push(['Cross-Origin-Embedder-Policy', 'require-corp']);
    if (o.xfo !== 'omit') list.push(['X-Frame-Options', o.xfo]);
    return list;
  }

  function formatConfig(fmt, list) {
    var out = [];
    if (fmt === 'nginx') {
      out.push('# inside server { } (or location { }). add_header is NOT inherited if a deeper block defines its own add_header.');
      list.forEach(function (h) { out.push('add_header ' + h[0] + ' "' + h[1] + '" always;'); });
      out.push('');
      out.push('# hide the version (http { } or server { })');
      out.push('server_tokens off;');
      out.push('# when proxying an app that sets X-Powered-By:');
      out.push('# proxy_hide_header X-Powered-By;');
    } else if (fmt === 'apache') {
      out.push('# needs mod_headers (a2enmod headers)');
      out.push('<IfModule mod_headers.c>');
      list.forEach(function (h) { out.push('    Header always set ' + h[0] + ' "' + h[1] + '"'); });
      out.push('    Header always unset X-Powered-By');
      out.push('</IfModule>');
      out.push('');
      out.push('# server config only (not .htaccess)');
      out.push('ServerTokens Prod');
      out.push('ServerSignature Off');
    } else if (fmt === 'caddy') {
      out.push('# inside a site block of your Caddyfile');
      out.push('header {');
      list.forEach(function (h) { out.push('    ' + h[0] + ' "' + h[1] + '"'); });
      out.push('    -Server');
      out.push('    -X-Powered-By');
      out.push('}');
    } else {
      out.push('# _headers file at the root of the published folder (Cloudflare Pages and Netlify)');
      out.push('/*');
      list.forEach(function (h) { out.push('  ' + h[0] + ': ' + h[1]); });
    }
    return out.join('\n');
  }

  // ====================================================================
  // Samples (clearly invented; example.org)
  // ====================================================================
  var SAMPLES = [
    { id: 'excellent', label: 'Very good (invented, example.org)', text: [
      'HTTP/2 200',
      'content-type: text/html; charset=utf-8',
      "content-security-policy: default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'; upgrade-insecure-requests",
      'strict-transport-security: max-age=63072000; includeSubDomains; preload',
      'x-content-type-options: nosniff',
      'referrer-policy: strict-origin-when-cross-origin',
      'permissions-policy: camera=(), microphone=(), geolocation=(), payment=(), usb=()',
      'cross-origin-opener-policy: same-origin',
      'cross-origin-embedder-policy: require-corp',
      'cross-origin-resource-policy: same-origin',
      'x-frame-options: DENY',
      'cache-control: no-store',
      'set-cookie: __Host-session=abc123; Path=/; Secure; HttpOnly; SameSite=Strict',
      'server: example-edge'
    ].join('\n') },
    { id: 'decent', label: 'Decent (invented, example.org)', text: [
      'HTTP/1.1 200 OK',
      'Date: Wed, 11 Nov 2026 10:00:00 GMT',
      'Content-Type: text/html',
      'Strict-Transport-Security: max-age=31536000',
      "Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.example.org; img-src *; object-src 'none'",
      'X-Content-Type-Options: nosniff',
      'X-Frame-Options: SAMEORIGIN',
      'Referrer-Policy: no-referrer-when-downgrade',
      'Set-Cookie: sid=9f8e7d; Path=/; Secure; HttpOnly',
      'Server: nginx'
    ].join('\n') },
    { id: 'weak', label: 'Weak (invented, example.org)', text: [
      'HTTP/1.1 200 OK',
      'Date: Wed, 11 Nov 2026 10:00:00 GMT',
      'Server: Apache/2.4.41 (Ubuntu)',
      'X-Powered-By: PHP/7.4.3',
      'X-XSS-Protection: 1; mode=block',
      'Strict-Transport-Security: max-age=300',
      "Content-Security-Policy-Report-Only: default-src 'self'; report-uri https://example.org/csp-report",
      'Content-Type: text/html; charset=UTF-8',
      'Set-Cookie: PHPSESSID=abc123; path=/',
      'Cache-Control: public, max-age=3600'
    ].join('\n') },
    { id: 'terrible', label: 'Terrible (invented, example.org)', text: [
      'HTTP/1.1 200 OK',
      'Server: Microsoft-IIS/8.5',
      'X-AspNet-Version: 4.0.30319',
      'X-Powered-By: ASP.NET',
      'Content-Type: text/html',
      "Content-Security-Policy: script-src * 'unsafe-inline' 'unsafe-eval'; object-src *",
      'Access-Control-Allow-Origin: *',
      'Access-Control-Allow-Credentials: true',
      'Referrer-Policy: unsafe-url',
      'X-Frame-Options: ALLOW-FROM https://example.org',
      'Set-Cookie: auth_token=eyJhbGciOi; Domain=example.org',
      'Set-Cookie: __Host-id=1; Domain=example.org; SameSite=None'
    ].join('\n') }
  ];

  // ====================================================================
  // UI
  // ====================================================================
  function el(tag, cls, text) {
    var n = document.createElement(tag);
    if (cls) n.className = cls;
    if (text !== undefined && text !== null) n.textContent = text;
    return n;
  }

  var LEVEL_LABEL = { pass: 'ok', warn: 'warn', fail: 'fail', info: 'note', na: 'n/a' };

  function normalizeDomain(input) {
    return String(input || '').trim().toLowerCase().replace(/^[a-z]+:\/\//, '').replace(/^.*@/, '').replace(/[\/?#:].*$/, '').replace(/\.+$/, '');
  }
  function validDomain(d) {
    if (!d || d.length > 253 || d.indexOf('.') === -1) return false;
    return d.split('.').every(function (l) { return /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/.test(l); });
  }

  function copyText(text, btn) {
    var done = function (ok) {
      var old = btn.getAttribute('data-label') || btn.textContent;
      btn.setAttribute('data-label', old);
      btn.textContent = ok ? 'Copied' : 'Press Ctrl+C';
      setTimeout(function () { btn.textContent = old; }, 1600);
    };
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(function () { done(true); }, function () { done(false); });
    } else done(false);
  }

  function renderFindings(parent, findings) {
    if (!findings.length) return;
    var ul = el('ul', 'findings');
    findings.forEach(function (fd) {
      var li = el('li');
      li.append(el('span', 'chk ' + fd.level, LEVEL_LABEL[fd.level] || fd.level), el('span', 'ftext', fd.text));
      ul.append(li);
    });
    parent.append(ul);
  }

  function clip(s, n) { return s.length > n ? s.slice(0, n) + '...' : s; }

  function renderResult(res, parsed) {
    var box = $('resultContainer');
    box.textContent = '';
    var cls = res.grade === 'A+' || res.grade === 'A' ? 'ok' : (res.grade === 'B' || res.grade === 'C') ? 'warn' : 'fail';

    var top = el('div', 'state ' + cls);
    var gr = el('div', 'grade-row');
    gr.append(el('div', 'grade-badge', res.grade));
    var meta = el('div', 'grade-meta');
    meta.append(el('p', 'state-title', 'Score ' + res.score + ' / 100'));
    meta.append(el('p', '', res.count + ' header' + (res.count === 1 ? '' : 's') + ' parsed' + (res.status ? ', HTTP status ' + res.status : ', no status line') + '.'));
    meta.append(el('p', 'heur', 'This grade is a heuristic: a weighted checklist, not a guarantee. A+ does not mean the site is secure, and a low grade on a static page may be acceptable.'));
    gr.append(meta);
    top.append(gr);
    if (res.capReasons.length) {
      var cl = el('ul', 'caps');
      res.capReasons.forEach(function (t) { cl.append(el('li', '', 'Grade capped: ' + t)); });
      top.append(cl);
    }
    box.append(top);

    if (parsed.bad.length || parsed.ignored) {
      var pw = el('div', 'state warn');
      if (parsed.bad.length) {
        pw.append(el('p', 'state-title', parsed.bad.length + ' line' + (parsed.bad.length === 1 ? '' : 's') + ' could not be parsed'));
        var bl = el('ul', 'badlines');
        parsed.bad.slice(0, 8).forEach(function (l) { bl.append(el('li', '', clip(l, 90))); });
        if (parsed.bad.length > 8) bl.append(el('li', '', '... and ' + (parsed.bad.length - 8) + ' more'));
        pw.append(bl);
        pw.append(el('p', '', 'Expected "Name: value" lines, one header per line. The lines above were skipped.'));
      }
      if (parsed.ignored) pw.append(el('p', '', parsed.ignored + ' request or info line' + (parsed.ignored === 1 ? '' : 's') + ' (curl -v "> " and "* " lines, HTTP/2 pseudo-headers) skipped.'));
      box.append(pw);
    }

    var list = el('div', 'hdr-list');
    res.items.forEach(function (it) {
      var card = el('article', 'hdr');
      var head = el('div', 'hdr-head');
      head.append(el('span', 'chk ' + it.level, LEVEL_LABEL[it.level]));
      head.append(el('h3', 'hdr-name', it.title));
      if (it.score !== null && it.score !== undefined && it.weight) head.append(el('span', 'hdr-pts', Math.round(it.score * it.weight * 10) / 10 + ' / ' + it.weight + ' pts'));
      else head.append(el('span', 'hdr-pts', 'not scored'));
      card.append(head);
      if (it.value && it.value.length) {
        var pre = el('div', 'hdr-value');
        it.value.slice(0, 6).forEach(function (v) { pre.append(el('div', '', clip(v, 600))); });
        if (it.value.length > 6) pre.append(el('div', '', '... ' + (it.value.length - 6) + ' more'));
        card.append(pre);
      } else if (it.id !== 'cookies' && it.id !== 'leaks' && it.id !== 'cache') card.append(el('div', 'hdr-value missing', 'not present'));
      renderFindings(card, it.findings);
      if (it.cookies) {
        it.cookies.forEach(function (c) {
          var cb = el('div', 'cookie');
          cb.append(el('div', 'cookie-name', c.name));
          renderFindings(cb, c.findings);
          card.append(cb);
        });
      }
      if (it.fix && it.level !== 'pass') {
        var fx = el('p', 'fix');
        fx.append(el('strong', '', 'Fix: '), document.createTextNode(it.fix));
        card.append(fx);
      }
      list.append(card);
    });
    box.append(list);

    if (res.observations.length) {
      var ob = el('div', 'state');
      ob.append(el('p', 'state-title', 'Other observations'));
      renderFindings(ob, res.observations);
      box.append(ob);
    }
  }

  function showMessage(kind, title, text) {
    var box = $('resultContainer');
    box.textContent = '';
    var s = el('div', 'state ' + kind);
    s.append(el('p', 'state-title', title));
    s.append(el('p', '', text));
    box.append(s);
  }

  function runGrade() {
    var text = $('headersInput').value;
    if (!text.trim()) { showMessage('empty', 'Nothing to grade', 'Paste the response headers first, or load a sample.'); return; }
    var parsed = parseHeaders(text);
    if (!parsed.headers.length) {
      showMessage('fail', 'No headers found', 'None of the pasted lines look like "Name: value". Paste the output of curl -sI or the response headers from your browser dev tools (Network tab, select the request, Headers).' + (parsed.bad.length ? ' First unparsable line: ' + clip(parsed.bad[0], 90) : ''));
      return;
    }
    renderResult(grade(parsed, { sensitive: $('sensitive').checked }), parsed);
  }

  function updateCommand() {
    var raw = $('domainInput').value;
    var err = $('domainError');
    var links = $('siblingLinks');
    links.textContent = '';
    var d = normalizeDomain(raw);
    var shown = 'example.com';
    err.classList.remove('visible'); err.textContent = '';
    if (raw.trim()) {
      if (validDomain(d)) shown = d;
      else {
        err.textContent = 'Enter a plain hostname such as example.com (ASCII; use the punycode form for internationalised names).';
        err.classList.add('visible');
      }
    }
    // Only a validated hostname (letters, digits, dots, hyphens) is ever put into the command.
    $('curlCmd').textContent = 'curl -sI https://' + shown;
    $('curlCmd2').textContent = 'curl -sIL https://' + shown;
    if (shown !== 'example.com' || (raw.trim() && validDomain(d))) {
      ['ssl', 'dnssec', 'caa', 'mx', 'spf', 'dmarc', 'rdap', 'ip'].forEach(function (t) {
        var a = el('a', 'link', t);
        a.href = 'https://' + t + '.hbenali.ovh/?domain=' + encodeURIComponent(shown);
        a.target = '_blank'; a.rel = 'noopener noreferrer';
        links.append(a);
      });
    }
  }

  function genOptions() {
    return {
      csp: $('genCsp').value.trim(),
      hstsAge: $('genHstsAge').value,
      includeSub: $('genSub').checked,
      preload: $('genPreload').checked,
      referrer: $('genReferrer').value,
      xfo: $('genXfo').value,
      corp: $('genCorp').value,
      coep: $('genCoep').checked
    };
  }

  function updateGenerator() {
    var o = genOptions();
    var err = $('genError');
    var out = $('genOutput');
    var hint = $('genCspCheck');
    hint.textContent = '';
    err.classList.remove('visible'); err.textContent = '';
    if (!o.csp) { err.textContent = 'The CSP is empty.'; err.classList.add('visible'); out.textContent = ''; return; }
    if (!safeValue(o.csp)) { err.textContent = 'The CSP contains a character that is unsafe inside quoted server config (double quote, backslash, $, backtick, braces or non-ASCII). Remove it.'; err.classList.add('visible'); out.textContent = ''; return; }
    if (o.preload && !o.includeSub) { $('genSub').checked = true; o.includeSub = true; }
    if (o.preload && parseInt(o.hstsAge, 10) < 31536000) { err.textContent = 'preload requires max-age of at least 31536000.'; err.classList.add('visible'); }
    var a = analyzeCsp(o.csp, { hasXfo: o.xfo !== 'omit' });
    a.findings.filter(function (fd) { return fd.level === 'fail' || fd.level === 'warn'; }).forEach(function (fd) { hint.append(el('li', '', fd.text)); });
    out.textContent = formatConfig($('genFormat').value, buildHeaders(o));
  }

  function init() {
    var sel = $('sampleSelect');
    SAMPLES.forEach(function (s) { var op = el('option', '', s.label); op.value = s.id; sel.append(op); });
    sel.addEventListener('change', function () {
      var s = SAMPLES.filter(function (x) { return x.id === sel.value; })[0];
      if (s) { $('headersInput').value = s.text; $('sensitive').checked = s.id !== 'decent'; runGrade(); }
    });

    $('gradeBtn').addEventListener('click', runGrade);
    $('clearBtn').addEventListener('click', function () {
      $('headersInput').value = ''; sel.value = '';
      showMessage('empty', 'Ready', 'Paste headers and press "Grade headers".');
      $('headersInput').focus();
    });
    $('sensitive').addEventListener('change', function () { if ($('headersInput').value.trim()) runGrade(); });
    $('headersInput').addEventListener('keydown', function (e) { if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') runGrade(); });

    $('domainInput').addEventListener('input', updateCommand);
    $('domainInput').addEventListener('keydown', function (e) { if (e.key === 'Enter') { e.preventDefault(); updateCommand(); $('headersInput').focus(); } });
    $('copyCurl').addEventListener('click', function () { copyText($('curlCmd').textContent, $('copyCurl')); });
    $('copyCurl2').addEventListener('click', function () { copyText($('curlCmd2').textContent, $('copyCurl2')); });

    ['genCsp', 'genHstsAge', 'genSub', 'genPreload', 'genReferrer', 'genXfo', 'genCorp', 'genCoep', 'genFormat'].forEach(function (id) {
      $(id).addEventListener(id === 'genCsp' ? 'input' : 'change', updateGenerator);
    });
    $('genCsp').value = DEFAULT_CSP;
    $('genCopy').addEventListener('click', function () { copyText($('genOutput').textContent, $('genCopy')); });

    var param = new URLSearchParams(window.location.search).get('domain');
    if (param) $('domainInput').value = normalizeDomain(param).slice(0, 253);
    updateCommand();
    updateGenerator();
    if (param) $('headersInput').focus();

    if ('serviceWorker' in navigator) navigator.serviceWorker.register('/sw.js');
  }

  var api = { parseHeaders: parseHeaders, grade: grade, analyzeCsp: analyzeCsp, buildHeaders: buildHeaders, formatConfig: formatConfig, SAMPLES: SAMPLES, DEFAULT_CSP: DEFAULT_CSP, validDomain: validDomain, normalizeDomain: normalizeDomain, safeValue: safeValue };
  if (typeof module === 'object' && module && module.exports) module.exports = api;
  if (typeof document !== 'undefined' && document.getElementById('gradeBtn')) init();
})();
