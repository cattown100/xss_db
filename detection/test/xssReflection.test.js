'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');

const {
  analyzeExchange,
  analyze,
  extractCandidates,
  computeFindingRisk,
  riskLevel,
  overallRisk,
} = require('../lib/xssReflection');
const { XssCandidateStore } = require('../lib/xssCandidateStore');

const HTML = 'text/html; charset=utf-8';

// ── 반영 검사: 다양한 XSS 벡터 (우리 공격 스위트와 동일 벡터) ─────────────────
const REFLECTED_VECTORS = [
  '<script>alert(1)</script>',
  '<img src=x onerror=alert(1)>',
  '<svg onload=alert(1)>',
  '<iframe src="javascript:alert(1)"></iframe>',
  '<body onload=alert(1)>',
  '<a href="javascript:alert(1)">x</a>',
  '<details open ontoggle=alert(1)>',
  '<input autofocus onfocus=alert(1)>',
  '<ScRiPt>alert(1)</ScRiPt>',
  '<IMG SRC=x ONERROR=alert(1)>',
];

for (const payload of REFLECTED_VECTORS) {
  test(`reflected 벡터를 잡는다: ${payload.slice(0, 28)}`, () => {
    const req = { method: 'GET', url: `/search?q=${encodeURIComponent(payload)}`, responseContentType: HTML };
    const body = `<html><body><p>No results for ${payload}</p></body></html>`;
    const r = analyzeExchange(req, body, {}, null);
    assert.equal(r.detected, true, 'detected여야 함');
    assert.ok(r.tags.some((t) => t.startsWith('xss:reflected-')), `tags=${r.tags}`);
    assert.equal(r.severity, 'critical'); // 전부 self-contained
    assert.ok(r.maxRisk >= 80, `maxRisk=${r.maxRisk}`);
  });
}

test('이스케이프된 반영은 잡지 않는다(오탐 방지)', () => {
  const payload = '<script>alert(1)</script>';
  const req = { method: 'GET', url: `/search?q=${encodeURIComponent(payload)}`, responseContentType: HTML };
  const escaped = '<html><body>No results for &lt;script&gt;alert(1)&lt;/script&gt;</body></html>';
  const r = analyzeExchange(req, escaped, {}, null);
  assert.equal(r.detected, false);
  assert.equal(r.tags.length, 0);
});

test('메타문자 없는 값은 검사 대상이 아니다', () => {
  const req = { method: 'GET', url: '/search?q=applejuice', responseContentType: HTML };
  const body = '<html><body>No results for applejuice</body></html>';
  const r = analyzeExchange(req, body, {}, null);
  assert.equal(r.detected, false);
});

test('속성값 문맥 탈출은 attribute/high 이상으로 잡는다', () => {
  const payload = 'x" title="pwned';
  const req = { method: 'GET', url: `/greet?name=${encodeURIComponent(payload)}`, responseContentType: HTML };
  const body = `<html><body><input value="${payload}" placeholder="name"></body></html>`;
  const r = analyzeExchange(req, body, {}, null);
  assert.equal(r.detected, true);
  const f = r.findings[0];
  assert.equal(f.contextType, 'attribute');
  assert.ok(['high', 'critical'].includes(f.severity));
});

test('Location 헤더 반사(javascript:)는 header 채널 critical', () => {
  const payload = 'javascript:alert(1)';
  const req = { method: 'GET', url: `/redirect?url=${encodeURIComponent(payload)}`, responseContentType: HTML };
  const r = analyze(extractCandidates(req), '<html></html>', HTML, { Location: payload }, null);
  assert.equal(r.detected, true);
  const f = r.findings.find((x) => x.channel === 'header');
  assert.ok(f, 'header finding이 있어야 함');
  assert.equal(f.severity, 'critical');
});

test('JSON 응답은 body 검사를 건너뛴다(DOM XSS는 범위 밖)', () => {
  const payload = '<script>alert(1)</script>';
  const req = { method: 'GET', url: `/rest/products/search?q=${encodeURIComponent(payload)}`, responseContentType: 'application/json' };
  const body = `{"data": [], "q": "${payload}"}`;
  const r = analyzeExchange(req, body, { 'content-type': 'application/json' }, null);
  assert.equal(r.detected, false);
});

// ── Stored XSS: observe -> 나중 응답에서 탐지 ────────────────────────────────
test('observe한 값이 나중의 무관한 응답에 나타나면 stored로 잡는다', () => {
  const store = new XssCandidateStore();
  const writeReq = { method: 'POST', url: '/reviews', body: { text: "<script>steal()</script>" }, contentType: 'application/json' };
  store.observe(extractCandidates(writeReq), '/reviews');

  const readReq = { method: 'GET', url: '/reviews', responseContentType: HTML };
  const body = '<html><body><ul><li><script>steal()</script></li></ul></body></html>';
  const r = analyzeExchange(readReq, body, {}, store);
  assert.equal(r.detected, true);
  assert.ok(r.tags.some((t) => t.startsWith('xss:stored-')), `tags=${r.tags}`);
  const f = r.findings.find((x) => x.vulnerabilityType === 'stored');
  assert.equal(f.storedFromEndpoint, '/reviews');
  assert.equal(f.riskScore, 100); // critical + self-contained + stored
});

test('이번 요청 자신의 값은 stored로 이중 리포트하지 않는다', () => {
  const store = new XssCandidateStore();
  const payload = "<script>alert('me')</script>";
  const req = { method: 'GET', url: `/search?q=${encodeURIComponent(payload)}`, responseContentType: HTML };
  store.observe(extractCandidates(req), '/search');
  const body = `<html><body>No results for ${payload}</body></html>`;
  const r = analyzeExchange(req, body, {}, store);
  const stored = r.findings.filter((f) => f.vulnerabilityType === 'stored');
  assert.equal(stored.length, 0);
});

// ── 저장소 자체 ──────────────────────────────────────────────────────────────
test('저장소는 값 기준 중복 제거 + 메타문자 없는 값 무시', () => {
  const store = new XssCandidateStore();
  assert.equal(store.observe([{ value: '<b>x</b>', parameter: 'a', source: 'json' }], '/a'), 1);
  assert.equal(store.observe([{ value: '<b>x</b>', parameter: 'a', source: 'json' }], '/a'), 0); // 중복
  assert.equal(store.observe([{ value: 'plainnometacharsss', parameter: 'b', source: 'json' }], '/b'), 0); // 메타문자 없음
  assert.equal(store.size(), 1);
});

test('TTL 만료된 값은 사라진다', () => {
  let t = 1000;
  const store = new XssCandidateStore({ ttlMs: 100, now: () => t });
  store.observe([{ value: '<i>x</i>', parameter: 'a', source: 'json' }], '/a');
  assert.equal(store.size(), 1);
  t = 1000 + 200; // TTL 초과
  assert.equal(store.size(), 0);
});

test('최대 개수 초과 시 가장 오래된 것부터 제거', () => {
  const store = new XssCandidateStore({ maxEntries: 2 });
  store.observe([{ value: '<a1>', parameter: 'x', source: 'json' }], '/a');
  store.observe([{ value: '<a2>', parameter: 'x', source: 'json' }], '/a');
  store.observe([{ value: '<a3>', parameter: 'x', source: 'json' }], '/a');
  assert.equal(store.size(), 2);
  const values = store.all().map((e) => e.value);
  assert.ok(!values.includes('<a1>'), '가장 오래된 <a1>은 제거돼야 함');
});

// ── 위험도 단조성 ────────────────────────────────────────────────────────────
test('위험도: severity 밴드 단조 + self-contained/stored 가산', () => {
  const crit = computeFindingRisk('critical', false, 'reflected');
  const high = computeFindingRisk('high', false, 'reflected');
  const med = computeFindingRisk('medium', false, 'reflected');
  assert.ok(crit > high && high > med);
  assert.equal(riskLevel(crit), 'critical');
  assert.equal(riskLevel(high), 'high');
  assert.equal(riskLevel(med), 'medium');
  assert.ok(computeFindingRisk('critical', true, 'stored') === 100);
  assert.equal(overallRisk([]), 0);
  assert.ok(overallRisk([34, 94]) >= 94);
});
