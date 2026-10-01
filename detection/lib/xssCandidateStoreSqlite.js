'use strict';
/**
 * xssCandidateStoreSqlite.js
 * XssCandidateStore와 동일한 인터페이스를 SQLite(파일/메모리)로 구현한 드롭인 스토어.
 * Node 내장 node:sqlite 사용 → 서버·npm 불필요. 파일 모드면 재시작해도 데이터 보존.
 *
 * 제공: observe(cands, endpoint, plantedBy), all(), size(), delete(value), clear(),
 *       confirm(finding), isConfirmed(value), confirmedList(), confirmedSize()
 * 성능: WAL + synchronous=NORMAL로 쓰기 fsync 부담을 낮추고,
 *       TTL/상한 정리는 읽기 경로가 아니라 주기적 sweep(기본 60초)에서 수행 → 읽기는 순수 SELECT.
 */
const { DatabaseSync } = require('node:sqlite');

const DEFAULT_TTL_MS = 60 * 60 * 1000;      // 1시간
const DEFAULT_MAX_ENTRIES = 2000;
const DEFAULT_MAX_CONFIRMED = 1000;
const SWEEP_INTERVAL_MS = 60 * 1000;        // TTL/상한 정리 최소 간격

const META = new Set(['<', '>', '"', "'", '(', ')', ';', '`']);
function hasMeta(v){ for (const c of v) if (META.has(c)) return true; return false; }

class XssCandidateStoreSqlite {
  constructor({ dbPath = ':memory:', ttlMs = DEFAULT_TTL_MS, maxEntries = DEFAULT_MAX_ENTRIES,
                maxConfirmed = DEFAULT_MAX_CONFIRMED, now = Date.now } = {}) {
    this.ttlMs = ttlMs > 0 ? ttlMs : DEFAULT_TTL_MS;
    this.maxEntries = maxEntries > 0 ? maxEntries : DEFAULT_MAX_ENTRIES;
    this.maxConfirmed = maxConfirmed > 0 ? maxConfirmed : DEFAULT_MAX_CONFIRMED;
    this._now = now;
    this._lastSweep = 0;
    this.db = new DatabaseSync(dbPath);
    if (dbPath !== ':memory:') { try { this.db.exec('PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;'); } catch {} }
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS cand(
        value TEXT PRIMARY KEY, parameter TEXT, source TEXT, endpoint TEXT,
        planted_session TEXT, planted_ip TEXT,
        first_seen INTEGER, last_seen INTEGER, times_seen INTEGER);
      CREATE INDEX IF NOT EXISTS idx_cand_last ON cand(last_seen);
      CREATE TABLE IF NOT EXISTS confirmed(
        value TEXT PRIMARY KEY, parameter TEXT, severity TEXT, risk_score INTEGER,
        planted_session TEXT, planted_ip TEXT, endpoint TEXT,
        first_confirmed INTEGER, last_confirmed INTEGER, times_confirmed INTEGER, vuln_type TEXT, status TEXT, note TEXT);`);
    for (const col of ['vuln_type TEXT','status TEXT','note TEXT']) { try { this.db.exec('ALTER TABLE confirmed ADD COLUMN ' + col); } catch (_) {} }
    this._ins = this.db.prepare(`INSERT INTO cand(value,parameter,source,endpoint,planted_session,planted_ip,first_seen,last_seen,times_seen)
      VALUES(?,?,?,?,?,?,?,?,1)
      ON CONFLICT(value) DO UPDATE SET last_seen=excluded.last_seen, times_seen=times_seen+1,
        planted_session=COALESCE(planted_session, excluded.planted_session),
        planted_ip=COALESCE(planted_ip, excluded.planted_ip)`);
    this._selAll = this.db.prepare(`SELECT value,parameter,source,endpoint,planted_session,planted_ip,
      first_seen AS firstSeen,last_seen AS lastSeen,times_seen AS timesSeen FROM cand WHERE last_seen>=? ORDER BY last_seen`);
    this._count = this.db.prepare(`SELECT COUNT(*) AS c FROM cand`);
    this._del = this.db.prepare(`DELETE FROM cand WHERE value=?`);
    this._delExpired = this.db.prepare(`DELETE FROM cand WHERE last_seen < ?`);
    this._overflow = this.db.prepare(`DELETE FROM cand WHERE value IN (SELECT value FROM cand ORDER BY last_seen LIMIT ?)`);
    // confirmed
    this._cGet = this.db.prepare(`SELECT risk_score AS riskScore FROM confirmed WHERE value=?`);
    this._cIns = this.db.prepare(`INSERT INTO confirmed(value,parameter,severity,risk_score,planted_session,planted_ip,endpoint,first_confirmed,last_confirmed,times_confirmed,vuln_type,status,note)
      VALUES(?,?,?,?,?,?,?,?,?,1,?,?,?)`);
    this._cUpd = this.db.prepare(`UPDATE confirmed SET last_confirmed=?, times_confirmed=times_confirmed+1,
      risk_score=MAX(risk_score,?), severity=CASE WHEN ?>risk_score THEN ? ELSE severity END WHERE value=?`);
    this._cList = this.db.prepare(`SELECT value,parameter,severity,risk_score AS riskScore,planted_session,endpoint,
      first_confirmed AS firstConfirmedAt,last_confirmed AS lastConfirmedAt,times_confirmed AS timesConfirmed,vuln_type AS vulnType,status,note FROM confirmed ORDER BY last_confirmed DESC`);
    this._cCount = this.db.prepare(`SELECT COUNT(*) AS c FROM confirmed`);
    this._cOverflow = this.db.prepare(`DELETE FROM confirmed WHERE value IN (SELECT value FROM confirmed ORDER BY last_confirmed LIMIT ?)`);
    this._cDel = this.db.prepare(`DELETE FROM confirmed WHERE value=?`);
    this._cUpdMeta = this.db.prepare(`UPDATE confirmed SET status=COALESCE(?,status), note=COALESCE(?,note) WHERE value=?`);
  }

  _maybeSweep(now){
    if (now - this._lastSweep < SWEEP_INTERVAL_MS) return;
    this._lastSweep = now;
    this._delExpired.run(now - this.ttlMs);
    const n = this._count.get().c;
    if (n > this.maxEntries) this._overflow.run(n - this.maxEntries);
  }

  observe(candidates, endpoint, plantedBy = null){
    const now = this._now(); this._maybeSweep(now);
    const sid = plantedBy && plantedBy.sessionId || null;
    const pip = plantedBy && plantedBy.ip || null;
    let added = 0;
    for (const c of candidates || []){
      if (!c || typeof c.value !== 'string' || !hasMeta(c.value)) continue;
      this._ins.run(c.value, c.parameter ?? null, c.source ?? null, endpoint ?? null, sid, pip, now, now);
      added++;
    }
    return added;
  }
  all(){
    const now = this._now();
    return this._selAll.all(now - this.ttlMs).map(r => ({
      value: r.value, parameter: r.parameter, source: r.source, endpoint: r.endpoint,
      plantedBy: r.planted_session ? { sessionId: r.planted_session, ip: r.planted_ip } : null,
      firstSeen: r.firstSeen, lastSeen: r.lastSeen, timesSeen: r.timesSeen,
    }));
  }
  size(){ return this._count.get().c; }
  delete(value){ return this._del.run(value).changes > 0; }
  clear(){ this.db.exec('DELETE FROM cand'); }

  confirm(finding){
    if (!finding || typeof finding.value !== 'string' || !finding.value) return false;
    const now = this._now();
    const risk = Number(finding.riskScore) || 0;
    if (this._cGet.get(finding.value)){
      this._cUpd.run(now, risk, risk, finding.severity || null, finding.value);
      return false;
    }
    this._cIns.run(finding.value, finding.parameter ?? null, finding.severity ?? null, risk,
      finding.plantedBy && finding.plantedBy.sessionId || null,
      finding.plantedBy && finding.plantedBy.ip || null,
      finding.endpoint ?? finding.storedFromEndpoint ?? null, now, now,
      finding.vulnerabilityType || finding.vulnType || 'stored', 'open', null);
    const n = this._cCount.get().c;
    if (n > this.maxConfirmed) this._cOverflow.run(n - this.maxConfirmed);
    return true;
  }
  isConfirmed(value){ return !!this._cGet.get(value); }
  confirmedList(){
    return this._cList.all().map(r => ({
      value: r.value, parameter: r.parameter, severity: r.severity, riskScore: r.riskScore,
      plantedBy: r.planted_session ? { sessionId: r.planted_session } : null,
      endpoint: r.endpoint, firstConfirmedAt: r.firstConfirmedAt, lastConfirmedAt: r.lastConfirmedAt,
      timesConfirmed: r.timesConfirmed, vulnType: r.vulnType || 'stored',
      status: r.status || 'open', note: r.note || '',
    }));
  }
  confirmedSize(){ return this._cCount.get().c; }
  removeConfirmed(value){ return this._cDel.run(value).changes > 0; }
  updateConfirmed(value, patch = {}){ return this._cUpdMeta.run(patch.status ?? null, patch.note ?? null, value).changes > 0; }
}
module.exports = { XssCandidateStoreSqlite };
