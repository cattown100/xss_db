'use strict';

/**
 * xssCandidateStore.js
 *
 * Stored XSS 대조용 인메모리 후보 저장소. 쓰기 요청(리뷰/댓글/프로필 등록 등)에서 관찰한
 * "나중에 다른 응답으로 새어 나올 수 있는 값"을 값 기준으로 중복 제거해 쌓아두고,
 * xssReflection.analyze()가 나중 응답과 대조할 수 있게 한다.
 *
 * 우리 파이썬 CandidateStore를 이식한 것. Map은 삽입 순서를 보존하므로 그걸로 LRU를 구현.
 * TTL 만료 + 최대 개수 초과 시 가장 오래된 것부터 제거.
 */

const DEFAULT_TTL_MS = 60 * 60 * 1000; // 1시간
const DEFAULT_MAX_ENTRIES = 2000;
// 공격으로 "확정"된 payload 보관소 상한. 확정은 극소수라 TTL 없이 보관해도 안전(개수만 유계).
const DEFAULT_MAX_CONFIRMED = 1000;

const META_CHARS = new Set(['<', '>', '"', "'", '(', ')', ';', '`']);
function hasMetaChars(value) {
  for (const ch of value) if (META_CHARS.has(ch)) return true;
  return false;
}

class XssCandidateStore {
  constructor({
    ttlMs = DEFAULT_TTL_MS,
    maxEntries = DEFAULT_MAX_ENTRIES,
    maxConfirmed = DEFAULT_MAX_CONFIRMED,
    now = Date.now,
  } = {}) {
    this.ttlMs = ttlMs > 0 ? ttlMs : DEFAULT_TTL_MS;
    this.maxEntries = maxEntries > 0 ? maxEntries : DEFAULT_MAX_ENTRIES;
    this.maxConfirmed = maxConfirmed > 0 ? maxConfirmed : DEFAULT_MAX_CONFIRMED;
    this._now = now;
    this._map = new Map(); // value -> { value, parameter, source, endpoint, plantedBy, firstSeen, lastSeen, timesSeen }
    // 공격으로 확정된 payload 보관소(관찰용 _map과 별개). TTL 없음, 개수만 유계.
    this._confirmed = new Map(); // value -> { value, parameter, severity, riskScore, plantedBy, endpoint, firstConfirmedAt, lastConfirmedAt, timesConfirmed }
  }

  /**
   * 후보 값들을 관찰해 저장한다(메타문자 없는 값은 XSS가 될 수 없어 무시).
   * @returns {number} 이번 호출로 새로 추가된(처음 보는) 값의 개수
   */
  observe(candidates, endpoint, plantedBy = null) {
    this._evictExpired();
    let added = 0;
    const now = this._now();
    for (const c of candidates || []) {
      if (!c || typeof c.value !== 'string' || !hasMetaChars(c.value)) continue;
      const existing = this._map.get(c.value);
      if (existing) {
        existing.lastSeen = now;
        existing.timesSeen += 1;
        if (!existing.plantedBy && plantedBy) existing.plantedBy = plantedBy;
        this._map.delete(c.value);
        this._map.set(c.value, existing); // 최근 사용으로 이동(LRU)
      } else {
        this._map.set(c.value, {
          value: c.value,
          parameter: c.parameter,
          source: c.source,
          endpoint: endpoint || null,
          plantedBy: plantedBy || null,
          firstSeen: now,
          lastSeen: now,
          timesSeen: 1,
        });
        added += 1;
      }
    }
    this._evictOverflow();
    return added;
  }

  /** 만료되지 않은 모든 후보를 배열로 반환. */
  all() {
    this._evictExpired();
    return [...this._map.values()];
  }

  size() {
    this._evictExpired();
    return this._map.size;
  }

  clear() {
    this._map.clear();
  }

  /** 특정 값 후보를 제거한다(stored XSS로 탐지되면 더 이상 비교하지 않기 위해). */
  delete(value) {
    return this._map.delete(value);
  }

  /**
   * 공격으로 "확정"된 payload를 별도 보관소로 승격한다. 관찰용 저장소(_map)에서
   * delete로 지워져도 이 기록은 사라지지 않는다(증거 보존 + 재출현 즉시 식별용).
   * @returns {boolean} 이번 호출로 "처음" 확정된 값이면 true
   */
  confirm(finding) {
    if (!finding || typeof finding.value !== 'string' || !finding.value) return false;
    const now = this._now();
    const existing = this._confirmed.get(finding.value);
    if (existing) {
      existing.lastConfirmedAt = now;
      existing.timesConfirmed += 1;
      if ((Number(finding.riskScore) || 0) > (existing.riskScore || 0)) {
        existing.riskScore = Number(finding.riskScore) || 0;
        existing.severity = finding.severity || existing.severity;
      }
      return false;
    }
    this._confirmed.set(finding.value, {
      value: finding.value,
      parameter: finding.parameter || null,
      severity: finding.severity || null,
      riskScore: Number(finding.riskScore) || 0,
      plantedBy: finding.plantedBy || null,
      endpoint: finding.endpoint || finding.storedFromEndpoint || null,
      vulnType: finding.vulnerabilityType || finding.vulnType || 'stored',
      status: 'open',
      note: '',
      firstConfirmedAt: now,
      lastConfirmedAt: now,
      timesConfirmed: 1,
    });
    while (this._confirmed.size > this.maxConfirmed) {
      const oldest = this._confirmed.keys().next().value;
      this._confirmed.delete(oldest);
    }
    return true;
  }

  /** 이 값이 이미 공격으로 확정된 payload인지(관찰 시점 즉시 식별용). */
  isConfirmed(value) {
    return this._confirmed.has(value);
  }

  /** 확정 악성 payload 목록(탐지 담당자 조회용). */
  confirmedList() {
    return [...this._confirmed.values()];
  }

  confirmedSize() {
    return this._confirmed.size;
  }

  removeConfirmed(value) {
    return this._confirmed.delete(value);
  }

  updateConfirmed(value, patch = {}) {
    const e = this._confirmed.get(value);
    if (!e) return false;
    if (patch.status != null) e.status = patch.status;
    if (patch.note != null) e.note = patch.note;
    return true;
  }

  _evictExpired() {
    const cutoff = this._now() - this.ttlMs;
    for (const [value, entry] of this._map) {
      if (entry.lastSeen < cutoff) this._map.delete(value);
    }
  }

  _evictOverflow() {
    while (this._map.size > this.maxEntries) {
      const oldest = this._map.keys().next().value; // 삽입/사용 순 가장 오래된 것
      this._map.delete(oldest);
    }
  }
}

module.exports = { XssCandidateStore, DEFAULT_TTL_MS, DEFAULT_MAX_ENTRIES };
