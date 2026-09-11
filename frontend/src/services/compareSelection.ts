const STORAGE_KEY = "suricata-compare-selection-v1";
export const MAX_COMPARE_RULES = 4;
export const COMPARE_SELECTION_EVENT = "compare-selection-change";

function normalize(values: number[]): number[] {
  return [...new Set(values.filter((value) => Number.isSafeInteger(value) && value > 0))]
    .slice(0, MAX_COMPARE_RULES);
}

export function loadCompareSelection(): number[] {
  try {
    const value = JSON.parse(localStorage.getItem(STORAGE_KEY) || "[]");
    return Array.isArray(value) ? normalize(value.map(Number)) : [];
  } catch {
    return [];
  }
}

function saveCompareSelection(values: number[]): number[] {
  const next = normalize(values);
  localStorage.setItem(STORAGE_KEY, JSON.stringify(next));
  window.dispatchEvent(new Event(COMPARE_SELECTION_EVENT));
  return next;
}

export function setCompareSelection(values: number[]): number[] {
  return saveCompareSelection(values);
}

export function addCompareSid(sid: number): { sids: number[]; added: boolean; full: boolean } {
  const current = loadCompareSelection();
  if (current.includes(sid)) return { sids: current, added: false, full: false };
  if (current.length >= MAX_COMPARE_RULES) return { sids: current, added: false, full: true };
  return { sids: saveCompareSelection([...current, sid]), added: true, full: false };
}

export function toggleCompareSid(sid: number): { sids: number[]; added: boolean; removed: boolean; full: boolean } {
  const current = loadCompareSelection();
  if (current.includes(sid)) {
    return { sids: saveCompareSelection(current.filter((value) => value !== sid)), added: false, removed: true, full: false };
  }
  if (current.length >= MAX_COMPARE_RULES) return { sids: current, added: false, removed: false, full: true };
  return { sids: saveCompareSelection([...current, sid]), added: true, removed: false, full: false };
}

export function removeCompareSid(sid: number): number[] {
  return saveCompareSelection(loadCompareSelection().filter((value) => value !== sid));
}

export function clearCompareSelection(): number[] {
  return saveCompareSelection([]);
}
