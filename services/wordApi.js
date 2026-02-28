const cache = new Map();

async function isValidEnglishWord(word) {
  const w = String(word || "").toLowerCase().trim();
  if (!/^[a-z]{5}$/.test(w)) return false;

  if (cache.has(w)) return cache.get(w);

  const res = await fetch(`https://api.datamuse.com/words?sp=${encodeURIComponent(w)}&max=1`);
  if (!res.ok) {
    cache.set(w, false);
    return false;
  }

  const arr = await res.json();
  const ok = Array.isArray(arr) && arr.length > 0 && arr[0]?.word === w;

  cache.set(w, ok);
  return ok;
}

module.exports = { isValidEnglishWord };