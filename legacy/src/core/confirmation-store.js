const crypto = require('node:crypto');

function createConfirmationStore({ now = Date.now, randomBytes = crypto.randomBytes, ttlMs = 5 * 60 * 1000 } = {}) {
  const pending = new Map();
  const fingerprint = (type, values) => crypto.createHash('sha256').update(`${type}\0${JSON.stringify(values)}`).digest('hex');
  function issue(type, values) {
    const token = randomBytes(24).toString('base64url');
    pending.set(token, { type, fingerprint: fingerprint(type, values), expiresAt: now() + ttlMs });
    if (pending.size > 100) for (const [key, item] of pending) if (item.expiresAt <= now()) pending.delete(key);
    return token;
  }
  function consume(token, type, values) {
    const key = String(token || '');
    const item = pending.get(key);
    pending.delete(key);
    if (!item || item.expiresAt <= now() || item.type !== type || item.fingerprint !== fingerprint(type, values)) {
      throw new Error('确认请求已失效，请重新核对操作内容。');
    }
  }
  return { issue, consume, clear: () => pending.clear() };
}
module.exports = { createConfirmationStore };
