const { isIP } = require('node:net');
const windowsTimezoneMap = require('../timezone-map.json');

const DEFAULT_PROVIDERS = Object.freeze([
  {
    name: 'ipwho.is',
    url: 'https://ipwho.is/',
    parse(body) {
      if (body.success === false) throw new Error(body.message || 'ipwho.is lookup failed');
      return {
        ip: body.ip,
        countryCode: body.country_code,
        city: body.city,
        timezone: body.timezone && body.timezone.id,
      };
    },
  },
  {
    name: 'ipapi.co',
    url: 'https://ipapi.co/json/',
    parse(body) {
      if (body.error) throw new Error(body.reason || 'ipapi.co lookup failed');
      return {
        ip: body.ip,
        countryCode: body.country_code,
        city: body.city,
        timezone: body.timezone,
      };
    },
  },
]);

function isValidIanaTimezone(value) {
  if (typeof value !== 'string' || value.length < 3 || value.length > 80
    || !/^[A-Za-z0-9_+\-/]+$/.test(value)) return false;
  try {
    new Intl.DateTimeFormat('en-US', { timeZone: value }).format(new Date(0));
    return true;
  } catch {
    return false;
  }
}

function ianaToWindowsId(timezone) {
  if (!isValidIanaTimezone(timezone)) return null;
  return windowsTimezoneMap.ianaToWindows[timezone] || null;
}

async function readJsonResponse(response) {
  if (!response || !response.ok) throw new Error(`HTTP ${response ? response.status : 'unknown'}`);
  const contentLength = Number(response.headers?.get?.('content-length') || 0);
  if (contentLength > 65536) throw new Error('IP location response is too large');
  const text = await response.text();
  if (Buffer.byteLength(text, 'utf8') > 65536) throw new Error('IP location response is too large');
  return JSON.parse(text);
}

async function lookupExitLocation(fetchImpl, options = {}) {
  if (typeof fetchImpl !== 'function') throw new Error('未提供安全的公网出口查询能力。');
  const providers = options.providers || DEFAULT_PROVIDERS;
  const timeoutMs = Number.isInteger(options.timeoutMs) ? options.timeoutMs : 8000;
  const errors = [];

  for (const provider of providers) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
      const url = new URL(provider.url);
      if (url.protocol !== 'https:') throw new Error('provider must use HTTPS');
      const response = await fetchImpl(url.toString(), {
        method: 'GET',
        headers: { Accept: 'application/json' },
        credentials: 'omit',
        cache: 'no-store',
        signal: controller.signal,
      });
      const parsed = provider.parse(await readJsonResponse(response));
      if (!isIP(parsed.ip)) throw new Error('invalid public IP');
      if (!isValidIanaTimezone(parsed.timezone)) throw new Error('invalid timezone');
      return {
        ip: parsed.ip,
        countryCode: typeof parsed.countryCode === 'string' ? parsed.countryCode.slice(0, 3).toUpperCase() : '',
        city: typeof parsed.city === 'string' ? parsed.city.slice(0, 80) : '',
        timezone: parsed.timezone,
        provider: provider.name,
      };
    } catch (error) {
      errors.push(`${provider.name}: ${error.name === 'AbortError' ? 'timeout' : error.message}`);
    } finally {
      clearTimeout(timer);
    }
  }
  throw new Error(`无法识别当前公网出口地区，系统时区未更改。${errors.join('；')}`);
}

function maskIp(ip) {
  if (isIP(ip) === 4) return ip.replace(/\.\d+$/, '.***');
  if (isIP(ip) === 6) return `${ip.split(':').slice(0, 3).join(':')}:…`;
  return '';
}

module.exports = {
  DEFAULT_PROVIDERS,
  ianaToWindowsId,
  isValidIanaTimezone,
  lookupExitLocation,
  maskIp,
};
