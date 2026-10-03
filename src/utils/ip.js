const net = require('net');

/**
 * Normalizes an IP address:
 * - Trims whitespace
 * - Unwraps IPv4-mapped IPv6 addresses (e.g. ::ffff:192.0.2.1 -> 192.0.2.1)
 * - Validates format via net.isIP()
 *
 * @param {any} rawIp - The raw IP string
 * @returns {string|null} Normalized IP string or null if invalid
 */
function normalizeIp(rawIp) {
  if (typeof rawIp !== 'string') {
    return null;
  }

  let trimmed = rawIp.trim();
  if (!trimmed) {
    return null;
  }

  // Handle IPv4-mapped IPv6 (e.g. ::ffff:192.168.1.1 or ::ffff:127.0.0.1)
  if (trimmed.toLowerCase().startsWith('::ffff:')) {
    const candidateIpv4 = trimmed.slice(7);
    if (net.isIPv4(candidateIpv4)) {
      return candidateIpv4;
    }
  }

  if (net.isIP(trimmed) === 0) {
    return null;
  }

  return trimmed;
}

/**
 * Checks whether an IP address belongs to loopback, private, link-local, or reserved ranges.
 * Geolocation lookups should not attempt to assign physical locations to these addresses.
 *
 * @param {string} ip - Normalized IP address
 * @returns {boolean} True if the IP is private, loopback, or reserved
 */
function isPrivateOrLoopbackIp(ip) {
  const normalized = normalizeIp(ip);
  if (!normalized) {
    return true; // Invalid IPs cannot have valid physical geolocation
  }

  const family = net.isIP(normalized);
  if (family === 4) {
    const parts = normalized.split('.').map((p) => parseInt(p, 10));
    const [b0, b1, b2] = parts;

    // Loopback 127.0.0.0/8
    if (b0 === 127) return true;

    // Current network / Unspecified 0.0.0.0/8
    if (b0 === 0) return true;

    // RFC 1918 Private: 10.0.0.0/8
    if (b0 === 10) return true;

    // RFC 1918 Private: 172.16.0.0/12 (172.16.0.0 – 172.31.255.255)
    if (b0 === 172 && b1 >= 16 && b1 <= 31) return true;

    // RFC 1918 Private: 192.168.0.0/16
    if (b0 === 192 && b1 === 168) return true;

    // Link-local: 169.254.0.0/16
    if (b0 === 169 && b1 === 254) return true;

    // Carrier-grade NAT: 100.64.0.0/10 (100.64.0.0 – 100.127.255.255)
    if (b0 === 100 && b1 >= 64 && b1 <= 127) return true;

    // Documentation / Test networks: 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24
    if (b0 === 192 && b1 === 0 && b2 === 2) return true;
    if (b0 === 198 && b1 === 51 && b2 === 100) return true;
    if (b0 === 203 && b1 === 0 && b2 === 113) return true;

    // Multicast & Reserved (224.0.0.0/4 and 240.0.0.0/4, broadcast 255.255.255.255)
    if (b0 >= 224) return true;

    return false;
  }

  if (family === 6) {
    const lower = normalized.toLowerCase();

    // Loopback ::1
    if (lower === '::1' || lower === '0:0:0:0:0:0:0:1') return true;

    // Unspecified ::
    if (lower === '::' || lower === '0:0:0:0:0:0:0:0') return true;

    // Unique Local Address (ULA) fc00::/7 (fc or fd)
    if (lower.startsWith('fc') || lower.startsWith('fd')) return true;

    // Link-local unicast fe80::/10 (fe8, fe9, fea, feb)
    if (/^fe[89ab]/i.test(lower)) return true;

    // Multicast ff00::/8
    if (lower.startsWith('ff')) return true;

    // Documentation 2001:db8::/32
    if (lower.startsWith('2001:db8:') || lower.startsWith('2001:0db8:')) return true;

    return false;
  }

  return true;
}

module.exports = {
  normalizeIp,
  isPrivateOrLoopbackIp
};
