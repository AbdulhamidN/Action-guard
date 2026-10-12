const net = require('net');

/**
 * Parses a valid dotted-quad IPv4 address into a 4-byte Uint8Array.
 *
 * @param {string} ip
 * @returns {Uint8Array|null}
 */
function parseIpv4Bytes(ip) {
  if (typeof ip !== 'string' || !net.isIPv4(ip)) {
    return null;
  }
  const parts = ip.split('.');
  if (parts.length !== 4) {
    return null;
  }
  const bytes = new Uint8Array(4);
  for (let i = 0; i < 4; i += 1) {
    const num = Number.parseInt(parts[i], 10);
    if (!Number.isInteger(num) || num < 0 || num > 255) {
      return null;
    }
    bytes[i] = num;
  }
  return bytes;
}

/**
 * Parses a valid IPv6 address (including compressed `::` and embedded trailing IPv4 notations)
 * into a canonical 16-byte big-endian Uint8Array.
 *
 * @param {string} ip
 * @returns {Uint8Array|null}
 */
function parseIpv6Bytes(ip) {
  if (typeof ip !== 'string') {
    return null;
  }
  const trimmed = ip.trim().toLowerCase();
  // Strip optional zone index (e.g. %eth0) before structural parsing if present
  const zoneIndex = trimmed.indexOf('%');
  const candidate = zoneIndex !== -1 ? trimmed.slice(0, zoneIndex) : trimmed;

  if (!net.isIPv6(candidate)) {
    return null;
  }

  let working = candidate;
  // Convert trailing dotted-quad IPv4 (e.g. ::ffff:127.0.0.1 or 64:ff9b::127.0.0.1) into two 16-bit hex groups
  const lastColon = working.lastIndexOf(':');
  if (lastColon !== -1 && working.slice(lastColon + 1).includes('.')) {
    const ipv4Part = working.slice(lastColon + 1);
    const ipv4Bytes = parseIpv4Bytes(ipv4Part);
    if (!ipv4Bytes) {
      return null;
    }
    const highWord = ((ipv4Bytes[0] << 8) | ipv4Bytes[1]).toString(16);
    const lowWord = ((ipv4Bytes[2] << 8) | ipv4Bytes[3]).toString(16);
    working = `${working.slice(0, lastColon)}:${highWord}:${lowWord}`;
  }

  const doubleColonParts = working.split('::');
  if (doubleColonParts.length > 2) {
    return null;
  }

  const leftGroups =
    doubleColonParts[0].length > 0 ? doubleColonParts[0].split(':') : [];
  const rightGroups =
    doubleColonParts.length === 2 && doubleColonParts[1].length > 0
      ? doubleColonParts[1].split(':')
      : [];

  const missingGroups = 8 - (leftGroups.length + rightGroups.length);
  if (
    (doubleColonParts.length === 1 && missingGroups !== 0) ||
    (doubleColonParts.length === 2 && missingGroups < 1)
  ) {
    return null;
  }

  const fullGroups = [
    ...leftGroups,
    ...new Array(missingGroups).fill('0'),
    ...rightGroups
  ];
  if (fullGroups.length !== 8) {
    return null;
  }

  const bytes = new Uint8Array(16);
  for (let i = 0; i < 8; i += 1) {
    const word = Number.parseInt(fullGroups[i], 16);
    if (!Number.isInteger(word) || word < 0 || word > 0xffff) {
      return null;
    }
    bytes[i * 2] = (word >> 8) & 0xff;
    bytes[i * 2 + 1] = word & 0xff;
  }

  return bytes;
}

/**
 * Checks whether an IP byte array falls within a given CIDR prefix.
 *
 * @param {Uint8Array} addrBytes
 * @param {number[]} prefixBytes
 * @param {number} prefixBits
 * @returns {boolean}
 */
function matchesCidrBytes(addrBytes, prefixBytes, prefixBits) {
  const fullBytes = Math.floor(prefixBits / 8);
  const remainingBits = prefixBits % 8;

  for (let i = 0; i < fullBytes; i += 1) {
    if (addrBytes[i] !== (prefixBytes[i] || 0)) {
      return false;
    }
  }

  if (remainingBits > 0) {
    const mask = (0xff << (8 - remainingBits)) & 0xff;
    if ((addrBytes[fullBytes] & mask) !== ((prefixBytes[fullBytes] || 0) & mask)) {
      return false;
    }
  }

  return true;
}

const NON_PUBLIC_IPV4_CIDRS = [
  // 0.0.0.0/8 — "This network" / Unspecified (RFC 1122)
  { prefix: [0, 0, 0, 0], bits: 8 },
  // 10.0.0.0/8 — Private-Use (RFC 1918)
  { prefix: [10, 0, 0, 0], bits: 8 },
  // 100.64.0.0/10 — Shared Address Space / CGNAT (RFC 6598)
  { prefix: [100, 64, 0, 0], bits: 10 },
  // 127.0.0.0/8 — Loopback (RFC 1122)
  { prefix: [127, 0, 0, 0], bits: 8 },
  // 169.254.0.0/16 — Link-Local / Cloud Metadata (RFC 3927)
  { prefix: [169, 254, 0, 0], bits: 16 },
  // 172.16.0.0/12 — Private-Use (RFC 1918)
  { prefix: [172, 16, 0, 0], bits: 12 },
  // 192.0.0.0/24 — IETF Protocol Assignments (RFC 6890)
  { prefix: [192, 0, 0, 0], bits: 24 },
  // 192.0.2.0/24 — Documentation TEST-NET-1 (RFC 5737)
  { prefix: [192, 0, 2, 0], bits: 24 },
  // 192.88.99.0/24 — 6to4 Relay Anycast (RFC 7526)
  { prefix: [192, 88, 99, 0], bits: 24 },
  // 192.168.0.0/16 — Private-Use (RFC 1918)
  { prefix: [192, 168, 0, 0], bits: 16 },
  // 198.18.0.0/15 — Benchmarking (RFC 2544)
  { prefix: [198, 18, 0, 0], bits: 15 },
  // 198.51.100.0/24 — Documentation TEST-NET-2 (RFC 5737)
  { prefix: [198, 51, 100, 0], bits: 24 },
  // 203.0.113.0/24 — Documentation TEST-NET-3 (RFC 5737)
  { prefix: [203, 0, 113, 0], bits: 24 },
  // 224.0.0.0/4 — Multicast (RFC 5771)
  { prefix: [224, 0, 0, 0], bits: 4 },
  // 240.0.0.0/4 — Reserved for Future Use & Broadcast 255.255.255.255 (RFC 1112)
  { prefix: [240, 0, 0, 0], bits: 4 }
];

const NON_PUBLIC_IPV6_CIDRS = [
  // ::/96 — Unspecified (::/128), Loopback (::1/128), and deprecated IPv4-compatible IPv6 (RFC 4291)
  { prefix: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], bits: 96 },
  // ::ffff:0:0:0/96 — IPv4-translated addresses (RFC 2765)
  { prefix: [0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0, 0], bits: 96 },
  // 64:ff9b::/96 — NAT64 Well-Known Prefix (RFC 6052)
  { prefix: [0x00, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0], bits: 96 },
  // 64:ff9b:1::/48 — NAT64 Local-Use Prefix (RFC 8215)
  { prefix: [0x00, 0x64, 0xff, 0x9b, 0x00, 0x01], bits: 48 },
  // 100::/64 — Discard-Only Address Block (RFC 6666)
  { prefix: [0x01, 0x00, 0, 0, 0, 0, 0, 0], bits: 64 },
  // 2001::/23 — IETF Protocol Assignments (RFC 2928), including Teredo (2001::/32), Benchmarking (2001:2::/48), ORCHID
  { prefix: [0x20, 0x01, 0x00], bits: 23 },
  // 2001:db8::/32 — Documentation (RFC 3849)
  { prefix: [0x20, 0x01, 0x0d, 0xb8], bits: 32 },
  // 2002::/16 — 6to4 Transition Addressing (RFC 3056 / deprecated RFC 7526)
  { prefix: [0x20, 0x02], bits: 16 },
  // fc00::/7 — Unique Local Addresses (ULA, RFC 4193)
  { prefix: [0xfc], bits: 7 },
  // fe80::/10 — Link-Local Unicast (RFC 4291)
  { prefix: [0xfe, 0x80], bits: 10 },
  // fec0::/10 — Deprecated Site-Local Unicast (RFC 3879)
  { prefix: [0xfe, 0xc0], bits: 10 },
  // ff00::/8 — Multicast (RFC 4291)
  { prefix: [0xff], bits: 8 }
];

/**
 * Evaluates whether a 4-byte IPv4 address belongs to a non-public or special-purpose range.
 *
 * @param {Uint8Array} ipv4Bytes
 * @returns {boolean}
 */
function isNonPublicIpv4Bytes(ipv4Bytes) {
  return NON_PUBLIC_IPV4_CIDRS.some((cidr) =>
    matchesCidrBytes(ipv4Bytes, cidr.prefix, cidr.bits)
  );
}

/**
 * Evaluates whether a 16-byte IPv6 address belongs to a non-public, transition, or special-purpose range.
 *
 * @param {Uint8Array} ipv6Bytes
 * @returns {boolean}
 */
function isNonPublicIpv6Bytes(ipv6Bytes) {
  // Check IPv4-mapped IPv6 ::ffff:0:0/96 -> classify using the embedded 32-bit IPv4 address
  if (
    matchesCidrBytes(
      ipv6Bytes,
      [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff],
      96
    )
  ) {
    const embeddedIpv4 = ipv6Bytes.subarray(12, 16);
    return isNonPublicIpv4Bytes(embeddedIpv4);
  }

  if (
    NON_PUBLIC_IPV6_CIDRS.some((cidr) =>
      matchesCidrBytes(ipv6Bytes, cidr.prefix, cidr.bits)
    )
  ) {
    return true;
  }

  // Only IANA Global Unicast (2000::/3) is public routable IPv6 space
  if (!matchesCidrBytes(ipv6Bytes, [0x20], 3)) {
    return true;
  }

  return false;
}

/**
 * Normalizes an IP address:
 * - Trims whitespace
 * - Unwraps IPv4-mapped IPv6 addresses (both dotted `::ffff:192.0.2.1` and hex `::ffff:7f00:1`)
 * - Validates format via net.isIP()
 *
 * @param {any} rawIp - The raw IP string
 * @returns {string|null} Normalized IP string or null if invalid
 */
function normalizeIp(rawIp) {
  if (typeof rawIp !== 'string') {
    return null;
  }

  const trimmed = rawIp.trim();
  if (!trimmed) {
    return null;
  }

  // Handle dotted IPv4-mapped IPv6 (e.g. ::ffff:192.168.1.1 or ::ffff:127.0.0.1)
  if (trimmed.toLowerCase().startsWith('::ffff:')) {
    const candidateIpv4 = trimmed.slice(7);
    if (net.isIPv4(candidateIpv4)) {
      return candidateIpv4;
    }
    const ipv6Bytes = parseIpv6Bytes(trimmed);
    if (ipv6Bytes) {
      return `${ipv6Bytes[12]}.${ipv6Bytes[13]}.${ipv6Bytes[14]}.${ipv6Bytes[15]}`;
    }
  }

  if (net.isIP(trimmed) === 0) {
    return null;
  }

  return trimmed;
}

/**
 * Checks whether an IP address belongs to loopback, private, link-local, transition, or special-purpose ranges.
 * Geolocation lookups and outbound webhook destinations must not treat these addresses as public targets.
 *
 * @param {string} ip - Raw or normalized IP address
 * @returns {boolean} True if the IP is private, loopback, transition, or reserved
 */
function isPrivateOrLoopbackIp(ip) {
  const normalized = normalizeIp(ip);
  if (!normalized) {
    return true;
  }

  const family = net.isIP(normalized);
  if (family === 4) {
    const ipv4Bytes = parseIpv4Bytes(normalized);
    if (!ipv4Bytes) {
      return true;
    }
    return isNonPublicIpv4Bytes(ipv4Bytes);
  }

  if (family === 6) {
    const ipv6Bytes = parseIpv6Bytes(normalized);
    if (!ipv6Bytes) {
      return true;
    }
    return isNonPublicIpv6Bytes(ipv6Bytes);
  }

  return true;
}

module.exports = {
  parseIpv4Bytes,
  parseIpv6Bytes,
  matchesCidrBytes,
  normalizeIp,
  isPrivateOrLoopbackIp
};
