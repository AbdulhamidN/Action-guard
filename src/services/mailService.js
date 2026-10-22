'use strict';

const net = require('net');
const tls = require('tls');
const crypto = require('crypto');

/**
 * In-memory test outbox for deterministic test-mode verification.
 * @type {Array<object>}
 */
const testMailOutbox = [];

/** @type {Function|null} */
let mockTransport = null;

/**
 * Retrieves the test outbox messages. Test mode only.
 * @returns {Array<object>}
 */
function getTestMailOutbox() {
  return [...testMailOutbox];
}

/**
 * Clears the test outbox. Test mode only.
 */
function clearTestMailOutbox() {
  testMailOutbox.length = 0;
}

/**
 * Overrides the transport with a mock function for custom test assertions.
 * @param {Function} fn
 */
function setMockTransport(fn) {
  mockTransport = fn;
}

/**
 * Resets the mock transport to default behavior.
 */
function resetMockTransport() {
  mockTransport = null;
}

/**
 * Simple line-oriented SMTP client using Node.js native net/tls.
 * Avoids third-party dependencies while providing RFC 5321 compliance with STARTTLS and AUTH.
 *
 * @param {object} config
 * @param {object} message - { from, to, subject, text, html }
 * @returns {Promise<{ messageId: string }>}
 */
function sendViaSmtp(config, message) {
  return new Promise((resolve, reject) => {
    const {
      host,
      port = 587,
      secure = false,
      user,
      pass,
      timeoutMs = 15000
    } = config;

    let socket = null;
    let timer = null;
    let buffer = '';
    let currentResolver = null;
    let currentRejecter = null;

    const cleanup = () => {
      if (timer) clearTimeout(timer);
      if (socket) {
        socket.removeAllListeners();
        try {
          socket.end();
          socket.destroy();
        } catch (_) {}
        socket = null;
      }
    };

    const fail = (err) => {
      cleanup();
      if (currentRejecter) {
        currentRejecter(err);
      } else {
        reject(err);
      }
    };

    const resetTimeout = () => {
      if (timer) clearTimeout(timer);
      timer = setTimeout(() => {
        fail(new Error(`SMTP connection timed out after ${timeoutMs}ms`));
      }, timeoutMs);
    };

    const readResponse = () => {
      return new Promise((res, rej) => {
        currentResolver = res;
        currentRejecter = rej;
        checkBuffer();
      });
    };

    const checkBuffer = () => {
      if (!currentResolver) return;
      const lines = buffer.split('\r\n');
      if (lines.length < 2) return; // Haven't seen a full line yet

      // Multiline responses in SMTP have '-' after code (e.g. '250-SIZE')
      // Final line has space after code (e.g. '250 OK')
      for (let i = 0; i < lines.length - 1; i++) {
        const line = lines[i];
        const match = line.match(/^(\d{3})( |$)/);
        if (match) {
          const code = parseInt(match[1], 10);
          const fullResponse = lines.slice(0, i + 1).join('\r\n');
          buffer = lines.slice(i + 1).join('\r\n');
          const resolver = currentResolver;
          currentResolver = null;
          currentRejecter = null;
          resolver({ code, text: fullResponse });
          return;
        }
      }
    };

    const attachSocketListeners = (sock) => {
      sock.on('data', (chunk) => {
        resetTimeout();
        buffer += chunk.toString('utf8');
        checkBuffer();
      });

      sock.on('error', (err) => {
        fail(err);
      });

      sock.on('close', () => {
        if (currentRejecter) {
          fail(new Error('SMTP socket closed prematurely by remote server'));
        }
      });
    };

    const sendCmd = async (cmd, expectedCodes = [250]) => {
      resetTimeout();
      socket.write(cmd + '\r\n');
      const resp = await readResponse();
      if (!expectedCodes.includes(resp.code)) {
        throw new Error(`SMTP command "${cmd.split(' ')[0]}" failed with code ${resp.code}: ${resp.text}`);
      }
      return resp;
    };

    (async () => {
      try {
        resetTimeout();

        if (secure) {
          socket = tls.connect({ host, port, minVersion: 'TLSv1.2' });
        } else {
          socket = net.createConnection({ host, port });
        }
        attachSocketListeners(socket);

        // 1. Initial 220 banner
        const banner = await readResponse();
        if (banner.code !== 220) {
          throw new Error(`Invalid SMTP banner: ${banner.code} ${banner.text}`);
        }

        // 2. EHLO
        let ehloResp = await sendCmd('EHLO localhost', [250]);

        // 3. Optional STARTTLS upgrade
        if (!secure && ehloResp.text.includes('STARTTLS')) {
          await sendCmd('STARTTLS', [220]);
          socket.removeAllListeners('data');
          socket.removeAllListeners('error');
          socket.removeAllListeners('close');

          const upgradedSocket = tls.connect({
            socket,
            host,
            minVersion: 'TLSv1.2'
          });

          socket = upgradedSocket;
          attachSocketListeners(socket);

          // Re-EHLO after TLS upgrade
          ehloResp = await sendCmd('EHLO localhost', [250]);
        }

        // 4. Authentication if credentials provided
        if (user && pass) {
          await sendCmd('AUTH LOGIN', [334]);
          await sendCmd(Buffer.from(String(user)).toString('base64'), [334]);
          await sendCmd(Buffer.from(String(pass)).toString('base64'), [235]);
        }

        // 5. Envelope sender & recipient
        const fromAddress = message.from.includes('<')
          ? message.from.replace(/.*<([^>]+)>.*/, '$1').trim()
          : message.from.trim();
        const toAddress = message.to.includes('<')
          ? message.to.replace(/.*<([^>]+)>.*/, '$1').trim()
          : message.to.trim();

        await sendCmd(`MAIL FROM:<${fromAddress}>`, [250]);
        await sendCmd(`RCPT TO:<${toAddress}>`, [250]);

        // 6. Message Data
        await sendCmd('DATA', [354]);

        const messageId = `<${crypto.randomUUID()}@actionguard.local>`;
        const dateHeader = new Date().toUTCString();

        let payload = '';
        payload += `From: ${message.from}\r\n`;
        payload += `To: ${message.to}\r\n`;
        payload += `Subject: ${message.subject}\r\n`;
        payload += `Date: ${dateHeader}\r\n`;
        payload += `Message-ID: ${messageId}\r\n`;
        payload += `MIME-Version: 1.0\r\n`;

        if (message.html) {
          const boundary = `----=_Part_${crypto.randomUUID()}`;
          payload += `Content-Type: multipart/alternative; boundary="${boundary}"\r\n\r\n`;
          payload += `--${boundary}\r\n`;
          payload += `Content-Type: text/plain; charset=utf-8\r\n\r\n`;
          payload += `${message.text || ''}\r\n\r\n`;
          payload += `--${boundary}\r\n`;
          payload += `Content-Type: text/html; charset=utf-8\r\n\r\n`;
          payload += `${message.html}\r\n\r\n`;
          payload += `--${boundary}--\r\n`;
        } else {
          payload += `Content-Type: text/plain; charset=utf-8\r\n\r\n`;
          payload += `${message.text || ''}\r\n`;
        }

        // Terminate data with <CRLF>.<CRLF>
        payload += '\r\n.';
        await sendCmd(payload, [250]);

        // 7. QUIT
        try {
          await sendCmd('QUIT', [221]);
        } catch (_) {
          // Non-critical if remote drops after QUIT
        }

        cleanup();
        resolve({ messageId, delivered: true });
      } catch (err) {
        fail(err);
      }
    })();
  });
}

/**
 * Sends an email notification.
 *
 * @param {object} options
 * @param {string} options.to - Recipient email
 * @param {string} options.subject - Email subject
 * @param {string} [options.text] - Plain text body
 * @param {string} [options.html] - HTML formatted body
 * @param {string} [options.otp] - Step-up OTP (recorded only in test outbox, NEVER in production logs)
 * @param {number} [options.ttlSeconds] - Expiry duration
 * @returns {Promise<{ messageId: string, delivered: boolean }>}
 */
async function sendMail(options) {
  const { to, subject, text, html, otp, ttlSeconds } = options || {};

  if (!to || typeof to !== 'string' || !to.includes('@')) {
    const err = new Error('Invalid recipient email address');
    err.code = 'INVALID_RECIPIENT_EMAIL';
    throw err;
  }

  if (!subject || typeof subject !== 'string') {
    const err = new Error('Email subject is required');
    err.code = 'INVALID_SUBJECT';
    throw err;
  }

  // 1. Check for custom mock transport override (testing hook)
  if (typeof mockTransport === 'function') {
    return await mockTransport({ to, subject, text, html, otp, ttlSeconds });
  }

  // 2. Test mode / Safe Local Development Outbox
  const isTest = process.env.NODE_ENV === 'test';
  const isProd = process.env.NODE_ENV === 'production';
  const isTestTransport = !isProd && (process.env.MAIL_TRANSPORT === 'test' || process.env.MAIL_TRANSPORT === 'outbox');

  if (isTest || isTestTransport) {
    const messageId = `test_${crypto.randomUUID()}`;
    testMailOutbox.push({
      messageId,
      to,
      subject,
      text,
      html,
      otp,
      ttlSeconds,
      sentAt: new Date().toISOString()
    });
    return { messageId, delivered: true };
  }

  // 3. Demo mode fallback when SMTP is unconfigured in development
  const isDemo = process.env.ACTIONGUARD_DEMO_MODE === 'true';
  const smtpHost = process.env.SMTP_HOST;

  if (!smtpHost || String(smtpHost).trim() === '') {
    if (isProd) {
      const err = new Error('SMTP transport is not configured in production environment (SMTP_HOST missing)');
      err.code = 'SMTP_NOT_CONFIGURED';
      throw err;
    }
    if (isDemo || process.env.NODE_ENV === 'development') {
      const messageId = `dev_${crypto.randomUUID()}`;
      testMailOutbox.push({
        messageId,
        to,
        subject,
        text,
        html,
        otp,
        ttlSeconds,
        sentAt: new Date().toISOString()
      });
      return { messageId, delivered: true };
    }
    const err = new Error('SMTP transport is not configured');
    err.code = 'SMTP_NOT_CONFIGURED';
    throw err;
  }

  // 4. Real SMTP transport delivery
  const config = {
    host: smtpHost.trim(),
    port: parseInt(process.env.SMTP_PORT || '587', 10),
    secure: process.env.SMTP_SECURE === 'true',
    user: process.env.SMTP_USER || null,
    pass: process.env.SMTP_PASS || null
  };

  const mailFrom = process.env.MAIL_FROM || 'ActionGuard Security <security@actionguard.local>';

  return await sendViaSmtp(config, {
    from: mailFrom,
    to: to.trim(),
    subject,
    text,
    html
  });
}

/**
 * Sends a step-up identity re-verification challenge code.
 *
 * @param {string} toEmail - User registration email
 * @param {string} otp - 6-digit one-time verification code
 * @param {number} ttlSeconds - Expiration duration in seconds
 * @returns {Promise<{ messageId: string, delivered: boolean }>}
 */
async function sendStepUpCode(toEmail, otp, ttlSeconds = 300) {
  if (!otp || typeof otp !== 'string' || !/^\d{6}$/.test(otp)) {
    const err = new Error('Invalid OTP code format: expected 6 digits');
    err.code = 'INVALID_OTP_FORMAT';
    throw err;
  }

  const minutes = Math.max(1, Math.round(ttlSeconds / 60));
  const subject = 'ActionGuard — Identity Re-verification Code';

  const text = [
    'Your ActionGuard step-up verification code is: ' + otp,
    '',
    `This code will expire in ${minutes} minutes (${ttlSeconds} seconds).`,
    '',
    'If you did not initiate this action or login, your account may be compromised. Please sign in and review your active sessions immediately.',
    '',
    '--',
    'ActionGuard Continuous Security'
  ].join('\n');

  const html = `
    <!DOCTYPE html>
    <html>
      <head>
        <meta charset="utf-8" />
        <title>ActionGuard Verification Code</title>
      </head>
      <body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background-color: #f9fafb; margin: 0; padding: 32px;">
        <div style="max-width: 520px; margin: 0 auto; background: #ffffff; border: 1px solid #e5e7eb; border-radius: 8px; padding: 32px;">
          <h2 style="color: #111827; margin-top: 0; font-size: 20px;">Identity Re-verification</h2>
          <p style="color: #4b5563; font-size: 14px; line-height: 1.5;">
            ActionGuard detected a sensitive action requiring temporary privilege elevation. Use the verification code below to authorize your request:
          </p>
          <div style="background-color: #f3f4f6; border-radius: 6px; padding: 16px; text-align: center; margin: 24px 0;">
            <span style="font-size: 32px; font-weight: 700; letter-spacing: 6px; color: #1e40af; font-family: monospace;">${otp}</span>
          </div>
          <p style="color: #6b7280; font-size: 13px; margin: 0 0 16px 0;">
            This code expires in <strong>${minutes} minutes</strong> (${ttlSeconds} seconds) and can only be used once.
          </p>
          <div style="border-top: 1px solid #e5e7eb; padding-top: 16px; margin-top: 24px;">
            <p style="color: #9ca3af; font-size: 12px; margin: 0;">
              If you did not request this verification, someone may have access to your credentials. Terminate your active sessions immediately from the ActionGuard Security Portal.
            </p>
          </div>
        </div>
      </body>
    </html>
  `.trim();

  return await sendMail({
    to: toEmail,
    subject,
    text,
    html,
    otp,
    ttlSeconds
  });
}

module.exports = {
  sendMail,
  sendStepUpCode,
  sendViaSmtp,
  getTestMailOutbox,
  clearTestMailOutbox,
  setMockTransport,
  resetMockTransport
};
