'use strict';

const mailService = require('../src/services/mailService');
const stepUpService = require('../src/services/stepUpService');

describe('Mail Service Unit Tests (Module 10d / Security Fix)', () => {
  beforeEach(() => {
    mailService.clearTestMailOutbox();
    mailService.resetMockTransport();
  });

  afterEach(() => {
    mailService.clearTestMailOutbox();
    mailService.resetMockTransport();
  });

  test('T-MAIL-01: Input validation rejects invalid recipient email and missing subject', async () => {
    await expect(mailService.sendMail({ to: 'invalid-email', subject: 'Test' })).rejects.toThrow(
      'Invalid recipient email address'
    );
    await expect(mailService.sendMail({ to: 'user@example.com', subject: '' })).rejects.toThrow(
      'Email subject is required'
    );
  });

  test('T-MAIL-02: Input validation rejects malformed or non-6-digit OTP codes for sendStepUpCode', async () => {
    await expect(mailService.sendStepUpCode('user@example.com', '12345')).rejects.toThrow(
      'Invalid OTP code format: expected 6 digits'
    );
    await expect(mailService.sendStepUpCode('user@example.com', 'abcdef')).rejects.toThrow(
      'Invalid OTP code format: expected 6 digits'
    );
    await expect(mailService.sendStepUpCode('user@example.com', '1234567')).rejects.toThrow(
      'Invalid OTP code format: expected 6 digits'
    );
  });

  test('T-MAIL-03: Test-mode capture stores sent emails in in-memory test outbox with subject, text, HTML, and OTP', async () => {
    const res = await mailService.sendStepUpCode('alice@example.com', '482910', 300);
    expect(res.delivered).toBe(true);
    expect(res.messageId).toMatch(/^test_/);

    const outbox = mailService.getTestMailOutbox();
    expect(outbox).toHaveLength(1);
    expect(outbox[0].to).toBe('alice@example.com');
    expect(outbox[0].otp).toBe('482910');
    expect(outbox[0].subject).toBe('ActionGuard — Identity Re-verification Code');
    expect(outbox[0].text).toContain('482910');
    expect(outbox[0].html).toContain('482910');
  });

  test('T-MAIL-04: Test-mode outbox clearing flushes stored messages deterministically', async () => {
    await mailService.sendStepUpCode('alice@example.com', '111222', 180);
    expect(mailService.getTestMailOutbox()).toHaveLength(1);

    mailService.clearTestMailOutbox();
    expect(mailService.getTestMailOutbox()).toHaveLength(0);
  });

  test('T-MAIL-05: Production fail-closed behavior throws SMTP_NOT_CONFIGURED when SMTP_HOST is missing in production', async () => {
    const originalEnv = process.env.NODE_ENV;
    const originalHost = process.env.SMTP_HOST;
    try {
      process.env.NODE_ENV = 'production';
      delete process.env.SMTP_HOST;

      await expect(
        mailService.sendMail({
          to: 'bob@example.com',
          subject: 'Security Alert',
          text: 'Notice'
        })
      ).rejects.toThrow('SMTP transport is not configured in production environment');
    } finally {
      process.env.NODE_ENV = originalEnv;
      if (originalHost !== undefined) {
        process.env.SMTP_HOST = originalHost;
      } else {
        delete process.env.SMTP_HOST;
      }
    }
  });

  test('T-MAIL-06: Mock transport override allows overriding delivery function and resetting', async () => {
    const customMock = jest.fn().mockResolvedValue({ messageId: 'custom_123', delivered: true });
    mailService.setMockTransport(customMock);

    const res = await mailService.sendStepUpCode('carol@example.com', '654321', 300);
    expect(customMock).toHaveBeenCalledTimes(1);
    expect(customMock).toHaveBeenCalledWith(
      expect.objectContaining({
        to: 'carol@example.com',
        otp: '654321'
      })
    );
    expect(res.messageId).toBe('custom_123');

    mailService.resetMockTransport();
    const resAfterReset = await mailService.sendStepUpCode('carol@example.com', '654321', 300);
    expect(resAfterReset.messageId).toMatch(/^test_/);
  });

  test('T-MAIL-07: stepUpService imports cleanly and references mailService', () => {
    expect(typeof stepUpService.issueStepUpChallenge).toBe('function');
    expect(typeof stepUpService.verifyStepUpChallenge).toBe('function');
  });
});
