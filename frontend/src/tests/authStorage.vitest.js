import { describe, it, expect, beforeEach } from 'vitest';
import {
  getUserToken,
  setUserToken,
  clearUserToken,
  getAdminToken,
  setAdminToken,
  clearAdminToken,
  clearAllAuth
} from '../services/authStorage.js';

describe('Token Storage & Boundary Rules', () => {
  beforeEach(() => {
    sessionStorage.clear();
    localStorage.clear();
    clearAllAuth();
  });

  it('stores user token strictly in sessionStorage and never in localStorage', () => {
    setUserToken('jwt-user-token-example');

    expect(getUserToken()).toBe('jwt-user-token-example');
    expect(sessionStorage.getItem('ag_user_token')).toBe('jwt-user-token-example');

    // Strict Zero Trust: localStorage must NOT contain the token
    expect(localStorage.getItem('ag_user_token')).toBeNull();
    expect(localStorage.length).toBe(0);
  });

  it('clears user token from sessionStorage on clearUserToken', () => {
    setUserToken('jwt-user-token-example');
    clearUserToken();

    expect(getUserToken()).toBeNull();
    expect(sessionStorage.getItem('ag_user_token')).toBeNull();
  });

  it('stores admin token strictly in memory and never in sessionStorage or localStorage', () => {
    setAdminToken('agadm_in_memory_operator_token');

    expect(getAdminToken()).toBe('agadm_in_memory_operator_token');

    // Strict Zero Trust: neither web storage mechanism holds the admin token
    expect(sessionStorage.getItem('agadm_in_memory_operator_token')).toBeNull();
    expect(sessionStorage.getItem('ag_admin_token')).toBeNull();
    expect(localStorage.getItem('ag_admin_token')).toBeNull();
    expect(sessionStorage.length).toBe(0);
    expect(localStorage.length).toBe(0);
  });

  it('clears admin token from memory on clearAdminToken', () => {
    setAdminToken('agadm_in_memory_operator_token');
    clearAdminToken();

    expect(getAdminToken()).toBeNull();
  });

  it('clearAllAuth clears both user sessionStorage token and in-memory admin token', () => {
    setUserToken('jwt-user-token');
    setAdminToken('agadm_token');

    expect(getUserToken()).toBe('jwt-user-token');
    expect(getAdminToken()).toBe('agadm_token');

    clearAllAuth();

    expect(getUserToken()).toBeNull();
    expect(getAdminToken()).toBeNull();
  });
});
