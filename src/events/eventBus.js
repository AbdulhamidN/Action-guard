const { EventEmitter } = require('events');

/**
 * ActionGuard decoupled in-memory EventBus singleton.
 * Wraps Node's EventEmitter with fail-safe emission and error-isolated listeners.
 */
class ActionGuardEventBus {
  constructor() {
    this._emitter = new EventEmitter();
    this._emitter.setMaxListeners(50);
  }

  /**
   * Registers an event listener wrapped in a safe try/catch block.
   * Prevents any listener error from bubbling up or blocking subsequent listeners.
   *
   * @param {string} eventName
   * @param {Function} listener
   * @returns {ActionGuardEventBus}
   */
  on(eventName, listener) {
    if (typeof listener !== 'function') {
      throw new TypeError('Listener must be a function');
    }

    const safeListener = (...args) => {
      try {
        const result = listener(...args);
        if (result && typeof result.catch === 'function') {
          result.catch((err) => {
            console.warn(`[EventBus] Async listener error on event "${eventName}":`, err.message);
          });
        }
      } catch (err) {
        console.warn(`[EventBus] Synchronous listener error on event "${eventName}":`, err.message);
      }
    };

    safeListener.__originalListener = listener;
    this._emitter.on(eventName, safeListener);
    return this;
  }

  /**
   * Safely emits an event with payload. Never throws into the caller.
   *
   * @param {string} eventName
   * @param {*} data
   * @returns {boolean}
   */
  safeEmit(eventName, data) {
    try {
      return this._emitter.emit(eventName, data);
    } catch (err) {
      console.warn(`[EventBus] Error while emitting event "${eventName}":`, err.message);
      return false;
    }
  }

  /**
   * Removes all listeners for all events or for a specific event.
   * Used for clean teardown and test isolation.
   *
   * @param {string} [eventName]
   * @returns {ActionGuardEventBus}
   */
  removeAllListeners(eventName) {
    if (eventName) {
      this._emitter.removeAllListeners(eventName);
    } else {
      this._emitter.removeAllListeners();
    }
    return this;
  }

  /**
   * Returns listener count for an event.
   *
   * @param {string} eventName
   * @returns {number}
   */
  listenerCount(eventName) {
    return this._emitter.listenerCount(eventName);
  }
}

const eventBus = new ActionGuardEventBus();

module.exports = eventBus;
