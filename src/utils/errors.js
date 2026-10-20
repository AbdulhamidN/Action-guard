class ApiError extends Error {
  constructor(status, code, message) {
    super(message);
    this.status = status;
    this.code = code;
  }
}

function sendError(res, status, code, message) {
  return res.status(status).json({
    error: {
      code,
      message,
      status
    }
  });
}

module.exports = {
  ApiError,
  sendError
};
