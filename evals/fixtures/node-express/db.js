// Minimal stub so the fixture is self-contained; no real database.
module.exports = {
  query: (_sql, _params, cb) => cb(null, []),
  users: { findOne: (_q, cb) => cb(null, null), create: (_d, cb) => cb(null, _d) },
  orders: { findById: (_id, cb) => cb(null, {}) },
  charges: { create: (_d, cb) => cb(null, _d) },
};
