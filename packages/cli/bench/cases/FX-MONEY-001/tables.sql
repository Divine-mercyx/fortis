CREATE TABLE ledger (
  id BIGINT PRIMARY KEY,
  amount DOUBLE PRECISION, -- @hit
  balance FLOAT, -- @hit
  fee REAL, -- @hit
  latitude DOUBLE PRECISION,
  total NUMERIC(14, 2),
  price BIGINT
);
