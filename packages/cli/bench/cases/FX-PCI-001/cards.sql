CREATE TABLE cards (
  id BIGINT PRIMARY KEY,
  card_number VARCHAR(19), -- @hit
  cvv CHAR(4), -- @hit
  card_token TEXT,
  last4 CHAR(4)
);
