import { logger } from './logger';

export function trace(card: { number: string; cvv: string; last4: string }) {
  console.log('charging card');
  logger.info({ last4: card.last4 });
  logger.info({ cardNumber: mask(card.number) });
  logger.info({ hasCvv: Boolean(card.cvv) });
  logger.info('length', card.number.length);
  console.log('card number is required');
  logger.info({ tokenisedCard: tokenize(card.number) });
  logger.debug({ bin: card.number.slice(0, 6), last4: card.number.slice(-4) });
}
