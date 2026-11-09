import { logger } from './logger';

export function charge(card: { number: string; cvv: string; pan: string }, body: { cardNumber: string; cvv: string; card_expiry: string }) {
  console.log('charging card', body.cardNumber); // @hit
  console.error(`declined: ${card.number}`); // @hit
  logger.info({ cvv: body.cvv }); // @hit
  logger.debug('card', card.pan); // @hit
  logger.warn({ // @hit
    message: 'retry',
    card_number: body.cardNumber,
  });
  console.info('expiry', body.card_expiry); // @hit
  winston.error('failed', { cardCvv: body.cvv }); // @hit
}
