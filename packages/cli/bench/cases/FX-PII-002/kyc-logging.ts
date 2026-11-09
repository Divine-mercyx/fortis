import { logger } from './logger';

export function trace(customer: { bvn: string; nin: string; id: string }, request: { body: { bvn: string; nationalId: string } }) {
  console.info('bvn lookup', customer.bvn); // @hit
  console.error(`NIN check failed: ${customer.nin}`); // @hit
  logger.info({ bvn: request.body.bvn }); // @hit
  logger.debug('kyc payload', request.body.nationalId); // @hit
  logger.warn({ // @hit
    customer: customer.id,
    nin: customer.nin,
  });
  log.info(customer.bvn); // @hit
  winston.error('failed', { bvnNumber: customer.bvn }); // @hit

  // None of these print the value.
  console.log('bvn lookup started');
  logger.info({ hasBvn: Boolean(customer.bvn) });
  logger.info({ bvn: mask(customer.bvn) });
  logger.info('bvn length', customer.bvn.length);
}
