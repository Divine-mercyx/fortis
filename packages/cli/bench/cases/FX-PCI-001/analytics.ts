export function track(body: { cardNumber: string; cvv: string }) {
  analytics.track('card_added', { cardNumber: body.cardNumber }); // @hit
  mixpanel.track('checkout', { cvv: body.cvv }); // @hit
  Sentry.setExtra('card', body.cardNumber); // @hit
  posthog.capture('card', { card_number: body.cardNumber }); // @hit
  analytics.track('card_added', { brand: 'visa' });
  mixpanel.track('checkout');
}
