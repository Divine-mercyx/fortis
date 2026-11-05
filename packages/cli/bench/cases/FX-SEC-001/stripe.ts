import Stripe from 'stripe';

export const stripe = new Stripe('{{STRIPE_LIVE}}'); // @hit
export const reporting = new Stripe('{{STRIPE_RESTRICTED}}'); // @hit
export const webhookSecret = '{{STRIPE_WEBHOOK}}'; // @hit
export const publishable = 'pk_live_51ExamplePublishableKeyThatShipsInTheBrowserAnyway';
export const stripeKey = process.env.STRIPE_SECRET_KEY;
