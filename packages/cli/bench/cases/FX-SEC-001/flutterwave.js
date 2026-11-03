const Flutterwave = require('flutterwave-node-v3');
const flw = new Flutterwave(process.env.FLW_PUBLIC_KEY, '{{FLW_LIVE}}'); // @hit
module.exports = flw;
