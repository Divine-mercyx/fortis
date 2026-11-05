export const sendgrid = '{{SENDGRID}}'; // @hit
export const mailgun = '{{MAILGUN}}'; // @hit
export const resend = '{{RESEND}}'; // @hit
export const slackHook = '{{SLACK_HOOK}}'; // @hit
export const discordHook = '{{DISCORD_HOOK}}'; // @hit
export const telegram = '{{TELEGRAM}}'; // @hit
export const openai = '{{OPENAI}}'; // @hit
export const anthropic = '{{ANTHROPIC}}'; // @hit
export const azure = '{{AZURE_STORAGE}}'; // @hit
export const doToken = '{{DIGITALOCEAN}}'; // @hit
export const npmToken = '{{NPM}}'; // @hit
export const pypi = '{{PYPI}}'; // @hit
export const gems = '{{RUBYGEMS}}'; // @hit
export const docker = '{{DOCKER}}'; // @hit
export const TWILIO_AUTH_TOKEN = '{{TWILIO_TOKEN}}'; // @hit
export const supabaseAdmin = '{{SUPABASE_SERVICE}}'; // @hit

// Not secrets
export const supabaseAnon = '{{SUPABASE_ANON}}';
export const twilioFromEnv = process.env.TWILIO_AUTH_TOKEN;
export const twilioSid = 'AC' + 'x'.repeat(32);
export const slackDocs = 'https://hooks.slack.com/services/YOUR/WEBHOOK/URL';
