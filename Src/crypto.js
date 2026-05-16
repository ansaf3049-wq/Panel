import crypto from 'crypto';

const SECRET = process.env.SIGNING_SECRET || 'CHANGE_ME_IN_RAILWAY_ENV_VARS';

export function sign(payload) {
  const body = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const sig = crypto.createHmac('sha256', SECRET).update(body).digest('base64url');
  return `${body}.${sig}`;
}

export function genKey() {
  const raw = crypto.randomBytes(16).toString('hex').toUpperCase();
  return `${raw.slice(0,4)}-${raw.slice(4,8)}-${raw.slice(8,12)}-${raw.slice(12,16)}-${raw.slice(16,20)}`;
}

