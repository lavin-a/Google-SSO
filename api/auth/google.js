const axios = require('axios');
const { kv } = require('@vercel/kv');

// ─────────────────────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────────────────────

const allowedOrigins = [
  'https://aware-amount-178968.framer.app',
  'https://almeidaracingacademy.com',
  'https://www.almeidaracingacademy.com',
];

const allowedReturnUrls = [
  'https://aware-amount-178968.framer.app/sign-in',
  'https://almeidaracingacademy.com/sign-in',
  'https://www.almeidaracingacademy.com/sign-in',
];
const DEFAULT_RETURN_URL = allowedReturnUrls[0];

const redirectHostAllowlist = new Set([
  ...allowedReturnUrls.map(getHost),
  'aware-amount-178968.framer.app',
  'almeidaracingacademy.com',
  'www.almeidaracingacademy.com',
].filter(Boolean));

function getHost(url) {
  try {
    return new URL(url).host;
  } catch (err) {
    return null;
  }
}

function sanitizeRedirect(targetUrl, fallbackUrl) {
  if (!targetUrl) return fallbackUrl;
  try {
    const parsed = new URL(targetUrl);
    if (parsed.protocol !== 'https:') {
      return fallbackUrl;
    }
    if (allowedReturnUrls.includes(parsed.toString())) {
      return parsed.toString();
    }
    if (redirectHostAllowlist.has(parsed.host)) {
      return parsed.toString();
    }
  } catch (err) {
    return fallbackUrl;
  }
  return fallbackUrl;
}

// Rate limiting: 10 requests per minute per IP
async function checkRateLimit(ip) {
  const key = `google:ratelimit:${ip}`;
  const count = await kv.incr(key);
  if (count === 1) await kv.expire(key, 60);
  return count <= 10;
}

// ─────────────────────────────────────────────────────────────
// Main handler
// ─────────────────────────────────────────────────────────────

module.exports = async (req, res) => {
  const origin = req.headers.origin;
  if (allowedOrigins.includes(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
  }

  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  res.setHeader('Access-Control-Allow-Credentials', 'true');

  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  // Rate limiting
  const ip = req.headers['x-forwarded-for']?.split(',')[0] || req.connection?.remoteAddress || 'unknown';
  if (!await checkRateLimit(ip)) {
    return res.status(429).json({ error: 'Too many requests. Please try again later.' });
  }

  const { code } = req.query;

  if (!code) {
    return handleStart(req, res);
  }

  return handleCallback(req, res, code);
};

// ─────────────────────────────────────────────────────────────
// OAuth start
// ─────────────────────────────────────────────────────────────

async function handleStart(req, res) {
  if (!process.env.GOOGLE_CLIENT_ID) {
    return res.status(500).send('Google client ID not configured');
  }

  const requestedReturnUrl = req.query.return_url;

  const returnUrl = sanitizeRedirect(requestedReturnUrl, DEFAULT_RETURN_URL);

  const redirectUri = `${getBaseUrl(req)}/api/auth/google`;

  // Store return URL in Vercel KV with 10 minute expiration
  const state = require('crypto').randomBytes(16).toString('hex');
  await kv.set(`google:state:${state}`, { returnUrl, createdAt: Date.now() }, { ex: 600 });

  const googleAuthUrl =
    'https://accounts.google.com/o/oauth2/v2/auth' +
    `?client_id=${encodeURIComponent(process.env.GOOGLE_CLIENT_ID)}` +
    `&redirect_uri=${encodeURIComponent(redirectUri)}` +
    `&response_type=code` +
    `&scope=${encodeURIComponent('openid email profile')}` +
    `&state=${encodeURIComponent(state)}`;

  res.writeHead(302, { Location: googleAuthUrl });
  res.end();
}

// ─────────────────────────────────────────────────────────────
// OAuth callback
// ─────────────────────────────────────────────────────────────

async function handleCallback(req, res, code) {
  if (req.query.error) {
    console.error('Google OAuth error:', req.query.error);
    return res.send(renderErrorPage('Google authentication failed.'));
  }

  try {
    const state = req.query.state;
    const stateData = await kv.get(`google:state:${state}`);
    const returnUrl = stateData?.returnUrl;

    if (!returnUrl) {
      console.error('State not found for Google OAuth');
      return res.send(renderErrorPage('Session expired. Please try again.'));
    }

    await kv.del(`google:state:${state}`);

    const redirectUri = `${getBaseUrl(req)}/api/auth/google`;

    const tokenResponse = await axios.post(
      'https://oauth2.googleapis.com/token',
      new URLSearchParams({
        code,
        client_id: process.env.GOOGLE_CLIENT_ID,
        client_secret: process.env.GOOGLE_CLIENT_SECRET,
        redirect_uri: redirectUri,
        grant_type: 'authorization_code',
      }),
      {
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        timeout: 8000,
      }
    );

    const accessToken = tokenResponse.data.access_token;

    const userResponse = await axios.get('https://www.googleapis.com/oauth2/v2/userinfo', {
      headers: { Authorization: `Bearer ${accessToken}` },
      timeout: 8000,
    });

    const googleUser = userResponse.data;

    const outsetaPerson = await findOrCreateOutsetaUser(googleUser);

    const outsetaToken = await generateOutsetaToken(outsetaPerson.Email);

    return res.send(renderSuccessPage(outsetaToken, returnUrl));
  } catch (err) {
    dumpError('[GoogleSSO]', err);
    return res.send(renderErrorPage('Unable to complete sign in.'));
  }
}

// ─────────────────────────────────────────────────────────────
// Outseta helpers
// ─────────────────────────────────────────────────────────────

async function findOrCreateOutsetaUser(googleUser) {
  const apiBase = `https://${process.env.OUTSETA_DOMAIN}/api/v1`;
  const authHeader = { Authorization: `Outseta ${process.env.OUTSETA_API_KEY}:${process.env.OUTSETA_SECRET_KEY}` };

  // Try to find existing person
  try {
    const search = await axios.get(`${apiBase}/crm/people`, {
      headers: authHeader,
      params: { Email: googleUser.email },
      timeout: 8000,
    });

    if (search.data.items && search.data.items.length > 0) {
      return search.data.items[0];
    }
  } catch (err) {
    console.warn('Outseta search failed, will try to create:', err.message);
  }

  const firstName = googleUser.given_name || 'Google';
  const lastName = googleUser.family_name || 'User';

  // Use /crm/registrations endpoint with free subscription
  // This is the same endpoint Outseta's signup form uses
  const createPayload = {
    Name: `${firstName} ${lastName}`,
    PersonAccount: [
      {
        IsPrimary: true,
        Person: {
          Email: googleUser.email,
          FirstName: firstName,
          LastName: lastName,
        },
      },
    ],
    Subscriptions: [
      {
        Plan: {
          Uid: process.env.OUTSETA_FREE_PLAN_UID,
        },
        BillingRenewalTerm: 1, // 1=Monthly (free plan doesn't support OneTime)
      },
    ],
  };

  const createResponse = await axios.post(
    `${apiBase}/crm/registrations`,
    createPayload,
    {
      headers: {
        ...authHeader,
        'Content-Type': 'application/json',
      },
      timeout: 8000,
    }
  );

  return createResponse.data.PrimaryContact;
}

async function generateOutsetaToken(email) {
  const apiBase = `https://${process.env.OUTSETA_DOMAIN}/api/v1`;
  const authHeader = { Authorization: `Outseta ${process.env.OUTSETA_API_KEY}:${process.env.OUTSETA_SECRET_KEY}` };

  const tokenResponse = await axios.post(
    `${apiBase}/tokens`,
    { username: email },
    {
      headers: {
        ...authHeader,
        'Content-Type': 'application/json',
      },
      timeout: 8000,
    }
  );

  return tokenResponse.data.access_token || tokenResponse.data;
}

// ─────────────────────────────────────────────────────────────
// UI helpers
// ─────────────────────────────────────────────────────────────

function renderSuccessPage(token, returnUrl) {
  return `<!DOCTYPE html>
<html>
  <head>
    <meta charset="utf-8" />
    <title>Signing in...</title>
  </head>
  <body>
    <script>
      (function() {
        const token = ${JSON.stringify(token)};
        const returnUrl = ${JSON.stringify(returnUrl)};
        
        const url = new URL(returnUrl);
        url.hash = 'google_token=' + token;
        window.location.href = url.toString();
      })();
    </script>
  </body>
</html>`;
}

function renderErrorPage(message) {
  return `<!DOCTYPE html>
<html>
  <head>
    <meta charset="utf-8" />
    <title>Authentication error</title>
    <style>
      body { margin: 0; font-family: sans-serif; display: flex; align-items: center; justify-content: center; height: 100vh; }
      p { color: #555; }
    </style>
  </head>
  <body>
    <div style="text-align:center;">
      <h1>Sign in failed</h1>
      <p>${message}</p>
    </div>
  </body>
</html>`;
}

function getBaseUrl(req) {
  const protocol = req.headers['x-forwarded-proto'] || 'https';
  const host = req.headers['x-forwarded-host'] || req.headers.host;
  return `${protocol}://${host}`;
}

function dumpError(tag, error) {
  const payload = {
    tag,
    message: error?.message,
    stack: error?.stack,
    response: error?.response
      ? {
          status: error.response.status,
          statusText: error.response.statusText,
          data: toJsonSafe(error.response.data),
          headers: error.response.headers,
        }
      : null,
    request: error?.config
      ? {
          method: error.config.method,
          url: error.config.url,
          data: toJsonSafe(error.config.data),
          headers: error.config.headers,
        }
      : null,
  };

  try {
    console.error(`${tag} error`, JSON.stringify(payload, null, 2));
  } catch (serializationError) {
    console.error(`${tag} error (serialization failed)`, payload);
  }
}

function toJsonSafe(value) {
  if (value == null) return null;
  if (typeof value === 'string') return value;
  try {
    return JSON.parse(JSON.stringify(value));
  } catch (err) {
    return String(value);
  }
}