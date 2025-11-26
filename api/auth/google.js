const axios = require('axios');
const { kv } = require('@vercel/kv');

// ─────────────────────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────────────────────

const allowedOrigins = [
  'https://almeidaracingacademy.com',
  'https://aware-amount-178968.framer.app',
];

const allowedReturnUrls = [
  'https://almeidaracingacademy.com/success',
  'https://aware-amount-178968.framer.app/success',
];
const DEFAULT_RETURN_URL = allowedReturnUrls[0];

const ACCOUNT_CONFLICT_MESSAGE = "This email is already registered. Please sign in using a known method, then link this provider from your account settings.";

const redirectHostAllowlist = new Set([
  ...allowedReturnUrls.map(getHost),
  'almeidaracingacademy.com',
  'aware-amount-178968.framer.app',
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
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  res.setHeader('Access-Control-Allow-Credentials', 'true');

  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  // Rate limiting
  const ip = req.headers['x-forwarded-for']?.split(',')[0] || req.connection?.remoteAddress || 'unknown';
  if (!await checkRateLimit(ip)) {
    return res.status(429).json({ error: 'Too many requests. Please try again later.' });
  }

  const { code, action } = req.query;

  if (req.method === 'POST') {
    if (action === 'disconnect') {
      return handleDisconnect(req, res);
    }
    if (action === 'send-password-reset') {
      return handleSendPasswordReset(req, res);
    }
  }

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

  const intent = (req.query.intent || 'login').toLowerCase();
  if (!['login', 'link'].includes(intent)) {
    return res.status(400).send('Invalid intent');
  }

  const requestedReturnUrl = req.query.return_url;
  const returnUrl = sanitizeRedirect(requestedReturnUrl, DEFAULT_RETURN_URL);

  let linkPersonUid = null;
  if (intent === 'link') {
    const linkToken = req.query.link_token;
    const requestedLinkUid = req.query.link_person_uid;

    if (!linkToken || !requestedLinkUid) {
      return res.status(400).send('Missing linking parameters');
    }

    try {
      const profile = await verifyOutsetaAccessToken(linkToken);
      if (profile?.Uid !== requestedLinkUid) {
        return res.status(403).send('Invalid linking session');
      }
    } catch (err) {
      console.error('Outseta token verification failed', err.message);
      return res.status(403).send('Invalid linking session');
    }

    linkPersonUid = requestedLinkUid;
  }

  const redirectUri = `${getBaseUrl(req)}/api/auth/google`;

  // Store return URL in Vercel KV with 10 minute expiration
  const state = require('crypto').randomBytes(16).toString('hex');
  await kv.set(
    `google:state:${state}`,
    { returnUrl, intent, linkPersonUid, createdAt: Date.now() },
    { ex: 600 }
  );

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
    const intent = stateData?.intent || 'login';
    const linkPersonUid = stateData?.linkPersonUid || null;

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
    const googleId = googleUser.id;
    const normalizedEmail = googleUser.email ? googleUser.email.toLowerCase() : null;
    const googleEmail = googleUser.email || normalizedEmail;

    console.log('[GoogleSSO] callback params', {
      intent,
      googleId,
      emailPresent: Boolean(normalizedEmail),
    });

    const existingByGoogleId = await findPersonByField('GoogleId', googleId);

    if (existingByGoogleId) {
      console.log('[GoogleSSO] matched by GoogleId', {
        personUid: existingByGoogleId.Uid,
        intent,
      });
      if (intent === 'link') {
        if (!linkPersonUid || existingByGoogleId.Uid !== linkPersonUid) {
          return res.send(renderRedirectWithError(returnUrl, 'account_exists', ACCOUNT_CONFLICT_MESSAGE, 'google'));
        }

        if (googleEmail && existingByGoogleId.GoogleEmail !== googleEmail) {
          await updatePerson(existingByGoogleId.Uid, {
            Uid: existingByGoogleId.Uid,
            Email: existingByGoogleId.Email,
            FirstName: existingByGoogleId.FirstName,
            LastName: existingByGoogleId.LastName,
            GoogleId: googleId,
            GoogleEmail: googleEmail,
          });
        }

        return res.send(renderLinkSuccessPage(returnUrl, 'google'));
      }

      if (googleEmail && existingByGoogleId.GoogleEmail !== googleEmail) {
        await updatePerson(existingByGoogleId.Uid, {
          Uid: existingByGoogleId.Uid,
          Email: existingByGoogleId.Email,
          FirstName: existingByGoogleId.FirstName,
          LastName: existingByGoogleId.LastName,
          GoogleId: googleId,
          GoogleEmail: googleEmail,
        });
      }

      const outsetaToken = await generateOutsetaToken(existingByGoogleId.Email);
      return res.send(renderSuccessPage(outsetaToken, returnUrl));
    }

    if (intent === 'link') {
      if (!linkPersonUid) {
        console.log('[GoogleSSO] link intent missing UID');
        return res.send(renderErrorPage('Linking session expired.'));
      }

      const person = await getPersonByUid(linkPersonUid);
      if (!person) {
        return res.send(renderErrorPage('Unable to locate your account.'));
      }

      console.log('[GoogleSSO] updating link person with GoogleId', {
        linkPersonUid,
      });
      const updatePayload = {
        Uid: linkPersonUid,
        Email: person.Email,
        FirstName: person.FirstName,
        LastName: person.LastName,
        GoogleId: googleId,
      };

      if (googleEmail) {
        updatePayload.GoogleEmail = googleEmail;
      }

      await updatePerson(linkPersonUid, updatePayload);

      return res.send(renderLinkSuccessPage(returnUrl, 'google'));
    }

    if (normalizedEmail) {
      const existingByEmail = await findPersonByEmail(normalizedEmail);
      if (existingByEmail) {
        const storedGoogleId = existingByEmail.GoogleId
          ? String(existingByEmail.GoogleId).replace(/,/g, '')
          : null;
        const hasAccount = personHasAccount(existingByEmail);
        if (!hasAccount && intent === 'login') {
          const ensured = await ensurePersonHasAccount(existingByEmail.Email, existingByEmail);
          if (ensured) {
            await updatePerson(existingByEmail.Uid, {
              Uid: existingByEmail.Uid,
              Email: existingByEmail.Email,
              FirstName: existingByEmail.FirstName,
              LastName: existingByEmail.LastName,
              GoogleId: googleId,
              GoogleEmail: googleEmail || normalizedEmail,
            });
            const outsetaToken = await generateOutsetaToken(existingByEmail.Email);
            return res.send(renderSuccessPage(outsetaToken, returnUrl));
          }
        }

        console.log('[GoogleSSO] matched by email', {
          personUid: existingByEmail.Uid,
          storedGoogleId,
          intent,
        });
        if (intent === 'login' && storedGoogleId && storedGoogleId === googleId) {
          if (googleEmail && existingByEmail.GoogleEmail !== googleEmail) {
            await updatePerson(existingByEmail.Uid, {
              Uid: existingByEmail.Uid,
              Email: existingByEmail.Email,
              FirstName: existingByEmail.FirstName,
              LastName: existingByEmail.LastName,
              GoogleId: googleId,
              GoogleEmail: googleEmail,
            });
          }
          const outsetaToken = await generateOutsetaToken(existingByEmail.Email);
          return res.send(renderSuccessPage(outsetaToken, returnUrl));
        }

        console.log('[GoogleSSO] email conflict', {
          reason: 'googleId mismatch or linking attempt',
        });
        return res.send(renderRedirectWithError(returnUrl, 'account_exists', ACCOUNT_CONFLICT_MESSAGE, 'google'));
      } else {
        console.log('[GoogleSSO] no user by email');
      }
    }

    console.log('[GoogleSSO] creating new user for Google login');
    const createdPerson = await createGoogleOutsetaUser(googleUser);
    const outsetaToken = await generateOutsetaToken(createdPerson.Email);

    return res.send(renderSuccessPage(outsetaToken, returnUrl));
  } catch (err) {
    dumpError('[GoogleSSO]', err);
    return res.send(renderErrorPage('Unable to complete sign in.'));
  }
}

async function handleDisconnect(req, res) {
  try {
    const authHeader = req.headers.authorization || req.headers.Authorization;
    if (!authHeader || !authHeader.toLowerCase().startsWith('bearer ')) {
      return res.status(401).json({ error: 'Missing authorization bearer token.' });
    }

    const accessToken = authHeader.slice(7).trim();
    if (!accessToken) {
      return res.status(401).json({ error: 'Missing authorization bearer token.' });
    }

    const profile = await verifyOutsetaAccessToken(accessToken);
    if (!profile?.Uid) {
      return res.status(403).json({ error: 'Unable to validate session.' });
    }

    const person = await getPersonByUid(profile.Uid);
    if (!person) {
      return res.status(404).json({ error: 'Account not found.' });
    }

    if (!hasPassword(person)) {
      return res.status(412).json({
        error: 'Add a password to your account before disconnecting Google.',
      });
    }

    const alreadyDisconnected = !person.GoogleId && !person.GoogleEmail;

    if (!alreadyDisconnected) {
      await updatePerson(person.Uid, {
        Uid: person.Uid,
        Email: person.Email,
        FirstName: person.FirstName,
        LastName: person.LastName,
        GoogleId: '',
        GoogleEmail: '',
      });
    }

    return res.status(200).json({
      success: true,
      provider: 'google',
      disconnected: !alreadyDisconnected,
    });
  } catch (err) {
    dumpError('[GoogleSSO][disconnect]', err);
    return res.status(500).json({ error: 'Unable to disconnect Google at this time.' });
  }
}

async function handleSendPasswordReset(req, res) {
  try {
    const authHeader = req.headers.authorization || req.headers.Authorization;
    if (!authHeader || !authHeader.toLowerCase().startsWith('bearer ')) {
      return res.status(401).json({ error: 'Missing authorization bearer token.' });
    }

    const accessToken = authHeader.slice(7).trim();
    if (!accessToken) {
      return res.status(401).json({ error: 'Missing authorization bearer token.' });
    }

    const profile = await verifyOutsetaAccessToken(accessToken);
    if (!profile?.Uid) {
      return res.status(403).json({ error: 'Unable to validate session.' });
    }

    const person = await getPersonByUid(profile.Uid);
    if (!person?.Email) {
      return res.status(400).json({ error: 'No email found for this account.' });
    }

    await sendPasswordResetEmail(person.Email);

    return res.status(200).json({ success: true });
  } catch (err) {
    dumpError('[GoogleSSO][password-reset]', err);
    return res.status(500).json({ error: 'Unable to send password email. Please try again later.' });
  }
}

// ─────────────────────────────────────────────────────────────
// Outseta helpers
// ─────────────────────────────────────────────────────────────

async function createGoogleOutsetaUser(googleUser) {
  const firstName = googleUser.given_name || 'Google';
  const lastName = googleUser.family_name || 'User';

  const registration = await createRegistration({
    Name: `${firstName} ${lastName}`,
    PersonAccount: [
      {
        IsPrimary: true,
        Person: {
          Email: googleUser.email,
          FirstName: firstName,
          LastName: lastName,
          GoogleId: googleUser.id,
          GoogleEmail: googleUser.email,
        },
      },
    ],
    Subscriptions: [
      {
        Plan: {
          Uid: process.env.OUTSETA_FREE_PLAN_UID,
        },
        BillingRenewalTerm: 1,
      },
    ],
  });

  return registration.PrimaryContact;
}

async function generateOutsetaToken(email) {
  const apiBase = `https://${process.env.OUTSETA_DOMAIN}/api/v1`;
  const authHeader = { Authorization: `Outseta ${process.env.OUTSETA_API_KEY}:${process.env.OUTSETA_SECRET_KEY}` };

  try {
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
  } catch (error) {
    if (isInvalidGrantError(error)) {
      const accountCreated = await ensurePersonHasAccount(email);
      if (accountCreated) {
        return generateOutsetaToken(email);
      }
    }
    throw error;
  }
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

function renderRedirectWithError(returnUrl, code, message, provider) {
  const url = new URL(returnUrl);
  const params = new URLSearchParams(url.hash?.replace(/^#/, '') || '');
  params.set('error', code);
  if (message) {
    params.set('message', message);
  }
  if (provider) {
    params.set('provider', provider);
  }
  url.hash = params.toString();

  return `<!DOCTYPE html>
<html>
  <head>
    <meta charset="utf-8" />
    <title>Redirecting...</title>
  </head>
  <body>
    <script>
      window.location.href = ${JSON.stringify(url.toString())};
    </script>
  </body>
</html>`;
}

function renderLinkSuccessPage(returnUrl, provider) {
  const url = new URL(returnUrl);
  const params = new URLSearchParams(url.hash?.replace(/^#/, '') || '');
  params.set('link', 'success');
  params.set('provider', provider);
  url.hash = params.toString();

  return `<!DOCTYPE html>
<html>
  <head>
    <meta charset="utf-8" />
    <title>Link Successful</title>
  </head>
  <body>
    <script>
      window.location.href = ${JSON.stringify(url.toString())};
    </script>
  </body>
</html>`;
}

function getBaseUrl(req) {
  const protocol = req.headers['x-forwarded-proto'] || 'https';
  const host = req.headers['x-forwarded-host'] || req.headers.host;
  return `${protocol}://${host}`;
}

function getOutsetaApiBase() {
  if (!process.env.OUTSETA_DOMAIN) {
    throw new Error('OUTSETA_DOMAIN not configured');
  }
  return `https://${process.env.OUTSETA_DOMAIN}/api/v1`;
}

function getOutsetaAuthHeaders() {
  if (!process.env.OUTSETA_API_KEY || !process.env.OUTSETA_SECRET_KEY) {
    throw new Error('Outseta API credentials not configured');
  }

  return {
    Authorization: `Outseta ${process.env.OUTSETA_API_KEY}:${process.env.OUTSETA_SECRET_KEY}`,
    'Content-Type': 'application/json',
  };
}

async function verifyOutsetaAccessToken(token) {
  if (!token) {
    throw new Error('Missing Outseta access token');
  }

  const apiBase = getOutsetaApiBase();

  const response = await axios.get(`${apiBase}/profile`, {
    headers: {
      Authorization: `Bearer ${token}`,
    },
    timeout: 8000,
  });

  return response.data;
}

async function getPersonByUid(uid) {
  if (!uid) return null;

  const apiBase = getOutsetaApiBase();
  const response = await axios.get(`${apiBase}/crm/people/${uid}`, {
    headers: getOutsetaAuthHeaders(),
    timeout: 8000,
  });

  return response.data;
}

async function findPersonByEmail(email) {
  if (!email) return null;

  const apiBase = getOutsetaApiBase();
  const response = await axios.get(`${apiBase}/crm/people`, {
    headers: getOutsetaAuthHeaders(),
    params: {
      Email: email,
      fields: 'Uid,Email,FirstName,LastName,PersonAccount.Account.Uid',
    },
    timeout: 8000,
  });

  return response.data.items?.[0] ?? null;
}

async function findPersonByField(field, value) {
  if (!field || value == null) return null;

  const apiBase = getOutsetaApiBase();
  const response = await axios.get(`${apiBase}/crm/people`, {
    headers: getOutsetaAuthHeaders(),
    params: { [field]: value },
    timeout: 8000,
  });

  return response.data.items?.[0] ?? null;
}

async function updatePerson(uid, payload) {
  if (!uid) throw new Error('Cannot update person without UID');

  const apiBase = getOutsetaApiBase();
  await axios.put(`${apiBase}/crm/people/${uid}`, payload, {
    headers: getOutsetaAuthHeaders(),
    timeout: 8000,
  });
}

async function createRegistration(payload) {
  const apiBase = getOutsetaApiBase();
  const response = await axios.post(`${apiBase}/crm/registrations`, payload, {
    headers: getOutsetaAuthHeaders(),
    timeout: 8000,
  });

  return response.data;
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

async function sendPasswordResetEmail(email) {
  const apiBase = getOutsetaApiBase();
  const config = {
    headers: getOutsetaAuthHeaders(),
    timeout: 8000,
    params: {
      donotlog: 1,
    },
  };

  await axios.post(
    `${apiBase}/crm/people/forgotPassword`,
    { Email: email },
    config
  );
}

function isInvalidGrantError(error) {
  const status = error?.response?.status;
  const data = typeof error?.response?.data === 'string' ? error.response.data : '';
  return status === 400 && data.toLowerCase().includes('invalid_grant');
}

async function ensurePersonHasAccount(email, existingPerson) {
  try {
    const person = existingPerson ?? (await findPersonByEmail(email));
    if (!person || !person.Uid) {
      return false;
    }

    if (personHasAccount(person)) {
      return false;
    }

    await createAccountForPerson(person);
    return true;
  } catch (error) {
    console.warn('[GoogleSSO] ensurePersonHasAccount failed', error?.message || error);
    return false;
  }
}

async function createAccountForPerson(person) {
  const apiBase = getOutsetaApiBase();
  const freePlanUid = process.env.OUTSETA_FREE_PLAN_UID;
  if (!freePlanUid) {
    throw new Error('OUTSETA_FREE_PLAN_UID not configured');
  }

  const accountName = buildAccountName(person);

  await axios.post(
    `${apiBase}/crm/accounts`,
    {
      Name: accountName,
      PersonAccount: [
        {
          IsPrimary: true,
          Person: { Uid: person.Uid },
        },
      ],
      Subscriptions: [
        {
          Plan: { Uid: freePlanUid },
          BillingRenewalTerm: 1,
        },
      ],
    },
    {
      headers: getOutsetaAuthHeaders(),
      timeout: 8000,
    }
  );
}

function buildAccountName(person) {
  const first = (person?.FirstName || '').trim();
  const last = (person?.LastName || '').trim();
  const email = person?.Email || 'Account';
  const combined = `${first} ${last}`.trim();
  return combined.length > 0 ? `${combined}'s Account` : `${email} Account`;
}

function personHasAccount(person) {
  const memberships = Array.isArray(person?.PersonAccount) ? person.PersonAccount : [];
  return memberships.some((membership) => membership?.Account?.Uid);
}

module.exports.config = {
  maxDuration: 30,
  memory: 1024,
};

function hasPassword(person) {
  if (!person) return false;

  const candidateKeys = [
    'PasswordLastUpdated',
    'PasswordLastUpdatedUtc',
    'PasswordLastUpdatedDate',
    'PasswordLastUpdatedDateUtc',
    'PasswordLastUpdatedDateTime',
    'PasswordLastUpdatedDateTimeUtc',
  ];

  for (const key of candidateKeys) {
    const value = person[key];
    if (!value) continue;
    if (typeof value === 'string' && value.trim().length > 0) return true;
    if (value instanceof Date && !isNaN(value.getTime())) return true;
    if (typeof value === 'number' && value > 0) return true;
  }

  if (person.PasswordMustChange === true) return false;
    if (person.HasPassword === true) return true;

  return false;
}