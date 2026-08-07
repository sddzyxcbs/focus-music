/**
 * Cloudflare Pages Function — Subscription Verification
 * Path: /subscription-verify
 *
 * Receives { subscriptionID, uid } from frontend,
 * verifies the subscription with PayPal API,
 * then writes the subscription status to Firestore.
 */

// CORS headers shared across all responses
const CORS_HEADERS = {
  'Content-Type': 'application/json',
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type',
};

// Use onRequest (catch-all) to handle all methods in one place
export async function onRequest(context) {
  const { request, env } = context;
  const method = request.method;

  // Handle CORS preflight
  if (method === 'OPTIONS') {
    return new Response(null, { status: 204, headers: CORS_HEADERS });
  }

  // Only allow POST
  if (method !== 'POST') {
    return new Response(JSON.stringify({ error: 'Method not allowed' }), {
      status: 405,
      headers: CORS_HEADERS,
    });
  }

  try {
    const body = await request.json();
    const { subscriptionID, uid } = body;

    if (!subscriptionID || !uid) {
      return new Response(JSON.stringify({ error: 'missing subscriptionID or uid' }), {
        status: 400,
        headers: CORS_HEADERS,
      });
    }

    // 1. Get PayPal access token
    const paypalToken = await getPayPalAccessToken(env.PAYPAL_CLIENT_SECRET);

    // 2. Call PayPal API to get subscription details
    const subDetails = await getPayPalSubscription(subscriptionID, paypalToken);

    // 3. Only proceed if the subscription is actually active
    if (subDetails.status !== 'ACTIVE' && subDetails.status !== 'APPROVED') {
      return new Response(JSON.stringify({ error: 'subscription not active', status: subDetails.status }), {
        status: 400,
        headers: CORS_HEADERS,
      });
    }

    // 4. Write to Firestore — server-side, bypasses security rules
    const serviceAccount = JSON.parse(env.FIREBASE_SERVICE_ACCOUNT);
    const projectId = env.FIREBASE_PROJECT_ID;

    await writeSubscriptionToFirestore(serviceAccount, projectId, uid, {
      status: 'active',
      subscriptionId: subscriptionID,
      planId: subDetails.plan_id || '',
      subscribedAt: new Date().toISOString(),
    });

    return new Response(JSON.stringify({ ok: true }), {
      headers: CORS_HEADERS,
    });
  } catch (err) {
    return new Response(JSON.stringify({ error: err.message }), {
      status: 500,
      headers: CORS_HEADERS,
    });
  }
}

/* ============================================================
   Step 1: Get PayPal Access Token
   ============================================================ */
async function getPayPalAccessToken(clientSecret) {
  // SANDBOX — for testing. Switch back to live Client ID after testing.
  const clientId = 'ASlGxYk4HDyZYbQeix-ZR83RijkdxjKuhiv2hDAZCp5RUjNnAD-LgM3ZfDKrKMo_yA3ayQUw6M2Wsf2A';

  const auth = btoa(`${clientId}:${clientSecret}`);

  // SANDBOX — for testing. Switch back to https://api.paypal.com after testing.
  const res = await fetch('https://api-m.sandbox.paypal.com/v1/oauth2/token', {
    method: 'POST',
    headers: {
      Authorization: `Basic ${auth}`,
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body: 'grant_type=client_credentials',
  });

  const data = await res.json();
  if (!data.access_token) {
    throw new Error(`PayPal OAuth failed: ${JSON.stringify(data)}`);
  }
  return data.access_token;
}

/* ============================================================
   Step 2: Get Subscription Details from PayPal
   ============================================================ */
async function getPayPalSubscription(subscriptionID, accessToken) {
  // SANDBOX — for testing. Switch back to https://api.paypal.com after testing.
  const res = await fetch(`https://api-m.sandbox.paypal.com/v1/billing/subscriptions/${subscriptionID}`, {
    headers: {
      Authorization: `Bearer ${accessToken}`,
      'Content-Type': 'application/json',
    },
  });

  if (!res.ok) {
    const errText = await res.text();
    throw new Error(`PayPal API error: ${errText}`);
  }

  return await res.json();
}

/* ============================================================
   Step 3: Write subscription to Firestore
   ============================================================ */
async function writeSubscriptionToFirestore(serviceAccount, projectId, uid, data) {
  const accessToken = await getFirebaseAccessToken(serviceAccount);

  const url =
    `https://firestore.googleapis.com/v1/projects/${projectId}` +
    `/databases/(default)/documents/users/${uid}`;

  const res = await fetch(`${url}?updateMask.fieldPaths=subscription`, {
    method: 'PATCH',
    headers: {
      Authorization: `Bearer ${accessToken}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      fields: {
        subscription: {
          mapValue: {
            fields: {
              status: { stringValue: data.status },
              subscriptionId: { stringValue: data.subscriptionId },
              planId: { stringValue: data.planId },
              subscribedAt: { timestampValue: data.subscribedAt },
            },
          },
        },
      },
    }),
  });

  if (!res.ok) {
    const errText = await res.text();
    throw new Error(`Firestore write failed: ${errText}`);
  }
}

/* ============================================================
   Firebase OAuth2 — Service Account JWT
   ============================================================ */
async function getFirebaseAccessToken(serviceAccount) {
  const header = b64Url(JSON.stringify({ alg: 'RS256', typ: 'JWT' }));
  const now = Math.floor(Date.now() / 1000);
  const claim = b64Url(
    JSON.stringify({
      iss: serviceAccount.client_email,
      sub: serviceAccount.client_email,
      scope: 'https://www.googleapis.com/auth/datastore',
      aud: 'https://oauth2.googleapis.com/token',
      iat: now,
      exp: now + 3600,
    })
  );

  const signingInput = `${header}.${claim}`;
  const signature = await signRSA(serviceAccount.private_key, signingInput);
  const jwt = `${signingInput}.${signature}`;

  const res = await fetch('https://oauth2.googleapis.com/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
      assertion: jwt,
    }),
  });

  const tokenData = await res.json();
  if (!tokenData.access_token) {
    throw new Error(`Firebase OAuth error: ${JSON.stringify(tokenData)}`);
  }
  return tokenData.access_token;
}

async function signRSA(privateKeyPem, message) {
  const header = '-----BEGIN PRIVATE KEY-----';
  const footer = '-----END PRIVATE KEY-----';
  const start = privateKeyPem.indexOf(header) + header.length;
  const end = privateKeyPem.indexOf(footer);
  const b64 = privateKeyPem.slice(start, end).replace(/\s/g, '');

  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }

  const key = await crypto.subtle.importKey(
    'pkcs8',
    bytes,
    { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
    false,
    ['sign']
  );

  const sig = await crypto.subtle.sign(
    'RSASSA-PKCS1-v1_5',
    key,
    new TextEncoder().encode(message)
  );

  const sigBytes = new Uint8Array(sig);
  let sigStr = '';
  for (let i = 0; i < sigBytes.length; i++) {
    sigStr += String.fromCharCode(sigBytes[i]);
  }
  return b64Url(sigStr);
}

function b64Url(str) {
  return btoa(str)
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}
