/**
 * Cloudflare Pages Function — PayPal IPN Handler
 * Path: /ipn-handler
 *
 * Receives PayPal Instant Payment Notifications for Buy Now buttons,
 * verifies them, and records payment status to Firestore.
 */

export async function onRequestPost(context) {
  try {
    // 1. Parse IPN payload
    const formData = await context.request.formData();
    const ipnData = Object.fromEntries(formData);

    // 2. Verify with PayPal
    const isValid = await verifyIPN(ipnData);
    if (!isValid) {
      console.warn('IPN verification failed');
      return new Response('INVALID', { status: 400 });
    }

    // 3. Extract fields for one-time payment (Buy Now)
    const payerEmail = ipnData.payer_email || '';
    const paymentStatus = ipnData.payment_status || '';
    const txnId = ipnData.txn_id || '';
    const mcGross = ipnData.mc_gross || '';
    const itemName = ipnData.item_name || '';
    const txnType = ipnData.txn_type || '';

    // Only process completed payments (or pending that later complete)
    if (paymentStatus !== 'Completed') {
      console.log('IPN ignored — payment status:', paymentStatus);
      return new Response('OK'); // Acknowledge but ignore
    }

    if (!payerEmail) {
      console.warn('IPN missing payer_email');
      return new Response('NO_EMAIL', { status: 400 });
    }

    // 4. Write to Firestore
    const serviceAccount = JSON.parse(context.env.FIREBASE_SERVICE_ACCOUNT);
    const projectId = context.env.FIREBASE_PROJECT_ID;

    // Record payment under email_payments/{email}
    await writeEmailPayment(serviceAccount, projectId, payerEmail, {
      status: 'active',
      txnId,
      amount: mcGross,
      itemName,
      updatedAt: new Date().toISOString(),
    });

    return new Response('OK');
  } catch (err) {
    console.error('IPN handler error:', err);
    return new Response('ERROR', { status: 500 });
  }
}

/* ============================================================
   PayPal IPN Verification
   ============================================================ */
async function verifyIPN(data) {
  const body = new URLSearchParams();
  body.append('cmd', '_notify-validate');

  for (const [key, value] of Object.entries(data)) {
    body.append(key, value);
  }

  const res = await fetch('https://ipnpb.paypal.com/cgi-bin/webscr', {
    method: 'POST',
    body,
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
  });

  const text = await res.text();
  return text === 'VERIFIED';
}

/* ============================================================
   Firestore Write — email_payments
   ============================================================ */
async function writeEmailPayment(serviceAccount, projectId, email, data) {
  const accessToken = await getAccessToken(serviceAccount);

  // Use email as document ID (safe for small site; email is needed for lookup anyway)
  const url =
    `https://firestore.googleapis.com/v1/projects/${projectId}` +
    `/databases/(default)/documents/email_payments/${encodeURIComponent(email)}`;

  const res = await fetch(url, {
    method: 'PATCH',
    headers: {
      Authorization: `Bearer ${accessToken}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      fields: {
        status: { stringValue: data.status },
        txnId: { stringValue: data.txnId || '' },
        amount: { stringValue: data.amount || '' },
        itemName: { stringValue: data.itemName || '' },
        updatedAt: { timestampValue: data.updatedAt },
      },
    }),
  });

  if (!res.ok) {
    const errText = await res.text();
    throw new Error(`Firestore write failed: ${errText}`);
  }
}

/* ============================================================
   Google OAuth2 — Service Account JWT
   ============================================================ */
async function getAccessToken(serviceAccount) {
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
    throw new Error(`OAuth token error: ${JSON.stringify(tokenData)}`);
  }
  return tokenData.access_token;
}

/* ============================================================
   RSA-SHA256 Sign with PEM private key (Web Crypto)
   ============================================================ */
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

/* Base64URL encode (no padding, replace +/ with -_) */
function b64Url(str) {
  return btoa(str)
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}
