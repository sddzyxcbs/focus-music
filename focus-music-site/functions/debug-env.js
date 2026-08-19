// Debug endpoint — visit /debug-env to inspect environment variables
// (shows presence + length only, never returns actual secrets)
export async function onRequestGet(context) {
  const { env } = context;

  const report = {
    paypal_secret: env.PAYPAL_CLIENT_SECRET ? `present (${env.PAYPAL_CLIENT_SECRET.length} chars)` : 'MISSING',
    firebase_service_account: env.FIREBASE_SERVICE_ACCOUNT ? `present (${env.FIREBASE_SERVICE_ACCOUNT.length} chars)` : 'MISSING',
    firebase_project_id: env.FIREBASE_PROJECT_ID || 'MISSING',
    all_env_keys: Object.keys(env),
  };

  return new Response(JSON.stringify(report, null, 2), {
    headers: { 'Content-Type': 'application/json' },
  });
}