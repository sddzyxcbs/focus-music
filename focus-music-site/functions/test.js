// Simple test function — visit /test to verify Pages Functions work
export async function onRequestGet() {
  return new Response(JSON.stringify({ ok: true, message: 'Pages Function is working!' }), {
    headers: { 'Content-Type': 'application/json' },
  });
}
