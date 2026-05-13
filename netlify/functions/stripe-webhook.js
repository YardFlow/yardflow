const crypto = require('crypto');

function verifyStripeSignature(rawBody, signature, secret) {
  const parts = signature.split(',');
  const tPart = parts.find(p => p.startsWith('t='));
  const v1Part = parts.find(p => p.startsWith('v1='));
  if (!tPart || !v1Part) throw new Error('Invalid signature format');
  const timestamp = tPart.slice(2);
  const sig = v1Part.slice(3);
  const payload = `${timestamp}.${rawBody}`;
  const expected = crypto.createHmac('sha256', secret).update(payload, 'utf8').digest('hex');
  if (expected !== sig) throw new Error('Signature mismatch');
  const age = Math.floor(Date.now() / 1000) - parseInt(timestamp);
  if (age > 300) throw new Error('Timestamp too old');
}

async function updateYard(supabaseUrl, serviceKey, email, status) {
  const res = await fetch(`${supabaseUrl}/rest/v1/yards?owner_email=eq.${encodeURIComponent(email)}`, {
    method: 'PATCH',
    headers: {
      'apikey': serviceKey,
      'Authorization': `Bearer ${serviceKey}`,
      'Content-Type': 'application/json',
      'Prefer': 'return=minimal',
    },
    body: JSON.stringify({ subscription_status: status }),
  });
  if (!res.ok) console.error('Supabase yard update failed:', await res.text());
  else console.log(`Set ${email} subscription_status to ${status}`);
}

async function savePendingPayment(supabaseUrl, serviceKey, email) {
  const res = await fetch(`${supabaseUrl}/rest/v1/pending_payments`, {
    method: 'POST',
    headers: {
      'apikey': serviceKey,
      'Authorization': `Bearer ${serviceKey}`,
      'Content-Type': 'application/json',
      'Prefer': 'resolution=merge-duplicates',
    },
    body: JSON.stringify({ email }),
  });
  if (!res.ok) console.error('Failed to save pending payment:', await res.text());
  else console.log(`Saved pending payment for ${email}`);
}

exports.handler = async (event) => {
  if (event.httpMethod !== 'POST') return { statusCode: 405, body: 'Method Not Allowed' };

  const sig = event.headers['stripe-signature'];
  const webhookSecret = process.env.STRIPE_WEBHOOK_SECRET;
  const supabaseUrl = process.env.SUPABASE_URL;
  const serviceKey = process.env.SUPABASE_SERVICE_KEY;

  try {
    verifyStripeSignature(event.body, sig, webhookSecret);
  } catch (err) {
    console.error('Signature error:', err.message);
    return { statusCode: 400, body: `Webhook Error: ${err.message}` };
  }

  const stripeEvent = JSON.parse(event.body);
  console.log('Stripe event received:', stripeEvent.type);

  if (stripeEvent.type === 'checkout.session.completed') {
    const email = stripeEvent.data.object.customer_details?.email || stripeEvent.data.object.customer_email;
    if (email) {
      await updateYard(supabaseUrl, serviceKey, email, 'paid');
      await savePendingPayment(supabaseUrl, serviceKey, email);
    }
  }

  if (stripeEvent.type === 'invoice.payment_succeeded') {
    const email = stripeEvent.data.object.customer_email;
    if (email) {
      await updateYard(supabaseUrl, serviceKey, email, 'paid');
      await savePendingPayment(supabaseUrl, serviceKey, email);
    }
  }

  if (stripeEvent.type === 'customer.subscription.deleted') {
    const email = stripeEvent.data.object.customer_email;
    if (email) await updateYard(supabaseUrl, serviceKey, email, 'cancelled');
  }

  return { statusCode: 200, body: JSON.stringify({ received: true }) };
};
