# BillShield Complete Launch Kit

This package combines everything into one ready-to-deploy product:
- **sales page** at `/`
- **app dashboard** at `/app`
- **push reminders** using Web Push + VAPID
- **SMS alerts** using Twilio
- **AES-256-GCM encryption at rest** when `APP_ENCRYPTION_KEY` is set
- **rate limiting** and security headers
- **PWA install support** with branded icons and logo

## Fast launch
1. `.env` is already included with generated encryption + VAPID keys so the app can run immediately.
2. Install and run:
   - `npm install`
   - `npm start`
3. Open `http://localhost:3000`
4. For selling, replace `CHECKOUT_URL=/app/` with your real Stripe, Gumroad, or Lemon Squeezy checkout link.
5. For live deploy, change `APP_URL` to your public domain and `FORCE_HTTPS=true`.
6. Add Twilio credentials only if you want SMS alerts.

## What customers will see
- Landing/sales page: `https://your-domain.com/`
- App: `https://your-domain.com/app/`

## Cron for live reminders
Call this every morning:

```bash
curl -X POST https://your-domain.com/api/reminders/run -H "x-cron-secret: YOUR_CRON_SECRET"
```

Example cron:

```bash
0 8 * * * curl -X POST https://your-domain.com/api/reminders/run -H "x-cron-secret: YOUR_CRON_SECRET"
```

## Recommended hosting
- Render
- Railway
- Fly.io
- VPS with Node 18+

## Before selling today
- Put your real checkout URL in `.env` as `CHECKOUT_URL`
- Set `APP_URL` to your live domain
- Turn on HTTPS on your host
- Set `APP_ENCRYPTION_KEY`
- Add Twilio + VAPID keys for reminders

## Notes
- This is designed to be **user friendly** with no bank connection required.
- Data is encrypted at rest on the server when `APP_ENCRYPTION_KEY` is set.
- Full end-to-end encryption is not used because the server must read due dates and phone numbers to send scheduled reminders.


## Included now
- Pre-generated AES encryption key
- Pre-generated VAPID keys for push notifications
- Sensible local defaults so it works immediately
- `render.yaml` for quick Render deployment
- `/health` endpoint for deploy checks

## What I could not pre-complete
- Your live checkout link (needs your Stripe/Gumroad/Lemon Squeezy account)
- Your final public domain (depends on where you deploy)
- Twilio credentials and sender number for SMS (belongs to your Twilio account)

Until you add a checkout link, all buy buttons safely fall back to `/app/` so the site is still usable for demos and testing.
