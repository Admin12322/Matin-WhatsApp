# WhatsApp Team Desk — starter project

A self-hosted multi-agent inbox starter for the **official Meta WhatsApp Business Platform Cloud API**.

## Included

- Separate administrator and staff sign-in
- Admin creates users and teams, disables accounts, and assigns devices
- Multiple WhatsApp Cloud API phone-number connections
- Staff see only devices assigned to them
- Staff see masked customer numbers; admins see full numbers
- Webhook receiver for incoming text and image messages
- Text and image sending through Cloud API
- Conversation assignment and message history
- Password hashing, signed sessions, basic rate limiting, and optional Meta webhook signature validation

## Requirements

- Node.js 20+
- A Meta developer app with WhatsApp product enabled
- A WhatsApp Business Account and Cloud API phone number
- A public HTTPS URL for production webhooks

## Run on Windows

1. Install Node.js 20 or newer.
2. Extract this ZIP.
3. Open Command Prompt in this folder.
4. Run:

   ```bat
   copy .env.example .env
   notepad .env
   ```

5. In `.env`, set:
   - `JWT_SECRET` to a long random secret (32+ characters)
   - `META_VERIFY_TOKEN` to a random value you choose
   - `META_GRAPH_VERSION` to the current Graph API version shown in your Meta app
   - Admin email and a strong initial admin password
   - Optional `META_APP_SECRET` for webhook signature verification

6. Install and start:

   ```bat
   npm install
   npm start
   ```

7. Open `http://localhost:3000`.

The first start creates the admin account from `ADMIN_EMAIL` and `ADMIN_PASSWORD` in `.env`. Change the password after first login. Do not share `.env`.

## Connect a WhatsApp number

In Admin → Devices → Add device, enter:
- A friendly device name
- Display phone number
- Phone Number ID from Meta
- A long-lived System User access token with the required WhatsApp permissions
- The staff members who may use that number

The token is stored server-side and is never returned to staff. For production, use a secrets manager or encrypted credential storage rather than a plain JSON file.

## Configure Meta webhooks

Use the public HTTPS URL:

`https://YOUR-DOMAIN/webhook`

In the Meta App Dashboard, configure the webhook verify token to exactly match `META_VERIFY_TOKEN`, complete verification, and subscribe to the WhatsApp `messages` field. The server supports GET verification and POST message/status notifications.

Set `META_APP_SECRET` to your Meta app secret to validate `X-Hub-Signature-256`. Keep the webhook endpoint publicly reachable over HTTPS.

## Important WhatsApp rules

- This application does not bypass Meta messaging rules.
- Free-form replies are generally available during the customer-service window. Outside that window, use approved message templates where required.
- Customers must have provided the appropriate consent for business-initiated messaging.
- Meta controls phone-number eligibility, quality, rate limits, template approval and pricing.
- The Cloud API uses Phone Number IDs and access tokens, not QR pairing.
- To onboard many unrelated businesses' WhatsApp accounts, build Meta Embedded Signup and the required Tech Provider/partner setup; this starter expects an admin to configure each connected number.

## Production checklist before real customer use

This is an MVP starter, not a fully hardened production deployment. Before public launch:
- Replace JSON-file persistence with PostgreSQL or another managed database.
- Encrypt Meta access tokens at rest and rotate them.
- Add HTTPS, secure reverse proxy, backups, monitoring and audit logs.
- Add CSRF protection if changing to cookie-based sessions, stronger rate limits and login lockout.
- Add pagination, message delivery/read status UI, webhook retry/idempotency handling, media retention controls and staff audit trails.
- Review privacy, retention, consent, and applicable local laws.
- Test with Meta's test number before connecting a live business number.

## API notes

Cloud API send endpoint used by the server:
`/{PHONE_NUMBER_ID}/messages`

Media upload endpoint:
`/{PHONE_NUMBER_ID}/media`

Meta docs:
- https://developers.facebook.com/documentation/business-messaging/whatsapp/overview
- https://developers.facebook.com/docs/graph-api/webhooks/getting-started/
