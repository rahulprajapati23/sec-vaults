# SendGrid Email Setup Guide

## Problem
Render's free tier **blocks outbound SMTP connections** (port 587/465). Gmail SMTP doesn't work on Render free tier.

## Solution
Use **SendGrid API** (HTTP-based) instead of SMTP. SendGrid works perfectly on Render free tier.

---

## Step 1: Create SendGrid Account

1. Go to [sendgrid.com](https://sendgrid.com)
2. Click **Sign Up**
3. Fill in details:
   - **Name**: Your name
   - **Email**: Your email
   - **Password**: Strong password
4. Verify your email
5. Complete the onboarding (select "Transactional Email")

---

## Step 2: Create SendGrid API Key

1. Login to SendGrid Dashboard
2. Click **Settings** (left sidebar)
3. Click **API Keys**
4. Click **Create API Key**
5. Choose:
   - **Name**: "SecureVault Registration"
   - **API Key Type**: "Full Access" (for testing)
   - For production: Restrict to "Mail Send"
6. Click **Create & Copy**
7. **Save this key somewhere safe!** You'll need it.

---

## Step 3: Update Environment Variables

### Local Development (`.env` file)

```env
EMAIL_PROVIDER=sendgrid
SENDGRID_API_KEY=SG.your-api-key-here
```

Replace `your-api-key-here` with the actual API key you copied above.

---

## Step 4: Update Render Environment

1. Go to [dashboard.render.com](https://dashboard.render.com)
2. Click your **Backend Service** (sec-vaults)
3. Click **Settings** → **Environment**
4. Add or update:
   ```
   EMAIL_PROVIDER=sendgrid
   SENDGRID_API_KEY=SG.your-actual-api-key
   ```
5. Click **Save Changes**
6. Go to **Deployments** → **Redeploy Latest Commit**

---

## Step 5: Verify It Works

1. After redeployment, go to: `https://sec-vaults.onrender.com/auth/test-email`
2. You should see:
   ```json
   {
     "status": "success",
     "data": {
       "status": "connected",
       "email_provider": "sendgrid",
       "message": "SendGrid API is accessible"
     }
   }
   ```

3. Test registration:
   - Go to `https://sec-vaults.vercel.app/register`
   - Enter email and click "Get OTP"
   - Check your email inbox for the verification code

---

## Troubleshooting

### Email Not Arriving
- **Check SendGrid Dashboard**: Go to Dashboard → Deployments → check "Activity" feed
- **Wrong API Key?** Verify key starts with `SG.`
- **Domain Verification**: In SendGrid, go to Settings → Sender Authentication → Verify Sender

### API Connectivity Error
- **Run test endpoint**: `/auth/test-email` shows the exact error
- **Check key format**: Must start with `SG.`
- **Check quota**: SendGrid free tier has 100 emails/day

### Still Getting OTP in Logs
- Deployment hasn't finished redeploying with new env vars
- Wait 5-10 minutes after redeploy
- Refresh the page

---

## SendGrid Free Tier Limits
- **100 emails/day** (upgrade for more)
- **Enough for development/testing**
- Upgrade to Pro for production (pay-as-you-go)

---

## Code Structure

**Email sending is handled in**: `backend/app/services/email.py`

### Key Functions:
- `send_email_via_sendgrid()` - Core SendGrid API integration
- `send_otp_email()` - Sends OTP with HTML template
- `test_email_connection()` - Diagnostic test endpoint

### Fallback Behavior:
- If SendGrid fails → OTP is logged (doesn't break registration)
- In production, monitor these logs to catch failures

---

## For Production
1. **Use restricted API key** (Mail Send only)
2. **Monitor delivery**: SendGrid Dashboard → Activity
3. **Handle bounces**: Configure webhooks for bounce events
4. **Consider rate limits**: Upgrade plan if needed

---

## Questions?
- SendGrid Docs: https://docs.sendgrid.com/
- Test endpoint: `GET /auth/test-email`
- Check logs: Render Dashboard → Logs
