# Surya's General Store API

## Email verification codes

The API generates a random six-digit code for each email verification request,
sends it through Gmail SMTP, and accepts it for five minutes. The code is kept
on the server and is never returned in the API response.

Configure these environment variables on the Render service:

- `EMAIL_USER`: the Gmail address used as the sender.
- `EMAIL_PASS`: a Gmail App Password for that account (requires 2-Step
  Verification).

Set them in the Render service's **Environment** settings. Do not put the values
in `render.yaml`, source control, or client code. After changing environment
variables, redeploy the service. If delivery fails, check the Render service
logs for the mail transport error and check the recipient's spam folder.
