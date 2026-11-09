# Changelog

## 1.0.1

- AWS WAF Challenge and CAPTCHA responses are no longer reported as a pass. AWS answers a Challenge with 202 and a CAPTCHA with 405 and names the action in `x-amzn-waf-action`; the AWS detector only looked at 403, 429 and 5xx, and 405 was treated as an ordinary "method not allowed". Both now land on the `challenge` layer as blocked, whatever the status.
- The `aws-waf-token` cookie counts as an AWS WAF marker.
- Vendor verdict headers outrank the status code everywhere, including the low-confidence CDN labels and the no-vendor fallback: `x-amzn-waf-action`, Cloudflare `cf-mitigated: challenge` (a 429 carrying it is now `challenge`, not `rate-limit`) and Vercel `x-vercel-mitigated`.
- Vercel `x-vercel-mitigated: deny` is reported as an `http` block; it used to come out as a pass.

## 1.0.0

- First public release.
