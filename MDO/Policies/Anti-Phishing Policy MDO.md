# Step-by-Step Guide to Create an Anti-Phishing Policy in MDO 🛡️
## *Technology enables security, but discipline ensures its effectiveness.*

**Authors:** Ernesto Cobos Roqueñí, Arturo Mandujano

An **Anti‑phishing policy in Microsoft Defender for Office 365 detects and blocks emails designed to deceive the user**, even when the message **appears legitimate** and does not contain obvious malware

---
1. Go to: https://security.microsoft.com/antiphishing
2. Click **Create**
3. In the **Policy name** section:
   - **Name**: Anti‑Phishing – BEC Protection
   - **Description**: BEC protection with impersonation for Executives, Finance, and Legal
4. Click **Next**
5. In the **Users, groups, and domains** section:
   - Apply the policy to:
     - **Domains**
       - Add all your domains
   - Avoid exclusions unless highly justified
6. Click **Next**
7. In the **Phishing threshold & protection** section:
   - Under **Phishing email threshold**, set the slider to:
     - **3 – More aggressive**
       - Increases sensitivity to detect targeted phishing and BEC
8. Configure **Impersonation**:
   - Enable **Enable users to protect**
   - Click **Manage sender(s)**
     - Add users (Name + email):
       - Executives (CEO, CFO, COO, etc.)
       - Finance users
       - Legal users
     - Maximum: **350 users per policy**
   - Finish with **Done**
9. Enable **domain protection**:
   - Check **Include the domains I own**
   - Check **Include custom domains**
     - Under **Manage custom domains**, add:
       - Banks
       - Key vendors
       - Strategic partners
10. **Mailbox Intelligence (Required)**:
    - Enable mailbox intelligence
    - Enable intelligence for impersonation protection

    > Detects thread hijacking and anomalous behavior even without classic spoofing

11. Under **Spoof Intelligence**:
    - Verify that **Enable spoof intelligence** is enabled
12. Click **Next**
13. In the **Actions** section
14. Configure **Message action**:
    - User impersonation → **Quarantine the message**
      - Quarantine policy: `DefaultFullAccessPolicy` (or dedicated SOC policy)
    - Domain impersonation → **Quarantine the message**
      - Quarantine policy: `DefaultFullAccessPolicy` (or dedicated SOC policy)
    - Select **Honor DMARC record policy**
    - Spoof + DMARC `p=quarantine` → **Quarantine the message**
    - Spoof + DMARC `p=reject` → **Reject the message**
    - Spoof by spoof intelligence → **Quarantine the message**
15. Under **Safety Tips & Indicators**, enable:
    - Show first contact safety tip
    - Show user impersonation safety tip
    - Show domain impersonation safety tip
    - Show user impersonation unusual characters safety tip
    - Show ? for unauthenticated sender for spoof
    - Show "via" tag
16. Click **Next** and **Submit**