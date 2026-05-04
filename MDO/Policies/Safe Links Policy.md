# Step-by-Step Guide to Create a Safe Links Policy in MDO 🛡️
## *Technology enables security, but discipline ensures its effectiveness.*
This configuration strengthens protection against malicious URLs used in BEC attacks, especially in impersonation scenarios, thread hijacking, and vendor fraud.

**Authors:** Ernesto Cobos Roqueñí, Arturo Mandujano

---

## 1. Go to the Microsoft 365 Defender portal
1. Go to: https://security.microsoft.com/safelinksv2  
2. Click: **+ Create**  
3. Assign a clear name, for example:  
   **Safe Links** or **Safe Links – BEC Protection** (if the policy is only for this function)  
4. Recommended description:  
   *"Enhanced URL protection to prevent BEC fraud, vendor compromise, and thread hijacking."*

---

## 2. Name your policy
1. Assign a clear name, for example:  
   **Safe Links** or **Safe Links – BEC Protection** (if the policy is only for this function)
2. Recommended description:  
   *"Enhanced URL protection to prevent BEC fraud, vendor compromise, and thread hijacking."*
3. Click **Next**

---

## 3. Users and domains
1. Under **Users, Groups and domains**, select:

If all users have an E5 license or if the organization has an MDO Plan, all organization domains can be included.

Or priority users (recommended for BEC):
- Executives (CEO, CFO, COO)
- Finance / Accounts Payable
- Legal
- Procurement
- Critical Operations

Optional: you can later expand to **All users**.

---

## 4. URL &amp; click protection settings  
This is the most important part for BEC.

### Email
1. Check:
   - **On – Enable Safe Links for email messages**
     - Apply Safe Links to email messages sent within the organization  
     - Apply real-time URL scanning for suspicious links and links that point to files  
       - Wait for URLs scanning to complete before delivering the message  
     - Do not rewrite URLs, do checks via Safe Links API only

---

### Teams
1. Enable:
   - **On:** Safe Links checks a list of known, malicious links when users click links in Microsoft Teams.  
     *URLs are not rewritten.*

---

### Office 365 Apps
1. Enable:
   - **On:** Safe Links checks a list of known, malicious links when users click links in Microsoft Office.  
     *URLs are not rewritten.*

---

### Click protection settings
1. Enable:
   - Track user clicks  
   - Display the organization branding on notification and warning pages

---

## 6. Notification  
**How would you like to notify users?**

1. Enable:
   - Use the default notification text

---

## Finish
Click **Next** and then **Submit**.