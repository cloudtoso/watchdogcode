# Step-by-Step Guide to Create a Safe Attachments Policy in MDO 🛡️
## *Technology enables security, but discipline ensures its effectiveness.*
**Safe Attachments** is part of **Microsoft Defender for Office 365 Plan 1 or Plan 2** and provides advanced malware protection through sandbox analysis ("detonation") before delivering files to users.

**Authors:** Ernesto Cobos Roqueñí, Arturo Mandujano

---

## 1. Verify that you have the appropriate permissions

You must have one of the following roles:

- **Security Administrator**
- **Global Administrator**
- **Security Operator**

> If you already manage Defender in your tenant, you most likely already have one of these permissions.

---

## 2. Creating the Safe Attachments policy

### 2.1 Portal access

1. Go to:  
    https://security.microsoft.com/safeattachmentv2

2. Before creating the policy, verify that the following options are enabled:
   - **Defender for Office 365 for SharePoint, OneDrive, and Microsoft Teams**
   - **Turn on Safe Documents for Office clients**

3. Click **Global settings**.

4. Verify that:
   -  Defender for Office 365 for SharePoint, OneDrive, and Microsoft Teams is **turned on**
   -  Turn on Safe Documents for Office clients is **turned on**

---

### 2.2 Creating the policy

5. Click **+ Create**.

6. Under **Name your policy**:
   - Assign a clear name, for example:
     - `Safe Attachments - Standard Protection`
     - `Safe Attachments - Critical Executives (VIP)`
   - Under **Description**, add a brief summary of the policy.

7. Click **Next**.

---

### 2.3 Selecting users and domains

8. Under **Users and domains**, select as appropriate:

- **Users**
  - If the policy is targeted at one or more specific users.
- **Groups**
  - If it is targeted at a group of users, for example **Critical Executives (VIP)**.
- **Domains**
  - You can add all **accepted domains** of the tenant.

9. Click **Next**.

---

### 2.4 Configuring actions (Settings)

10. Under **Settings**, define the policy actions.  
   >  This section is critical and should be reviewed carefully.

11. Select **Dynamic Delivery** or **Block**.

12. Available modes:

| Mode              | Recommended | Reason |
|-------------------|-------------|--------|
| Monitor           |  No        | Does not block, only reports. |
| Block             |  Good      | Blocks malicious files. |
| Replace           |  Good      | Replaces the malicious attachment with a safe message. |
| Dynamic Delivery  |  Recommended | Delivers the email immediately and adds the attachment only if it is safe. |

**Select: `Dynamic Delivery` (best practice Zero Trust)**

13. Click **Next**.

---

### 2.5 Review and creation

14. Microsoft Defender will display a summary of the configuration.

15. Carefully validate the options and press **Submit**.

16. **Done!** The policy takes effect immediately.