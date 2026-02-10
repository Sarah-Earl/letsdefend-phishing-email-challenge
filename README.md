# LetsDefend Phishing Email Challenge

The first step for this LetsDefend challenge is to connect to the lab environment and download and extract the ZIP file using the password `infected` before opening the email.

![Email](/assets/images/email.png)

Initial impressions suggest this is likely a phishing email, as it is written in German and does not address the recipient by their full name. It can also be observed that there is a URL contained within the email.

---

## Email Header Analysis

In order to determine whether the email is malicious, the first step is to examine the sender and compare it to the return path.

![EmailHeader01](/assets/images/email-header01.png)

**From:**  
`IHKH0MFEWW@kodehexa[.]net`  

**Return-Path:**  
`bounce@rjttznyzjjzydnillquh[.]designclub[.]uk[.]com`



These domains are clearly not associated with PayPal. Official PayPal emails would originate from domains such as `paypal[.]com` or `paypal[.]co[.]uk`, illustrating that this email is illegitimate.

---

## URL Analysis

The next stage is to determine whether the URL contained in the email is malicious.

![EmailHeader02](/assets/images/email-header02.png)

**URL**: `https://storage[.]googleapis[.]com/hqyoqzatqthj/aemmfcylvxeo[.]html#QORHNZC44FT4[.]QORHNZC44FT4?dYCTywccxr3jcxxrmcdcKBdmc5D6qfcJVcbbb4M`


Using **VirusTotal** to analyse the URL confirms that it is malicious.

![VirusTotal01](/assets/images/virustotal01.png)

---

## SHA-256 Hash Identification

The final stage required in the challenge is identifying the **SHA-256 hash** of the URL domain. By searching the domain in VirusTotal, this information is accessible in the **Details** tab.

![VirusTotal02](/assets/images/virustotal02.png)

**SHA-256:** `13945ecc33afee74ac7f72e1d5bb73050894356c4bf63d02a1a53e76830567f5`


---

## Conclusion

After investigation, it is clear that the email is a **malicious phishing email**.

Although outside the scope of the challenge, the next steps in a professional environment would include:

- Deleting the email from the affected inbox  
- Checking whether other users received the same email and removing it  
- Reviewing logs to determine whether any users clicked the URL  
- Escalating the incident as necessary based on findings

