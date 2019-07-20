> The goal of this project is to build an extension for the Chrome browser that passively audits the security posture of the websites that the user of the extension is visiting. Assume that the tool is to be used on non-malicious websites, currently not under attack or compromised. We want to report security misconfigurations, or failure to use best security practices.

- The extension trys to analysis the commonly vulnerable setting of servers: lack of use of security-relevant headers, including:
    - strict-transport-security
    - x-xss-protection
    - content-security-policy
    - x-frame-options
    - x-content-type-options

- The extension work on recent versions of Chrome (74.0.3729.131).
- The extension work out-of-the-box when using the "load unpacked extension" functionality of Chrome.
- The extension is active and not crash on large, reactive websites such as Facebook, etc.
- The extension does not to interfere with the functioning of the visited website.
    - The extension does not tamper with request parameters, or issue requests that were not initiated by the user (it is not active scanning).
- The extension incrementally generate a report in a separate window.
- Each report entry have a numeric score to indicate approximately its severity, as a way to prioritise further investigation by a human analyst.

- Given the limited amount of time to be spent on the project, we assign the score manually, One can connect it with [Common Vulnerability Scoring System](https://en.wikipedia.org/wiki/Common_Vulnerability_Scoring_System) for better results.
