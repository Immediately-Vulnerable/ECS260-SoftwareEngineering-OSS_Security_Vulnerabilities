# Link Snyk DB 
Notes on Running `extract_snyk.py`

## Prerequisite & Notes
This scripts can be running **only locally** for now, because `Snyk CLI` requires authentication, which I haven't figure out how to bypass in Google Colab.

That being said, to run the script, we need both
* Install `Snyk CLI`
* Complete authentication by `synk auth`

To run (for now):
`python3 -c 'import extract_snyk; extract_snyk.para_wrapper("github_releases", 1, skip = 4562)'`

## Vulnerability Lookup in Snyk DB
Lookup by
* package name & version 
* github url (if the first choice is not working)

## Vulnerability Info Extracted (As for Nov 1)
Use the *pacakage name* and *version* from `library.io`, we can obtain a full vulnerability report in Json (see Appendix A for example).

So far, I only output the following vulnerability info from the Json file:
* *is_ok*: boolean, if the pacakge@version has any vulnerabilites
* *num_vuln*: int, number of vulnerabilites
* *critical*: int, number of critical serverity vulnerabilities
* *high*: int, number of high serverity vulnerabilities
* *medium*: int, number of medium serverity vulnerabilities
* *low*: int, number of low serverity vulnerabilities

A sample output can be found at `snyk/data/npm/output/project_vuln_sample.csv`.

## Appendix A: Sample Snyk Json output 
Example `npm` package: `jquery-ui`, vulnerable version <1.13.0.

Example 1: Good package `snyk test jquery-ui --json`
```json
{
  "ok": true,
  "vulnerabilities": [],
  "numDependencies": 1,
  "severityMap": {
    "critical": 0,
    "high": 0,
    "medium": 0,
    "low": 0
  },
  "org": "nanma3214",
  "packageManager": "npm",
  "summary": "No known vulnerabilities",
  "filesystemPolicy": false,
  "uniqueCount": 0,
  "path": "jquery-ui"
}

```

Example 2: Package with some vulnerabilites `snyk test jquery-ui@1.12.0 --json`
```json
{
  "ok": false,
  "vulnerabilities": [
    {
      "CVSSv3": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:H/A:N/E:P",
      "alternativeIds": [],
      "creationTime": "2021-10-27T09:24:29.516770Z",
      "credit": [
        "Esben Sparre Andreasen"
      ],
      "cvssScore": 7.1,
      "description": "## Overview\n[jquery-ui](https://github.com/jquery/jquery-ui) is a library for manipulating UI elements via jQuery.\n\nAffected versions of this package are vulnerable to Cross-site Scripting (XSS) when accepting the value of `altField` option of the `Datepicker` widget from untrusted sources, which may lead to execution of untrusted code.\r\n\r\n### POC\r\nInitializing the 'datepicker' in the following way:\r\n```\r\n$( \"#datepicker\" ).datepicker( {\r\n\taltField: \"<img onerror='doEvilThing()' src='/404' />\",\r\n} );\r\n\r\n```\r\nwill call the `doEvilThing` function.\n## Details\n\nA cross-site scripting attack occurs when the attacker tricks a legitimate web-based application or site to accept a request as originating from a trusted source.\n\nThis is done by escaping the context of the web application; the web application then delivers that data to its users along with other trusted dynamic content, without validating it. The browser unknowingly executes malicious script on the client side (through client-side languages; usually JavaScript or HTML)  in order to perform actions that are otherwise typically blocked by the browser’s Same Origin Policy.\n\nInjecting malicious code is the most prevalent manner by which XSS is exploited; for this reason, escaping characters in order to prevent this manipulation is the top method for securing code against this vulnerability.\n\nEscaping means that the application is coded to mark key characters, and particularly key characters included in user input, to prevent those characters from being interpreted in a dangerous context. For example, in HTML, `<` can be coded as  `&lt`; and `>` can be coded as `&gt`; in order to be interpreted and displayed as themselves in text, while within the code itself, they are used for HTML tags. If malicious content is injected into an application that escapes special characters and that malicious content uses `<` and `>` as HTML tags, those characters are nonetheless not interpreted as HTML tags by the browser if they’ve been correctly escaped in the application code and in this way the attempted attack is diverted.\n \nThe most prominent use of XSS is to steal cookies (source: OWASP HttpOnly) and hijack user sessions, but XSS exploits have been used to expose sensitive information, enable access to privileged services and functionality and deliver malware. \n\n### Types of attacks\nThere are a few methods by which XSS can be manipulated:\n\n|Type|Origin|Description|\n|--|--|--|\n|**Stored**|Server|The malicious code is inserted in the application (usually as a link) by the attacker. The code is activated every time a user clicks the link.|\n|**Reflected**|Server|The attacker delivers a malicious link externally from the vulnerable web site application to a user. When clicked, malicious code is sent to the vulnerable web site, which reflects the attack back to the user’s browser.| \n|**DOM-based**|Client|The attacker forces the user’s browser to render a malicious page. The data in the page itself delivers the cross-site scripting data.|\n|**Mutated**| |The attacker injects code that appears safe, but is then rewritten and modified by the browser, while parsing the markup. An example is rebalancing unclosed quotation marks or even adding quotation marks to unquoted parameters.|\n\n### Affected environments\nThe following environments are susceptible to an XSS attack:\n\n* Web servers\n* Application servers\n* Web application environments\n\n### How to prevent\nThis section describes the top best practices designed to specifically protect your code: \n\n* Sanitize data input in an HTTP request before reflecting it back, ensuring all data is validated, filtered or escaped before echoing anything back to the user, such as the values of query parameters during searches. \n* Convert special characters such as `?`, `&`, `/`, `<`, `>` and spaces to their respective HTML or URL encoded equivalents. \n* Give users the option to disable client-side scripts.\n* Redirect invalid requests.\n* Detect simultaneous logins, including those from two separate IP addresses, and invalidate those sessions.\n* Use and enforce a Content Security Policy (source: Wikipedia) to disable any features that might be manipulated for an XSS attack.\n* Read the documentation for any of the libraries referenced in your code to understand which elements allow for embedded HTML.\n\n## Remediation\nUpgrade `jquery-ui` to version 1.13.0 or higher.\n## References\n- [GitHub Commit](https://github.com/jquery/jquery-ui/commit/32850869d308d5e7c9bf3e3b4d483ea886d373ce)\n- [GitHub PR](https://github.com/jquery/jquery-ui/pull/1954)\n- [jQuery Release Note](https://blog.jqueryui.com/2021/10/jquery-ui-1-13-0-released/)\n",
      "disclosureTime": "2021-10-27T09:01:39Z",
      "exploit": "Proof of Concept",
      "fixedIn": [
        "1.13.0"
      ],
      "functions": [],
      "functions_new": [],
      "id": "SNYK-JS-JQUERYUI-1767167",
      "identifiers": {
        "CVE": [
          "CVE-2021-41182"
        ],
        "CWE": [
          "CWE-79"
        ],
        "GHSA": [
          "GHSA-9gj3-hwp5-pmwc"
        ]
      },
      "language": "js",
      "malicious": false,
      "modificationTime": "2021-10-27T16:55:16.491887Z",
      "moduleName": "jquery-ui",
      "packageManager": "npm",
      "packageName": "jquery-ui",
      "patches": [],
      "proprietary": false,
      "publicationTime": "2021-10-27T16:55:16.651847Z",
      "references": [
        {
          "title": "GitHub Commit",
          "url": "https://github.com/jquery/jquery-ui/commit/32850869d308d5e7c9bf3e3b4d483ea886d373ce"
        },
        {
          "title": "GitHub PR",
          "url": "https://github.com/jquery/jquery-ui/pull/1954"
        },
        {
          "title": "jQuery Release Note",
          "url": "https://blog.jqueryui.com/2021/10/jquery-ui-1-13-0-released/"
        }
      ],
      "semver": {
        "vulnerable": [
          "<1.13.0"
        ]
      },
      "severity": "high",
      "severityWithCritical": "high",
      "socialTrendAlert": false,
      "title": "Cross-site Scripting (XSS)",
      "from": [
        "jquery-ui@1.12.0"
      ],
      "upgradePath": [
        "jquery-ui@1.13.0"
      ],
      "version": "1.12.0",
      "name": "jquery-ui",
      "isUpgradable": true,
      "isPatchable": false,
      "isPinnable": false
    },
    {
      "CVSSv3": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:H/A:N",
      "alternativeIds": [],
      "creationTime": "2021-10-27T10:52:16.755721Z",
      "credit": [
        "Esben Sparre Andreasen"
      ],
      "cvssScore": 7.1,
      "description": "## Overview\n[jquery-ui](https://github.com/jquery/jquery-ui) is a library for manipulating UI elements via jQuery.\n\nAffected versions of this package are vulnerable to Cross-site Scripting (XSS) when accepting the value of the `of` option of the `.position()` util from untrusted sources which may lead to execution of untrusted code.\n## Details\n\nA cross-site scripting attack occurs when the attacker tricks a legitimate web-based application or site to accept a request as originating from a trusted source.\n\nThis is done by escaping the context of the web application; the web application then delivers that data to its users along with other trusted dynamic content, without validating it. The browser unknowingly executes malicious script on the client side (through client-side languages; usually JavaScript or HTML)  in order to perform actions that are otherwise typically blocked by the browser’s Same Origin Policy.\n\nInjecting malicious code is the most prevalent manner by which XSS is exploited; for this reason, escaping characters in order to prevent this manipulation is the top method for securing code against this vulnerability.\n\nEscaping means that the application is coded to mark key characters, and particularly key characters included in user input, to prevent those characters from being interpreted in a dangerous context. For example, in HTML, `<` can be coded as  `&lt`; and `>` can be coded as `&gt`; in order to be interpreted and displayed as themselves in text, while within the code itself, they are used for HTML tags. If malicious content is injected into an application that escapes special characters and that malicious content uses `<` and `>` as HTML tags, those characters are nonetheless not interpreted as HTML tags by the browser if they’ve been correctly escaped in the application code and in this way the attempted attack is diverted.\n \nThe most prominent use of XSS is to steal cookies (source: OWASP HttpOnly) and hijack user sessions, but XSS exploits have been used to expose sensitive information, enable access to privileged services and functionality and deliver malware. \n\n### Types of attacks\nThere are a few methods by which XSS can be manipulated:\n\n|Type|Origin|Description|\n|--|--|--|\n|**Stored**|Server|The malicious code is inserted in the application (usually as a link) by the attacker. The code is activated every time a user clicks the link.|\n|**Reflected**|Server|The attacker delivers a malicious link externally from the vulnerable web site application to a user. When clicked, malicious code is sent to the vulnerable web site, which reflects the attack back to the user’s browser.| \n|**DOM-based**|Client|The attacker forces the user’s browser to render a malicious page. The data in the page itself delivers the cross-site scripting data.|\n|**Mutated**| |The attacker injects code that appears safe, but is then rewritten and modified by the browser, while parsing the markup. An example is rebalancing unclosed quotation marks or even adding quotation marks to unquoted parameters.|\n\n### Affected environments\nThe following environments are susceptible to an XSS attack:\n\n* Web servers\n* Application servers\n* Web application environments\n\n### How to prevent\nThis section describes the top best practices designed to specifically protect your code: \n\n* Sanitize data input in an HTTP request before reflecting it back, ensuring all data is validated, filtered or escaped before echoing anything back to the user, such as the values of query parameters during searches. \n* Convert special characters such as `?`, `&`, `/`, `<`, `>` and spaces to their respective HTML or URL encoded equivalents. \n* Give users the option to disable client-side scripts.\n* Redirect invalid requests.\n* Detect simultaneous logins, including those from two separate IP addresses, and invalidate those sessions.\n* Use and enforce a Content Security Policy (source: Wikipedia) to disable any features that might be manipulated for an XSS attack.\n* Read the documentation for any of the libraries referenced in your code to understand which elements allow for embedded HTML.\n\n## Remediation\nUpgrade `jquery-ui` to version 1.13.0 or higher.\n## References\n- [GitHub Commit](https://github.com/jquery/jquery-ui/commit/effa323f1505f2ce7a324e4f429fa9032c72f280)\n- [GitHub PR](https://github.com/jquery/jquery-ui/pull/1955)\n- [jQuery Released Note](https://blog.jqueryui.com/2021/10/jquery-ui-1-13-0-released/)\n",
      "disclosureTime": "2021-10-27T09:34:36Z",
      "exploit": "Not Defined",
      "fixedIn": [
        "1.13.0"
      ],
      "functions": [],
      "functions_new": [],
      "id": "SNYK-JS-JQUERYUI-1767175",
      "identifiers": {
        "CVE": [
          "CVE-2021-41184"
        ],
        "CWE": [
          "CWE-79"
        ],
        "GHSA": [
          "GHSA-gpqq-952q-5327"
        ]
      },
      "language": "js",
      "malicious": false,
      "modificationTime": "2021-10-27T16:55:17.539389Z",
      "moduleName": "jquery-ui",
      "packageManager": "npm",
      "packageName": "jquery-ui",
      "patches": [],
      "proprietary": false,
      "publicationTime": "2021-10-27T16:55:17.705676Z",
      "references": [
        {
          "title": "GitHub Commit",
          "url": "https://github.com/jquery/jquery-ui/commit/effa323f1505f2ce7a324e4f429fa9032c72f280"
        },
        {
          "title": "GitHub PR",
          "url": "https://github.com/jquery/jquery-ui/pull/1955"
        },
        {
          "title": "jQuery Released Note",
          "url": "https://blog.jqueryui.com/2021/10/jquery-ui-1-13-0-released/"
        }
      ],
      "semver": {
        "vulnerable": [
          "<1.13.0"
        ]
      },
      "severity": "high",
      "severityWithCritical": "high",
      "socialTrendAlert": false,
      "title": "Cross-site Scripting (XSS)",
      "from": [
        "jquery-ui@1.12.0"
      ],
      "upgradePath": [
        "jquery-ui@1.13.0"
      ],
      "version": "1.12.0",
      "name": "jquery-ui",
      "isUpgradable": true,
      "isPatchable": false,
      "isPinnable": false
    },
    {
      "CVSSv3": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:H/A:N/E:P",
      "alternativeIds": [],
      "creationTime": "2021-10-27T11:11:35.554669Z",
      "credit": [
        "Unknown"
      ],
      "cvssScore": 7.1,
      "description": "## Overview\n[jquery-ui](https://github.com/jquery/jquery-ui) is a library for manipulating UI elements via jQuery.\n\nAffected versions of this package are vulnerable to Cross-site Scripting (XSS). When accepting the value of various `*Text` options of the `Datepicker` widget from untrusted sources it may lead to execution of untrusted code.\r\n\r\n###POC\r\nInitializing the 'Datepicker' in the following way:\r\n```\r\n$( \"#datepicker\" ).datepicker( {\r\n\tshowButtonPanel: true,\r\n\tshowOn: \"both\",\r\n\tcloseText: \"<script>doEvilThing( 'closeText XSS' )</script>\",\r\n\tcurrentText: \"<script>doEvilThing( 'currentText XSS' )</script>\",\r\n\tprevText: \"<script>doEvilThing( 'prevText XSS' )</script>\",\r\n\tnextText: \"<script>doEvilThing( 'nextText XSS' )</script>\",\r\n\tbuttonText: \"<script>doEvilThing( 'buttonText XSS' )</script>\",\r\n\tappendText: \"<script>doEvilThing( 'appendText XSS' )</script>\",\r\n} );\r\n```\r\nwill call the `doEvilThing()` function.\n## Details\n\nA cross-site scripting attack occurs when the attacker tricks a legitimate web-based application or site to accept a request as originating from a trusted source.\n\nThis is done by escaping the context of the web application; the web application then delivers that data to its users along with other trusted dynamic content, without validating it. The browser unknowingly executes malicious script on the client side (through client-side languages; usually JavaScript or HTML)  in order to perform actions that are otherwise typically blocked by the browser’s Same Origin Policy.\n\nInjecting malicious code is the most prevalent manner by which XSS is exploited; for this reason, escaping characters in order to prevent this manipulation is the top method for securing code against this vulnerability.\n\nEscaping means that the application is coded to mark key characters, and particularly key characters included in user input, to prevent those characters from being interpreted in a dangerous context. For example, in HTML, `<` can be coded as  `&lt`; and `>` can be coded as `&gt`; in order to be interpreted and displayed as themselves in text, while within the code itself, they are used for HTML tags. If malicious content is injected into an application that escapes special characters and that malicious content uses `<` and `>` as HTML tags, those characters are nonetheless not interpreted as HTML tags by the browser if they’ve been correctly escaped in the application code and in this way the attempted attack is diverted.\n \nThe most prominent use of XSS is to steal cookies (source: OWASP HttpOnly) and hijack user sessions, but XSS exploits have been used to expose sensitive information, enable access to privileged services and functionality and deliver malware. \n\n### Types of attacks\nThere are a few methods by which XSS can be manipulated:\n\n|Type|Origin|Description|\n|--|--|--|\n|**Stored**|Server|The malicious code is inserted in the application (usually as a link) by the attacker. The code is activated every time a user clicks the link.|\n|**Reflected**|Server|The attacker delivers a malicious link externally from the vulnerable web site application to a user. When clicked, malicious code is sent to the vulnerable web site, which reflects the attack back to the user’s browser.| \n|**DOM-based**|Client|The attacker forces the user’s browser to render a malicious page. The data in the page itself delivers the cross-site scripting data.|\n|**Mutated**| |The attacker injects code that appears safe, but is then rewritten and modified by the browser, while parsing the markup. An example is rebalancing unclosed quotation marks or even adding quotation marks to unquoted parameters.|\n\n### Affected environments\nThe following environments are susceptible to an XSS attack:\n\n* Web servers\n* Application servers\n* Web application environments\n\n### How to prevent\nThis section describes the top best practices designed to specifically protect your code: \n\n* Sanitize data input in an HTTP request before reflecting it back, ensuring all data is validated, filtered or escaped before echoing anything back to the user, such as the values of query parameters during searches. \n* Convert special characters such as `?`, `&`, `/`, `<`, `>` and spaces to their respective HTML or URL encoded equivalents. \n* Give users the option to disable client-side scripts.\n* Redirect invalid requests.\n* Detect simultaneous logins, including those from two separate IP addresses, and invalidate those sessions.\n* Use and enforce a Content Security Policy (source: Wikipedia) to disable any features that might be manipulated for an XSS attack.\n* Read the documentation for any of the libraries referenced in your code to understand which elements allow for embedded HTML.\n\n## Remediation\nUpgrade `jquery-ui` to version 1.13.0 or higher.\n## References\n- [GitHub PR](https://github.com/jquery/jquery-ui/pull/1953)\n- [jQuery Blog Release Note](https://blog.jqueryui.com/2021/10/jquery-ui-1-13-0-released/)\n- [jQuery Issue](https://bugs.jqueryui.com/ticket/15284)\n",
      "disclosureTime": "2021-10-27T10:59:13Z",
      "exploit": "Proof of Concept",
      "fixedIn": [
        "1.13.0"
      ],
      "functions": [],
      "functions_new": [],
      "id": "SNYK-JS-JQUERYUI-1767767",
      "identifiers": {
        "CVE": [
          "CVE-2021-41183"
        ],
        "CWE": [
          "CWE-79"
        ],
        "GHSA": [
          "GHSA-j7qv-pgf6-hvh4"
        ]
      },
      "language": "js",
      "malicious": false,
      "modificationTime": "2021-10-27T16:55:15.406898Z",
      "moduleName": "jquery-ui",
      "packageManager": "npm",
      "packageName": "jquery-ui",
      "patches": [],
      "proprietary": false,
      "publicationTime": "2021-10-27T16:55:15.563218Z",
      "references": [
        {
          "title": "GitHub PR",
          "url": "https://github.com/jquery/jquery-ui/pull/1953"
        },
        {
          "title": "jQuery Blog Release Note",
          "url": "https://blog.jqueryui.com/2021/10/jquery-ui-1-13-0-released/"
        },
        {
          "title": "jQuery Issue",
          "url": "https://bugs.jqueryui.com/ticket/15284"
        }
      ],
      "semver": {
        "vulnerable": [
          "<1.13.0"
        ]
      },
      "severity": "high",
      "severityWithCritical": "high",
      "socialTrendAlert": false,
      "title": "Cross-site Scripting (XSS)",
      "from": [
        "jquery-ui@1.12.0"
      ],
      "upgradePath": [
        "jquery-ui@1.13.0"
      ],
      "version": "1.12.0",
      "name": "jquery-ui",
      "isUpgradable": true,
      "isPatchable": false,
      "isPinnable": false
    }
  ],
  "numDependencies": 0,
  "severityMap": {
    "critical": 0,
    "high": 3,
    "medium": 0,
    "low": 0
  },
  "org": "nanma3214",
  "packageManager": "npm",
  "summary": "3 vulnerable dependency paths",
  "filesystemPolicy": false,
  "filtered": {
    "ignore": [],
    "patch": []
  },
  "uniqueCount": 3,
  "path": "jquery-ui@1.12.0"
}

```