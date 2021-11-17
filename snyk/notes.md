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

Example 2: Package with some vulnerabilites `snyk test react-dom@v15.7.0 --json`
```json
{
  "ok": false,
  "vulnerabilities": [
    {
      "CVSSv3": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H/E:U/RL:O/RC:R",
      "alternativeIds": [],
      "creationTime": "2020-09-11T10:50:56.354201Z",
      "credit": [
        "Unknown"
      ],
      "cvssScore": 5.9,
      "description": "## Overview\n[node-fetch](https://www.npmjs.com/package/node-fetch) is an A light-weight module that brings window.fetch to node.js\n\nAffected versions of this package are vulnerable to Denial of Service. Node Fetch did not honor the `size` option after following a redirect, which means that when a content size was over the limit, a FetchError would never get thrown and the process would end without failure.\n## Remediation\nUpgrade `node-fetch` to version 2.6.1, 3.0.0-beta.9 or higher.\n## References\n- [GitHub Advisory](https://github.com/node-fetch/node-fetch/security/advisories/GHSA-w7rc-rwvf-8q5r)\n",
      "disclosureTime": "2020-09-10T17:55:53Z",
      "exploit": "Unproven",
      "fixedIn": [
        "2.6.1",
        "3.0.0-beta.9"
      ],
      "functions": [],
      "functions_new": [],
      "id": "SNYK-JS-NODEFETCH-674311",
      "identifiers": {
        "CVE": [
          "CVE-2020-15168"
        ],
        "CWE": [
          "CWE-400"
        ],
        "GHSA": [
          "GHSA-w7rc-rwvf-8q5r"
        ]
      },
      "language": "js",
      "malicious": false,
      "modificationTime": "2020-09-11T14:12:46.019991Z",
      "moduleName": "node-fetch",
      "packageManager": "npm",
      "packageName": "node-fetch",
      "patches": [],
      "proprietary": false,
      "publicationTime": "2020-09-11T14:12:46Z",
      "references": [
        {
          "title": "GitHub Advisory",
          "url": "https://github.com/node-fetch/node-fetch/security/advisories/GHSA-w7rc-rwvf-8q5r"
        }
      ],
      "semver": {
        "vulnerable": [
          "<2.6.1",
          ">=3.0.0-beta.1 <3.0.0-beta.9"
        ]
      },
      "severity": "medium",
      "severityWithCritical": "medium",
      "socialTrendAlert": false,
      "title": "Denial of Service",
      "from": [
        "react-dom@15.7.0",
        "fbjs@0.8.18",
        "isomorphic-fetch@2.2.1",
        "node-fetch@1.7.3"
      ],
      "upgradePath": [
        "react-dom@16.5.0"
      ],
      "version": "1.7.3",
      "name": "node-fetch",
      "isUpgradable": true,
      "isPatchable": false,
      "isPinnable": false
    }
  ],
  "numDependencies": 18,
  "severityMap": {
    "critical": 0,
    "high": 0,
    "medium": 1,
    "low": 0
  },
  "org": "nanma3214",
  "packageManager": "npm",
  "summary": "1 vulnerable dependency path",
  "filesystemPolicy": false,
  "filtered": {
    "ignore": [],
    "patch": []
  },
  "uniqueCount": 1,
  "path": "react-dom@v15.7.0"
}
```