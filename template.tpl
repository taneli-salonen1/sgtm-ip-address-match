___TERMS_OF_SERVICE___

By creating or modifying this file you agree to Google Tag Manager's Community
Template Gallery Developer Terms of Service available at
https://developers.google.com/tag-manager/gallery-tos (or such other URL as
Google may provide), as modified from time to time.


___INFO___

{
  "type": "MACRO",
  "id": "cvt_temp_public_id",
  "version": 1,
  "securityGroups": [],
  "displayName": "IP Address Match",
  "categories": ["UTILITY"],
  "description": "Compare the originating IP address of the request to a list of IP patterns. Returns true if one of the patterns matches.\n\nThe template can be used for IP address exclusion.",
  "containerContexts": [
    "SERVER"
  ]
}


___TEMPLATE_PARAMETERS___

[
  {
    "type": "PARAM_TABLE",
    "name": "excludedIPs",
    "displayName": "IP adressess",
    "paramTableColumns": [
      {
        "param": {
          "type": "SELECT",
          "name": "matchType",
          "displayName": "Match type",
          "macrosInSelect": false,
          "selectItems": [
            {
              "value": "equals",
              "displayValue": "IP address equals"
            },
            {
              "value": "begins",
              "displayValue": "IP address begins with"
            },
            {
              "value": "ends",
              "displayValue": "IP address ends with"
            },
            {
              "value": "contains",
              "displayValue": "IP address contains"
            },
            {
              "value": "cidr4",
              "displayValue": "IPv4 address is in CIDR range"
            }
          ],
          "simpleValueType": true
        },
        "isUnique": false
      },
      {
        "param": {
          "type": "TEXT",
          "name": "value",
          "displayName": "Value",
          "simpleValueType": true,
          "alwaysInSummary": true,
          "valueValidators": [
            {
              "type": "NON_EMPTY"
            },
            {
              "type": "NON_EMPTY"
            }
          ]
        },
        "isUnique": false
      },
      {
        "param": {
          "type": "TEXT",
          "name": "description",
          "displayName": "Description",
          "simpleValueType": true,
          "help": "An optional field that can be used for documentation"
        },
        "isUnique": false
      }
    ],
    "alwaysInSummary": true,
    "help": "List the IP addresses or address patterns that should be excluded"
  }
]


___SANDBOXED_JS_FOR_SERVER___

const getRequestHeader = require('getRequestHeader');
const makeInteger = require('makeInteger');
const Math = require('Math');
const log = require('logToConsole');

// This header contains the originating IP
const xForwardedFor = getRequestHeader('X-Forwarded-For');

const requestIp = xForwardedFor ? xForwardedFor.split(',')[0] : undefined;
const excludedIPs = data.excludedIPs;

/*
The following two CIDR related functions are copied from here:
https://tech.mybuilder.com/determining-if-an-ipv4-address-is-within-a-cidr-range-in-javascript/
*/
const ip4ToInt = (ip) =>
  ip.split('.').reduce((int, oct) => (int << 8) + makeInteger(oct), 0) >>> 0;

const isIp4InCidr = (ip, cidr) => {
  const range = cidr.split('/')[0];
  const bits = cidr.split('/')[1];
  const mask = ~(Math.pow(2, (32 - bits)) - 1);
  return (ip4ToInt(ip) & mask) === (ip4ToInt(range) & mask);
};

// a function for ends with matching
const strEndsWith = (str, suffix) => {
    return str.indexOf(suffix, str.length - suffix.length) !== -1;
};

// the function for performing IP comparisons
const ipMatch = (matchType, value, ip) => {
  if(matchType === 'equals') {
    return ip === value;
  } else if(matchType === 'begins') {
    return ip.indexOf(value) === 0;
  } if (matchType === 'ends') {
    return strEndsWith(ip, value);
  } if (matchType === 'contains') {
    return ip.indexOf(value) !== -1;
  } if (matchType === 'cidr4') {
    // there is no proper validation for cidr ranges
    if(value.split('/').length === 2) {
      return isIp4InCidr(ip, value);
    }
  }
};

if (requestIp) {
  if (excludedIPs) {
    // return true if any of the patterns match the visitor's IP
    for (let i = 0; i < excludedIPs.length; i++) {
      const obj = excludedIPs[i];
      if (ipMatch(obj.matchType, obj.value, requestIp) === true) {
        return true;
      }
    }
  }
  
  return false;
}


___SERVER_PERMISSIONS___

[
  {
    "instance": {
      "key": {
        "publicId": "read_request",
        "versionId": "1"
      },
      "param": [
        {
          "key": "headerWhitelist",
          "value": {
            "type": 2,
            "listItem": [
              {
                "type": 3,
                "mapKey": [
                  {
                    "type": 1,
                    "string": "headerName"
                  }
                ],
                "mapValue": [
                  {
                    "type": 1,
                    "string": "X-Forwarded-For"
                  }
                ]
              }
            ]
          }
        },
        {
          "key": "remoteAddressAllowed",
          "value": {
            "type": 8,
            "boolean": true
          }
        },
        {
          "key": "headersAllowed",
          "value": {
            "type": 8,
            "boolean": true
          }
        },
        {
          "key": "requestAccess",
          "value": {
            "type": 1,
            "string": "specific"
          }
        },
        {
          "key": "headerAccess",
          "value": {
            "type": 1,
            "string": "specific"
          }
        },
        {
          "key": "queryParameterAccess",
          "value": {
            "type": 1,
            "string": "any"
          }
        }
      ]
    },
    "clientAnnotations": {
      "isEditedByUser": true
    },
    "isRequired": true
  },
  {
    "instance": {
      "key": {
        "publicId": "logging",
        "versionId": "1"
      },
      "param": [
        {
          "key": "environments",
          "value": {
            "type": 1,
            "string": "debug"
          }
        }
      ]
    },
    "clientAnnotations": {
      "isEditedByUser": true
    },
    "isRequired": true
  }
]


___TESTS___

scenarios:
- name: Contains match
  code: |-
    const mockData = {
      excludedIPs: [
        {"matchType":"equals","value":"xxxxxxxxxx"},
        {"matchType":"begins","value":"xxxxxxxxxx"},
        {"matchType":"ends","value":"xxxxxxxxxx"},
        {"matchType":"contains","value":".123.62."}]
    };

    mock('getRequestHeader', (key) => {
      if (key === 'X-Forwarded-For') {
        return '80.123.62.123';
      }
    });

    // Call runCode to run the template's code.
    let variableResult = runCode(mockData);

    // Verify that the variable returns a result.
    assertThat(variableResult).isEqualTo(true);
- name: Ends with match
  code: |-
    const mockData = {
      excludedIPs: [
        {"matchType":"equals","value":"xxxxxxxxxx"},
        {"matchType":"begins","value":"xxxxxxxxxx"},
        {"matchType":"ends","value":".123"},
        {"matchType":"contains","value":"xxxxxxxxxx"}]
    };

    mock('getRequestHeader', (key) => {
      if (key === 'X-Forwarded-For') {
        return '80.123.62.123';
      }
    });

    // Call runCode to run the template's code.
    let variableResult = runCode(mockData);

    // Verify that the variable returns a result.
    assertThat(variableResult).isEqualTo(true);
- name: Equals match
  code: |-
    const mockData = {
      excludedIPs: [
        {"matchType":"equals","value":"80.123.62.123"},
        {"matchType":"begins","value":"xxxxxxxxxx"},
        {"matchType":"ends","value":"xxxxxxxxxx"},
        {"matchType":"contains","value":"xxxxxxxxxx"}]
    };

    mock('getRequestHeader', (key) => {
      if (key === 'X-Forwarded-For') {
        return '80.123.62.123';
      }
    });

    // Call runCode to run the template's code.
    let variableResult = runCode(mockData);

    // Verify that the variable returns a result.
    assertThat(variableResult).isEqualTo(true);
- name: Begins with match
  code: |-
    const mockData = {
      excludedIPs: [
        {"matchType":"equals","value":"xxxxxxxxxx"},
        {"matchType":"begins","value":"80.123"},
        {"matchType":"ends","value":"xxxxxxxxxx"},
        {"matchType":"contains","value":"xxxxxxxxxx"}]
    };

    mock('getRequestHeader', (key) => {
      if (key === 'X-Forwarded-For') {
        return '80.123.62.123';
      }
    });

    // Call runCode to run the template's code.
    let variableResult = runCode(mockData);

    // Verify that the variable returns a result.
    assertThat(variableResult).isEqualTo(true);
- name: IPv4 address in CIDR range
  code: |-
    const mockData = {
      excludedIPs: [
        {"matchType":"equals","value":"xxxxxxxxxx"},
        {"matchType":"begins","value":"xxxxxxxxxx"},
        {"matchType":"ends","value":"xxxxxxxxxx"},
        {"matchType":"contains","value":"xxxxxxxxxx"},
        {"matchType":"cidr4","value":"192.168.1.1/24"}]
    };

    mock('getRequestHeader', (key) => {
      if (key === 'X-Forwarded-For') {
        return '192.168.1.5';
      }
    });

    // Call runCode to run the template's code.
    let variableResult = runCode(mockData);

    // Verify that the variable returns a result.
    assertThat(variableResult).isEqualTo(true);
- name: No match
  code: |-
    const mockData = {
      excludedIPs: [
        {"matchType":"equals","value":"xxxxxxxxxx"},
        {"matchType":"begins","value":"xxxxxxxxxx"},
        {"matchType":"ends","value":"xxxxxxxxxx"},
        {"matchType":"contains","value":"xxxxxxxxxx"},
        {"matchType":"cidr4","value":"192.168.1.1/24"}]
    };

    mock('getRequestHeader', (key) => {
      if (key === 'X-Forwarded-For') {
        return '192.20.1.5';
      }
    });

    // Call runCode to run the template's code.
    let variableResult = runCode(mockData);

    // Verify that the variable returns a result.
    assertThat(variableResult).isEqualTo(false);
- name: no ip patterns
  code: |-
    const mockData = {
      // Mocked field values
    };

    mock('getRequestHeader', (key) => {
      if (key === 'X-Forwarded-For') {
        return '192.20.1.5';
      }
    });

    // Call runCode to run the template's code.
    let variableResult = runCode(mockData);

    // Verify that the variable returns a result.
    assertThat(variableResult).isEqualTo(false);
- name: out of CIDR range
  code: |-
    const mockData = {
      excludedIPs: [
        {"matchType":"equals","value":"xxxxxxxxxx"},
        {"matchType":"begins","value":"xxxxxxxxxx"},
        {"matchType":"ends","value":"xxxxxxxxxx"},
        {"matchType":"contains","value":"xxxxxxxxxx"},
        {"matchType":"cidr4","value":"194.85.35.38/31"}]
    };

    mock('getRequestHeader', (key) => {
      if (key === 'X-Forwarded-For') {
        return '194.85.35.40';
      }
    });

    // Call runCode to run the template's code.
    let variableResult = runCode(mockData);

    // Verify that the variable returns a result.
    assertThat(variableResult).isEqualTo(false);


___NOTES___

Created on 3/7/2022, 3:39:26 PM


