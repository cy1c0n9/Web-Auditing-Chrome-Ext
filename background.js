var HSTSdict = {};
// record hosts that declared strict transport security

var tabsInfo = {};
// collect all data that needs to be reported
// classified by tab id
var a=true

chrome.webRequest.onHeadersReceived.addListener(
	function(details) {
		if (parseInt(details.tabId, 10) <= 0) {
			return;
		}
		if (typeof tabsInfo[details.tabId] == "undefined") {
			// check if the record for this tab has been initialized or not
			tabInit(details.tabId);
		}
		var host = getHostName(details.url);
		checkIfHSTS(details, host);
		// console.log("NOT HSTS: ", tabsInfo[details.tabId].securityHeaders.notHSTS);

		checkIfXSSProtected(details, host);
		// console.log("NOT X-XSS: ", tabsInfo[details.tabId].securityHeaders.notXSSPro);

		checkIfThereExistsCSP(details, host);
		// console.log("NOT CSP: ", tabsInfo[details.tabId].securityHeaders.notCSP);

		checkIfFrameOption(details, host);
		// console.log("NOT x-frame-options: ", tabsInfo[details.tabId].securityHeaders.notXFO);

		checkIfXContentTypeOptions(details, host);
		// console.log("NOT X-Content-Type-Options: ", tabsInfo[details.tabId].securityHeaders.notXCTO);
		// chrome.storage.sync.set({dict: tabsInfo});
		console.log(tabsInfo);


	},
	{urls: ["<all_urls>"]},
	["responseHeaders"]
);

function tabInit(tabId) {
	tabsInfo[tabId] = {};
	tabsInfo[tabId].securityHeaders = {};
	// our general concern is security headers,
	// other concerns can be extanded easily by adding new categories hear
	tabsInfo[tabId].securityHeaders.notHSTS = [];
	// not using strict-transport-security field
	tabsInfo[tabId].securityHeaders.shortHSTS = [];
	// the max age of strict-transport-security is too short
	tabsInfo[tabId].securityHeaders.notXSSPro = [];
	// not using x-xss-protection field
	tabsInfo[tabId].securityHeaders.notCSP = [];
	// not using content-security-policy
	tabsInfo[tabId].securityHeaders.notXFO = [];
	// not using x-frame-options
	tabsInfo[tabId].securityHeaders.badXFO = [];
	// using x-frame-options with ALLOW-FROM parameter
	tabsInfo[tabId].securityHeaders.notXCTO = [];
	// not using x-content-type-options
	HSTSdict[tabId] = [];
	// recoding those who had declared strict-transport-security
}

function getHostName(url) {
	/**
	  * get Host server name of the url,
	  */
	var match = url.match(/:\/\/(www[0-9]?\.)?(.[^/:]+)/i);
	if (match != null &&
		match.length > 2 &&
		typeof match[2] === 'string' &&
		match[2].length > 0) {
		return match[2];
	} else {
		return null;
	}
}

function checkIfHSTS(details, host) {
	/**
	  * check if the host has set strict-transport-security field
	  * and the parameter is reasonable
	  */
	var isHSTS = false;
	for (var d in HSTSdict[details.tabId]) {
		// Check if host has already declared hsts
		if (host.endsWith(d)) {
			return;
		}
	}
	for (var i = 0; i < details.responseHeaders.length; ++i) {
		if (details.responseHeaders[i].name.toLowerCase() === 'strict-transport-security') {
			// found strict-transport-security
			isHSTS = true;
			// mark the host as declared-hsts host
			HSTSdict[details.tabId][host] = 1;
			// retrieve value of parameter max-age
			// check if it too small to be secure
			v = details.responseHeaders[i].value;
			sec = parseInt(v.match(/max-age=(\d+)/)[1]);
			if (sec < 15768000) {
				console.log("host : (" + host + ") is HSTSed, \
							 but expire time is too short");
				// check if already reported
				if (!tabsInfo[details.tabId].securityHeaders.shortHSTS.includes(host)) {
					tabsInfo[details.tabId].securityHeaders.shortHSTS.push(host);
				}
			}
			break;
		}
	}
	if (!(Boolean(isHSTS))) {
		// found host that not use strict-transport-security field
		console.log("host : (" + host + ") is not HSTSed");
		// check if already reported
		if (!tabsInfo[details.tabId].securityHeaders.notHSTS.includes(host)) {
			tabsInfo[details.tabId].securityHeaders.notHSTS.push(host);
		}
	}
}

function checkIfXSSProtected(details, host) {
	/**
	  * check if the host has set x-xss-protection field
	  * and the parameter is reasonable
	  */
	var isXSSPro = false;
	for (var i = 0; i < details.responseHeaders.length; ++i) {
		if (details.responseHeaders[i].name.toLowerCase() === 'x-xss-protection') {
			// found x-xss-protection field
			var XSSFlag = details.responseHeaders[i].value.slice(0,1);
			// check if it is enabled
			if(XSSFlag === '1'){
				isXSSPro = true;
				break;
			}
		}
	}
	if(!(Boolean(isXSSPro))) {
		// found host that not use x-xss-protection field
		console.log("host : (" + host + ") is not XSS protected.");
		// check if already reported
		if(!tabsInfo[details.tabId].securityHeaders.notXSSPro.includes(host)){
			tabsInfo[details.tabId].securityHeaders.notXSSPro.push(host);
		}
	}
}

function checkIfThereExistsCSP(details, host) {
	var isCSP = false;
	// a list of csp field that may be used
	var csp = ["content-security-policy", "x-content-security-policy", "x-webkit-csp", "content-security-policy-report-only"];

	for (var i = 0; i < details.responseHeaders.length; ++i) {
		if (csp.includes(details.responseHeaders[i].name.toLowerCase())) {
			// found csp is used
			isCSP = true;
		}
	}
	if(!(Boolean(isCSP))) {
		// found host that not use CSP
		console.log("host : (" + host + ") is not CSP protected.");
		// check if already reported
		if(!tabsInfo[details.tabId].securityHeaders.notCSP.includes(host)){
			tabsInfo[details.tabId].securityHeaders.notCSP.push(host);
		}
	}
}

function checkIfFrameOption(details, host) {
	/**
	  * check if the host has set x-frame-options
	  */
	var isXframe = false;
	var relatedTypes = ["main_frame", "sub_frame"];
	if (!relatedTypes.includes(details.type.toLowerCase())) {
		// typically this field is target at frame and iframe
		return;
	}
	for (var i = 0; i < details.responseHeaders.length; ++i) {
		if (details.responseHeaders[i].name.toLowerCase() === 'x-frame-options') {
			// found x-frame-options
			isXframe = true;
			v = details.responseHeaders[i].value.toLowerCase();
			if (v.indexOf("allow-from") != -1) {
				// using ALLOW-FROM parameter may be less safer
				// than use DENY or SAMEORIGIN
				console.log("host : (" + host + ") is using x-frame-options \
							 with allow-from parameter");
				// check if already reported
				if(!tabsInfo[details.tabId].securityHeaders.badXFO.includes(host)){
					tabsInfo[details.tabId].securityHeaders.badXFO.push(host);
				}
			}
		}
	}
	if (!(Boolean(isXframe))) {
		// found host that not use x-frame-options
		console.log("host : (" + host + ") is not using x-frame-options");
		// check if already reported
		if(!tabsInfo[details.tabId].securityHeaders.notXFO.includes(host)){
			tabsInfo[details.tabId].securityHeaders.notXFO.push(host);
		}
	}
}

function checkIfXContentTypeOptions(details, host) {
	/**
	  * check if the host has set x-content-type-options field
	  */
	var isXCTO = false;
	var host = getHostName(details.url);
	// restrict response type because we only care about following in this case
	var relatedTypes = ["script", "xmlhttprequest", "image", "stylesheet", "font"];
	if (!relatedTypes.includes(details.type.toLowerCase())) {
		return;
	}
	for (var i = 0; i < details.responseHeaders.length; ++i) {
		// check if x-content-type-options is used
		if (details.responseHeaders[i].name.toLowerCase() === "x-content-type-options") {
			isXCTO = true;
			break;
		}
	}
	if (!(Boolean(isXCTO))) {
		// found host that not use x-content-type-options
		console.log("Response header from " + host + " is not XCTOed");
		// check if already reported
		if(!tabsInfo[details.tabId].securityHeaders.notXCTO.includes(host)){
			tabsInfo[details.tabId].securityHeaders.notXCTO.push(host);
		}
	}
}
