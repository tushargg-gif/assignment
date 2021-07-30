// Note that new active scripts will initially be disabled
// Right click the script in the Scripts tree and select "enable"  

/**
 * Scans a "node", i.e. an individual entry in the Sites Tree.
 * The scanNode function will typically be called once for every page. 
 * 
 * @param as - the ActiveScan parent object that will do all the core interface tasks 
 *     (i.e.: sending and receiving messages, providing access to Strength and Threshold settings,
 *     raising alerts, etc.). This is an ScriptsActiveScanner object.
 * @param msg - the HTTP Message being scanned. This is an HttpMessage object.
 */

function scanNode(as, msg) {
	// Debugging can be done using println like this
	var alertRisk = 1
	var alertConfidence = 2
	var alertTitle = 'WP user enum vulnerability'
	var url = "https://www.ibab.ac.in";

	var msg2 = msg.cloneRequest();
	msg2.getRequestHeader().setHeader("Accept", "/wp-json/wp/v2/users")
	as.sendAndReceive(msg2, false, true);
	var re = '"id:"1'
	var body = msg2.getResponseBody().toString()

	if (re.test(body)) {
		as.raiseAlert(alertRisk, alertConfidence, alertTitle,
          url, '', '', body.match(re)[0], msg2);
		return; 
    }

	var msg3 = msg.cloneRequest();
	msg3.getRequestHeader().setHeader("Accept", "/?author=1")
	as.sendAndReceive(msg3, false, true);
	var re = admin
	var body = msg3.getResponseBody().toString()

	if (re.test(body)) {
		as.raiseAlert(alertRisk, alertConfidence, alertTitle,
          url, '', '',  body.match(re)[0], msg2);
		return; 
    }

	var msg4 = msg.cloneRequest();
	msg4.getRequestHeader().setHeader("Accept", "/?author=2")
	as.sendAndReceive(msg2, false, true);
	var re = user2
	var body = msg4.getResponseBody().toString()

	if (re.test(body)) {
		as.raiseAlert(alertRisk, alertConfidence, alertTitle,
          url, '', '', body.match(re)[0], msg2);
		return; 
    }
}

/**
 * Scans a specific parameter in an HTTP message.
 * The scan function will typically be called for every parameter in every URL and Form for every page.
 * 
 * @param as - the ActiveScan parent object that will do all the core interface tasks 
 *     (i.e.: sending and receiving messages, providing access to Strength and Threshold settings,
 *     raising alerts, etc.). This is an ScriptsActiveScanner object.
 * @param msg - the HTTP Message being scanned. This is an HttpMessage object.
 * @param {string} param - the name of the parameter being manipulated for this test/scan.
 * @param {string} value - the original parameter value.
 */
function scan(as, msg, param, value) {
	// unused
}

