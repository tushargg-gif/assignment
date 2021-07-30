var attacks = ["acct_login",                                                                                                                                                                                                                                
"admin_login" ,                                                                                                                                                                                                                               
"adminlogin",                                                                                                                                                                                                                                 
"autologin"  ,                                                                                                                                                                                                                                
"blogindex"   ,                                                                                                                                                                                                                               
"customer_login",                                                                                                                                                                                                                             
"dir-login",                                                                                                                                                                                                                                  
"dologin",
"formslogin",
"login",
"login_db",
"login_sendpass",
"login1",
"loginadmin",
"loginflat",
"login-redirect",
"logins",
"login-us",
"manuallogin",
"memlogin",
"meta_login",
"platz_login",
"secure_login",
"showlogin",
"simplelogin",
"smblogin",
"sub-login",
"support_login",
"userlogin",
"utility_login",
"viewlogin",
"weblogic",
"wp-login",
"xlogin",
"_admin",
"_vti_bin/_vti_adm/admin.dll",
"~admin",
"~administrator",
"~sysadmin",
"admin",
"admin.cgi",
"admin.php",
"admin.pl",
"admin_",
"admin_area",
"admin_banner",
"admin_c",
"admin_index",
"admin_interface",
"admin_login",
"admin_logon",
"admin1",
"admin2",
"admin3",
"admin4_account",
"admin4_colon",
"admin-admin",
"admin-console",
"admincontrol",
"admincp",
"adminhelp",
"admin-interface",
"administer",
"administr8",
"administracion",
"administrador",
"administrat",
"administratie",
"administration",
"administrator",
"administratoraccounts",
"administrators",
"administrivia",
"adminlogin",
"adminlogon",
"adminpanel",
"adminpro",
"admins",
"adminsessions",
"adminsql",
"admintools",
"admissions",
"aspadmin",
"AT-admin.cgi",
"axis2-admin",
"axis-admin",
"banneradmin",
"bbadmin",
"bigadmin",
"cadmins",
"ccp14admin",
"cmsadmin",
"cpadmin",
"database_administration",
"dbadmin",
"dh_phpmyadmin",
"directadmin",
"e107_admin",
"ezsqliteadmin",
"fileadmin",
"globes_admin",
"hpwebjetadmin",
"iisadmin",
"index_admin",
"indy_admin",
"Indy_admin",
"INSTALL_admin",
"irc-macadmin",
"listadmin",
"loginadmin",
"logo_sysadmin",
"macadmin",
"myadmin",
"navsiteadmin",
"newadmin",
"newsadmin",
"openvpnadmin",
"pgadmin",
"phpadmin",
"phpldapadmin",
"phpmyadmin",
"phpmyadmin2",
"phppgadmin",
"project-admins",
"pureadmin",
"radmind",
"radmind-1",
"resin-admin",
"server_admin_small",
"shopadmin",
"siteadmin",
"sohoadmin",
"sqladmin",
"sql-admin",
"ss_vms_admin_sm",
"sshadmin",
"staradmin",
"sysadmin",
"sys-admin",
"sysadmin2",
"sysadmins",
"system_admin",
"system_administration",
"system-admin",
"system-administration",
"topicadmin",
"ur-admin",
"useradmin",
"vadmind",
"vmailadmin",
"vsadmin",
"wbsadmin",
"webadmin",
"wizmysqladmin",
"wp-admin"]
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
	// Debugging can be done using print like this
	//print('scan called for url=' + msg.getRequestHeader().getURI().toString() + 
	//	' param=' + param + ' value=' + value);
	
	var max_attacks = attacks.length	// No limit for the "INSANE" level ;)
	
	if (as.getAttackStrength() == "LOW") {
		max_attacks = 6
	} else if (as.getAttackStrength() == "MEDIUM") {
		max_attacks = 12
	} else if (as.getAttackStrength() == "HIGH") {
		max_attacks = 24
	}

	for (var i in attacks) {
		// Dont exceed recommended number of attacks for strength
		// feel free to disable this locally ;)
		if (i > max_attacks) {
			return
		}
		// Copy requests before reusing them
		msg = msg.cloneRequest();

		// setParam (message, parameterName, newValue)
		as.setParam(msg, param, attacks[i]);
		
		// sendAndReceive(msg, followRedirect, handleAntiCSRFtoken)
		as.sendAndReceive(msg, false, false);

		// Add any generic checks here, eg
		var code = msg.getResponseHeader().getStatusCode()
		if (code = 200) {
			raiseAlert(as, msg, param, attacks[i], code)
			// Only raise one alert per param
			return
		}
	
		// Check if the scan was stopped before performing lengthy tasks
		if (as.isStop()) {
			return
		}
	}
}

function raiseAlert(as, msg, param, attack) {
	// Replace with more suitable information
	// raiseAlert(risk, int confidence, String name, String description, String uri, 
	//		String param, String attack, String otherInfo, String solution, String evidence, 
	//		int cweId, int wascId, HttpMessage msg)
	// risk: 0: info, 1: low, 2: medium, 3: high
	// confidence: 0: falsePositive, 1: low, 2: medium, 3: high, 4: confirmed
	as.raiseAlert(1, 1, 'Active Vulnerability Title', 'Full description', 
		msg.getRequestHeader().getURI().toString(), 
		param, attack, msg);
}
