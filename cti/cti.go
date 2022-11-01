package cti

// Technique has MITER ATT&CK Technique or CAPEC information
type Technique struct {
	Name      string   `json:"name"`
	Platforms []string `json:"platforms"`
}

// TechniqueDict is the MITRE ATT&CK Technique and CAPEC dictionary
var TechniqueDict = map[string]Technique{
	"CAPEC-1": {
		Name: "CAPEC-1: Accessing Functionality Not Properly Constrained by ACLs",
	},
	"CAPEC-10": {
		Name: "CAPEC-10: Buffer Overflow via Environment Variables",
	},
	"CAPEC-100": {
		Name: "CAPEC-100: Overflow Buffers",
	},
	"CAPEC-101": {
		Name: "CAPEC-101: Server Side Include (SSI) Injection",
	},
	"CAPEC-102": {
		Name: "CAPEC-102: Session Sidejacking",
	},
	"CAPEC-103": {
		Name: "CAPEC-103: Clickjacking",
	},
	"CAPEC-104": {
		Name: "CAPEC-104: Cross Zone Scripting",
	},
	"CAPEC-105": {
		Name: "CAPEC-105: HTTP Request Splitting",
	},
	"CAPEC-107": {
		Name: "CAPEC-107: Cross Site Tracing",
	},
	"CAPEC-108": {
		Name: "CAPEC-108: Command Line Execution through SQL Injection",
	},
	"CAPEC-109": {
		Name: "CAPEC-109: Object Relational Mapping Injection",
	},
	"CAPEC-11": {
		Name: "CAPEC-11: Cause Web Server Misclassification",
	},
	"CAPEC-110": {
		Name: "CAPEC-110: SQL Injection through SOAP Parameter Tampering",
	},
	"CAPEC-111": {
		Name: "CAPEC-111: JSON Hijacking (aka JavaScript Hijacking)",
	},
	"CAPEC-112": {
		Name: "CAPEC-112: Brute Force",
	},
	"CAPEC-113": {
		Name: "CAPEC-113: Interface Manipulation",
	},
	"CAPEC-114": {
		Name: "CAPEC-114: Authentication Abuse",
	},
	"CAPEC-115": {
		Name: "CAPEC-115: Authentication Bypass",
	},
	"CAPEC-116": {
		Name: "CAPEC-116: Excavation",
	},
	"CAPEC-117": {
		Name: "CAPEC-117: Interception",
	},
	"CAPEC-12": {
		Name: "CAPEC-12: Choosing Message Identifier",
	},
	"CAPEC-120": {
		Name: "CAPEC-120: Double Encoding",
	},
	"CAPEC-121": {
		Name: "CAPEC-121: Exploit Non-Production Interfaces",
	},
	"CAPEC-122": {
		Name: "CAPEC-122: Privilege Abuse",
	},
	"CAPEC-123": {
		Name: "CAPEC-123: Buffer Manipulation",
	},
	"CAPEC-124": {
		Name: "CAPEC-124: Shared Resource Manipulation",
	},
	"CAPEC-125": {
		Name: "CAPEC-125: Flooding",
	},
	"CAPEC-126": {
		Name: "CAPEC-126: Path Traversal",
	},
	"CAPEC-127": {
		Name: "CAPEC-127: Directory Indexing",
	},
	"CAPEC-128": {
		Name: "CAPEC-128: Integer Attacks",
	},
	"CAPEC-129": {
		Name: "CAPEC-129: Pointer Manipulation",
	},
	"CAPEC-13": {
		Name: "CAPEC-13: Subverting Environment Variable Values",
	},
	"CAPEC-130": {
		Name: "CAPEC-130: Excessive Allocation",
	},
	"CAPEC-131": {
		Name: "CAPEC-131: Resource Leak Exposure",
	},
	"CAPEC-132": {
		Name: "CAPEC-132: Symlink Attack",
	},
	"CAPEC-133": {
		Name: "CAPEC-133: Try All Common Switches",
	},
	"CAPEC-134": {
		Name: "CAPEC-134: Email Injection",
	},
	"CAPEC-135": {
		Name: "CAPEC-135: Format String Injection",
	},
	"CAPEC-136": {
		Name: "CAPEC-136: LDAP Injection",
	},
	"CAPEC-137": {
		Name: "CAPEC-137: Parameter Injection",
	},
	"CAPEC-138": {
		Name: "CAPEC-138: Reflection Injection",
	},
	"CAPEC-139": {
		Name: "CAPEC-139: Relative Path Traversal",
	},
	"CAPEC-14": {
		Name: "CAPEC-14: Client-side Injection-induced Buffer Overflow",
	},
	"CAPEC-140": {
		Name: "CAPEC-140: Bypassing of Intermediate Forms in Multiple-Form Sets",
	},
	"CAPEC-141": {
		Name: "CAPEC-141: Cache Poisoning",
	},
	"CAPEC-142": {
		Name: "CAPEC-142: DNS Cache Poisoning",
	},
	"CAPEC-143": {
		Name: "CAPEC-143: Detect Unpublicized Web Pages",
	},
	"CAPEC-144": {
		Name: "CAPEC-144: Detect Unpublicized Web Services",
	},
	"CAPEC-145": {
		Name: "CAPEC-145: Checksum Spoofing",
	},
	"CAPEC-146": {
		Name: "CAPEC-146: XML Schema Poisoning",
	},
	"CAPEC-147": {
		Name: "CAPEC-147: XML Ping of the Death",
	},
	"CAPEC-148": {
		Name: "CAPEC-148: Content Spoofing",
	},
	"CAPEC-149": {
		Name: "CAPEC-149: Explore for Predictable Temporary File Names",
	},
	"CAPEC-15": {
		Name: "CAPEC-15: Command Delimiters",
	},
	"CAPEC-150": {
		Name: "CAPEC-150: Collect Data from Common Resource Locations",
	},
	"CAPEC-151": {
		Name: "CAPEC-151: Identity Spoofing",
	},
	"CAPEC-153": {
		Name: "CAPEC-153: Input Data Manipulation",
	},
	"CAPEC-154": {
		Name: "CAPEC-154: Resource Location Spoofing",
	},
	"CAPEC-155": {
		Name: "CAPEC-155: Screen Temporary Files for Sensitive Information",
	},
	"CAPEC-157": {
		Name: "CAPEC-157: Sniffing Attacks",
	},
	"CAPEC-158": {
		Name: "CAPEC-158: Sniffing Network Traffic",
	},
	"CAPEC-159": {
		Name: "CAPEC-159: Redirect Access to Libraries",
	},
	"CAPEC-16": {
		Name: "CAPEC-16: Dictionary-based Password Attack",
	},
	"CAPEC-160": {
		Name: "CAPEC-160: Exploit Script-Based APIs",
	},
	"CAPEC-161": {
		Name: "CAPEC-161: Infrastructure Manipulation",
	},
	"CAPEC-162": {
		Name: "CAPEC-162: Manipulating Hidden Fields",
	},
	"CAPEC-163": {
		Name: "CAPEC-163: Spear Phishing",
	},
	"CAPEC-164": {
		Name: "CAPEC-164: Mobile Phishing",
	},
	"CAPEC-165": {
		Name: "CAPEC-165: File Manipulation",
	},
	"CAPEC-166": {
		Name: "CAPEC-166: Force the System to Reset Values",
	},
	"CAPEC-167": {
		Name: "CAPEC-167: White Box Reverse Engineering",
	},
	"CAPEC-168": {
		Name: "CAPEC-168: Windows ::DATA Alternate Data Stream",
	},
	"CAPEC-169": {
		Name: "CAPEC-169: Footprinting",
	},
	"CAPEC-17": {
		Name: "CAPEC-17: Using Malicious Files",
	},
	"CAPEC-170": {
		Name: "CAPEC-170: Web Application Fingerprinting",
	},
	"CAPEC-173": {
		Name: "CAPEC-173: Action Spoofing",
	},
	"CAPEC-174": {
		Name: "CAPEC-174: Flash Parameter Injection",
	},
	"CAPEC-175": {
		Name: "CAPEC-175: Code Inclusion",
	},
	"CAPEC-176": {
		Name: "CAPEC-176: Configuration/Environment Manipulation",
	},
	"CAPEC-177": {
		Name: "CAPEC-177: Create files with the same name as files protected with a higher classification",
	},
	"CAPEC-178": {
		Name: "CAPEC-178: Cross-Site Flashing",
	},
	"CAPEC-179": {
		Name: "CAPEC-179: Calling Micro-Services Directly",
	},
	"CAPEC-18": {
		Name: "CAPEC-18: XSS Targeting Non-Script Elements",
	},
	"CAPEC-180": {
		Name: "CAPEC-180: Exploiting Incorrectly Configured Access Control Security Levels",
	},
	"CAPEC-181": {
		Name: "CAPEC-181: Flash File Overlay",
	},
	"CAPEC-182": {
		Name: "CAPEC-182: Flash Injection",
	},
	"CAPEC-183": {
		Name: "CAPEC-183: IMAP/SMTP Command Injection",
	},
	"CAPEC-184": {
		Name: "CAPEC-184: Software Integrity Attack",
	},
	"CAPEC-185": {
		Name: "CAPEC-185: Malicious Software Download",
	},
	"CAPEC-186": {
		Name: "CAPEC-186: Malicious Software Update",
	},
	"CAPEC-187": {
		Name: "CAPEC-187: Malicious Automated Software Update via Redirection",
	},
	"CAPEC-188": {
		Name: "CAPEC-188: Reverse Engineering",
	},
	"CAPEC-189": {
		Name: "CAPEC-189: Black Box Reverse Engineering",
	},
	"CAPEC-19": {
		Name: "CAPEC-19: Embedding Scripts within Scripts",
	},
	"CAPEC-190": {
		Name: "CAPEC-190: Reverse Engineer an Executable to Expose Assumed Hidden Functionality",
	},
	"CAPEC-191": {
		Name: "CAPEC-191: Read Sensitive Constants Within an Executable",
	},
	"CAPEC-192": {
		Name: "CAPEC-192: Protocol Analysis",
	},
	"CAPEC-193": {
		Name: "CAPEC-193: PHP Remote File Inclusion",
	},
	"CAPEC-194": {
		Name: "CAPEC-194: Fake the Source of Data",
	},
	"CAPEC-195": {
		Name: "CAPEC-195: Principal Spoof",
	},
	"CAPEC-196": {
		Name: "CAPEC-196: Session Credential Falsification through Forging",
	},
	"CAPEC-197": {
		Name: "CAPEC-197: Exponential Data Expansion",
	},
	"CAPEC-198": {
		Name: "CAPEC-198: XSS Targeting Error Pages",
	},
	"CAPEC-199": {
		Name: "CAPEC-199: XSS Using Alternate Syntax",
	},
	"CAPEC-2": {
		Name: "CAPEC-2: Inducing Account Lockout",
	},
	"CAPEC-20": {
		Name: "CAPEC-20: Encryption Brute Forcing",
	},
	"CAPEC-200": {
		Name: "CAPEC-200: Removal of filters: Input filters, output filters, data masking",
	},
	"CAPEC-201": {
		Name: "CAPEC-201: Serialized Data External Linking",
	},
	"CAPEC-202": {
		Name: "CAPEC-202: Create Malicious Client",
	},
	"CAPEC-203": {
		Name: "CAPEC-203: Manipulate Registry Information",
	},
	"CAPEC-204": {
		Name: "CAPEC-204: Lifting Sensitive Data Embedded in Cache",
	},
	"CAPEC-206": {
		Name: "CAPEC-206: Signing Malicious Code",
	},
	"CAPEC-207": {
		Name: "CAPEC-207: Removing Important Client Functionality",
	},
	"CAPEC-208": {
		Name: "CAPEC-208: Removing/short-circuiting 'Purse' logic: removing/mutating 'cash' decrements",
	},
	"CAPEC-209": {
		Name: "CAPEC-209: XSS Using MIME Type Mismatch",
	},
	"CAPEC-21": {
		Name: "CAPEC-21: Exploitation of Trusted Identifiers",
	},
	"CAPEC-212": {
		Name: "CAPEC-212: Functionality Misuse",
	},
	"CAPEC-215": {
		Name: "CAPEC-215: Fuzzing for application mapping",
	},
	"CAPEC-216": {
		Name: "CAPEC-216: Communication Channel Manipulation",
	},
	"CAPEC-217": {
		Name: "CAPEC-217: Exploiting Incorrectly Configured SSL/TLS",
	},
	"CAPEC-218": {
		Name: "CAPEC-218: Spoofing of UDDI/ebXML Messages",
	},
	"CAPEC-219": {
		Name: "CAPEC-219: XML Routing Detour Attacks",
	},
	"CAPEC-22": {
		Name: "CAPEC-22: Exploiting Trust in Client",
	},
	"CAPEC-220": {
		Name: "CAPEC-220: Client-Server Protocol Manipulation",
	},
	"CAPEC-221": {
		Name: "CAPEC-221: Data Serialization External Entities Blowup",
	},
	"CAPEC-222": {
		Name: "CAPEC-222: iFrame Overlay",
	},
	"CAPEC-224": {
		Name: "CAPEC-224: Fingerprinting",
	},
	"CAPEC-226": {
		Name: "CAPEC-226: Session Credential Falsification through Manipulation",
	},
	"CAPEC-227": {
		Name: "CAPEC-227: Sustained Client Engagement",
	},
	"CAPEC-228": {
		Name: "CAPEC-228: DTD Injection",
	},
	"CAPEC-229": {
		Name: "CAPEC-229: Serialized Data Parameter Blowup",
	},
	"CAPEC-23": {
		Name: "CAPEC-23: File Content Injection",
	},
	"CAPEC-230": {
		Name: "CAPEC-230: Serialized Data with Nested Payloads",
	},
	"CAPEC-231": {
		Name: "CAPEC-231: Oversized Serialized Data Payloads",
	},
	"CAPEC-233": {
		Name: "CAPEC-233: Privilege Escalation",
	},
	"CAPEC-234": {
		Name: "CAPEC-234: Hijacking a privileged process",
	},
	"CAPEC-237": {
		Name: "CAPEC-237: Escaping a Sandbox by Calling Code in Another Language",
	},
	"CAPEC-24": {
		Name: "CAPEC-24: Filter Failure through Buffer Overflow",
	},
	"CAPEC-240": {
		Name: "CAPEC-240: Resource Injection",
	},
	"CAPEC-242": {
		Name: "CAPEC-242: Code Injection",
	},
	"CAPEC-243": {
		Name: "CAPEC-243: XSS Targeting HTML Attributes",
	},
	"CAPEC-244": {
		Name: "CAPEC-244: XSS Targeting URI Placeholders",
	},
	"CAPEC-245": {
		Name: "CAPEC-245: XSS Using Doubled Characters",
	},
	"CAPEC-247": {
		Name: "CAPEC-247: XSS Using Invalid Characters",
	},
	"CAPEC-248": {
		Name: "CAPEC-248: Command Injection",
	},
	"CAPEC-25": {
		Name: "CAPEC-25: Forced Deadlock",
	},
	"CAPEC-250": {
		Name: "CAPEC-250: XML Injection",
	},
	"CAPEC-251": {
		Name: "CAPEC-251: Local Code Inclusion",
	},
	"CAPEC-252": {
		Name: "CAPEC-252: PHP Local File Inclusion",
	},
	"CAPEC-253": {
		Name: "CAPEC-253: Remote Code Inclusion",
	},
	"CAPEC-256": {
		Name: "CAPEC-256: SOAP Array Overflow",
	},
	"CAPEC-26": {
		Name: "CAPEC-26: Leveraging Race Conditions",
	},
	"CAPEC-261": {
		Name: "CAPEC-261: Fuzzing for garnering other adjacent user/sensitive data",
	},
	"CAPEC-263": {
		Name: "CAPEC-263: Force Use of Corrupted Files",
	},
	"CAPEC-267": {
		Name: "CAPEC-267: Leverage Alternate Encoding",
	},
	"CAPEC-268": {
		Name: "CAPEC-268: Audit Log Manipulation",
	},
	"CAPEC-27": {
		Name: "CAPEC-27: Leveraging Race Conditions via Symbolic Links",
	},
	"CAPEC-270": {
		Name: "CAPEC-270: Modification of Registry Run Keys",
	},
	"CAPEC-271": {
		Name: "CAPEC-271: Schema Poisoning",
	},
	"CAPEC-272": {
		Name: "CAPEC-272: Protocol Manipulation",
	},
	"CAPEC-273": {
		Name: "CAPEC-273: HTTP Response Smuggling",
	},
	"CAPEC-274": {
		Name: "CAPEC-274: HTTP Verb Tampering",
	},
	"CAPEC-275": {
		Name: "CAPEC-275: DNS Rebinding",
	},
	"CAPEC-276": {
		Name: "CAPEC-276: Inter-component Protocol Manipulation",
	},
	"CAPEC-277": {
		Name: "CAPEC-277: Data Interchange Protocol Manipulation",
	},
	"CAPEC-278": {
		Name: "CAPEC-278: Web Services Protocol Manipulation",
	},
	"CAPEC-279": {
		Name: "CAPEC-279: SOAP Manipulation",
	},
	"CAPEC-28": {
		Name: "CAPEC-28: Fuzzing",
	},
	"CAPEC-285": {
		Name: "CAPEC-285: ICMP Echo Request Ping",
	},
	"CAPEC-287": {
		Name: "CAPEC-287: TCP SYN Scan",
	},
	"CAPEC-29": {
		Name: "CAPEC-29: Leveraging Time-of-Check and Time-of-Use (TOCTOU) Race Conditions",
	},
	"CAPEC-290": {
		Name: "CAPEC-290: Enumerate Mail Exchange (MX) Records",
	},
	"CAPEC-291": {
		Name: "CAPEC-291: DNS Zone Transfers",
	},
	"CAPEC-292": {
		Name: "CAPEC-292: Host Discovery",
	},
	"CAPEC-293": {
		Name: "CAPEC-293: Traceroute Route Enumeration",
	},
	"CAPEC-294": {
		Name: "CAPEC-294: ICMP Address Mask Request",
	},
	"CAPEC-295": {
		Name: "CAPEC-295: Timestamp Request",
	},
	"CAPEC-296": {
		Name: "CAPEC-296: ICMP Information Request",
	},
	"CAPEC-297": {
		Name: "CAPEC-297: TCP ACK Ping",
	},
	"CAPEC-298": {
		Name: "CAPEC-298: UDP Ping",
	},
	"CAPEC-299": {
		Name: "CAPEC-299: TCP SYN Ping",
	},
	"CAPEC-3": {
		Name: "CAPEC-3: Using Leading 'Ghost' Character Sequences to Bypass Input Filters",
	},
	"CAPEC-30": {
		Name: "CAPEC-30: Hijacking a Privileged Thread of Execution",
	},
	"CAPEC-300": {
		Name: "CAPEC-300: Port Scanning",
	},
	"CAPEC-301": {
		Name: "CAPEC-301: TCP Connect Scan",
	},
	"CAPEC-302": {
		Name: "CAPEC-302: TCP FIN Scan",
	},
	"CAPEC-303": {
		Name: "CAPEC-303: TCP Xmas Scan",
	},
	"CAPEC-304": {
		Name: "CAPEC-304: TCP Null Scan",
	},
	"CAPEC-305": {
		Name: "CAPEC-305: TCP ACK Scan",
	},
	"CAPEC-306": {
		Name: "CAPEC-306: TCP Window Scan",
	},
	"CAPEC-307": {
		Name: "CAPEC-307: TCP RPC Scan",
	},
	"CAPEC-308": {
		Name: "CAPEC-308: UDP Scan",
	},
	"CAPEC-309": {
		Name: "CAPEC-309: Network Topology Mapping",
	},
	"CAPEC-31": {
		Name: "CAPEC-31: Accessing/Intercepting/Modifying HTTP Cookies",
	},
	"CAPEC-310": {
		Name: "CAPEC-310: Scanning for Vulnerable Software",
	},
	"CAPEC-312": {
		Name: "CAPEC-312: Active OS Fingerprinting",
	},
	"CAPEC-313": {
		Name: "CAPEC-313: Passive OS Fingerprinting",
	},
	"CAPEC-317": {
		Name: "CAPEC-317: IP ID Sequencing Probe",
	},
	"CAPEC-318": {
		Name: "CAPEC-318: IP 'ID' Echoed Byte-Order Probe",
	},
	"CAPEC-319": {
		Name: "CAPEC-319: IP (DF) 'Don't Fragment Bit' Echoing Probe",
	},
	"CAPEC-32": {
		Name: "CAPEC-32: XSS Through HTTP Query Strings",
	},
	"CAPEC-320": {
		Name: "CAPEC-320: TCP Timestamp Probe",
	},
	"CAPEC-321": {
		Name: "CAPEC-321: TCP Sequence Number Probe",
	},
	"CAPEC-322": {
		Name: "CAPEC-322: TCP (ISN) Greatest Common Divisor Probe",
	},
	"CAPEC-323": {
		Name: "CAPEC-323: TCP (ISN) Counter Rate Probe",
	},
	"CAPEC-324": {
		Name: "CAPEC-324: TCP (ISN) Sequence Predictability Probe",
	},
	"CAPEC-325": {
		Name: "CAPEC-325: TCP Congestion Control Flag (ECN) Probe",
	},
	"CAPEC-326": {
		Name: "CAPEC-326: TCP Initial Window Size Probe",
	},
	"CAPEC-327": {
		Name: "CAPEC-327: TCP Options Probe",
	},
	"CAPEC-328": {
		Name: "CAPEC-328: TCP 'RST' Flag Checksum Probe",
	},
	"CAPEC-329": {
		Name: "CAPEC-329: ICMP Error Message Quoting Probe",
	},
	"CAPEC-33": {
		Name: "CAPEC-33: HTTP Request Smuggling",
	},
	"CAPEC-330": {
		Name: "CAPEC-330: ICMP Error Message Echoing Integrity Probe",
	},
	"CAPEC-331": {
		Name: "CAPEC-331: ICMP IP Total Length Field Probe",
	},
	"CAPEC-332": {
		Name: "CAPEC-332: ICMP IP 'ID' Field Error Message Probe",
	},
	"CAPEC-34": {
		Name: "CAPEC-34: HTTP Response Splitting",
	},
	"CAPEC-35": {
		Name: "CAPEC-35: Leverage Executable Code in Non-Executable Files",
	},
	"CAPEC-36": {
		Name: "CAPEC-36: Using Unpublished Interfaces or Functionality",
	},
	"CAPEC-37": {
		Name: "CAPEC-37: Retrieve Embedded Sensitive Data",
	},
	"CAPEC-38": {
		Name: "CAPEC-38: Leveraging/Manipulating Configuration File Search Paths",
	},
	"CAPEC-383": {
		Name: "CAPEC-383: Harvesting Information via API Event Monitoring",
	},
	"CAPEC-384": {
		Name: "CAPEC-384: Application API Message Manipulation via Man-in-the-Middle",
	},
	"CAPEC-385": {
		Name: "CAPEC-385: Transaction or Event Tampering via Application API Manipulation",
	},
	"CAPEC-386": {
		Name: "CAPEC-386: Application API Navigation Remapping",
	},
	"CAPEC-387": {
		Name: "CAPEC-387: Navigation Remapping To Propagate Malicious Content",
	},
	"CAPEC-388": {
		Name: "CAPEC-388: Application API Button Hijacking",
	},
	"CAPEC-389": {
		Name: "CAPEC-389: Content Spoofing Via Application API Manipulation",
	},
	"CAPEC-39": {
		Name: "CAPEC-39: Manipulating Opaque Client-based Data Tokens",
	},
	"CAPEC-390": {
		Name: "CAPEC-390: Bypassing Physical Security",
	},
	"CAPEC-391": {
		Name: "CAPEC-391: Bypassing Physical Locks",
	},
	"CAPEC-392": {
		Name: "CAPEC-392: Lock Bumping",
	},
	"CAPEC-393": {
		Name: "CAPEC-393: Lock Picking",
	},
	"CAPEC-394": {
		Name: "CAPEC-394: Using a Snap Gun Lock to Force a Lock",
	},
	"CAPEC-395": {
		Name: "CAPEC-395: Bypassing Electronic Locks and Access Controls",
	},
	"CAPEC-397": {
		Name: "CAPEC-397: Cloning Magnetic Strip Cards",
	},
	"CAPEC-398": {
		Name: "CAPEC-398: Magnetic Strip Card Brute Force Attacks",
	},
	"CAPEC-399": {
		Name: "CAPEC-399: Cloning RFID Cards or Chips",
	},
	"CAPEC-4": {
		Name: "CAPEC-4: Using Alternative IP Address Encodings",
	},
	"CAPEC-40": {
		Name: "CAPEC-40: Manipulating Writeable Terminal Devices",
	},
	"CAPEC-400": {
		Name: "CAPEC-400: RFID Chip Deactivation or Destruction",
	},
	"CAPEC-401": {
		Name: "CAPEC-401: Physically Hacking Hardware",
	},
	"CAPEC-402": {
		Name: "CAPEC-402: Bypassing ATA Password Security",
	},
	"CAPEC-406": {
		Name: "CAPEC-406: Dumpster Diving",
	},
	"CAPEC-407": {
		Name: "CAPEC-407: Pretexting",
	},
	"CAPEC-41": {
		Name: "CAPEC-41: Using Meta-characters in E-mail Headers to Inject Malicious Payloads",
	},
	"CAPEC-410": {
		Name: "CAPEC-410: Information Elicitation",
	},
	"CAPEC-412": {
		Name: "CAPEC-412: Pretexting via Customer Service",
	},
	"CAPEC-413": {
		Name: "CAPEC-413: Pretexting via Tech Support",
	},
	"CAPEC-414": {
		Name: "CAPEC-414: Pretexting via Delivery Person",
	},
	"CAPEC-415": {
		Name: "CAPEC-415: Pretexting via Phone",
	},
	"CAPEC-416": {
		Name: "CAPEC-416: Manipulate Human Behavior",
	},
	"CAPEC-417": {
		Name: "CAPEC-417: Influence Perception",
	},
	"CAPEC-418": {
		Name: "CAPEC-418: Influence Perception of Reciprocation",
	},
	"CAPEC-42": {
		Name: "CAPEC-42: MIME Conversion",
	},
	"CAPEC-420": {
		Name: "CAPEC-420: Influence Perception of Scarcity",
	},
	"CAPEC-421": {
		Name: "CAPEC-421: Influence Perception of Authority",
	},
	"CAPEC-422": {
		Name: "CAPEC-422: Influence Perception of Commitment and Consistency",
	},
	"CAPEC-423": {
		Name: "CAPEC-423: Influence Perception of Liking",
	},
	"CAPEC-424": {
		Name: "CAPEC-424: Influence Perception of Consensus or Social Proof",
	},
	"CAPEC-425": {
		Name: "CAPEC-425: Target Influence via Framing",
	},
	"CAPEC-426": {
		Name: "CAPEC-426: Influence via Incentives",
	},
	"CAPEC-427": {
		Name: "CAPEC-427: Influence via Psychological Principles",
	},
	"CAPEC-428": {
		Name: "CAPEC-428: Influence via Modes of Thinking",
	},
	"CAPEC-429": {
		Name: "CAPEC-429: Target Influence via Eye Cues",
	},
	"CAPEC-43": {
		Name: "CAPEC-43: Exploiting Multiple Input Interpretation Layers",
	},
	"CAPEC-433": {
		Name: "CAPEC-433: Target Influence via The Human Buffer Overflow",
	},
	"CAPEC-434": {
		Name: "CAPEC-434: Target Influence via Interview and Interrogation",
	},
	"CAPEC-435": {
		Name: "CAPEC-435: Target Influence via Instant Rapport",
	},
	"CAPEC-438": {
		Name: "CAPEC-438: Modification During Manufacture",
	},
	"CAPEC-439": {
		Name: "CAPEC-439: Manipulation During Distribution",
	},
	"CAPEC-44": {
		Name: "CAPEC-44: Overflow Binary Resource File",
	},
	"CAPEC-440": {
		Name: "CAPEC-440: Hardware Integrity Attack",
	},
	"CAPEC-441": {
		Name: "CAPEC-441: Malicious Logic Insertion",
	},
	"CAPEC-442": {
		Name: "CAPEC-442: Infected Software",
	},
	"CAPEC-443": {
		Name: "CAPEC-443: Malicious Logic Inserted Into Product by Authorized Developer",
	},
	"CAPEC-444": {
		Name: "CAPEC-444: Development Alteration",
	},
	"CAPEC-445": {
		Name: "CAPEC-445: Malicious Logic Insertion into Product Software via Configuration Management Manipulation",
	},
	"CAPEC-446": {
		Name: "CAPEC-446: Malicious Logic Insertion into Product via Inclusion of Third-Party Component",
	},
	"CAPEC-447": {
		Name: "CAPEC-447: Design Alteration",
	},
	"CAPEC-448": {
		Name: "CAPEC-448: Embed Virus into DLL",
	},
	"CAPEC-45": {
		Name: "CAPEC-45: Buffer Overflow via Symbolic Links",
	},
	"CAPEC-452": {
		Name: "CAPEC-452: Infected Hardware",
	},
	"CAPEC-456": {
		Name: "CAPEC-456: Infected Memory",
	},
	"CAPEC-457": {
		Name: "CAPEC-457: USB Memory Attacks",
	},
	"CAPEC-458": {
		Name: "CAPEC-458: Flash Memory Attacks",
	},
	"CAPEC-459": {
		Name: "CAPEC-459: Creating a Rogue Certification Authority Certificate",
	},
	"CAPEC-46": {
		Name: "CAPEC-46: Overflow Variables and Tags",
	},
	"CAPEC-460": {
		Name: "CAPEC-460: HTTP Parameter Pollution (HPP)",
	},
	"CAPEC-461": {
		Name: "CAPEC-461: Web Services API Signature Forgery Leveraging Hash Function Extension Weakness",
	},
	"CAPEC-462": {
		Name: "CAPEC-462: Cross-Domain Search Timing",
	},
	"CAPEC-463": {
		Name: "CAPEC-463: Padding Oracle Crypto Attack",
	},
	"CAPEC-464": {
		Name: "CAPEC-464: Evercookie",
	},
	"CAPEC-465": {
		Name: "CAPEC-465: Transparent Proxy Abuse",
	},
	"CAPEC-466": {
		Name: "CAPEC-466: Leveraging Active Adversary in the Middle Attacks to Bypass Same Origin Policy",
	},
	"CAPEC-467": {
		Name: "CAPEC-467: Cross Site Identification",
	},
	"CAPEC-468": {
		Name: "CAPEC-468: Generic Cross-Browser Cross-Domain Theft",
	},
	"CAPEC-469": {
		Name: "CAPEC-469: HTTP DoS",
	},
	"CAPEC-47": {
		Name: "CAPEC-47: Buffer Overflow via Parameter Expansion",
	},
	"CAPEC-470": {
		Name: "CAPEC-470: Expanding Control over the Operating System from the Database",
	},
	"CAPEC-471": {
		Name: "CAPEC-471: Search Order Hijacking",
	},
	"CAPEC-472": {
		Name: "CAPEC-472: Browser Fingerprinting",
	},
	"CAPEC-473": {
		Name: "CAPEC-473: Signature Spoof",
	},
	"CAPEC-474": {
		Name: "CAPEC-474: Signature Spoofing by Key Theft",
	},
	"CAPEC-475": {
		Name: "CAPEC-475: Signature Spoofing by Improper Validation",
	},
	"CAPEC-476": {
		Name: "CAPEC-476: Signature Spoofing by Misrepresentation",
	},
	"CAPEC-477": {
		Name: "CAPEC-477: Signature Spoofing by Mixing Signed and Unsigned Content",
	},
	"CAPEC-478": {
		Name: "CAPEC-478: Modification of Windows Service Configuration",
	},
	"CAPEC-479": {
		Name: "CAPEC-479: Malicious Root Certificate",
	},
	"CAPEC-48": {
		Name: "CAPEC-48: Passing Local Filenames to Functions That Expect a URL",
	},
	"CAPEC-480": {
		Name: "CAPEC-480: Escaping Virtualization",
	},
	"CAPEC-481": {
		Name: "CAPEC-481: Contradictory Destinations in Traffic Routing Schemes",
	},
	"CAPEC-482": {
		Name: "CAPEC-482: TCP Flood",
	},
	"CAPEC-485": {
		Name: "CAPEC-485: Signature Spoofing by Key Recreation",
	},
	"CAPEC-486": {
		Name: "CAPEC-486: UDP Flood",
	},
	"CAPEC-487": {
		Name: "CAPEC-487: ICMP Flood",
	},
	"CAPEC-488": {
		Name: "CAPEC-488: HTTP Flood",
	},
	"CAPEC-489": {
		Name: "CAPEC-489: SSL Flood",
	},
	"CAPEC-49": {
		Name: "CAPEC-49: Password Brute Forcing",
	},
	"CAPEC-490": {
		Name: "CAPEC-490: Amplification",
	},
	"CAPEC-491": {
		Name: "CAPEC-491: Quadratic Data Expansion",
	},
	"CAPEC-492": {
		Name: "CAPEC-492: Regular Expression Exponential Blowup",
	},
	"CAPEC-493": {
		Name: "CAPEC-493: SOAP Array Blowup",
	},
	"CAPEC-494": {
		Name: "CAPEC-494: TCP Fragmentation",
	},
	"CAPEC-495": {
		Name: "CAPEC-495: UDP Fragmentation",
	},
	"CAPEC-496": {
		Name: "CAPEC-496: ICMP Fragmentation",
	},
	"CAPEC-497": {
		Name: "CAPEC-497: File Discovery",
	},
	"CAPEC-498": {
		Name: "CAPEC-498: Probe iOS Screenshots",
	},
	"CAPEC-499": {
		Name: "CAPEC-499: Android Intent Intercept",
	},
	"CAPEC-5": {
		Name: "CAPEC-5: Blue Boxing",
	},
	"CAPEC-50": {
		Name: "CAPEC-50: Password Recovery Exploitation",
	},
	"CAPEC-500": {
		Name: "CAPEC-500: WebView Injection",
	},
	"CAPEC-501": {
		Name: "CAPEC-501: Android Activity Hijack",
	},
	"CAPEC-502": {
		Name: "CAPEC-502: Intent Spoof",
	},
	"CAPEC-503": {
		Name: "CAPEC-503: WebView Exposure",
	},
	"CAPEC-504": {
		Name: "CAPEC-504: Task Impersonation",
	},
	"CAPEC-505": {
		Name: "CAPEC-505: Scheme Squatting",
	},
	"CAPEC-506": {
		Name: "CAPEC-506: Tapjacking",
	},
	"CAPEC-507": {
		Name: "CAPEC-507: Physical Theft",
	},
	"CAPEC-508": {
		Name: "CAPEC-508: Shoulder Surfing",
	},
	"CAPEC-509": {
		Name: "CAPEC-509: Kerberoasting",
	},
	"CAPEC-51": {
		Name: "CAPEC-51: Poison Web Service Registry",
	},
	"CAPEC-510": {
		Name: "CAPEC-510: SaaS User Request Forgery",
	},
	"CAPEC-511": {
		Name: "CAPEC-511: Infiltration of Software Development Environment",
	},
	"CAPEC-516": {
		Name: "CAPEC-516: Hardware Component Substitution During Baselining",
	},
	"CAPEC-517": {
		Name: "CAPEC-517: Documentation Alteration to Circumvent Dial-down",
	},
	"CAPEC-518": {
		Name: "CAPEC-518: Documentation Alteration to Produce Under-performing Systems",
	},
	"CAPEC-519": {
		Name: "CAPEC-519: Documentation Alteration to Cause Errors in System Design",
	},
	"CAPEC-52": {
		Name: "CAPEC-52: Embedding NULL Bytes",
	},
	"CAPEC-520": {
		Name: "CAPEC-520: Counterfeit Hardware Component Inserted During Product Assembly",
	},
	"CAPEC-521": {
		Name: "CAPEC-521: Hardware Design Specifications Are Altered",
	},
	"CAPEC-522": {
		Name: "CAPEC-522: Malicious Hardware Component Replacement",
	},
	"CAPEC-523": {
		Name: "CAPEC-523: Malicious Software Implanted",
	},
	"CAPEC-524": {
		Name: "CAPEC-524: Rogue Integration Procedures",
	},
	"CAPEC-528": {
		Name: "CAPEC-528: XML Flood",
	},
	"CAPEC-529": {
		Name: "CAPEC-529: Malware-Directed Internal Reconnaissance",
	},
	"CAPEC-53": {
		Name: "CAPEC-53: Postfix, Null Terminate, and Backslash",
	},
	"CAPEC-530": {
		Name: "CAPEC-530: Provide Counterfeit Component",
	},
	"CAPEC-531": {
		Name: "CAPEC-531: Hardware Component Substitution",
	},
	"CAPEC-532": {
		Name: "CAPEC-532: Altered Installed BIOS",
	},
	"CAPEC-533": {
		Name: "CAPEC-533: Malicious Manual Software Update",
	},
	"CAPEC-534": {
		Name: "CAPEC-534: Malicious Hardware Update",
	},
	"CAPEC-535": {
		Name: "CAPEC-535: Malicious Gray Market Hardware",
	},
	"CAPEC-536": {
		Name: "CAPEC-536: Data Injected During Configuration",
	},
	"CAPEC-537": {
		Name: "CAPEC-537: Infiltration of Hardware Development Environment",
	},
	"CAPEC-538": {
		Name: "CAPEC-538: Open-Source Library Manipulation",
	},
	"CAPEC-539": {
		Name: "CAPEC-539: ASIC With Malicious Functionality",
	},
	"CAPEC-54": {
		Name: "CAPEC-54: Query System for Information",
	},
	"CAPEC-540": {
		Name: "CAPEC-540: Overread Buffers",
	},
	"CAPEC-541": {
		Name: "CAPEC-541: Application Fingerprinting",
	},
	"CAPEC-542": {
		Name: "CAPEC-542: Targeted Malware",
	},
	"CAPEC-543": {
		Name: "CAPEC-543: Counterfeit Websites",
	},
	"CAPEC-544": {
		Name: "CAPEC-544: Counterfeit Organizations",
	},
	"CAPEC-545": {
		Name: "CAPEC-545: Pull Data from System Resources",
	},
	"CAPEC-546": {
		Name: "CAPEC-546: Incomplete Data Deletion in a Multi-Tenant Environment",
	},
	"CAPEC-547": {
		Name: "CAPEC-547: Physical Destruction of Device or Component",
	},
	"CAPEC-548": {
		Name: "CAPEC-548: Contaminate Resource",
	},
	"CAPEC-549": {
		Name: "CAPEC-549: Local Execution of Code",
	},
	"CAPEC-55": {
		Name: "CAPEC-55: Rainbow Table Password Cracking",
	},
	"CAPEC-550": {
		Name: "CAPEC-550: Install New Service",
	},
	"CAPEC-551": {
		Name: "CAPEC-551: Modify Existing Service",
	},
	"CAPEC-552": {
		Name: "CAPEC-552: Install Rootkit ",
	},
	"CAPEC-554": {
		Name: "CAPEC-554: Functionality Bypass",
	},
	"CAPEC-555": {
		Name: "CAPEC-555: Remote Services with Stolen Credentials",
	},
	"CAPEC-556": {
		Name: "CAPEC-556: Replace File Extension Handlers",
	},
	"CAPEC-558": {
		Name: "CAPEC-558: Replace Trusted Executable",
	},
	"CAPEC-559": {
		Name: "CAPEC-559: Orbital Jamming",
	},
	"CAPEC-560": {
		Name: "CAPEC-560: Use of Known Domain Credentials",
	},
	"CAPEC-561": {
		Name: "CAPEC-561: Windows Admin Shares with Stolen Credentials",
	},
	"CAPEC-562": {
		Name: "CAPEC-562: Modify Shared File",
	},
	"CAPEC-563": {
		Name: "CAPEC-563: Add Malicious File to Shared Webroot",
	},
	"CAPEC-564": {
		Name: "CAPEC-564: Run Software at Logon",
	},
	"CAPEC-565": {
		Name: "CAPEC-565: Password Spraying",
	},
	"CAPEC-568": {
		Name: "CAPEC-568: Capture Credentials via Keylogger",
	},
	"CAPEC-569": {
		Name: "CAPEC-569: Collect Data as Provided by Users",
	},
	"CAPEC-57": {
		Name: "CAPEC-57: Utilizing REST's Trust in the System Resource to Obtain Sensitive Data",
	},
	"CAPEC-571": {
		Name: "CAPEC-571: Block Logging to Central Repository",
	},
	"CAPEC-572": {
		Name: "CAPEC-572: Artificially Inflate File Sizes",
	},
	"CAPEC-573": {
		Name: "CAPEC-573: Process Footprinting",
	},
	"CAPEC-574": {
		Name: "CAPEC-574: Services Footprinting",
	},
	"CAPEC-575": {
		Name: "CAPEC-575: Account Footprinting",
	},
	"CAPEC-576": {
		Name: "CAPEC-576: Group Permission Footprinting",
	},
	"CAPEC-577": {
		Name: "CAPEC-577: Owner Footprinting",
	},
	"CAPEC-578": {
		Name: "CAPEC-578: Disable Security Software",
	},
	"CAPEC-579": {
		Name: "CAPEC-579: Replace Winlogon Helper DLL",
	},
	"CAPEC-58": {
		Name: "CAPEC-58: Restful Privilege Elevation",
	},
	"CAPEC-580": {
		Name: "CAPEC-580: System Footprinting",
	},
	"CAPEC-581": {
		Name: "CAPEC-581: Security Software Footprinting",
	},
	"CAPEC-582": {
		Name: "CAPEC-582: Route Disabling",
	},
	"CAPEC-583": {
		Name: "CAPEC-583: Disabling Network Hardware",
	},
	"CAPEC-584": {
		Name: "CAPEC-584: BGP Route Disabling",
	},
	"CAPEC-585": {
		Name: "CAPEC-585: DNS Domain Seizure",
	},
	"CAPEC-586": {
		Name: "CAPEC-586: Object Injection",
	},
	"CAPEC-587": {
		Name: "CAPEC-587: Cross Frame Scripting (XFS)",
	},
	"CAPEC-588": {
		Name: "CAPEC-588: DOM-Based XSS",
	},
	"CAPEC-589": {
		Name: "CAPEC-589: DNS Blocking",
	},
	"CAPEC-59": {
		Name: "CAPEC-59: Session Credential Falsification through Prediction",
	},
	"CAPEC-590": {
		Name: "CAPEC-590: IP Address Blocking",
	},
	"CAPEC-591": {
		Name: "CAPEC-591: Reflected XSS",
	},
	"CAPEC-592": {
		Name: "CAPEC-592: Stored XSS",
	},
	"CAPEC-593": {
		Name: "CAPEC-593: Session Hijacking",
	},
	"CAPEC-594": {
		Name: "CAPEC-594: Traffic Injection",
	},
	"CAPEC-595": {
		Name: "CAPEC-595: Connection Reset",
	},
	"CAPEC-596": {
		Name: "CAPEC-596: TCP RST Injection",
	},
	"CAPEC-597": {
		Name: "CAPEC-597: Absolute Path Traversal",
	},
	"CAPEC-598": {
		Name: "CAPEC-598: DNS Spoofing",
	},
	"CAPEC-599": {
		Name: "CAPEC-599: Terrestrial Jamming",
	},
	"CAPEC-6": {
		Name: "CAPEC-6: Argument Injection",
	},
	"CAPEC-60": {
		Name: "CAPEC-60: Reusing Session IDs (aka Session Replay)",
	},
	"CAPEC-600": {
		Name: "CAPEC-600: Credential Stuffing",
	},
	"CAPEC-601": {
		Name: "CAPEC-601: Jamming",
	},
	"CAPEC-603": {
		Name: "CAPEC-603: Blockage",
	},
	"CAPEC-604": {
		Name: "CAPEC-604: Wi-Fi Jamming",
	},
	"CAPEC-605": {
		Name: "CAPEC-605: Cellular Jamming",
	},
	"CAPEC-606": {
		Name: "CAPEC-606: Weakening of Cellular Encryption",
	},
	"CAPEC-607": {
		Name: "CAPEC-607: Obstruction",
	},
	"CAPEC-608": {
		Name: "CAPEC-608: Cryptanalysis of Cellular Encryption",
	},
	"CAPEC-609": {
		Name: "CAPEC-609: Cellular Traffic Intercept",
	},
	"CAPEC-61": {
		Name: "CAPEC-61: Session Fixation",
	},
	"CAPEC-610": {
		Name: "CAPEC-610: Cellular Data Injection",
	},
	"CAPEC-611": {
		Name: "CAPEC-611: BitSquatting",
	},
	"CAPEC-612": {
		Name: "CAPEC-612: WiFi MAC Address Tracking",
	},
	"CAPEC-613": {
		Name: "CAPEC-613: WiFi SSID Tracking",
	},
	"CAPEC-614": {
		Name: "CAPEC-614: Rooting SIM Cards",
	},
	"CAPEC-615": {
		Name: "CAPEC-615: Evil Twin Wi-Fi Attack",
	},
	"CAPEC-616": {
		Name: "CAPEC-616: Establish Rogue Location",
	},
	"CAPEC-617": {
		Name: "CAPEC-617: Cellular Rogue Base Station",
	},
	"CAPEC-618": {
		Name: "CAPEC-618: Cellular Broadcast Message Request",
	},
	"CAPEC-619": {
		Name: "CAPEC-619: Signal Strength Tracking",
	},
	"CAPEC-62": {
		Name: "CAPEC-62: Cross Site Request Forgery",
	},
	"CAPEC-620": {
		Name: "CAPEC-620: Drop Encryption Level",
	},
	"CAPEC-621": {
		Name: "CAPEC-621: Analysis of Packet Timing and Sizes",
	},
	"CAPEC-622": {
		Name: "CAPEC-622: Electromagnetic Side-Channel Attack",
	},
	"CAPEC-623": {
		Name: "CAPEC-623: Compromising Emanations Attack",
	},
	"CAPEC-624": {
		Name: "CAPEC-624: Hardware Fault Injection",
	},
	"CAPEC-625": {
		Name: "CAPEC-625: Mobile Device Fault Injection",
	},
	"CAPEC-626": {
		Name: "CAPEC-626: Smudge Attack",
	},
	"CAPEC-627": {
		Name: "CAPEC-627: Counterfeit GPS Signals",
	},
	"CAPEC-628": {
		Name: "CAPEC-628: Carry-Off GPS Attack",
	},
	"CAPEC-63": {
		Name: "CAPEC-63: Cross-Site Scripting (XSS)",
	},
	"CAPEC-630": {
		Name: "CAPEC-630: TypoSquatting",
	},
	"CAPEC-631": {
		Name: "CAPEC-631: SoundSquatting",
	},
	"CAPEC-632": {
		Name: "CAPEC-632: Homograph Attack via Homoglyphs",
	},
	"CAPEC-633": {
		Name: "CAPEC-633: Token Impersonation",
	},
	"CAPEC-634": {
		Name: "CAPEC-634: Probe Audio and Video Peripherals",
	},
	"CAPEC-635": {
		Name: "CAPEC-635: Alternative Execution Due to Deceptive Filenames",
	},
	"CAPEC-636": {
		Name: "CAPEC-636: Hiding Malicious Data or Code within Files",
	},
	"CAPEC-637": {
		Name: "CAPEC-637: Collect Data from Clipboard",
	},
	"CAPEC-638": {
		Name: "CAPEC-638: Altered Component Firmware",
	},
	"CAPEC-639": {
		Name: "CAPEC-639: Probe System Files",
	},
	"CAPEC-64": {
		Name: "CAPEC-64: Using Slashes and URL Encoding Combined to Bypass Validation Logic",
	},
	"CAPEC-640": {
		Name: "CAPEC-640: Inclusion of Code in Existing Process",
	},
	"CAPEC-641": {
		Name: "CAPEC-641: DLL Side-Loading",
	},
	"CAPEC-642": {
		Name: "CAPEC-642: Replace Binaries",
	},
	"CAPEC-643": {
		Name: "CAPEC-643: Identify Shared Files/Directories on System",
	},
	"CAPEC-644": {
		Name: "CAPEC-644: Use of Captured Hashes (Pass The Hash)",
	},
	"CAPEC-645": {
		Name: "CAPEC-645: Use of Captured Tickets (Pass The Ticket)",
	},
	"CAPEC-646": {
		Name: "CAPEC-646: Peripheral Footprinting",
	},
	"CAPEC-647": {
		Name: "CAPEC-647: Collect Data from Registries",
	},
	"CAPEC-648": {
		Name: "CAPEC-648: Collect Data from Screen Capture",
	},
	"CAPEC-649": {
		Name: "CAPEC-649: Adding a Space to a File Extension",
	},
	"CAPEC-65": {
		Name: "CAPEC-65: Sniff Application Code",
	},
	"CAPEC-650": {
		Name: "CAPEC-650: Upload a Web Shell to a Web Server",
	},
	"CAPEC-651": {
		Name: "CAPEC-651: Eavesdropping",
	},
	"CAPEC-652": {
		Name: "CAPEC-652: Use of Known Kerberos Credentials",
	},
	"CAPEC-653": {
		Name: "CAPEC-653: Use of Known Operating System Credentials",
	},
	"CAPEC-654": {
		Name: "CAPEC-654: Credential Prompt Impersonation",
	},
	"CAPEC-655": {
		Name: "CAPEC-655: Avoid Security Tool Identification by Adding Data",
	},
	"CAPEC-656": {
		Name: "CAPEC-656: Voice Phishing",
	},
	"CAPEC-657": {
		Name: "CAPEC-657: Malicious Automated Software Update via Spoofing",
	},
	"CAPEC-66": {
		Name: "CAPEC-66: SQL Injection",
	},
	"CAPEC-660": {
		Name: "CAPEC-660: Root/Jailbreak Detection Evasion via Hooking",
	},
	"CAPEC-661": {
		Name: "CAPEC-661: Root/Jailbreak Detection Evasion via Debugging",
	},
	"CAPEC-662": {
		Name: "CAPEC-662: Adversary in the Browser (AiTB)",
	},
	"CAPEC-663": {
		Name: "CAPEC-663: Exploitation of Transient Instruction Execution",
	},
	"CAPEC-664": {
		Name: "CAPEC-664: Server Side Request Forgery",
	},
	"CAPEC-665": {
		Name: "CAPEC-665: Exploitation of Thunderbolt Protection Flaws",
	},
	"CAPEC-666": {
		Name: "CAPEC-666: BlueSmacking",
	},
	"CAPEC-667": {
		Name: "CAPEC-667: Bluetooth Impersonation AttackS (BIAS)",
	},
	"CAPEC-668": {
		Name: "CAPEC-668: Key Negotiation of Bluetooth Attack (KNOB)",
	},
	"CAPEC-669": {
		Name: "CAPEC-669: Alteration of a Software Update",
	},
	"CAPEC-67": {
		Name: "CAPEC-67: String Format Overflow in syslog()",
	},
	"CAPEC-670": {
		Name: "CAPEC-670: Software Development Tools Maliciously Altered",
	},
	"CAPEC-671": {
		Name: "CAPEC-671: Requirements for ASIC Functionality Maliciously Altered",
	},
	"CAPEC-672": {
		Name: "CAPEC-672: Malicious Code Implanted During Chip Programming",
	},
	"CAPEC-673": {
		Name: "CAPEC-673: Developer Signing Maliciously Altered Software",
	},
	"CAPEC-674": {
		Name: "CAPEC-674: Design for FPGA Maliciously Altered",
	},
	"CAPEC-675": {
		Name: "CAPEC-675: Retrieve Data from Decommissioned Devices",
	},
	"CAPEC-676": {
		Name: "CAPEC-676: NoSQL Injection",
	},
	"CAPEC-677": {
		Name: "CAPEC-677: Server Functionality Compromise",
	},
	"CAPEC-678": {
		Name: "CAPEC-678: System Build Data Maliciously Altered",
	},
	"CAPEC-679": {
		Name: "CAPEC-679: Exploitation of Improperly Configured or Implemented Memory Protections",
	},
	"CAPEC-68": {
		Name: "CAPEC-68: Subvert Code-signing Facilities",
	},
	"CAPEC-680": {
		Name: "CAPEC-680: Exploitation of Improperly Controlled Registers",
	},
	"CAPEC-681": {
		Name: "CAPEC-681: Exploitation of Improperly Controlled Hardware Security Identifiers",
	},
	"CAPEC-682": {
		Name: "CAPEC-682: Exploitation of Firmware or ROM Code with Unpatchable Vulnerabilities",
	},
	"CAPEC-69": {
		Name: "CAPEC-69: Target Programs with Elevated Privileges",
	},
	"CAPEC-690": {
		Name: "CAPEC-690: Metadata Spoofing",
	},
	"CAPEC-691": {
		Name: "CAPEC-691: Spoof Open-Source Software Metadata",
	},
	"CAPEC-692": {
		Name: "CAPEC-692: Spoof Version Control System Commit Metadata",
	},
	"CAPEC-693": {
		Name: "CAPEC-693: StarJacking",
	},
	"CAPEC-694": {
		Name: "CAPEC-694: System Location Discovery",
	},
	"CAPEC-695": {
		Name: "CAPEC-695: Repo Jacking",
	},
	"CAPEC-696": {
		Name: "CAPEC-696: Load Value Injection",
	},
	"CAPEC-697": {
		Name: "CAPEC-697: DHCP Spoofing",
	},
	"CAPEC-698": {
		Name: "CAPEC-698: Install Malicious Extension",
	},
	"CAPEC-7": {
		Name: "CAPEC-7: Blind SQL Injection",
	},
	"CAPEC-70": {
		Name: "CAPEC-70: Try Common or Default Usernames and Passwords",
	},
	"CAPEC-71": {
		Name: "CAPEC-71: Using Unicode Encoding to Bypass Validation Logic",
	},
	"CAPEC-72": {
		Name: "CAPEC-72: URL Encoding",
	},
	"CAPEC-73": {
		Name: "CAPEC-73: User-Controlled Filename",
	},
	"CAPEC-74": {
		Name: "CAPEC-74: Manipulating State",
	},
	"CAPEC-75": {
		Name: "CAPEC-75: Manipulating Writeable Configuration Files",
	},
	"CAPEC-76": {
		Name: "CAPEC-76: Manipulating Web Input to File System Calls",
	},
	"CAPEC-77": {
		Name: "CAPEC-77: Manipulating User-Controlled Variables",
	},
	"CAPEC-78": {
		Name: "CAPEC-78: Using Escaped Slashes in Alternate Encoding",
	},
	"CAPEC-79": {
		Name: "CAPEC-79: Using Slashes in Alternate Encoding",
	},
	"CAPEC-8": {
		Name: "CAPEC-8: Buffer Overflow in an API Call",
	},
	"CAPEC-80": {
		Name: "CAPEC-80: Using UTF-8 Encoding to Bypass Validation Logic",
	},
	"CAPEC-81": {
		Name: "CAPEC-81: Web Server Logs Tampering",
	},
	"CAPEC-83": {
		Name: "CAPEC-83: XPath Injection",
	},
	"CAPEC-84": {
		Name: "CAPEC-84: XQuery Injection",
	},
	"CAPEC-85": {
		Name: "CAPEC-85: AJAX Footprinting",
	},
	"CAPEC-86": {
		Name: "CAPEC-86: XSS Through HTTP Headers",
	},
	"CAPEC-87": {
		Name: "CAPEC-87: Forceful Browsing",
	},
	"CAPEC-88": {
		Name: "CAPEC-88: OS Command Injection",
	},
	"CAPEC-89": {
		Name: "CAPEC-89: Pharming",
	},
	"CAPEC-9": {
		Name: "CAPEC-9: Buffer Overflow in Local Command-Line Utilities",
	},
	"CAPEC-90": {
		Name: "CAPEC-90: Reflection Attack in Authentication Protocol",
	},
	"CAPEC-92": {
		Name: "CAPEC-92: Forced Integer Overflow",
	},
	"CAPEC-93": {
		Name: "CAPEC-93: Log Injection-Tampering-Forging",
	},
	"CAPEC-94": {
		Name: "CAPEC-94: Adversary in the Middle (AiTM)",
	},
	"CAPEC-95": {
		Name: "CAPEC-95: WSDL Scanning",
	},
	"CAPEC-96": {
		Name: "CAPEC-96: Block Access to Libraries",
	},
	"CAPEC-97": {
		Name: "CAPEC-97: Cryptanalysis",
	},
	"CAPEC-98": {
		Name: "CAPEC-98: Phishing",
	},
	"T1001": {
		Name:      "TA0011: Command and Control => T1001: Data Obfuscation",
		Platforms: []string{"Linux", "Windows", "macOS"},
	},
	"T1001.001": {
		Name:      "TA0011: Command and Control => T1001.001: Junk Data",
		Platforms: []string{"Linux", "Windows", "macOS"},
	},
	"T1001.002": {
		Name:      "TA0011: Command and Control => T1001.002: Steganography",
		Platforms: []string{"Linux", "Windows", "macOS"},
	},
	"T1001.003": {
		Name:      "TA0011: Command and Control => T1001.003: Protocol Impersonation",
		Platforms: []string{"Linux", "Windows", "macOS"},
	},
	"T1003": {
		Name:      "TA0006: Credential Access => T1003: OS Credential Dumping",
		Platforms: []string{"Linux", "Windows", "macOS"},
	},
	"T1003.001": {
		Name:      "TA0006: Credential Access => T1003.001: LSASS Memory",
		Platforms: []string{"Windows"},
	},
	"T1003.002": {
		Name:      "TA0006: Credential Access => T1003.002: Security Account Manager",
		Platforms: []string{"Windows"},
	},
	"T1003.003": {
		Name:      "TA0006: Credential Access => T1003.003: NTDS",
		Platforms: []string{"Windows"},
	},
	"T1003.004": {
		Name:      "TA0006: Credential Access => T1003.004: LSA Secrets",
		Platforms: []string{"Windows"},
	},
	"T1003.005": {
		Name:      "TA0006: Credential Access => T1003.005: Cached Domain Credentials",
		Platforms: []string{"Windows"},
	},
	"T1003.006": {
		Name:      "TA0006: Credential Access => T1003.006: DCSync",
		Platforms: []string{"Windows"},
	},
	"T1003.007": {
		Name:      "TA0006: Credential Access => T1003.007: Proc Filesystem",
		Platforms: []string{"Linux"},
	},
	"T1003.008": {
		Name:      "TA0006: Credential Access => T1003.008: /etc/passwd and /etc/shadow",
		Platforms: []string{"Linux"},
	},
	"T1005": {
		Name:      "TA0009: Collection => T1005: Data from Local System",
		Platforms: []string{"Linux", "Network", "Windows", "macOS"},
	},
	"T1006": {
		Name:      "TA0005: Defense Evasion => T1006: Direct Volume Access",
		Platforms: []string{"Windows"},
	},
	"T1007": {
		Name:      "TA0007: Discovery => T1007: System Service Discovery",
		Platforms: []string{"Linux", "Windows", "macOS"},
	},
	"T1008": {
		Name:      "TA0011: Command and Control => T1008: Fallback Channels",
		Platforms: []string{"Linux", "Windows", "macOS"},
	},
	"T1010": {
		Name:      "TA0007: Discovery => T1010: Application Window Discovery",
		Platforms: []string{"Linux", "Windows", "macOS"},
	},
	"T1011": {
		Name:      "TA0010: Exfiltration => T1011: Exfiltration Over Other Network Medium",
		Platforms: []string{"Linux", "Windows", "macOS"},
	},
	"T1011.001": {
		Name:      "TA0010: Exfiltration => T1011.001: Exfiltration Over Bluetooth",
		Platforms: []string{"Linux", "Windows", "macOS"},
	},
	"T1012": {
		Name:      "TA0007: Discovery => T1012: Query Registry",
		Platforms: []string{"Windows"},
	},
	"T1014": {
		Name:      "TA0005: Defense Evasion => T1014: Rootkit",
		Platforms: []string{"Linux", "Windows", "macOS"},
	},
	"T1016": {
		Name:      "TA0007: Discovery => T1016: System Network Configuration Discovery",
		Platforms: []string{"Linux", "Network", "Windows", "macOS"},
	},
	"T1016.001": {
		Name:      "TA0007: Discovery => T1016.001: Internet Connection Discovery",
		Platforms: []string{"Linux", "Windows", "macOS"},
	},
	"T1018": {
		Name:      "TA0007: Discovery => T1018: Remote System Discovery",
		Platforms: []string{"Linux", "Network", "Windows", "macOS"},
	},
	"T1020": {
		Name:      "TA0010: Exfiltration => T1020: Automated Exfiltration",
		Platforms: []string{"Linux", "Network", "Windows", "macOS"},
	},
	"T1020.001": {
		Name:      "TA0010: Exfiltration => T1020.001: Traffic Duplication",
		Platforms: []string{"Network"},
	},
	"T1021": {
		Name:      "TA0008: Lateral Movement => T1021: Remote Services",
		Platforms: []string{"Linux", "Windows", "macOS"},
	},
	"T1021.001": {
		Name:      "TA0008: Lateral Movement => T1021.001: Remote Desktop Protocol",
		Platforms: []string{"Windows"},
	},
	"T1021.002": {
		Name:      "TA0008: Lateral Movement => T1021.002: SMB/Windows Admin Shares",
		Platforms: []string{"Windows"},
	},
	"T1021.003": {
		Name:      "TA0008: Lateral Movement => T1021.003: Distributed Component Object Model",
		Platforms: []string{"Windows"},
	},
	"T1021.004": {
		Name:      "TA0008: Lateral Movement => T1021.004: SSH",
		Platforms: []string{"Linux", "macOS"},
	},
	"T1021.005": {
		Name:      "TA0008: Lateral Movement => T1021.005: VNC",
		Platforms: []string{"Linux", "Windows", "macOS"},
	},
	"T1021.006": {
		Name:      "TA0008: Lateral Movement => T1021.006: Windows Remote Management",
		Platforms: []string{"Windows"},
	},
	"T1025": {
		Name:      "TA0009: Collection => T1025: Data from Removable Media",
		Platforms: []string{"Linux", "Windows", "macOS"},
	},
	"T1027": {
		Name:      "TA0005: Defense Evasion => T1027: Obfuscated Files or Information",
		Platforms: []string{"Linux", "Windows", "macOS"},
	},
	"T1027.001": {
		Name:      "TA0005: Defense Evasion => T1027.001: Binary Padding",
		Platforms: []string{"Linux", "Windows", "macOS"},
	},
	"T1027.002": {
		Name:      "TA0005: Defense Evasion => T1027.002: Software Packing",
		Platforms: []string{"Linux", "Windows", "macOS"},
	},
	"T1027.003": {
		Name:      "TA0005: Defense Evasion => T1027.003: Steganography",
		Platforms: []string{"Linux", "Windows", "macOS"},
	},
	"T1027.004": {
		Name:      "TA0005: Defense Evasion => T1027.004: Compile After Delivery",
		Platforms: []string{"Linux", "Windows", "macOS"},
	},
	"T1027.005": {
		Name:      "TA0005: Defense Evasion => T1027.005: Indicator Removal from Tools",
		Platforms: []string{"Linux", "Windows", "macOS"},
	},
	"T1027.006": {
		Name:      "TA0005: Defense Evasion => T1027.006: HTML Smuggling",
		Platforms: []string{"Linux", "Windows", "macOS"},
	},
	"T1027.007": {
		Name:      "TA0005: Defense Evasion => T1027.007: Dynamic API Resolution",
		Platforms: []string{"Windows"},
	},
	"T1027.008": {
		Name:      "TA0005: Defense Evasion => T1027.008: Stripped Payloads",
		Platforms: []string{"Linux", "Windows", "macOS"},
	},
	"T1027.009": {
		Name:      "TA0005: Defense Evasion => T1027.009: Embedded Payloads",
		Platforms: []string{"Linux", "Windows", "macOS"},
	},
	"T1029": {
		Name:      "TA0010: Exfiltration => T1029: Scheduled Transfer",
		Platforms: []string{"Linux", "Windows", "macOS"},
	},
	"T1030": {
		Name:      "TA0010: Exfiltration => T1030: Data Transfer Size Limits",
		Platforms: []string{"Linux", "Windows", "macOS"},
	},
	"T1033": {
		Name:      "TA0007: Discovery => T1033: System Owner/User Discovery",
		Platforms: []string{"Linux", "Windows", "macOS"},
	},
	"T1036": {
		Name:      "TA0005: Defense Evasion => T1036: Masquerading",
		Platforms: []string{"Containers", "Linux", "Windows", "macOS"},
	},
	"T1036.001": {
		Name:      "TA0005: Defense Evasion => T1036.001: Invalid Code Signature",
		Platforms: []string{"Windows", "macOS"},
	},
	"T1036.002": {
		Name:      "TA0005: Defense Evasion => T1036.002: Right-to-Left Override",
		Platforms: []string{"Linux", "Windows", "macOS"},
	},
	"T1036.003": {
		Name:      "TA0005: Defense Evasion => T1036.003: Rename System Utilities",
		Platforms: []string{"Linux", "Windows", "macOS"},
	},
	"T1036.004": {
		Name:      "TA0005: Defense Evasion => T1036.004: Masquerade Task or Service",
		Platforms: []string{"Linux", "Windows", "macOS"},
	},
	"T1036.005": {
		Name:      "TA0005: Defense Evasion => T1036.005: Match Legitimate Name or Location",
		Platforms: []string{"Containers", "Linux", "Windows", "macOS"},
	},
	"T1036.006": {
		Name:      "TA0005: Defense Evasion => T1036.006: Space after Filename",
		Platforms: []string{"Linux", "macOS"},
	},
	"T1036.007": {
		Name:      "TA0005: Defense Evasion => T1036.007: Double File Extension",
		Platforms: []string{"Windows"},
	},
	"T1037": {
		Name:      "TA0003: Persistence, TA0004: Privilege Escalation => T1037: Boot or Logon Initialization Scripts",
		Platforms: []string{"Linux", "Windows", "macOS"},
	},
	"T1037.001": {
		Name:      "TA0003: Persistence, TA0004: Privilege Escalation => T1037.001: Logon Script (Windows)",
		Platforms: []string{"Windows"},
	},
	"T1037.002": {
		Name:      "TA0003: Persistence, TA0004: Privilege Escalation => T1037.002: Login Hook",
		Platforms: []string{"macOS"},
	},
	"T1037.003": {
		Name:      "TA0003: Persistence, TA0004: Privilege Escalation => T1037.003: Network Logon Script",
		Platforms: []string{"Windows"},
	},
	"T1037.004": {
		Name:      "TA0003: Persistence, TA0004: Privilege Escalation => T1037.004: RC Scripts",
		Platforms: []string{"Linux", "macOS"},
	},
	"T1037.005": {
		Name:      "TA0003: Persistence, TA0004: Privilege Escalation => T1037.005: Startup Items",
		Platforms: []string{"macOS"},
	},
	"T1039": {
		Name:      "TA0009: Collection => T1039: Data from Network Shared Drive",
		Platforms: []string{"Linux", "Windows", "macOS"},
	},
	"T1040": {
		Name:      "TA0006: Credential Access, TA0007: Discovery => T1040: Network Sniffing",
		Platforms: []string{"IaaS", "Linux", "Network", "Windows", "macOS"},
	},
	"T1041": {
		Name:      "TA0010: Exfiltration => T1041: Exfiltration Over C2 Channel",
		Platforms: []string{"Linux", "Windows", "macOS"},
	},
	"T1046": {
		Name:      "TA0007: Discovery => T1046: Network Service Discovery",
		Platforms: []string{"Containers", "IaaS", "Linux", "Network", "Windows", "macOS"},
	},
	"T1047": {
		Name:      "TA0002: Execution => T1047: Windows Management Instrumentation",
		Platforms: []string{"Windows"},
	},
	"T1048": {
		Name:      "TA0010: Exfiltration => T1048: Exfiltration Over Alternative Protocol",
		Platforms: []string{"Linux", "Windows", "macOS"},
	},
	"T1048.001": {
		Name:      "TA0010: Exfiltration => T1048.001: Exfiltration Over Symmetric Encrypted Non-C2 Protocol",
		Platforms: []string{"Linux", "Windows", "macOS"},
	},
	"T1048.002": {
		Name:      "TA0010: Exfiltration => T1048.002: Exfiltration Over Asymmetric Encrypted Non-C2 Protocol",
		Platforms: []string{"Linux", "Windows", "macOS"},
	},
	"T1048.003": {
		Name:      "TA0010: Exfiltration => T1048.003: Exfiltration Over Unencrypted Non-C2 Protocol",
		Platforms: []string{"Linux", "Windows", "macOS"},
	},
	"T1049": {
		Name:      "TA0007: Discovery => T1049: System Network Connections Discovery",
		Platforms: []string{"IaaS", "Linux", "Network", "Windows", "macOS"},
	},
	"T1052": {
		Name:      "TA0010: Exfiltration => T1052: Exfiltration Over Physical Medium",
		Platforms: []string{"Linux", "Windows", "macOS"},
	},
	"T1052.001": {
		Name:      "TA0010: Exfiltration => T1052.001: Exfiltration over USB",
		Platforms: []string{"Linux", "Windows", "macOS"},
	},
	"T1053": {
		Name:      "TA0002: Execution, TA0003: Persistence, TA0004: Privilege Escalation => T1053: Scheduled Task/Job",
		Platforms: []string{"Containers", "Linux", "Windows", "macOS"},
	},
	"T1053.002": {
		Name:      "TA0002: Execution, TA0003: Persistence, TA0004: Privilege Escalation => T1053.002: At",
		Platforms: []string{"Linux", "Windows", "macOS"},
	},
	"T1053.003": {
		Name:      "TA0002: Execution, TA0003: Persistence, TA0004: Privilege Escalation => T1053.003: Cron",
		Platforms: []string{"Linux", "macOS"},
	},
	"T1053.005": {
		Name:      "TA0002: Execution, TA0003: Persistence, TA0004: Privilege Escalation => T1053.005: Scheduled Task",
		Platforms: []string{"Windows"},
	},
	"T1053.006": {
		Name:      "TA0002: Execution, TA0003: Persistence, TA0004: Privilege Escalation => T1053.006: Systemd Timers",
		Platforms: []string{"Linux"},
	},
	"T1053.007": {
		Name:      "TA0002: Execution, TA0003: Persistence, TA0004: Privilege Escalation => T1053.007: Container Orchestration Job",
		Platforms: []string{"Containers"},
	},
	"T1055": {
		Name:      "TA0004: Privilege Escalation, TA0005: Defense Evasion => T1055: Process Injection",
		Platforms: []string{"Linux", "Windows", "macOS"},
	},
	"T1055.001": {
		Name:      "TA0004: Privilege Escalation, TA0005: Defense Evasion => T1055.001: Dynamic-link Library Injection",
		Platforms: []string{"Windows"},
	},
	"T1055.002": {
		Name:      "TA0004: Privilege Escalation, TA0005: Defense Evasion => T1055.002: Portable Executable Injection",
		Platforms: []string{"Windows"},
	},
	"T1055.003": {
		Name:      "TA0004: Privilege Escalation, TA0005: Defense Evasion => T1055.003: Thread Execution Hijacking",
		Platforms: []string{"Windows"},
	},
	"T1055.004": {
		Name:      "TA0004: Privilege Escalation, TA0005: Defense Evasion => T1055.004: Asynchronous Procedure Call",
		Platforms: []string{"Windows"},
	},
	"T1055.005": {
		Name:      "TA0004: Privilege Escalation, TA0005: Defense Evasion => T1055.005: Thread Local Storage",
		Platforms: []string{"Windows"},
	},
	"T1055.008": {
		Name:      "TA0004: Privilege Escalation, TA0005: Defense Evasion => T1055.008: Ptrace System Calls",
		Platforms: []string{"Linux"},
	},
	"T1055.009": {
		Name:      "TA0004: Privilege Escalation, TA0005: Defense Evasion => T1055.009: Proc Memory",
		Platforms: []string{"Linux"},
	},
	"T1055.011": {
		Name:      "TA0004: Privilege Escalation, TA0005: Defense Evasion => T1055.011: Extra Window Memory Injection",
		Platforms: []string{"Windows"},
	},
	"T1055.012": {
		Name:      "TA0004: Privilege Escalation, TA0005: Defense Evasion => T1055.012: Process Hollowing",
		Platforms: []string{"Windows"},
	},
	"T1055.013": {
		Name:      "TA0004: Privilege Escalation, TA0005: Defense Evasion => T1055.013: Process Doppelgänging",
		Platforms: []string{"Windows"},
	},
	"T1055.014": {
		Name:      "TA0004: Privilege Escalation, TA0005: Defense Evasion => T1055.014: VDSO Hijacking",
		Platforms: []string{"Linux"},
	},
	"T1055.015": {
		Name:      "TA0004: Privilege Escalation, TA0005: Defense Evasion => T1055.015: ListPlanting",
		Platforms: []string{"Windows"},
	},
	"T1056": {
		Name:      "TA0006: Credential Access, TA0009: Collection => T1056: Input Capture",
		Platforms: []string{"Linux", "Network", "Windows", "macOS"},
	},
	"T1056.001": {
		Name:      "TA0006: Credential Access, TA0009: Collection => T1056.001: Keylogging",
		Platforms: []string{"Linux", "Network", "Windows", "macOS"},
	},
	"T1056.002": {
		Name:      "TA0006: Credential Access, TA0009: Collection => T1056.002: GUI Input Capture",
		Platforms: []string{"Linux", "Windows", "macOS"},
	},
	"T1056.003": {
		Name:      "TA0006: Credential Access, TA0009: Collection => T1056.003: Web Portal Capture",
		Platforms: []string{"Linux", "Windows", "macOS"},
	},
	"T1056.004": {
		Name:      "TA0006: Credential Access, TA0009: Collection => T1056.004: Credential API Hooking",
		Platforms: []string{"Windows"},
	},
	"T1057": {
		Name:      "TA0007: Discovery => T1057: Process Discovery",
		Platforms: []string{"Linux", "Windows", "macOS"},
	},
	"T1059": {
		Name:      "TA0002: Execution => T1059: Command and Scripting Interpreter",
		Platforms: []string{"Linux", "Network", "Windows", "macOS"},
	},
	"T1059.001": {
		Name:      "TA0002: Execution => T1059.001: PowerShell",
		Platforms: []string{"Windows"},
	},
	"T1059.002": {
		Name:      "TA0002: Execution => T1059.002: AppleScript",
		Platforms: []string{"macOS"},
	},
	"T1059.003": {
		Name:      "TA0002: Execution => T1059.003: Windows Command Shell",
		Platforms: []string{"Windows"},
	},
	"T1059.004": {
		Name:      "TA0002: Execution => T1059.004: Unix Shell",
		Platforms: []string{"Linux", "macOS"},
	},
	"T1059.005": {
		Name:      "TA0002: Execution => T1059.005: Visual Basic",
		Platforms: []string{"Linux", "Windows", "macOS"},
	},
	"T1059.006": {
		Name:      "TA0002: Execution => T1059.006: Python",
		Platforms: []string{"Linux", "Windows", "macOS"},
	},
	"T1059.007": {
		Name:      "TA0002: Execution => T1059.007: JavaScript",
		Platforms: []string{"Linux", "Windows", "macOS"},
	},
	"T1059.008": {
		Name:      "TA0002: Execution => T1059.008: Network Device CLI",
		Platforms: []string{"Network"},
	},
	"T1068": {
		Name:      "TA0004: Privilege Escalation => T1068: Exploitation for Privilege Escalation",
		Platforms: []string{"Containers", "Linux", "Windows", "macOS"},
	},
	"T1069": {
		Name:      "TA0007: Discovery => T1069: Permission Groups Discovery",
		Platforms: []string{"Azure AD", "Containers", "Google Workspace", "IaaS", "Linux", "Office 365", "SaaS", "Windows", "macOS"},
	},
	"T1069.001": {
		Name:      "TA0007: Discovery => T1069.001: Local Groups",
		Platforms: []string{"Linux", "Windows", "macOS"},
	},
	"T1069.002": {
		Name:      "TA0007: Discovery => T1069.002: Domain Groups",
		Platforms: []string{"Linux", "Windows", "macOS"},
	},
	"T1069.003": {
		Name:      "TA0007: Discovery => T1069.003: Cloud Groups",
		Platforms: []string{"Azure AD", "Google Workspace", "IaaS", "Office 365", "SaaS"},
	},
	"T1070": {
		Name:      "TA0005: Defense Evasion => T1070: Indicator Removal",
		Platforms: []string{"Containers", "Google Workspace", "Linux", "Network", "Office 365", "Windows", "macOS"},
	},
	"T1070.001": {
		Name:      "TA0005: Defense Evasion => T1070.001: Clear Windows Event Logs",
		Platforms: []string{"Windows"},
	},
	"T1070.002": {
		Name:      "TA0005: Defense Evasion => T1070.002: Clear Linux or Mac System Logs",
		Platforms: []string{"Linux", "macOS"},
	},
	"T1070.003": {
		Name:      "TA0005: Defense Evasion => T1070.003: Clear Command History",
		Platforms: []string{"Linux", "Network", "Windows", "macOS"},
	},
	"T1070.004": {
		Name:      "TA0005: Defense Evasion => T1070.004: File Deletion",
		Platforms: []string{"Linux", "Windows", "macOS"},
	},
	"T1070.005": {
		Name:      "TA0005: Defense Evasion => T1070.005: Network Share Connection Removal",
		Platforms: []string{"Windows"},
	},
	"T1070.006": {
		Name:      "TA0005: Defense Evasion => T1070.006: Timestomp",
		Platforms: []string{"Linux", "Windows", "macOS"},
	},
	"T1070.007": {
		Name:      "TA0005: Defense Evasion => T1070.007: Clear Network Connection History and Configurations",
		Platforms: []string{"Linux", "Network", "Windows", "macOS"},
	},
	"T1070.008": {
		Name:      "TA0005: Defense Evasion => T1070.008: Clear Mailbox Data",
		Platforms: []string{"Google Workspace", "Linux", "Office 365", "Windows", "macOS"},
	},
	"T1070.009": {
		Name:      "TA0005: Defense Evasion => T1070.009: Clear Persistence",
		Platforms: []string{"Linux", "Windows", "macOS"},
	},
	"T1071": {
		Name:      "TA0011: Command and Control => T1071: Application Layer Protocol",
		Platforms: []string{"Linux", "Windows", "macOS"},
	},
	"T1071.001": {
		Name:      "TA0011: Command and Control => T1071.001: Web Protocols",
		Platforms: []string{"Linux", "Windows", "macOS"},
	},
	"T1071.002": {
		Name:      "TA0011: Command and Control => T1071.002: File Transfer Protocols",
		Platforms: []string{"Linux", "Windows", "macOS"},
	},
	"T1071.003": {
		Name:      "TA0011: Command and Control => T1071.003: Mail Protocols",
		Platforms: []string{"Linux", "Windows", "macOS"},
	},
	"T1071.004": {
		Name:      "TA0011: Command and Control => T1071.004: DNS",
		Platforms: []string{"Linux", "Windows", "macOS"},
	},
	"T1072": {
		Name:      "TA0002: Execution, TA0008: Lateral Movement => T1072: Software Deployment Tools",
		Platforms: []string{"Linux", "Windows", "macOS"},
	},
	"T1074": {
		Name:      "TA0009: Collection => T1074: Data Staged",
		Platforms: []string{"IaaS", "Linux", "Windows", "macOS"},
	},
	"T1074.001": {
		Name:      "TA0009: Collection => T1074.001: Local Data Staging",
		Platforms: []string{"Linux", "Windows", "macOS"},
	},
	"T1074.002": {
		Name:      "TA0009: Collection => T1074.002: Remote Data Staging",
		Platforms: []string{"IaaS", "Linux", "Windows", "macOS"},
	},
	"T1078": {
		Name:      "TA0001: Initial Access, TA0003: Persistence, TA0004: Privilege Escalation, TA0005: Defense Evasion => T1078: Valid Accounts",
		Platforms: []string{"Azure AD", "Containers", "Google Workspace", "IaaS", "Linux", "Network", "Office 365", "SaaS", "Windows", "macOS"},
	},
	"T1078.001": {
		Name:      "TA0001: Initial Access, TA0003: Persistence, TA0004: Privilege Escalation, TA0005: Defense Evasion => T1078.001: Default Accounts",
		Platforms: []string{"Azure AD", "Containers", "Google Workspace", "IaaS", "Linux", "Office 365", "SaaS", "Windows", "macOS"},
	},
	"T1078.002": {
		Name:      "TA0001: Initial Access, TA0003: Persistence, TA0004: Privilege Escalation, TA0005: Defense Evasion => T1078.002: Domain Accounts",
		Platforms: []string{"Linux", "Windows", "macOS"},
	},
	"T1078.003": {
		Name:      "TA0001: Initial Access, TA0003: Persistence, TA0004: Privilege Escalation, TA0005: Defense Evasion => T1078.003: Local Accounts",
		Platforms: []string{"Containers", "Linux", "Windows", "macOS"},
	},
	"T1078.004": {
		Name:      "TA0001: Initial Access, TA0003: Persistence, TA0004: Privilege Escalation, TA0005: Defense Evasion => T1078.004: Cloud Accounts",
		Platforms: []string{"Azure AD", "Google Workspace", "IaaS", "Office 365", "SaaS"},
	},
	"T1080": {
		Name:      "TA0008: Lateral Movement => T1080: Taint Shared Content",
		Platforms: []string{"Linux", "Office 365", "SaaS", "Windows", "macOS"},
	},
	"T1082": {
		Name:      "TA0007: Discovery => T1082: System Information Discovery",
		Platforms: []string{"IaaS", "Linux", "Network", "Windows", "macOS"},
	},
	"T1083": {
		Name:      "TA0007: Discovery => T1083: File and Directory Discovery",
		Platforms: []string{"Linux", "Network", "Windows", "macOS"},
	},
	"T1087": {
		Name:      "TA0007: Discovery => T1087: Account Discovery",
		Platforms: []string{"Azure AD", "Google Workspace", "IaaS", "Linux", "Office 365", "SaaS", "Windows", "macOS"},
	},
	"T1087.001": {
		Name:      "TA0007: Discovery => T1087.001: Local Account",
		Platforms: []string{"Linux", "Windows", "macOS"},
	},
	"T1087.002": {
		Name:      "TA0007: Discovery => T1087.002: Domain Account",
		Platforms: []string{"Linux", "Windows", "macOS"},
	},
	"T1087.003": {
		Name:      "TA0007: Discovery => T1087.003: Email Account",
		Platforms: []string{"Google Workspace", "Office 365", "Windows"},
	},
	"T1087.004": {
		Name:      "TA0007: Discovery => T1087.004: Cloud Account",
		Platforms: []string{"Azure AD", "Google Workspace", "IaaS", "Office 365", "SaaS"},
	},
	"T1090": {
		Name:      "TA0011: Command and Control => T1090: Proxy",
		Platforms: []string{"Linux", "Network", "Windows", "macOS"},
	},
	"T1090.001": {
		Name:      "TA0011: Command and Control => T1090.001: Internal Proxy",
		Platforms: []string{"Linux", "Windows", "macOS"},
	},
	"T1090.002": {
		Name:      "TA0011: Command and Control => T1090.002: External Proxy",
		Platforms: []string{"Linux", "Windows", "macOS"},
	},
	"T1090.003": {
		Name:      "TA0011: Command and Control => T1090.003: Multi-hop Proxy",
		Platforms: []string{"Linux", "Network", "Windows", "macOS"},
	},
	"T1090.004": {
		Name:      "TA0011: Command and Control => T1090.004: Domain Fronting",
		Platforms: []string{"Linux", "Windows", "macOS"},
	},
	"T1091": {
		Name:      "TA0001: Initial Access, TA0008: Lateral Movement => T1091: Replication Through Removable Media",
		Platforms: []string{"Windows"},
	},
	"T1092": {
		Name:      "TA0011: Command and Control => T1092: Communication Through Removable Media",
		Platforms: []string{"Linux", "Windows", "macOS"},
	},
	"T1095": {
		Name:      "TA0011: Command and Control => T1095: Non-Application Layer Protocol",
		Platforms: []string{"Linux", "Network", "Windows", "macOS"},
	},
	"T1098": {
		Name:      "TA0003: Persistence => T1098: Account Manipulation",
		Platforms: []string{"Azure AD", "Google Workspace", "IaaS", "Linux", "Office 365", "SaaS", "Windows", "macOS"},
	},
	"T1098.001": {
		Name:      "TA0003: Persistence => T1098.001: Additional Cloud Credentials",
		Platforms: []string{"Azure AD", "IaaS", "SaaS"},
	},
	"T1098.002": {
		Name:      "TA0003: Persistence => T1098.002: Additional Email Delegate Permissions",
		Platforms: []string{"Google Workspace", "Office 365", "Windows"},
	},
	"T1098.003": {
		Name:      "TA0003: Persistence => T1098.003: Additional Cloud Roles",
		Platforms: []string{"Azure AD", "Google Workspace", "IaaS", "Office 365", "SaaS"},
	},
	"T1098.004": {
		Name:      "TA0003: Persistence => T1098.004: SSH Authorized Keys",
		Platforms: []string{"IaaS", "Linux", "macOS"},
	},
	"T1098.005": {
		Name:      "TA0003: Persistence => T1098.005: Device Registration",
		Platforms: []string{"Azure AD", "SaaS", "Windows"},
	},
	"T1102": {
		Name:      "TA0011: Command and Control => T1102: Web Service",
		Platforms: []string{"Linux", "Windows", "macOS"},
	},
	"T1102.001": {
		Name:      "TA0011: Command and Control => T1102.001: Dead Drop Resolver",
		Platforms: []string{"Linux", "Windows", "macOS"},
	},
	"T1102.002": {
		Name:      "TA0011: Command and Control => T1102.002: Bidirectional Communication",
		Platforms: []string{"Linux", "Windows", "macOS"},
	},
	"T1102.003": {
		Name:      "TA0011: Command and Control => T1102.003: One-Way Communication",
		Platforms: []string{"Linux", "Windows", "macOS"},
	},
	"T1104": {
		Name:      "TA0011: Command and Control => T1104: Multi-Stage Channels",
		Platforms: []string{"Linux", "Windows", "macOS"},
	},
	"T1105": {
		Name:      "TA0011: Command and Control => T1105: Ingress Tool Transfer",
		Platforms: []string{"Linux", "Windows", "macOS"},
	},
	"T1106": {
		Name:      "TA0002: Execution => T1106: Native API",
		Platforms: []string{"Linux", "Windows", "macOS"},
	},
	"T1110": {
		Name:      "TA0006: Credential Access => T1110: Brute Force",
		Platforms: []string{"Azure AD", "Containers", "Google Workspace", "IaaS", "Linux", "Network", "Office 365", "SaaS", "Windows", "macOS"},
	},
	"T1110.001": {
		Name:      "TA0006: Credential Access => T1110.001: Password Guessing",
		Platforms: []string{"Azure AD", "Containers", "Google Workspace", "IaaS", "Linux", "Network", "Office 365", "SaaS", "Windows", "macOS"},
	},
	"T1110.002": {
		Name:      "TA0006: Credential Access => T1110.002: Password Cracking",
		Platforms: []string{"Azure AD", "Linux", "Network", "Office 365", "Windows", "macOS"},
	},
	"T1110.003": {
		Name:      "TA0006: Credential Access => T1110.003: Password Spraying",
		Platforms: []string{"Azure AD", "Containers", "Google Workspace", "IaaS", "Linux", "Office 365", "SaaS", "Windows", "macOS"},
	},
	"T1110.004": {
		Name:      "TA0006: Credential Access => T1110.004: Credential Stuffing",
		Platforms: []string{"Azure AD", "Containers", "Google Workspace", "IaaS", "Linux", "Office 365", "SaaS", "Windows", "macOS"},
	},
	"T1111": {
		Name:      "TA0006: Credential Access => T1111: Multi-Factor Authentication Interception",
		Platforms: []string{"Linux", "Windows", "macOS"},
	},
	"T1112": {
		Name:      "TA0005: Defense Evasion => T1112: Modify Registry",
		Platforms: []string{"Windows"},
	},
	"T1113": {
		Name:      "TA0009: Collection => T1113: Screen Capture",
		Platforms: []string{"Linux", "Windows", "macOS"},
	},
	"T1114": {
		Name:      "TA0009: Collection => T1114: Email Collection",
		Platforms: []string{"Google Workspace", "Linux", "Office 365", "Windows", "macOS"},
	},
	"T1114.001": {
		Name:      "TA0009: Collection => T1114.001: Local Email Collection",
		Platforms: []string{"Windows"},
	},
	"T1114.002": {
		Name:      "TA0009: Collection => T1114.002: Remote Email Collection",
		Platforms: []string{"Google Workspace", "Office 365", "Windows"},
	},
	"T1114.003": {
		Name:      "TA0009: Collection => T1114.003: Email Forwarding Rule",
		Platforms: []string{"Google Workspace", "Linux", "Office 365", "Windows", "macOS"},
	},
	"T1115": {
		Name:      "TA0009: Collection => T1115: Clipboard Data",
		Platforms: []string{"Linux", "Windows", "macOS"},
	},
	"T1119": {
		Name:      "TA0009: Collection => T1119: Automated Collection",
		Platforms: []string{"IaaS", "Linux", "SaaS", "Windows", "macOS"},
	},
	"T1120": {
		Name:      "TA0007: Discovery => T1120: Peripheral Device Discovery",
		Platforms: []string{"Linux", "Windows", "macOS"},
	},
	"T1123": {
		Name:      "TA0009: Collection => T1123: Audio Capture",
		Platforms: []string{"Linux", "Windows", "macOS"},
	},
	"T1124": {
		Name:      "TA0007: Discovery => T1124: System Time Discovery",
		Platforms: []string{"Windows"},
	},
	"T1125": {
		Name:      "TA0009: Collection => T1125: Video Capture",
		Platforms: []string{"Linux", "Windows", "macOS"},
	},
	"T1127": {
		Name:      "TA0005: Defense Evasion => T1127: Trusted Developer Utilities Proxy Execution",
		Platforms: []string{"Windows"},
	},
	"T1127.001": {
		Name:      "TA0005: Defense Evasion => T1127.001: MSBuild",
		Platforms: []string{"Windows"},
	},
	"T1129": {
		Name:      "TA0002: Execution => T1129: Shared Modules",
		Platforms: []string{"Windows"},
	},
	"T1132": {
		Name:      "TA0011: Command and Control => T1132: Data Encoding",
		Platforms: []string{"Linux", "Windows", "macOS"},
	},
	"T1132.001": {
		Name:      "TA0011: Command and Control => T1132.001: Standard Encoding",
		Platforms: []string{"Linux", "Windows", "macOS"},
	},
	"T1132.002": {
		Name:      "TA0011: Command and Control => T1132.002: Non-Standard Encoding",
		Platforms: []string{"Linux", "Windows", "macOS"},
	},
	"T1133": {
		Name:      "TA0001: Initial Access, TA0003: Persistence => T1133: External Remote Services",
		Platforms: []string{"Containers", "Linux", "Windows", "macOS"},
	},
	"T1134": {
		Name:      "TA0004: Privilege Escalation, TA0005: Defense Evasion => T1134: Access Token Manipulation",
		Platforms: []string{"Windows"},
	},
	"T1134.001": {
		Name:      "TA0004: Privilege Escalation, TA0005: Defense Evasion => T1134.001: Token Impersonation/Theft",
		Platforms: []string{"Windows"},
	},
	"T1134.002": {
		Name:      "TA0004: Privilege Escalation, TA0005: Defense Evasion => T1134.002: Create Process with Token",
		Platforms: []string{"Windows"},
	},
	"T1134.003": {
		Name:      "TA0004: Privilege Escalation, TA0005: Defense Evasion => T1134.003: Make and Impersonate Token",
		Platforms: []string{"Windows"},
	},
	"T1134.004": {
		Name:      "TA0004: Privilege Escalation, TA0005: Defense Evasion => T1134.004: Parent PID Spoofing",
		Platforms: []string{"Windows"},
	},
	"T1134.005": {
		Name:      "TA0004: Privilege Escalation, TA0005: Defense Evasion => T1134.005: SID-History Injection",
		Platforms: []string{"Windows"},
	},
	"T1135": {
		Name:      "TA0007: Discovery => T1135: Network Share Discovery",
		Platforms: []string{"Linux", "Windows", "macOS"},
	},
	"T1136": {
		Name:      "TA0003: Persistence => T1136: Create Account",
		Platforms: []string{"Azure AD", "Google Workspace", "IaaS", "Linux", "Office 365", "Windows", "macOS"},
	},
	"T1136.001": {
		Name:      "TA0003: Persistence => T1136.001: Local Account",
		Platforms: []string{"Linux", "Windows", "macOS"},
	},
	"T1136.002": {
		Name:      "TA0003: Persistence => T1136.002: Domain Account",
		Platforms: []string{"Linux", "Windows", "macOS"},
	},
	"T1136.003": {
		Name:      "TA0003: Persistence => T1136.003: Cloud Account",
		Platforms: []string{"Azure AD", "Google Workspace", "IaaS", "Office 365", "SaaS"},
	},
	"T1137": {
		Name:      "TA0003: Persistence => T1137: Office Application Startup",
		Platforms: []string{"Office 365", "Windows"},
	},
	"T1137.001": {
		Name:      "TA0003: Persistence => T1137.001: Office Template Macros",
		Platforms: []string{"Office 365", "Windows"},
	},
	"T1137.002": {
		Name:      "TA0003: Persistence => T1137.002: Office Test",
		Platforms: []string{"Office 365", "Windows"},
	},
	"T1137.003": {
		Name:      "TA0003: Persistence => T1137.003: Outlook Forms",
		Platforms: []string{"Office 365", "Windows"},
	},
	"T1137.004": {
		Name:      "TA0003: Persistence => T1137.004: Outlook Home Page",
		Platforms: []string{"Office 365", "Windows"},
	},
	"T1137.005": {
		Name:      "TA0003: Persistence => T1137.005: Outlook Rules",
		Platforms: []string{"Office 365", "Windows"},
	},
	"T1137.006": {
		Name:      "TA0003: Persistence => T1137.006: Add-ins",
		Platforms: []string{"Office 365", "Windows"},
	},
	"T1140": {
		Name:      "TA0005: Defense Evasion => T1140: Deobfuscate/Decode Files or Information",
		Platforms: []string{"Linux", "Windows", "macOS"},
	},
	"T1176": {
		Name:      "TA0003: Persistence => T1176: Browser Extensions",
		Platforms: []string{"Linux", "Windows", "macOS"},
	},
	"T1185": {
		Name:      "TA0009: Collection => T1185: Browser Session Hijacking",
		Platforms: []string{"Windows"},
	},
	"T1187": {
		Name:      "TA0006: Credential Access => T1187: Forced Authentication",
		Platforms: []string{"Windows"},
	},
	"T1189": {
		Name:      "TA0001: Initial Access => T1189: Drive-by Compromise",
		Platforms: []string{"Linux", "SaaS", "Windows", "macOS"},
	},
	"T1190": {
		Name:      "TA0001: Initial Access => T1190: Exploit Public-Facing Application",
		Platforms: []string{"Containers", "IaaS", "Linux", "Network", "Windows", "macOS"},
	},
	"T1195": {
		Name:      "TA0001: Initial Access => T1195: Supply Chain Compromise",
		Platforms: []string{"Linux", "Windows", "macOS"},
	},
	"T1195.001": {
		Name:      "TA0001: Initial Access => T1195.001: Compromise Software Dependencies and Development Tools",
		Platforms: []string{"Linux", "Windows", "macOS"},
	},
	"T1195.002": {
		Name:      "TA0001: Initial Access => T1195.002: Compromise Software Supply Chain",
		Platforms: []string{"Linux", "Windows", "macOS"},
	},
	"T1195.003": {
		Name:      "TA0001: Initial Access => T1195.003: Compromise Hardware Supply Chain",
		Platforms: []string{"Linux", "Windows", "macOS"},
	},
	"T1197": {
		Name:      "TA0003: Persistence, TA0005: Defense Evasion => T1197: BITS Jobs",
		Platforms: []string{"Windows"},
	},
	"T1199": {
		Name:      "TA0001: Initial Access => T1199: Trusted Relationship",
		Platforms: []string{"IaaS", "Linux", "Office 365", "SaaS", "Windows", "macOS"},
	},
	"T1200": {
		Name:      "TA0001: Initial Access => T1200: Hardware Additions",
		Platforms: []string{"Linux", "Windows", "macOS"},
	},
	"T1201": {
		Name:      "TA0007: Discovery => T1201: Password Policy Discovery",
		Platforms: []string{"IaaS", "Linux", "Network", "Windows", "macOS"},
	},
	"T1202": {
		Name:      "TA0005: Defense Evasion => T1202: Indirect Command Execution",
		Platforms: []string{"Windows"},
	},
	"T1203": {
		Name:      "TA0002: Execution => T1203: Exploitation for Client Execution",
		Platforms: []string{"Linux", "Windows", "macOS"},
	},
	"T1204": {
		Name:      "TA0002: Execution => T1204: User Execution",
		Platforms: []string{"Containers", "IaaS", "Linux", "Windows", "macOS"},
	},
	"T1204.001": {
		Name:      "TA0002: Execution => T1204.001: Malicious Link",
		Platforms: []string{"Linux", "Windows", "macOS"},
	},
	"T1204.002": {
		Name:      "TA0002: Execution => T1204.002: Malicious File",
		Platforms: []string{"Linux", "Windows", "macOS"},
	},
	"T1204.003": {
		Name:      "TA0002: Execution => T1204.003: Malicious Image",
		Platforms: []string{"Containers", "IaaS"},
	},
	"T1205": {
		Name:      "TA0003: Persistence, TA0005: Defense Evasion, TA0011: Command and Control => T1205: Traffic Signaling",
		Platforms: []string{"Linux", "Network", "Windows", "macOS"},
	},
	"T1205.001": {
		Name:      "TA0003: Persistence, TA0005: Defense Evasion, TA0011: Command and Control => T1205.001: Port Knocking",
		Platforms: []string{"Linux", "Network", "Windows", "macOS"},
	},
	"T1205.002": {
		Name:      "TA0003: Persistence, TA0005: Defense Evasion, TA0011: Command and Control => T1205.002: Socket Filters",
		Platforms: []string{"Linux", "Windows", "macOS"},
	},
	"T1207": {
		Name:      "TA0005: Defense Evasion => T1207: Rogue Domain Controller",
		Platforms: []string{"Windows"},
	},
	"T1210": {
		Name:      "TA0008: Lateral Movement => T1210: Exploitation of Remote Services",
		Platforms: []string{"Linux", "Windows", "macOS"},
	},
	"T1211": {
		Name:      "TA0005: Defense Evasion => T1211: Exploitation for Defense Evasion",
		Platforms: []string{"Linux", "Windows", "macOS"},
	},
	"T1212": {
		Name:      "TA0006: Credential Access => T1212: Exploitation for Credential Access",
		Platforms: []string{"Linux", "Windows", "macOS"},
	},
	"T1213": {
		Name:      "TA0009: Collection => T1213: Data from Information Repositories",
		Platforms: []string{"Google Workspace", "IaaS", "Linux", "Office 365", "SaaS", "Windows", "macOS"},
	},
	"T1213.001": {
		Name:      "TA0009: Collection => T1213.001: Confluence",
		Platforms: []string{"SaaS"},
	},
	"T1213.002": {
		Name:      "TA0009: Collection => T1213.002: Sharepoint",
		Platforms: []string{"Office 365", "Windows"},
	},
	"T1213.003": {
		Name:      "TA0009: Collection => T1213.003: Code Repositories",
		Platforms: []string{"SaaS"},
	},
	"T1216": {
		Name:      "TA0005: Defense Evasion => T1216: System Script Proxy Execution",
		Platforms: []string{"Windows"},
	},
	"T1216.001": {
		Name:      "TA0005: Defense Evasion => T1216.001: PubPrn",
		Platforms: []string{"Windows"},
	},
	"T1217": {
		Name:      "TA0007: Discovery => T1217: Browser Bookmark Discovery",
		Platforms: []string{"Linux", "Windows", "macOS"},
	},
	"T1218": {
		Name:      "TA0005: Defense Evasion => T1218: System Binary Proxy Execution",
		Platforms: []string{"Linux", "Windows", "macOS"},
	},
	"T1218.001": {
		Name:      "TA0005: Defense Evasion => T1218.001: Compiled HTML File",
		Platforms: []string{"Windows"},
	},
	"T1218.002": {
		Name:      "TA0005: Defense Evasion => T1218.002: Control Panel",
		Platforms: []string{"Windows"},
	},
	"T1218.003": {
		Name:      "TA0005: Defense Evasion => T1218.003: CMSTP",
		Platforms: []string{"Windows"},
	},
	"T1218.004": {
		Name:      "TA0005: Defense Evasion => T1218.004: InstallUtil",
		Platforms: []string{"Windows"},
	},
	"T1218.005": {
		Name:      "TA0005: Defense Evasion => T1218.005: Mshta",
		Platforms: []string{"Windows"},
	},
	"T1218.007": {
		Name:      "TA0005: Defense Evasion => T1218.007: Msiexec",
		Platforms: []string{"Windows"},
	},
	"T1218.008": {
		Name:      "TA0005: Defense Evasion => T1218.008: Odbcconf",
		Platforms: []string{"Windows"},
	},
	"T1218.009": {
		Name:      "TA0005: Defense Evasion => T1218.009: Regsvcs/Regasm",
		Platforms: []string{"Windows"},
	},
	"T1218.010": {
		Name:      "TA0005: Defense Evasion => T1218.010: Regsvr32",
		Platforms: []string{"Windows"},
	},
	"T1218.011": {
		Name:      "TA0005: Defense Evasion => T1218.011: Rundll32",
		Platforms: []string{"Windows"},
	},
	"T1218.012": {
		Name:      "TA0005: Defense Evasion => T1218.012: Verclsid",
		Platforms: []string{"Windows"},
	},
	"T1218.013": {
		Name:      "TA0005: Defense Evasion => T1218.013: Mavinject",
		Platforms: []string{"Windows"},
	},
	"T1218.014": {
		Name:      "TA0005: Defense Evasion => T1218.014: MMC",
		Platforms: []string{"Windows"},
	},
	"T1219": {
		Name:      "TA0011: Command and Control => T1219: Remote Access Software",
		Platforms: []string{"Linux", "Windows", "macOS"},
	},
	"T1220": {
		Name:      "TA0005: Defense Evasion => T1220: XSL Script Processing",
		Platforms: []string{"Windows"},
	},
	"T1221": {
		Name:      "TA0005: Defense Evasion => T1221: Template Injection",
		Platforms: []string{"Windows"},
	},
	"T1222": {
		Name:      "TA0005: Defense Evasion => T1222: File and Directory Permissions Modification",
		Platforms: []string{"Linux", "Windows", "macOS"},
	},
	"T1222.001": {
		Name:      "TA0005: Defense Evasion => T1222.001: Windows File and Directory Permissions Modification",
		Platforms: []string{"Windows"},
	},
	"T1222.002": {
		Name:      "TA0005: Defense Evasion => T1222.002: Linux and Mac File and Directory Permissions Modification",
		Platforms: []string{"Linux", "macOS"},
	},
	"T1480": {
		Name:      "TA0005: Defense Evasion => T1480: Execution Guardrails",
		Platforms: []string{"Linux", "Windows", "macOS"},
	},
	"T1480.001": {
		Name:      "TA0005: Defense Evasion => T1480.001: Environmental Keying",
		Platforms: []string{"Linux", "Windows", "macOS"},
	},
	"T1482": {
		Name:      "TA0007: Discovery => T1482: Domain Trust Discovery",
		Platforms: []string{"Windows"},
	},
	"T1484": {
		Name:      "TA0004: Privilege Escalation, TA0005: Defense Evasion => T1484: Domain Policy Modification",
		Platforms: []string{"Azure AD", "Windows"},
	},
	"T1484.001": {
		Name:      "TA0004: Privilege Escalation, TA0005: Defense Evasion => T1484.001: Group Policy Modification",
		Platforms: []string{"Windows"},
	},
	"T1484.002": {
		Name:      "TA0004: Privilege Escalation, TA0005: Defense Evasion => T1484.002: Domain Trust Modification",
		Platforms: []string{"Azure AD", "Windows"},
	},
	"T1485": {
		Name:      "TA0040: Impact => T1485: Data Destruction",
		Platforms: []string{"IaaS", "Linux", "Windows", "macOS"},
	},
	"T1486": {
		Name:      "TA0040: Impact => T1486: Data Encrypted for Impact",
		Platforms: []string{"IaaS", "Linux", "Windows", "macOS"},
	},
	"T1489": {
		Name:      "TA0040: Impact => T1489: Service Stop",
		Platforms: []string{"Linux", "Windows", "macOS"},
	},
	"T1490": {
		Name:      "TA0040: Impact => T1490: Inhibit System Recovery",
		Platforms: []string{"Linux", "Windows", "macOS"},
	},
	"T1491": {
		Name:      "TA0040: Impact => T1491: Defacement",
		Platforms: []string{"IaaS", "Linux", "Windows", "macOS"},
	},
	"T1491.001": {
		Name:      "TA0040: Impact => T1491.001: Internal Defacement",
		Platforms: []string{"Linux", "Windows", "macOS"},
	},
	"T1491.002": {
		Name:      "TA0040: Impact => T1491.002: External Defacement",
		Platforms: []string{"IaaS", "Linux", "Windows", "macOS"},
	},
	"T1495": {
		Name:      "TA0040: Impact => T1495: Firmware Corruption",
		Platforms: []string{"Linux", "Network", "Windows", "macOS"},
	},
	"T1496": {
		Name:      "TA0040: Impact => T1496: Resource Hijacking",
		Platforms: []string{"Containers", "IaaS", "Linux", "Windows", "macOS"},
	},
	"T1497": {
		Name:      "TA0005: Defense Evasion, TA0007: Discovery => T1497: Virtualization/Sandbox Evasion",
		Platforms: []string{"Linux", "Windows", "macOS"},
	},
	"T1497.001": {
		Name:      "TA0005: Defense Evasion, TA0007: Discovery => T1497.001: System Checks",
		Platforms: []string{"Linux", "Windows", "macOS"},
	},
	"T1497.002": {
		Name:      "TA0005: Defense Evasion, TA0007: Discovery => T1497.002: User Activity Based Checks",
		Platforms: []string{"Linux", "Windows", "macOS"},
	},
	"T1497.003": {
		Name:      "TA0005: Defense Evasion, TA0007: Discovery => T1497.003: Time Based Evasion",
		Platforms: []string{"Linux", "Windows", "macOS"},
	},
	"T1498": {
		Name:      "TA0040: Impact => T1498: Network Denial of Service",
		Platforms: []string{"Azure AD", "Containers", "Google Workspace", "IaaS", "Linux", "Office 365", "SaaS", "Windows", "macOS"},
	},
	"T1498.001": {
		Name:      "TA0040: Impact => T1498.001: Direct Network Flood",
		Platforms: []string{"Azure AD", "Google Workspace", "IaaS", "Linux", "Office 365", "SaaS", "Windows", "macOS"},
	},
	"T1498.002": {
		Name:      "TA0040: Impact => T1498.002: Reflection Amplification",
		Platforms: []string{"Azure AD", "Google Workspace", "IaaS", "Linux", "Office 365", "SaaS", "Windows", "macOS"},
	},
	"T1499": {
		Name:      "TA0040: Impact => T1499: Endpoint Denial of Service",
		Platforms: []string{"Azure AD", "Containers", "Google Workspace", "IaaS", "Linux", "Office 365", "SaaS", "Windows", "macOS"},
	},
	"T1499.001": {
		Name:      "TA0040: Impact => T1499.001: OS Exhaustion Flood",
		Platforms: []string{"Linux", "Windows", "macOS"},
	},
	"T1499.002": {
		Name:      "TA0040: Impact => T1499.002: Service Exhaustion Flood",
		Platforms: []string{"Azure AD", "Google Workspace", "IaaS", "Linux", "Office 365", "SaaS", "Windows", "macOS"},
	},
	"T1499.003": {
		Name:      "TA0040: Impact => T1499.003: Application Exhaustion Flood",
		Platforms: []string{"Azure AD", "Google Workspace", "IaaS", "Linux", "Office 365", "SaaS", "Windows", "macOS"},
	},
	"T1499.004": {
		Name:      "TA0040: Impact => T1499.004: Application or System Exploitation",
		Platforms: []string{"Azure AD", "Google Workspace", "IaaS", "Linux", "Office 365", "SaaS", "Windows", "macOS"},
	},
	"T1505": {
		Name:      "TA0003: Persistence => T1505: Server Software Component",
		Platforms: []string{"Linux", "Network", "Windows", "macOS"},
	},
	"T1505.001": {
		Name:      "TA0003: Persistence => T1505.001: SQL Stored Procedures",
		Platforms: []string{"Linux", "Windows"},
	},
	"T1505.002": {
		Name:      "TA0003: Persistence => T1505.002: Transport Agent",
		Platforms: []string{"Linux", "Windows"},
	},
	"T1505.003": {
		Name:      "TA0003: Persistence => T1505.003: Web Shell",
		Platforms: []string{"Linux", "Network", "Windows", "macOS"},
	},
	"T1505.004": {
		Name:      "TA0003: Persistence => T1505.004: IIS Components",
		Platforms: []string{"Windows"},
	},
	"T1505.005": {
		Name:      "TA0003: Persistence => T1505.005: Terminal Services DLL",
		Platforms: []string{"Windows"},
	},
	"T1518": {
		Name:      "TA0007: Discovery => T1518: Software Discovery",
		Platforms: []string{"Azure AD", "Google Workspace", "IaaS", "Linux", "Office 365", "SaaS", "Windows", "macOS"},
	},
	"T1518.001": {
		Name:      "TA0007: Discovery => T1518.001: Security Software Discovery",
		Platforms: []string{"Azure AD", "Google Workspace", "IaaS", "Linux", "Office 365", "SaaS", "Windows", "macOS"},
	},
	"T1525": {
		Name:      "TA0003: Persistence => T1525: Implant Internal Image",
		Platforms: []string{"Containers", "IaaS"},
	},
	"T1526": {
		Name:      "TA0007: Discovery => T1526: Cloud Service Discovery",
		Platforms: []string{"Azure AD", "Google Workspace", "IaaS", "Office 365", "SaaS"},
	},
	"T1528": {
		Name:      "TA0006: Credential Access => T1528: Steal Application Access Token",
		Platforms: []string{"Azure AD", "Containers", "Google Workspace", "Office 365", "SaaS"},
	},
	"T1529": {
		Name:      "TA0040: Impact => T1529: System Shutdown/Reboot",
		Platforms: []string{"Linux", "Network", "Windows", "macOS"},
	},
	"T1530": {
		Name:      "TA0009: Collection => T1530: Data from Cloud Storage",
		Platforms: []string{"IaaS", "SaaS"},
	},
	"T1531": {
		Name:      "TA0040: Impact => T1531: Account Access Removal",
		Platforms: []string{"Linux", "Office 365", "SaaS", "Windows", "macOS"},
	},
	"T1534": {
		Name:      "TA0008: Lateral Movement => T1534: Internal Spearphishing",
		Platforms: []string{"Google Workspace", "Linux", "Office 365", "SaaS", "Windows", "macOS"},
	},
	"T1535": {
		Name:      "TA0005: Defense Evasion => T1535: Unused/Unsupported Cloud Regions",
		Platforms: []string{"IaaS"},
	},
	"T1537": {
		Name:      "TA0010: Exfiltration => T1537: Transfer Data to Cloud Account",
		Platforms: []string{"IaaS"},
	},
	"T1538": {
		Name:      "TA0007: Discovery => T1538: Cloud Service Dashboard",
		Platforms: []string{"Azure AD", "Google Workspace", "IaaS", "Office 365"},
	},
	"T1539": {
		Name:      "TA0006: Credential Access => T1539: Steal Web Session Cookie",
		Platforms: []string{"Google Workspace", "Linux", "Office 365", "SaaS", "Windows", "macOS"},
	},
	"T1542": {
		Name:      "TA0003: Persistence, TA0005: Defense Evasion => T1542: Pre-OS Boot",
		Platforms: []string{"Linux", "Network", "Windows", "macOS"},
	},
	"T1542.001": {
		Name:      "TA0003: Persistence, TA0005: Defense Evasion => T1542.001: System Firmware",
		Platforms: []string{"Windows"},
	},
	"T1542.002": {
		Name:      "TA0003: Persistence, TA0005: Defense Evasion => T1542.002: Component Firmware",
		Platforms: []string{"Linux", "Windows", "macOS"},
	},
	"T1542.003": {
		Name:      "TA0003: Persistence, TA0005: Defense Evasion => T1542.003: Bootkit",
		Platforms: []string{"Linux", "Windows"},
	},
	"T1542.004": {
		Name:      "TA0003: Persistence, TA0005: Defense Evasion => T1542.004: ROMMONkit",
		Platforms: []string{"Network"},
	},
	"T1542.005": {
		Name:      "TA0003: Persistence, TA0005: Defense Evasion => T1542.005: TFTP Boot",
		Platforms: []string{"Network"},
	},
	"T1543": {
		Name:      "TA0003: Persistence, TA0004: Privilege Escalation => T1543: Create or Modify System Process",
		Platforms: []string{"Linux", "Windows", "macOS"},
	},
	"T1543.001": {
		Name:      "TA0003: Persistence, TA0004: Privilege Escalation => T1543.001: Launch Agent",
		Platforms: []string{"macOS"},
	},
	"T1543.002": {
		Name:      "TA0003: Persistence, TA0004: Privilege Escalation => T1543.002: Systemd Service",
		Platforms: []string{"Linux"},
	},
	"T1543.003": {
		Name:      "TA0003: Persistence, TA0004: Privilege Escalation => T1543.003: Windows Service",
		Platforms: []string{"Windows"},
	},
	"T1543.004": {
		Name:      "TA0003: Persistence, TA0004: Privilege Escalation => T1543.004: Launch Daemon",
		Platforms: []string{"macOS"},
	},
	"T1546": {
		Name:      "TA0003: Persistence, TA0004: Privilege Escalation => T1546: Event Triggered Execution",
		Platforms: []string{"IaaS", "Linux", "Office 365", "SaaS", "Windows", "macOS"},
	},
	"T1546.001": {
		Name:      "TA0003: Persistence, TA0004: Privilege Escalation => T1546.001: Change Default File Association",
		Platforms: []string{"Windows"},
	},
	"T1546.002": {
		Name:      "TA0003: Persistence, TA0004: Privilege Escalation => T1546.002: Screensaver",
		Platforms: []string{"Windows"},
	},
	"T1546.003": {
		Name:      "TA0003: Persistence, TA0004: Privilege Escalation => T1546.003: Windows Management Instrumentation Event Subscription",
		Platforms: []string{"Windows"},
	},
	"T1546.004": {
		Name:      "TA0003: Persistence, TA0004: Privilege Escalation => T1546.004: Unix Shell Configuration Modification",
		Platforms: []string{"Linux", "macOS"},
	},
	"T1546.005": {
		Name:      "TA0003: Persistence, TA0004: Privilege Escalation => T1546.005: Trap",
		Platforms: []string{"Linux", "macOS"},
	},
	"T1546.006": {
		Name:      "TA0003: Persistence, TA0004: Privilege Escalation => T1546.006: LC_LOAD_DYLIB Addition",
		Platforms: []string{"macOS"},
	},
	"T1546.007": {
		Name:      "TA0003: Persistence, TA0004: Privilege Escalation => T1546.007: Netsh Helper DLL",
		Platforms: []string{"Windows"},
	},
	"T1546.008": {
		Name:      "TA0003: Persistence, TA0004: Privilege Escalation => T1546.008: Accessibility Features",
		Platforms: []string{"Windows"},
	},
	"T1546.009": {
		Name:      "TA0003: Persistence, TA0004: Privilege Escalation => T1546.009: AppCert DLLs",
		Platforms: []string{"Windows"},
	},
	"T1546.010": {
		Name:      "TA0003: Persistence, TA0004: Privilege Escalation => T1546.010: AppInit DLLs",
		Platforms: []string{"Windows"},
	},
	"T1546.011": {
		Name:      "TA0003: Persistence, TA0004: Privilege Escalation => T1546.011: Application Shimming",
		Platforms: []string{"Windows"},
	},
	"T1546.012": {
		Name:      "TA0003: Persistence, TA0004: Privilege Escalation => T1546.012: Image File Execution Options Injection",
		Platforms: []string{"Windows"},
	},
	"T1546.013": {
		Name:      "TA0003: Persistence, TA0004: Privilege Escalation => T1546.013: PowerShell Profile",
		Platforms: []string{"Windows"},
	},
	"T1546.014": {
		Name:      "TA0003: Persistence, TA0004: Privilege Escalation => T1546.014: Emond",
		Platforms: []string{"macOS"},
	},
	"T1546.015": {
		Name:      "TA0003: Persistence, TA0004: Privilege Escalation => T1546.015: Component Object Model Hijacking",
		Platforms: []string{"Windows"},
	},
	"T1546.016": {
		Name:      "TA0003: Persistence, TA0004: Privilege Escalation => T1546.016: Installer Packages",
		Platforms: []string{"Linux", "Windows", "macOS"},
	},
	"T1547": {
		Name:      "TA0003: Persistence, TA0004: Privilege Escalation => T1547: Boot or Logon Autostart Execution",
		Platforms: []string{"Linux", "Windows", "macOS"},
	},
	"T1547.001": {
		Name:      "TA0003: Persistence, TA0004: Privilege Escalation => T1547.001: Registry Run Keys / Startup Folder",
		Platforms: []string{"Windows"},
	},
	"T1547.002": {
		Name:      "TA0003: Persistence, TA0004: Privilege Escalation => T1547.002: Authentication Package",
		Platforms: []string{"Windows"},
	},
	"T1547.003": {
		Name:      "TA0003: Persistence, TA0004: Privilege Escalation => T1547.003: Time Providers",
		Platforms: []string{"Windows"},
	},
	"T1547.004": {
		Name:      "TA0003: Persistence, TA0004: Privilege Escalation => T1547.004: Winlogon Helper DLL",
		Platforms: []string{"Windows"},
	},
	"T1547.005": {
		Name:      "TA0003: Persistence, TA0004: Privilege Escalation => T1547.005: Security Support Provider",
		Platforms: []string{"Windows"},
	},
	"T1547.006": {
		Name:      "TA0003: Persistence, TA0004: Privilege Escalation => T1547.006: Kernel Modules and Extensions",
		Platforms: []string{"Linux", "macOS"},
	},
	"T1547.007": {
		Name:      "TA0003: Persistence, TA0004: Privilege Escalation => T1547.007: Re-opened Applications",
		Platforms: []string{"macOS"},
	},
	"T1547.008": {
		Name:      "TA0003: Persistence, TA0004: Privilege Escalation => T1547.008: LSASS Driver",
		Platforms: []string{"Windows"},
	},
	"T1547.009": {
		Name:      "TA0003: Persistence, TA0004: Privilege Escalation => T1547.009: Shortcut Modification",
		Platforms: []string{"Windows"},
	},
	"T1547.010": {
		Name:      "TA0003: Persistence, TA0004: Privilege Escalation => T1547.010: Port Monitors",
		Platforms: []string{"Windows"},
	},
	"T1547.012": {
		Name:      "TA0003: Persistence, TA0004: Privilege Escalation => T1547.012: Print Processors",
		Platforms: []string{"Windows"},
	},
	"T1547.013": {
		Name:      "TA0003: Persistence, TA0004: Privilege Escalation => T1547.013: XDG Autostart Entries",
		Platforms: []string{"Linux"},
	},
	"T1547.014": {
		Name:      "TA0003: Persistence, TA0004: Privilege Escalation => T1547.014: Active Setup",
		Platforms: []string{"Windows"},
	},
	"T1547.015": {
		Name:      "TA0003: Persistence, TA0004: Privilege Escalation => T1547.015: Login Items",
		Platforms: []string{"macOS"},
	},
	"T1548": {
		Name:      "TA0004: Privilege Escalation, TA0005: Defense Evasion => T1548: Abuse Elevation Control Mechanism",
		Platforms: []string{"Linux", "Windows", "macOS"},
	},
	"T1548.001": {
		Name:      "TA0004: Privilege Escalation, TA0005: Defense Evasion => T1548.001: Setuid and Setgid",
		Platforms: []string{"Linux", "macOS"},
	},
	"T1548.002": {
		Name:      "TA0004: Privilege Escalation, TA0005: Defense Evasion => T1548.002: Bypass User Account Control",
		Platforms: []string{"Windows"},
	},
	"T1548.003": {
		Name:      "TA0004: Privilege Escalation, TA0005: Defense Evasion => T1548.003: Sudo and Sudo Caching",
		Platforms: []string{"Linux", "macOS"},
	},
	"T1548.004": {
		Name:      "TA0004: Privilege Escalation, TA0005: Defense Evasion => T1548.004: Elevated Execution with Prompt",
		Platforms: []string{"macOS"},
	},
	"T1550": {
		Name:      "TA0005: Defense Evasion, TA0008: Lateral Movement => T1550: Use Alternate Authentication Material",
		Platforms: []string{"Containers", "Google Workspace", "IaaS", "Office 365", "SaaS", "Windows"},
	},
	"T1550.001": {
		Name:      "TA0005: Defense Evasion, TA0008: Lateral Movement => T1550.001: Application Access Token",
		Platforms: []string{"Azure AD", "Containers", "Google Workspace", "IaaS", "Office 365", "SaaS"},
	},
	"T1550.002": {
		Name:      "TA0005: Defense Evasion, TA0008: Lateral Movement => T1550.002: Pass the Hash",
		Platforms: []string{"Windows"},
	},
	"T1550.003": {
		Name:      "TA0005: Defense Evasion, TA0008: Lateral Movement => T1550.003: Pass the Ticket",
		Platforms: []string{"Windows"},
	},
	"T1550.004": {
		Name:      "TA0005: Defense Evasion, TA0008: Lateral Movement => T1550.004: Web Session Cookie",
		Platforms: []string{"Google Workspace", "IaaS", "Office 365", "SaaS"},
	},
	"T1552": {
		Name:      "TA0006: Credential Access => T1552: Unsecured Credentials",
		Platforms: []string{"Azure AD", "Containers", "Google Workspace", "IaaS", "Linux", "Office 365", "SaaS", "Windows", "macOS"},
	},
	"T1552.001": {
		Name:      "TA0006: Credential Access => T1552.001: Credentials In Files",
		Platforms: []string{"Containers", "IaaS", "Linux", "Windows", "macOS"},
	},
	"T1552.002": {
		Name:      "TA0006: Credential Access => T1552.002: Credentials in Registry",
		Platforms: []string{"Windows"},
	},
	"T1552.003": {
		Name:      "TA0006: Credential Access => T1552.003: Bash History",
		Platforms: []string{"Linux", "macOS"},
	},
	"T1552.004": {
		Name:      "TA0006: Credential Access => T1552.004: Private Keys",
		Platforms: []string{"Linux", "Windows", "macOS"},
	},
	"T1552.005": {
		Name:      "TA0006: Credential Access => T1552.005: Cloud Instance Metadata API",
		Platforms: []string{"IaaS"},
	},
	"T1552.006": {
		Name:      "TA0006: Credential Access => T1552.006: Group Policy Preferences",
		Platforms: []string{"Windows"},
	},
	"T1552.007": {
		Name:      "TA0006: Credential Access => T1552.007: Container API",
		Platforms: []string{"Containers"},
	},
	"T1553": {
		Name:      "TA0005: Defense Evasion => T1553: Subvert Trust Controls",
		Platforms: []string{"Linux", "Windows", "macOS"},
	},
	"T1553.001": {
		Name:      "TA0005: Defense Evasion => T1553.001: Gatekeeper Bypass",
		Platforms: []string{"macOS"},
	},
	"T1553.002": {
		Name:      "TA0005: Defense Evasion => T1553.002: Code Signing",
		Platforms: []string{"Windows", "macOS"},
	},
	"T1553.003": {
		Name:      "TA0005: Defense Evasion => T1553.003: SIP and Trust Provider Hijacking",
		Platforms: []string{"Windows"},
	},
	"T1553.004": {
		Name:      "TA0005: Defense Evasion => T1553.004: Install Root Certificate",
		Platforms: []string{"Linux", "Windows", "macOS"},
	},
	"T1553.005": {
		Name:      "TA0005: Defense Evasion => T1553.005: Mark-of-the-Web Bypass",
		Platforms: []string{"Windows"},
	},
	"T1553.006": {
		Name:      "TA0005: Defense Evasion => T1553.006: Code Signing Policy Modification",
		Platforms: []string{"Windows", "macOS"},
	},
	"T1554": {
		Name:      "TA0003: Persistence => T1554: Compromise Client Software Binary",
		Platforms: []string{"Linux", "Windows", "macOS"},
	},
	"T1555": {
		Name:      "TA0006: Credential Access => T1555: Credentials from Password Stores",
		Platforms: []string{"Linux", "Windows", "macOS"},
	},
	"T1555.001": {
		Name:      "TA0006: Credential Access => T1555.001: Keychain",
		Platforms: []string{"macOS"},
	},
	"T1555.002": {
		Name:      "TA0006: Credential Access => T1555.002: Securityd Memory",
		Platforms: []string{"Linux", "macOS"},
	},
	"T1555.003": {
		Name:      "TA0006: Credential Access => T1555.003: Credentials from Web Browsers",
		Platforms: []string{"Linux", "Windows", "macOS"},
	},
	"T1555.004": {
		Name:      "TA0006: Credential Access => T1555.004: Windows Credential Manager",
		Platforms: []string{"Windows"},
	},
	"T1555.005": {
		Name:      "TA0006: Credential Access => T1555.005: Password Managers",
		Platforms: []string{"Linux", "Windows", "macOS"},
	},
	"T1556": {
		Name:      "TA0003: Persistence, TA0005: Defense Evasion, TA0006: Credential Access => T1556: Modify Authentication Process",
		Platforms: []string{"Azure AD", "Google Workspace", "IaaS", "Linux", "Network", "Office 365", "SaaS", "Windows", "macOS"},
	},
	"T1556.001": {
		Name:      "TA0003: Persistence, TA0005: Defense Evasion, TA0006: Credential Access => T1556.001: Domain Controller Authentication",
		Platforms: []string{"Windows"},
	},
	"T1556.002": {
		Name:      "TA0003: Persistence, TA0005: Defense Evasion, TA0006: Credential Access => T1556.002: Password Filter DLL",
		Platforms: []string{"Windows"},
	},
	"T1556.003": {
		Name:      "TA0003: Persistence, TA0005: Defense Evasion, TA0006: Credential Access => T1556.003: Pluggable Authentication Modules",
		Platforms: []string{"Linux", "macOS"},
	},
	"T1556.004": {
		Name:      "TA0003: Persistence, TA0005: Defense Evasion, TA0006: Credential Access => T1556.004: Network Device Authentication",
		Platforms: []string{"Network"},
	},
	"T1556.005": {
		Name:      "TA0003: Persistence, TA0005: Defense Evasion, TA0006: Credential Access => T1556.005: Reversible Encryption",
		Platforms: []string{"Windows"},
	},
	"T1556.006": {
		Name:      "TA0003: Persistence, TA0005: Defense Evasion, TA0006: Credential Access => T1556.006: Multi-Factor Authentication",
		Platforms: []string{"Azure AD", "Google Workspace", "IaaS", "Linux", "Office 365", "SaaS", "Windows", "macOS"},
	},
	"T1556.007": {
		Name:      "TA0003: Persistence, TA0005: Defense Evasion, TA0006: Credential Access => T1556.007: Hybrid Identity",
		Platforms: []string{"Azure AD", "Google Workspace", "IaaS", "Office 365", "SaaS", "Windows"},
	},
	"T1557": {
		Name:      "TA0006: Credential Access, TA0009: Collection => T1557: Adversary-in-the-Middle",
		Platforms: []string{"Linux", "Network", "Windows", "macOS"},
	},
	"T1557.001": {
		Name:      "TA0006: Credential Access, TA0009: Collection => T1557.001: LLMNR/NBT-NS Poisoning and SMB Relay",
		Platforms: []string{"Windows"},
	},
	"T1557.002": {
		Name:      "TA0006: Credential Access, TA0009: Collection => T1557.002: ARP Cache Poisoning",
		Platforms: []string{"Linux", "Windows", "macOS"},
	},
	"T1557.003": {
		Name:      "TA0006: Credential Access, TA0009: Collection => T1557.003: DHCP Spoofing",
		Platforms: []string{"Linux", "Windows", "macOS"},
	},
	"T1558": {
		Name:      "TA0006: Credential Access => T1558: Steal or Forge Kerberos Tickets",
		Platforms: []string{"Linux", "Windows", "macOS"},
	},
	"T1558.001": {
		Name:      "TA0006: Credential Access => T1558.001: Golden Ticket",
		Platforms: []string{"Windows"},
	},
	"T1558.002": {
		Name:      "TA0006: Credential Access => T1558.002: Silver Ticket",
		Platforms: []string{"Windows"},
	},
	"T1558.003": {
		Name:      "TA0006: Credential Access => T1558.003: Kerberoasting",
		Platforms: []string{"Windows"},
	},
	"T1558.004": {
		Name:      "TA0006: Credential Access => T1558.004: AS-REP Roasting",
		Platforms: []string{"Windows"},
	},
	"T1559": {
		Name:      "TA0002: Execution => T1559: Inter-Process Communication",
		Platforms: []string{"Linux", "Windows", "macOS"},
	},
	"T1559.001": {
		Name:      "TA0002: Execution => T1559.001: Component Object Model",
		Platforms: []string{"Windows"},
	},
	"T1559.002": {
		Name:      "TA0002: Execution => T1559.002: Dynamic Data Exchange",
		Platforms: []string{"Windows"},
	},
	"T1559.003": {
		Name:      "TA0002: Execution => T1559.003: XPC Services",
		Platforms: []string{"macOS"},
	},
	"T1560": {
		Name:      "TA0009: Collection => T1560: Archive Collected Data",
		Platforms: []string{"Linux", "Windows", "macOS"},
	},
	"T1560.001": {
		Name:      "TA0009: Collection => T1560.001: Archive via Utility",
		Platforms: []string{"Linux", "Windows", "macOS"},
	},
	"T1560.002": {
		Name:      "TA0009: Collection => T1560.002: Archive via Library",
		Platforms: []string{"Linux", "Windows", "macOS"},
	},
	"T1560.003": {
		Name:      "TA0009: Collection => T1560.003: Archive via Custom Method",
		Platforms: []string{"Linux", "Windows", "macOS"},
	},
	"T1561": {
		Name:      "TA0040: Impact => T1561: Disk Wipe",
		Platforms: []string{"Linux", "Windows", "macOS"},
	},
	"T1561.001": {
		Name:      "TA0040: Impact => T1561.001: Disk Content Wipe",
		Platforms: []string{"Linux", "Windows", "macOS"},
	},
	"T1561.002": {
		Name:      "TA0040: Impact => T1561.002: Disk Structure Wipe",
		Platforms: []string{"Linux", "Windows", "macOS"},
	},
	"T1562": {
		Name:      "TA0005: Defense Evasion => T1562: Impair Defenses",
		Platforms: []string{"Containers", "IaaS", "Linux", "Network", "Office 365", "Windows", "macOS"},
	},
	"T1562.001": {
		Name:      "TA0005: Defense Evasion => T1562.001: Disable or Modify Tools",
		Platforms: []string{"Containers", "IaaS", "Linux", "Windows", "macOS"},
	},
	"T1562.002": {
		Name:      "TA0005: Defense Evasion => T1562.002: Disable Windows Event Logging",
		Platforms: []string{"Windows"},
	},
	"T1562.003": {
		Name:      "TA0005: Defense Evasion => T1562.003: Impair Command History Logging",
		Platforms: []string{"Linux", "Network", "Windows", "macOS"},
	},
	"T1562.004": {
		Name:      "TA0005: Defense Evasion => T1562.004: Disable or Modify System Firewall",
		Platforms: []string{"Linux", "Windows", "macOS"},
	},
	"T1562.006": {
		Name:      "TA0005: Defense Evasion => T1562.006: Indicator Blocking",
		Platforms: []string{"Linux", "Windows", "macOS"},
	},
	"T1562.007": {
		Name:      "TA0005: Defense Evasion => T1562.007: Disable or Modify Cloud Firewall",
		Platforms: []string{"IaaS"},
	},
	"T1562.008": {
		Name:      "TA0005: Defense Evasion => T1562.008: Disable Cloud Logs",
		Platforms: []string{"IaaS"},
	},
	"T1562.009": {
		Name:      "TA0005: Defense Evasion => T1562.009: Safe Mode Boot",
		Platforms: []string{"Windows"},
	},
	"T1562.010": {
		Name:      "TA0005: Defense Evasion => T1562.010: Downgrade Attack",
		Platforms: []string{"Linux", "Windows", "macOS"},
	},
	"T1563": {
		Name:      "TA0008: Lateral Movement => T1563: Remote Service Session Hijacking",
		Platforms: []string{"Linux", "Windows", "macOS"},
	},
	"T1563.001": {
		Name:      "TA0008: Lateral Movement => T1563.001: SSH Hijacking",
		Platforms: []string{"Linux", "macOS"},
	},
	"T1563.002": {
		Name:      "TA0008: Lateral Movement => T1563.002: RDP Hijacking",
		Platforms: []string{"Windows"},
	},
	"T1564": {
		Name:      "TA0005: Defense Evasion => T1564: Hide Artifacts",
		Platforms: []string{"Linux", "Office 365", "Windows", "macOS"},
	},
	"T1564.001": {
		Name:      "TA0005: Defense Evasion => T1564.001: Hidden Files and Directories",
		Platforms: []string{"Linux", "Windows", "macOS"},
	},
	"T1564.002": {
		Name:      "TA0005: Defense Evasion => T1564.002: Hidden Users",
		Platforms: []string{"Linux", "Windows", "macOS"},
	},
	"T1564.003": {
		Name:      "TA0005: Defense Evasion => T1564.003: Hidden Window",
		Platforms: []string{"Linux", "Windows", "macOS"},
	},
	"T1564.004": {
		Name:      "TA0005: Defense Evasion => T1564.004: NTFS File Attributes",
		Platforms: []string{"Windows"},
	},
	"T1564.005": {
		Name:      "TA0005: Defense Evasion => T1564.005: Hidden File System",
		Platforms: []string{"Linux", "Windows", "macOS"},
	},
	"T1564.006": {
		Name:      "TA0005: Defense Evasion => T1564.006: Run Virtual Instance",
		Platforms: []string{"Linux", "Windows", "macOS"},
	},
	"T1564.007": {
		Name:      "TA0005: Defense Evasion => T1564.007: VBA Stomping",
		Platforms: []string{"Linux", "Windows", "macOS"},
	},
	"T1564.008": {
		Name:      "TA0005: Defense Evasion => T1564.008: Email Hiding Rules",
		Platforms: []string{"Google Workspace", "Linux", "Office 365", "Windows", "macOS"},
	},
	"T1564.009": {
		Name:      "TA0005: Defense Evasion => T1564.009: Resource Forking",
		Platforms: []string{"macOS"},
	},
	"T1564.010": {
		Name:      "TA0005: Defense Evasion => T1564.010: Process Argument Spoofing",
		Platforms: []string{"Windows"},
	},
	"T1565": {
		Name:      "TA0040: Impact => T1565: Data Manipulation",
		Platforms: []string{"Linux", "Windows", "macOS"},
	},
	"T1565.001": {
		Name:      "TA0040: Impact => T1565.001: Stored Data Manipulation",
		Platforms: []string{"Linux", "Windows", "macOS"},
	},
	"T1565.002": {
		Name:      "TA0040: Impact => T1565.002: Transmitted Data Manipulation",
		Platforms: []string{"Linux", "Windows", "macOS"},
	},
	"T1565.003": {
		Name:      "TA0040: Impact => T1565.003: Runtime Data Manipulation",
		Platforms: []string{"Linux", "Windows", "macOS"},
	},
	"T1566": {
		Name:      "TA0001: Initial Access => T1566: Phishing",
		Platforms: []string{"Google Workspace", "Linux", "Office 365", "SaaS", "Windows", "macOS"},
	},
	"T1566.001": {
		Name:      "TA0001: Initial Access => T1566.001: Spearphishing Attachment",
		Platforms: []string{"Linux", "Windows", "macOS"},
	},
	"T1566.002": {
		Name:      "TA0001: Initial Access => T1566.002: Spearphishing Link",
		Platforms: []string{"Google Workspace", "Linux", "Office 365", "SaaS", "Windows", "macOS"},
	},
	"T1566.003": {
		Name:      "TA0001: Initial Access => T1566.003: Spearphishing via Service",
		Platforms: []string{"Linux", "Windows", "macOS"},
	},
	"T1567": {
		Name:      "TA0010: Exfiltration => T1567: Exfiltration Over Web Service",
		Platforms: []string{"Linux", "Windows", "macOS"},
	},
	"T1567.001": {
		Name:      "TA0010: Exfiltration => T1567.001: Exfiltration to Code Repository",
		Platforms: []string{"Linux", "Windows", "macOS"},
	},
	"T1567.002": {
		Name:      "TA0010: Exfiltration => T1567.002: Exfiltration to Cloud Storage",
		Platforms: []string{"Linux", "Windows", "macOS"},
	},
	"T1568": {
		Name:      "TA0011: Command and Control => T1568: Dynamic Resolution",
		Platforms: []string{"Linux", "Windows", "macOS"},
	},
	"T1568.001": {
		Name:      "TA0011: Command and Control => T1568.001: Fast Flux DNS",
		Platforms: []string{"Linux", "Windows", "macOS"},
	},
	"T1568.002": {
		Name:      "TA0011: Command and Control => T1568.002: Domain Generation Algorithms",
		Platforms: []string{"Linux", "Windows", "macOS"},
	},
	"T1568.003": {
		Name:      "TA0011: Command and Control => T1568.003: DNS Calculation",
		Platforms: []string{"Linux", "Windows", "macOS"},
	},
	"T1569": {
		Name:      "TA0002: Execution => T1569: System Services",
		Platforms: []string{"Linux", "Windows", "macOS"},
	},
	"T1569.001": {
		Name:      "TA0002: Execution => T1569.001: Launchctl",
		Platforms: []string{"macOS"},
	},
	"T1569.002": {
		Name:      "TA0002: Execution => T1569.002: Service Execution",
		Platforms: []string{"Windows"},
	},
	"T1570": {
		Name:      "TA0008: Lateral Movement => T1570: Lateral Tool Transfer",
		Platforms: []string{"Linux", "Windows", "macOS"},
	},
	"T1571": {
		Name:      "TA0011: Command and Control => T1571: Non-Standard Port",
		Platforms: []string{"Linux", "Windows", "macOS"},
	},
	"T1572": {
		Name:      "TA0011: Command and Control => T1572: Protocol Tunneling",
		Platforms: []string{"Linux", "Windows", "macOS"},
	},
	"T1573": {
		Name:      "TA0011: Command and Control => T1573: Encrypted Channel",
		Platforms: []string{"Linux", "Windows", "macOS"},
	},
	"T1573.001": {
		Name:      "TA0011: Command and Control => T1573.001: Symmetric Cryptography",
		Platforms: []string{"Linux", "Windows", "macOS"},
	},
	"T1573.002": {
		Name:      "TA0011: Command and Control => T1573.002: Asymmetric Cryptography",
		Platforms: []string{"Linux", "Windows", "macOS"},
	},
	"T1574": {
		Name:      "TA0003: Persistence, TA0004: Privilege Escalation, TA0005: Defense Evasion => T1574: Hijack Execution Flow",
		Platforms: []string{"Linux", "Windows", "macOS"},
	},
	"T1574.001": {
		Name:      "TA0003: Persistence, TA0004: Privilege Escalation, TA0005: Defense Evasion => T1574.001: DLL Search Order Hijacking",
		Platforms: []string{"Windows"},
	},
	"T1574.002": {
		Name:      "TA0003: Persistence, TA0004: Privilege Escalation, TA0005: Defense Evasion => T1574.002: DLL Side-Loading",
		Platforms: []string{"Windows"},
	},
	"T1574.004": {
		Name:      "TA0003: Persistence, TA0004: Privilege Escalation, TA0005: Defense Evasion => T1574.004: Dylib Hijacking",
		Platforms: []string{"macOS"},
	},
	"T1574.005": {
		Name:      "TA0003: Persistence, TA0004: Privilege Escalation, TA0005: Defense Evasion => T1574.005: Executable Installer File Permissions Weakness",
		Platforms: []string{"Windows"},
	},
	"T1574.006": {
		Name:      "TA0003: Persistence, TA0004: Privilege Escalation, TA0005: Defense Evasion => T1574.006: Dynamic Linker Hijacking",
		Platforms: []string{"Linux", "macOS"},
	},
	"T1574.007": {
		Name:      "TA0003: Persistence, TA0004: Privilege Escalation, TA0005: Defense Evasion => T1574.007: Path Interception by PATH Environment Variable",
		Platforms: []string{"Windows"},
	},
	"T1574.008": {
		Name:      "TA0003: Persistence, TA0004: Privilege Escalation, TA0005: Defense Evasion => T1574.008: Path Interception by Search Order Hijacking",
		Platforms: []string{"Windows"},
	},
	"T1574.009": {
		Name:      "TA0003: Persistence, TA0004: Privilege Escalation, TA0005: Defense Evasion => T1574.009: Path Interception by Unquoted Path",
		Platforms: []string{"Windows"},
	},
	"T1574.010": {
		Name:      "TA0003: Persistence, TA0004: Privilege Escalation, TA0005: Defense Evasion => T1574.010: Services File Permissions Weakness",
		Platforms: []string{"Windows"},
	},
	"T1574.011": {
		Name:      "TA0003: Persistence, TA0004: Privilege Escalation, TA0005: Defense Evasion => T1574.011: Services Registry Permissions Weakness",
		Platforms: []string{"Windows"},
	},
	"T1574.012": {
		Name:      "TA0003: Persistence, TA0004: Privilege Escalation, TA0005: Defense Evasion => T1574.012: COR_PROFILER",
		Platforms: []string{"Windows"},
	},
	"T1574.013": {
		Name:      "TA0003: Persistence, TA0004: Privilege Escalation, TA0005: Defense Evasion => T1574.013: KernelCallbackTable",
		Platforms: []string{"Windows"},
	},
	"T1578": {
		Name:      "TA0005: Defense Evasion => T1578: Modify Cloud Compute Infrastructure",
		Platforms: []string{"IaaS"},
	},
	"T1578.001": {
		Name:      "TA0005: Defense Evasion => T1578.001: Create Snapshot",
		Platforms: []string{"IaaS"},
	},
	"T1578.002": {
		Name:      "TA0005: Defense Evasion => T1578.002: Create Cloud Instance",
		Platforms: []string{"IaaS"},
	},
	"T1578.003": {
		Name:      "TA0005: Defense Evasion => T1578.003: Delete Cloud Instance",
		Platforms: []string{"IaaS"},
	},
	"T1578.004": {
		Name:      "TA0005: Defense Evasion => T1578.004: Revert Cloud Instance",
		Platforms: []string{"IaaS"},
	},
	"T1580": {
		Name:      "TA0007: Discovery => T1580: Cloud Infrastructure Discovery",
		Platforms: []string{"IaaS"},
	},
	"T1583": {
		Name:      "TA0042: Resource Development => T1583: Acquire Infrastructure",
		Platforms: []string{"PRE"},
	},
	"T1583.001": {
		Name:      "TA0042: Resource Development => T1583.001: Domains",
		Platforms: []string{"PRE"},
	},
	"T1583.002": {
		Name:      "TA0042: Resource Development => T1583.002: DNS Server",
		Platforms: []string{"PRE"},
	},
	"T1583.003": {
		Name:      "TA0042: Resource Development => T1583.003: Virtual Private Server",
		Platforms: []string{"PRE"},
	},
	"T1583.004": {
		Name:      "TA0042: Resource Development => T1583.004: Server",
		Platforms: []string{"PRE"},
	},
	"T1583.005": {
		Name:      "TA0042: Resource Development => T1583.005: Botnet",
		Platforms: []string{"PRE"},
	},
	"T1583.006": {
		Name:      "TA0042: Resource Development => T1583.006: Web Services",
		Platforms: []string{"PRE"},
	},
	"T1583.007": {
		Name:      "TA0042: Resource Development => T1583.007: Serverless",
		Platforms: []string{"PRE"},
	},
	"T1584": {
		Name:      "TA0042: Resource Development => T1584: Compromise Infrastructure",
		Platforms: []string{"PRE"},
	},
	"T1584.001": {
		Name:      "TA0042: Resource Development => T1584.001: Domains",
		Platforms: []string{"PRE"},
	},
	"T1584.002": {
		Name:      "TA0042: Resource Development => T1584.002: DNS Server",
		Platforms: []string{"PRE"},
	},
	"T1584.003": {
		Name:      "TA0042: Resource Development => T1584.003: Virtual Private Server",
		Platforms: []string{"PRE"},
	},
	"T1584.004": {
		Name:      "TA0042: Resource Development => T1584.004: Server",
		Platforms: []string{"PRE"},
	},
	"T1584.005": {
		Name:      "TA0042: Resource Development => T1584.005: Botnet",
		Platforms: []string{"PRE"},
	},
	"T1584.006": {
		Name:      "TA0042: Resource Development => T1584.006: Web Services",
		Platforms: []string{"PRE"},
	},
	"T1584.007": {
		Name:      "TA0042: Resource Development => T1584.007: Serverless",
		Platforms: []string{"PRE"},
	},
	"T1585": {
		Name:      "TA0042: Resource Development => T1585: Establish Accounts",
		Platforms: []string{"PRE"},
	},
	"T1585.001": {
		Name:      "TA0042: Resource Development => T1585.001: Social Media Accounts",
		Platforms: []string{"PRE"},
	},
	"T1585.002": {
		Name:      "TA0042: Resource Development => T1585.002: Email Accounts",
		Platforms: []string{"PRE"},
	},
	"T1585.003": {
		Name:      "TA0042: Resource Development => T1585.003: Cloud Accounts",
		Platforms: []string{"PRE"},
	},
	"T1586": {
		Name:      "TA0042: Resource Development => T1586: Compromise Accounts",
		Platforms: []string{"PRE"},
	},
	"T1586.001": {
		Name:      "TA0042: Resource Development => T1586.001: Social Media Accounts",
		Platforms: []string{"PRE"},
	},
	"T1586.002": {
		Name:      "TA0042: Resource Development => T1586.002: Email Accounts",
		Platforms: []string{"PRE"},
	},
	"T1586.003": {
		Name:      "TA0042: Resource Development => T1586.003: Cloud Accounts",
		Platforms: []string{"PRE"},
	},
	"T1587": {
		Name:      "TA0042: Resource Development => T1587: Develop Capabilities",
		Platforms: []string{"PRE"},
	},
	"T1587.001": {
		Name:      "TA0042: Resource Development => T1587.001: Malware",
		Platforms: []string{"PRE"},
	},
	"T1587.002": {
		Name:      "TA0042: Resource Development => T1587.002: Code Signing Certificates",
		Platforms: []string{"PRE"},
	},
	"T1587.003": {
		Name:      "TA0042: Resource Development => T1587.003: Digital Certificates",
		Platforms: []string{"PRE"},
	},
	"T1587.004": {
		Name:      "TA0042: Resource Development => T1587.004: Exploits",
		Platforms: []string{"PRE"},
	},
	"T1588": {
		Name:      "TA0042: Resource Development => T1588: Obtain Capabilities",
		Platforms: []string{"PRE"},
	},
	"T1588.001": {
		Name:      "TA0042: Resource Development => T1588.001: Malware",
		Platforms: []string{"PRE"},
	},
	"T1588.002": {
		Name:      "TA0042: Resource Development => T1588.002: Tool",
		Platforms: []string{"PRE"},
	},
	"T1588.003": {
		Name:      "TA0042: Resource Development => T1588.003: Code Signing Certificates",
		Platforms: []string{"PRE"},
	},
	"T1588.004": {
		Name:      "TA0042: Resource Development => T1588.004: Digital Certificates",
		Platforms: []string{"PRE"},
	},
	"T1588.005": {
		Name:      "TA0042: Resource Development => T1588.005: Exploits",
		Platforms: []string{"PRE"},
	},
	"T1588.006": {
		Name:      "TA0042: Resource Development => T1588.006: Vulnerabilities",
		Platforms: []string{"PRE"},
	},
	"T1589": {
		Name:      "TA0043: Reconnaissance => T1589: Gather Victim Identity Information",
		Platforms: []string{"PRE"},
	},
	"T1589.001": {
		Name:      "TA0043: Reconnaissance => T1589.001: Credentials",
		Platforms: []string{"PRE"},
	},
	"T1589.002": {
		Name:      "TA0043: Reconnaissance => T1589.002: Email Addresses",
		Platforms: []string{"PRE"},
	},
	"T1589.003": {
		Name:      "TA0043: Reconnaissance => T1589.003: Employee Names",
		Platforms: []string{"PRE"},
	},
	"T1590": {
		Name:      "TA0043: Reconnaissance => T1590: Gather Victim Network Information",
		Platforms: []string{"PRE"},
	},
	"T1590.001": {
		Name:      "TA0043: Reconnaissance => T1590.001: Domain Properties",
		Platforms: []string{"PRE"},
	},
	"T1590.002": {
		Name:      "TA0043: Reconnaissance => T1590.002: DNS",
		Platforms: []string{"PRE"},
	},
	"T1590.003": {
		Name:      "TA0043: Reconnaissance => T1590.003: Network Trust Dependencies",
		Platforms: []string{"PRE"},
	},
	"T1590.004": {
		Name:      "TA0043: Reconnaissance => T1590.004: Network Topology",
		Platforms: []string{"PRE"},
	},
	"T1590.005": {
		Name:      "TA0043: Reconnaissance => T1590.005: IP Addresses",
		Platforms: []string{"PRE"},
	},
	"T1590.006": {
		Name:      "TA0043: Reconnaissance => T1590.006: Network Security Appliances",
		Platforms: []string{"PRE"},
	},
	"T1591": {
		Name:      "TA0043: Reconnaissance => T1591: Gather Victim Org Information",
		Platforms: []string{"PRE"},
	},
	"T1591.001": {
		Name:      "TA0043: Reconnaissance => T1591.001: Determine Physical Locations",
		Platforms: []string{"PRE"},
	},
	"T1591.002": {
		Name:      "TA0043: Reconnaissance => T1591.002: Business Relationships",
		Platforms: []string{"PRE"},
	},
	"T1591.003": {
		Name:      "TA0043: Reconnaissance => T1591.003: Identify Business Tempo",
		Platforms: []string{"PRE"},
	},
	"T1591.004": {
		Name:      "TA0043: Reconnaissance => T1591.004: Identify Roles",
		Platforms: []string{"PRE"},
	},
	"T1592": {
		Name:      "TA0043: Reconnaissance => T1592: Gather Victim Host Information",
		Platforms: []string{"PRE"},
	},
	"T1592.001": {
		Name:      "TA0043: Reconnaissance => T1592.001: Hardware",
		Platforms: []string{"PRE"},
	},
	"T1592.002": {
		Name:      "TA0043: Reconnaissance => T1592.002: Software",
		Platforms: []string{"PRE"},
	},
	"T1592.003": {
		Name:      "TA0043: Reconnaissance => T1592.003: Firmware",
		Platforms: []string{"PRE"},
	},
	"T1592.004": {
		Name:      "TA0043: Reconnaissance => T1592.004: Client Configurations",
		Platforms: []string{"PRE"},
	},
	"T1593": {
		Name:      "TA0043: Reconnaissance => T1593: Search Open Websites/Domains",
		Platforms: []string{"PRE"},
	},
	"T1593.001": {
		Name:      "TA0043: Reconnaissance => T1593.001: Social Media",
		Platforms: []string{"PRE"},
	},
	"T1593.002": {
		Name:      "TA0043: Reconnaissance => T1593.002: Search Engines",
		Platforms: []string{"PRE"},
	},
	"T1593.003": {
		Name:      "TA0043: Reconnaissance => T1593.003: Code Repositories",
		Platforms: []string{"PRE"},
	},
	"T1594": {
		Name:      "TA0043: Reconnaissance => T1594: Search Victim-Owned Websites",
		Platforms: []string{"PRE"},
	},
	"T1595": {
		Name:      "TA0043: Reconnaissance => T1595: Active Scanning",
		Platforms: []string{"PRE"},
	},
	"T1595.001": {
		Name:      "TA0043: Reconnaissance => T1595.001: Scanning IP Blocks",
		Platforms: []string{"PRE"},
	},
	"T1595.002": {
		Name:      "TA0043: Reconnaissance => T1595.002: Vulnerability Scanning",
		Platforms: []string{"PRE"},
	},
	"T1595.003": {
		Name:      "TA0043: Reconnaissance => T1595.003: Wordlist Scanning",
		Platforms: []string{"PRE"},
	},
	"T1596": {
		Name:      "TA0043: Reconnaissance => T1596: Search Open Technical Databases",
		Platforms: []string{"PRE"},
	},
	"T1596.001": {
		Name:      "TA0043: Reconnaissance => T1596.001: DNS/Passive DNS",
		Platforms: []string{"PRE"},
	},
	"T1596.002": {
		Name:      "TA0043: Reconnaissance => T1596.002: WHOIS",
		Platforms: []string{"PRE"},
	},
	"T1596.003": {
		Name:      "TA0043: Reconnaissance => T1596.003: Digital Certificates",
		Platforms: []string{"PRE"},
	},
	"T1596.004": {
		Name:      "TA0043: Reconnaissance => T1596.004: CDNs",
		Platforms: []string{"PRE"},
	},
	"T1596.005": {
		Name:      "TA0043: Reconnaissance => T1596.005: Scan Databases",
		Platforms: []string{"PRE"},
	},
	"T1597": {
		Name:      "TA0043: Reconnaissance => T1597: Search Closed Sources",
		Platforms: []string{"PRE"},
	},
	"T1597.001": {
		Name:      "TA0043: Reconnaissance => T1597.001: Threat Intel Vendors",
		Platforms: []string{"PRE"},
	},
	"T1597.002": {
		Name:      "TA0043: Reconnaissance => T1597.002: Purchase Technical Data",
		Platforms: []string{"PRE"},
	},
	"T1598": {
		Name:      "TA0043: Reconnaissance => T1598: Phishing for Information",
		Platforms: []string{"PRE"},
	},
	"T1598.001": {
		Name:      "TA0043: Reconnaissance => T1598.001: Spearphishing Service",
		Platforms: []string{"PRE"},
	},
	"T1598.002": {
		Name:      "TA0043: Reconnaissance => T1598.002: Spearphishing Attachment",
		Platforms: []string{"PRE"},
	},
	"T1598.003": {
		Name:      "TA0043: Reconnaissance => T1598.003: Spearphishing Link",
		Platforms: []string{"PRE"},
	},
	"T1599": {
		Name:      "TA0005: Defense Evasion => T1599: Network Boundary Bridging",
		Platforms: []string{"Network"},
	},
	"T1599.001": {
		Name:      "TA0005: Defense Evasion => T1599.001: Network Address Translation Traversal",
		Platforms: []string{"Network"},
	},
	"T1600": {
		Name:      "TA0005: Defense Evasion => T1600: Weaken Encryption",
		Platforms: []string{"Network"},
	},
	"T1600.001": {
		Name:      "TA0005: Defense Evasion => T1600.001: Reduce Key Space",
		Platforms: []string{"Network"},
	},
	"T1600.002": {
		Name:      "TA0005: Defense Evasion => T1600.002: Disable Crypto Hardware",
		Platforms: []string{"Network"},
	},
	"T1601": {
		Name:      "TA0005: Defense Evasion => T1601: Modify System Image",
		Platforms: []string{"Network"},
	},
	"T1601.001": {
		Name:      "TA0005: Defense Evasion => T1601.001: Patch System Image",
		Platforms: []string{"Network"},
	},
	"T1601.002": {
		Name:      "TA0005: Defense Evasion => T1601.002: Downgrade System Image",
		Platforms: []string{"Network"},
	},
	"T1602": {
		Name:      "TA0009: Collection => T1602: Data from Configuration Repository",
		Platforms: []string{"Network"},
	},
	"T1602.001": {
		Name:      "TA0009: Collection => T1602.001: SNMP (MIB Dump)",
		Platforms: []string{"Network"},
	},
	"T1602.002": {
		Name:      "TA0009: Collection => T1602.002: Network Device Configuration Dump",
		Platforms: []string{"Network"},
	},
	"T1606": {
		Name:      "TA0006: Credential Access => T1606: Forge Web Credentials",
		Platforms: []string{"Azure AD", "Google Workspace", "IaaS", "Linux", "Office 365", "SaaS", "Windows", "macOS"},
	},
	"T1606.001": {
		Name:      "TA0006: Credential Access => T1606.001: Web Cookies",
		Platforms: []string{"IaaS", "Linux", "SaaS", "Windows", "macOS"},
	},
	"T1606.002": {
		Name:      "TA0006: Credential Access => T1606.002: SAML Tokens",
		Platforms: []string{"Azure AD", "Google Workspace", "IaaS", "Office 365", "SaaS", "Windows"},
	},
	"T1608": {
		Name:      "TA0042: Resource Development => T1608: Stage Capabilities",
		Platforms: []string{"PRE"},
	},
	"T1608.001": {
		Name:      "TA0042: Resource Development => T1608.001: Upload Malware",
		Platforms: []string{"PRE"},
	},
	"T1608.002": {
		Name:      "TA0042: Resource Development => T1608.002: Upload Tool",
		Platforms: []string{"PRE"},
	},
	"T1608.003": {
		Name:      "TA0042: Resource Development => T1608.003: Install Digital Certificate",
		Platforms: []string{"PRE"},
	},
	"T1608.004": {
		Name:      "TA0042: Resource Development => T1608.004: Drive-by Target",
		Platforms: []string{"PRE"},
	},
	"T1608.005": {
		Name:      "TA0042: Resource Development => T1608.005: Link Target",
		Platforms: []string{"PRE"},
	},
	"T1608.006": {
		Name:      "TA0042: Resource Development => T1608.006: SEO Poisoning",
		Platforms: []string{"PRE"},
	},
	"T1609": {
		Name:      "TA0002: Execution => T1609: Container Administration Command",
		Platforms: []string{"Containers"},
	},
	"T1610": {
		Name:      "TA0002: Execution, TA0005: Defense Evasion => T1610: Deploy Container",
		Platforms: []string{"Containers"},
	},
	"T1611": {
		Name:      "TA0004: Privilege Escalation => T1611: Escape to Host",
		Platforms: []string{"Containers", "Linux", "Windows"},
	},
	"T1612": {
		Name:      "TA0005: Defense Evasion => T1612: Build Image on Host",
		Platforms: []string{"Containers"},
	},
	"T1613": {
		Name:      "TA0007: Discovery => T1613: Container and Resource Discovery",
		Platforms: []string{"Containers"},
	},
	"T1614": {
		Name:      "TA0007: Discovery => T1614: System Location Discovery",
		Platforms: []string{"IaaS", "Linux", "Windows", "macOS"},
	},
	"T1614.001": {
		Name:      "TA0007: Discovery => T1614.001: System Language Discovery",
		Platforms: []string{"Linux", "Windows", "macOS"},
	},
	"T1615": {
		Name:      "TA0007: Discovery => T1615: Group Policy Discovery",
		Platforms: []string{"Windows"},
	},
	"T1619": {
		Name:      "TA0007: Discovery => T1619: Cloud Storage Object Discovery",
		Platforms: []string{"IaaS"},
	},
	"T1620": {
		Name:      "TA0005: Defense Evasion => T1620: Reflective Code Loading",
		Platforms: []string{"Linux", "Windows", "macOS"},
	},
	"T1621": {
		Name:      "TA0006: Credential Access => T1621: Multi-Factor Authentication Request Generation",
		Platforms: []string{"Azure AD", "Google Workspace", "IaaS", "Linux", "Office 365", "SaaS", "Windows", "macOS"},
	},
	"T1622": {
		Name:      "TA0005: Defense Evasion, TA0007: Discovery => T1622: Debugger Evasion",
		Platforms: []string{"Linux", "Windows", "macOS"},
	},
	"T1647": {
		Name:      "TA0005: Defense Evasion => T1647: Plist File Modification",
		Platforms: []string{"macOS"},
	},
	"T1648": {
		Name:      "TA0002: Execution => T1648: Serverless Execution",
		Platforms: []string{"IaaS", "Office 365", "SaaS"},
	},
	"T1649": {
		Name:      "TA0006: Credential Access => T1649: Steal or Forge Authentication Certificates",
		Platforms: []string{"Azure AD", "Linux", "Windows", "macOS"},
	},
}
