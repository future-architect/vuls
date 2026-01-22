# Windows Update Vulnerability Detection Workflow - Detailed Analysis

## Overview
The Windows update vulnerability detection in Vuls follows a multi-step process that maps missing security updates (KBs - Knowledge Base articles) based on the current build version and compares them against applied vs. unapplied patches.

---

## HOW UNAPPLIED KBs ARE DISCOVERED (Scanning Phase)

**Important:** The `unapplied` KB list is not discovered by `microsoft.go`. It's populated during the **initial Windows system scanning phase** before vulnerability detection begins.

### **Discovery Process in scanner/windows.go**

#### **Step 1: Query Windows Update History**
The Windows scanner runs PowerShell on the target system:

```powershell
$UpdateSearcher = (New-Object -ComObject Microsoft.Update.Session).CreateUpdateSearcher()
$HistoryCount = $UpdateSearcher.GetTotalHistoryCount()
$UpdateSearcher.QueryHistory(0, $HistoryCount) | Sort-Object -Property Date | Format-List -Property Title, Operation, ResultCode
```

**Result:** This retrieves the **Applied KBs** (all KBs that have been installed historically)

#### **Step 2: Detect KBs from Kernel Version**
Function: `DetectKBsFromKernelVersion(release, kernelVersion)` (scanner/windows.go:4779)

**Process:**
1. Extract kernel version components:
   ```
   Format: <major>.<minor>.<build>.<revision>
   Example: 10.0.19044.2846
                        ↑
                    Revision number
   ```

2. Look up revision in hardcoded KB database `windowsReleases`:
   ```go
   var windowsReleases = map[string]map[string]updateProgram{
       "Windows 10": {
           "21H2": {
               rollup: []windowsRelease{
                   {revision: "", kb: "3172605"},      // Earliest KB
                   {revision: "", kb: "3179573"},
                   {revision: "", kb: "3185278"},
                   // ... more KBs in chronological order ...
                   {revision: "19044.2846", kb: "5025221"},   // Current system
                   {revision: "19044.2847", kb: "5025222"},   // Next KB (not yet applied)
                   // ... more KBs ...
               }
           }
       }
   }
   ```

3. **Match system's revision number** to find current position:
   ```
   System Revision: 19044.2846
   
   Find index where: nMyRevision (2846) < next_revision
   
   Applied KBs = all KBs up to and including current position
                = KBs with revisions 0, 3172605, 3179573, ..., up to 19044.2846
   
   Unapplied KBs = all KBs after current position
                 = KBs with revisions 19044.2847 onwards
   ```

#### **Step 3: Combine Results**
```go
// scanner/windows.go:1220-1231

applied := map[string]struct{}{}
unapplied := map[string]struct{}{}

// Add applied KBs from Windows Update History
for _, kb := range parseWindowsUpdateHistory(updateSearcher.Result) {
    applied[kb] = struct{}{}
}

// Add KBs detected from kernel version
kbs, err := DetectKBsFromKernelVersion(release, kernelVersion)
for _, kb := range kbs.Applied {
    applied[kb] = struct{}{}
}
for _, kb := range kbs.Unapplied {
    unapplied[kb] = struct{}{}
}

return &models.WindowsKB{
    Applied:   slices.Collect(maps.Keys(applied)),   // All KBs installed
    Unapplied: slices.Collect(maps.Keys(unapplied)), // All KBs not yet installed
}
```

### **Concrete Example**

```
System Information:
  OS: Windows 10 Version 21H2
  Kernel Version: 10.0.19044.2846  ← Revision is 2846

KB Database Entry for Windows 10 21H2:
  rollup: [
    {revision: "", kb: "3172605"},
    {revision: "", kb: "3179573"},
    {revision: "", kb: "3185278"},
    ...
    {revision: "19044.2845", kb: "5025220"},  ← Applied (revision 2845 < 2846)
    {revision: "19044.2846", kb: "5025221"},  ← Applied (revision 2846 = 2846)
    {revision: "19044.2847", kb: "5025222"},  ← UNAPPLIED (revision 2847 > 2846)
    {revision: "19044.2848", kb: "5025223"},  ← UNAPPLIED (revision 2848 > 2846)
    {revision: "19044.2849", kb: "5025224"},  ← UNAPPLIED (revision 2849 > 2846)
  ]

Result:
  Applied:   ["3172605", "3179573", "3185278", ..., "5025220", "5025221"]
  Unapplied: ["5025222", "5025223", "5025224"]
```

### **Key Algorithm (Binary Search-like approach)**

```go
nMyRevision := 2846  // From system kernel version

var index int
for i, r := range rels.rollup {
    nRevision := parseRevision(r.revision)  // e.g., 2847
    
    if nMyRevision < nRevision {
        break  // Found where to split
    }
    index = i  // Keep moving forward
}

// Everything up to index is APPLIED
kbs.Applied = rels.rollup[:index+1]

// Everything after index is UNAPPLIED
kbs.Unapplied = rels.rollup[index+1:]
```

### **Why Two Sources (History + Kernel Version)?**

1. **Windows Update History** - Query actual installed patches
2. **Kernel Version Database** - Infer from system build number (more reliable)

Two sources are used to be comprehensive:
- History might have gaps or incomplete data
- Kernel version is a source of truth for current state
- Combining both ensures accurate KB detection

---

## HOW OTHER PRODUCTS ARE DETECTED (.NET, SQL Server, Office, etc.)

**Unlike OS KBs**, other Windows products (**.NET Framework, SQL Server, Office, Visual Studio**, etc.) are handled differently:

### **Product Detection (Not KB-based)**

**Scanning Phase (scanner/windows.go:1075-1090):**

The Windows scanner executes PowerShell to discover **all installed packages**:

```powershell
Get-Package | Format-List -Property Name, Version, ProviderName
```

**Example Output:**
```
Name           : Microsoft .NET Framework 4.8.1
Version        : 4.8.01049
ProviderName   : NuGet

Name           : SQL Server Native Client 11.0
Version        : 11.0.7462.6
ProviderName   : msi

Name           : Microsoft Office 2019
Version        : 16.0.10383
ProviderName   : Windows Installer

Name           : Microsoft Visual C++ Runtime
Version        : 14.29.30139
ProviderName   : msi
```

**Parsing Logic:**
```go
// scanner/windows.go:1093-1127

func (w *windows) parseInstalledPackages(stdout string) {
    installed := models.Packages{}
    
    for each package in output:
        name = package.Name
        version = package.Version
        providerName = package.ProviderName
        
        // IMPORTANT: Skip MSU packages (Windows Updates)
        if providerName != "msu" {
            installed[name] = Package{Name: name, Version: version}
        }
    
    return installed
}
```

**Why MSU packages are filtered out?**
- MSU (Microsoft Update Standalone Package) = Windows KB updates
- These are tracked separately via KB numbers
- Other packages are tracked by name+version

### **Product to CVE Mapping**

After packages are detected, they're sent to GOST for vulnerability matching:

**Workflow:**
```
1. Scanner discovers: 
   {
     "Microsoft .NET Framework 4.8.1": "4.8.01049",
     "SQL Server 2019": "15.0.2000",
     "Microsoft Edge": "128.0.2739.79"
   }

2. Microsoft.go queries GOST products endpoint:
   POST /microsoft/products
   {
     "release": "Windows 10 Version 21H2",
     "kbs": ["5025221", "5025222", ...]
   }
   
3. GOST returns list of applicable products:
   [
     "Windows 10 Version 21H2",
     "Microsoft .NET Framework 4.8.1",
     "SQL Server 2019",
     "Microsoft Edge (Chromium-based)",
     ...
   ]

4. Filter products based on what's actually installed:
   filtered = [
     "Windows 10 Version 21H2",                      // OS - always included
     "Microsoft Edge (Chromium-based)",              // Installed with v128
     "SQL Server 2019"                               // Installed
   ]
   
   NOT included:
   - Office 365 (not in GOST response)
   - .NET Framework 3.5 (not running on this system)
```

### **CVE Detection for Non-KB Products**

For products like **.NET Framework, SQL Server, Office**, vulnerability detection uses **version comparison** instead of KB matching:

**Example: .NET Framework 4.8.1 vulnerable CVE-2023-XXXXX**

```
GOST CVE Data:
  CVE-2023-XXXXX
  Products: [
    {
      Name: "Microsoft .NET Framework 4.8"
      KBs: [
        {Article: "Security Advisory", FixedBuild: "4.8.01050"}
      ]
    }
  ]

Detection Logic:
1. Is KB numeric? NO (it's "Security Advisory")
   → Use version comparison instead
   
2. Current version: 4.8.01049
   Required version: 4.8.01050
   
3. Is 4.8.01049 >= 4.8.01050? NO
   → VULNERABLE (needs update to 4.8.01050)

4. Fix state: "fixed"
   FixedIn: "4.8.01050"
```

### **How to Query Only Relevant Products**

Vuls intelligently filters to only check CVEs for installed products:

**Product Filtering Logic (microsoft.go:125-149):**

```go
// Start with OS as base product
filtered := []string{r.Release}  // e.g., "Windows 10 Version 21H2"

// Add packages that are actually installed
for package in r.Packages {
    switch package.Name {
    
    case "Microsoft Edge":
        // Special handling: add appropriate Edge variant
        if version.Major > 44 {
            filtered += "Microsoft Edge (Chromium-based)"
        } else {
            filtered += "Microsoft Edge (EdgeHTML-based)"
        }
    
    // For all other products (.NET, SQL, Office, etc.):
    // GetRelatedProducts() from GOST matches them automatically
    }
}

// Query GOST with only relevant products
cves = GOST.GetFilteredCves(filtered, kbs)
```

**Result:** Only CVEs affecting installed products are retrieved, making the scan faster and results more accurate.

### **Key Difference: OS vs Other Products**

| Aspect | OS (Windows 10/Server 2019) | Other Products (.NET, SQL, Office) |
|--------|----------------------------|-------------------------------------|
| **Detection** | KB article numbers | Package name + version number |
| **Status Tracking** | Applied/Unapplied KB lists | Installed version number |
| **CVE Matching** | KB article lookup + build version | Version number comparison |
| **Database** | windowsReleases (hardcoded) | GOST (external database) |
| **Fix Application** | Windows Update (KB patches) | Product-specific installers |
| **Example** | KB5025221 for build 19044.2846 | .NET 4.8.01050 or SQL Server 2019 CU12 |

### **Concrete Example: Multi-Product System**

```
Installed Packages:
  Windows 10 Version 21H2 (Build 19044.2846)
  .NET Framework 4.8.1 (Version 4.8.01049)
  SQL Server 2019 (Version 15.0.1999)
  Microsoft Edge (Version 128.0.2739.79)
  Office 365 (Version 16.0.10382)

Scanning Process:
1. Detect KB status:
   Applied KBs:   [5025220, 5025221]  (from build 19044.2846)
   Unapplied KBs: [5025222, 5025223, 5025224]  (newer KBs available)

2. Query GOST for relevant products:
   Products: ["Windows 10 21H2", ".NET 4.8.1", "SQL Server 2019", "Edge Chromium", "Office 365"]

3. Get CVEs for these products:
   - CVE-2023-12345 (Windows 10): KB needed = 5025222 (UNAPPLIED) → VULNERABLE
   - CVE-2023-67890 (.NET): Fixed in 4.8.01050 (CURRENT is 4.8.01049) → VULNERABLE
   - CVE-2023-11111 (SQL Server): Fixed in CU15 (CURRENT is CU14) → VULNERABLE
   - CVE-2024-22222 (Edge): Fixed in 129.0 (CURRENT is 128.0) → VULNERABLE
   - CVE-2023-33333 (Office): Fixed in 16.0.10383 (CURRENT is 16.0.10382) → VULNERABLE

4. Output: 5 vulnerabilities detected across different products
```

---

## Core Data Structures

### Input Data (from ScanResult)
```
WindowsKB {
  Applied:   []string    // KB article IDs already installed (e.g., ["5025288"])
  Unapplied: []string    // KB article IDs not yet installed (e.g., ["5025221"])
}

ScanResult {
  Release:    string     // Windows version (e.g., "Windows 10 Version 21H2 for x64-based Systems")
  BuildNumber: string    // OS build number (e.g., "10.0.19044.2846")
  Packages:   map[string]Package  // Additional packages like "Microsoft Edge"
}
```

### CVE Data from GOST (Microsoft database)
```
MicrosoftCVE {
  CveID:   string
  Products: []MicrosoftProduct
}

MicrosoftProduct {
  Name: string    // e.g., "Windows Server 2012 R2" or "Microsoft Edge (Chromium-based)"
  KBs: []MicrosoftKB
}

MicrosoftKB {
  Article:    string    // KB article ID (e.g., "5025285")
  FixedBuild: string    // Build where fix was applied (e.g., "6.3.9600.20919")
}
```

---

## Exact Workflow - Step by Step

### **STEP 1: KB Expansion** (Lines 40-82)
**Function:** `DetectCVEs` - First section

**Purpose:** Expand KB aliases to actual KB numbers

**Process:**
1. Collect `applied` and `unapplied` KB lists from `ScanResult.WindowsKB`
2. If using external GOST server:
   - POST request to `/microsoft/kbs` endpoint
   - Send: `{applied: [...], unapplied: [...]}`
   - Receive expanded KB mappings back
3. If using internal driver:
   - Call `ms.driver.GetExpandKB(applied, unapplied)`
   - Resolves KB aliases to actual article numbers

**Example:**
```
Input:  applied=["5025288"], unapplied=["5026361"]
Output: applied=["5025288"], unapplied=["5026361", "5025221"] (after expansion)
```

**Why?** Some KB articles have aliases that need resolving to canonical IDs.

---

### **STEP 2: Product Identification** (Lines 83-124)
**Function:** `DetectCVEs` - Second section

**Purpose:** Determine which Windows products/versions are affected

**Process:**
1. Query `/microsoft/products` endpoint with:
   - `release`: Windows version string (e.g., "Windows Server 2012 R2")
   - `kbs`: Combined list of all applied + unapplied KBs
2. Returns list of affected products that relate to this system

**Key Logic:**
```go
// Filter Microsoft Edge versions based on installed version
for p := range r.Packages {
    if p.Name == "Microsoft Edge" {
        edgeVersion := p.Version    // e.g., "128.0.2739.79"
        
        if majorVersion > 44 {
            // Chromium-based Edge (v45+)
            products += ["Microsoft Edge (Chromium-based)", ...]
        } else {
            // EdgeHTML-based Edge (older versions)
            products += ["Microsoft Edge (EdgeHTML-based)", ...]
        }
    }
}

// Remove browser products that are not applicable to the OS
products -= ["Microsoft Edge", "Internet Explorer", ...]
```

**Output:** List of applicable products for this system.

---

### **STEP 3: CVE Filtering** (Lines 125-185)
**Function:** `DetectCVEs` - Third section

**Purpose:** Get CVEs relevant to the identified products

**Process:**
1. Query `/microsoft/filtered-cves` endpoint with:
   - `products`: Filtered product list from Step 2
   - `kbs`: All applied + unapplied KB article IDs
2. Returns: `map[CVE_ID] -> MicrosoftCVE`

**Important:** Only CVEs related to your system's products are returned.

---

### **STEP 4: Individual CVE Vulnerability Detection** (Lines 186-194 & `detect()` function)
**Function:** `detect()` - Lines 217-439

**Purpose:** For each CVE, determine if the system is actually vulnerable

**This is the CORE logic. Let's break it down:**

#### **Step 4.1: Filter KBs by Deployment Status**
```go
// For each Product in the CVE that affects this system:
p.KBs = filter(p.KBs, func(kb) bool {
    
    // For numeric KB articles (Windows patches):
    if isNumeric(kb.Article) {
        
        // IF KB is APPLIED -> REMOVE IT (not vulnerable)
        if slices.Contains(applied, kb.Article) {
            return false  // Skip this KB
        }
        
        // IF KB is UNAPPLIED -> KEEP IT (might be vulnerable)
        if slices.Contains(unapplied, kb.Article) {
            return true   // Include this KB
        }
        
        // If KB status unknown -> REMOVE IT
        return false
    }
    
    // For non-numeric KB articles (e.g., "Release Notes" for Edge):
    // Handle version comparisons instead of KB checks
    // ...
})
```

**This is critical:** The system only keeps KBs that are UNAPPLIED. If a KB is in the `applied` list, the vulnerability is marked as FIXED.

#### **Step 4.2: Handle Microsoft Edge (Non-numeric KBs)**
```go
if kb.Article is NOT numeric:  // e.g., "Release Notes"
    if product is Microsoft Edge:
        edgeVersion := r.Packages["Microsoft Edge"].Version
        fixedVersion := kb.FixedBuild
        
        // Version comparison for Edge
        if edgeVersion < fixedVersion {
            // Vulnerable - old Edge version installed
            keep kb
        } else {
            // Not vulnerable - Edge is up to date
            skip kb
        }
```

---

### **Step 5: Determine Vulnerability State** (Lines 318-397)
**Function:** `detect()` - Product processing

After filtering, check what KBs remain:

#### **Case 1: Product has no KBs after filtering**
```
Product has no KBs remaining after filtering
    ↓
Check product type:
    
    For Windows OS product (e.g., "Windows 10 Version 21H2"):
        → FixState = "unfixed"
        (No KB can fix it, so it's permanently vulnerable)
    
    For Microsoft Edge product:
        → FixState = "unknown"
        (Edge version comparison failed or inconclusive)
```

#### **Case 2: Product has KBs remaining after filtering**
```
Product has unapplied KBs (e.g., KB5025221)
    
    For numeric KB:
        → Create DistroAdvisory with KB identifier
        → Add to WindowsKBFixedIns list
        → This KB can fix the vulnerability
    
    For non-numeric KB (Edge version):
        → Check if version comparison succeeded
        
        If succeeded:
            → FixState = "fixed" (newer version installed)
        
        If failed:
            → FixState = "unknown" (couldn't determine version)
```

---

## Complete Decision Tree

```
START: Check if CVE affects this system
    ↓
For each Product in CVE:
    ↓
    Product has no KBs defined?
        YES → Keep product, mark as unfixed/unknown
        NO → Process KBs
    ↓
    For each KB:
        ↓
        Is KB numeric (Windows patch)?
            YES → Check if KB is in applied/unapplied lists
                    Applied?   → Remove KB (vulnerability is FIXED)
                    Unapplied? → Keep KB (vulnerability exists)
                    Unknown?   → Remove KB
            
            NO (e.g., Edge version) → Version comparison
                    CurrentVersion >= FixedVersion?
                        YES → Remove KB (vulnerability is FIXED)
                        NO  → Keep KB (vulnerability exists)
    ↓
    After filtering KBs:
        ↓
        Has remaining KBs?
            YES → Vulnerable (needs these KBs)
                  Mark FixState = "fixed" (if applicable)
                  Add to WindowsKBFixedIns
            
            NO → 
                For OS products:     FixState = "unfixed"
                For Edge products:   FixState = "unknown"
    ↓
If NO products remain after all filtering:
    → CVE does NOT affect this system
    → Skip CVE (return nil)
    
ELSE:
    → Create VulnInfo entry for this CVE
    → Include affected packages with their fix states
    → Mark confidence levels
```

---

## Real-World Examples

### **Example 1: CVE-2023-21554 on Windows Server 2012 R2**

```
System State:
  Release: "Windows Server 2012 R2"
  Applied KBs: ["5025288"]
  Unapplied KBs: []

CVE Data:
  CVE-2023-21554
  Product: Windows Server 2012 R2
  KBs needed:
    - KB5025285 (FixedBuild: 6.3.9600.20919)
    - KB5025288 (FixedBuild: 6.3.9600.20919)

Workflow:
1. Step 4.1 KB Filtering:
   - KB5025285: NOT in applied, NOT in unapplied → REMOVE
   - KB5025288: IN applied → REMOVE (already fixed!)

2. Result: No KBs remain for this product

3. Since both KBs are covered (one applied, one not applicable),
   and we only had those two KBs available → CVE is MITIGATED

4. Output: VulnInfo NOT created (return nil)
   → This CVE does not appear in scan results
```

### **Example 2: CVE-2023-21554 on Windows 10 21H2 (Vulnerable)**

```
System State:
  Release: "Windows 10 Version 21H2 for x64-based Systems"
  Applied KBs: []
  Unapplied KBs: ["5025221"]

CVE Data:
  CVE-2023-21554
  Product: Windows 10 Version 21H2 for x64-based Systems
  KBs needed:
    - KB5025221 (FixedBuild: 10.0.19044.2846)

Workflow:
1. Step 4.1 KB Filtering:
   - KB5025221: NOT in applied, IN unapplied → KEEP

2. KBs remaining: ["5025221"]

3. Create DistroAdvisory:
   - AdvisoryID: "KB5025221"
   - Description: "Microsoft Knowledge Base"

4. Output: VulnInfo created
   WindowsKBFixedIns: ["KB5025221"]
   FixState: "fixed" (can be fixed with this KB)
   Confidence: WindowsUpdateSearch (high confidence)
```

### **Example 3: CVE without KB (Unfixed)**

```
System State:
  Release: "Windows 10 Version 21H2 for x64-based Systems"

CVE Data:
  CVE-2013-3900
  Product: Windows 10 Version 21H2 for x64-based Systems
  KBs: []  ← No KBs defined!

Workflow:
1. Product has no KBs
   → Cannot be fixed with patches
   
2. Output: VulnInfo created
   AffectedPackages: [{
     Name: "Windows 10 Version 21H2 for x64-based Systems"
     FixState: "unfixed"  ← Permanently vulnerable
   }]
   WindowsKBFixedIns: []  ← No KB available
   Confidence: WindowsUpdateSearch
```

### **Example 4: Microsoft Edge Version Comparison**

```
System State:
  Release: "Windows Server 2016"
  Packages: {"Microsoft Edge": "128.0.2739.79"}

CVE Data:
  CVE-2024-8639
  Product: Microsoft Edge (Chromium-based)
  KB: {Article: "Release Notes", FixedBuild: "128.0.2739.79"}

Workflow:
1. KB is non-numeric ("Release Notes")
   
2. Compare versions:
   - Installed: 128.0.2739.79
   - Required:  128.0.2739.79
   
3. Installed >= Required?
   YES → Remove KB (vulnerability FIXED)

4. Result: No KBs remain

5. Output: VulnInfo NOT created (return nil)
   → System is not vulnerable (Edge is up to date)
```

---

## Key Decision Points

| Scenario | Decision | Reason |
|----------|----------|--------|
| KB is in `applied` list | Remove KB (Fixed) | Patch already installed |
| KB is in `unapplied` list | Keep KB (Vulnerable) | Patch not yet applied |
| KB in neither list | Remove KB (Assumed fixed) | KB info possibly outdated |
| Product has no KBs | FixState="unfixed" | No patch available |
| Microsoft Edge version >= required | Remove KB (Fixed) | Software version is current |
| Microsoft Edge version < required | Keep KB (Vulnerable) | Software needs updating |
| No products remain after filtering | Return nil | CVE doesn't affect system |
| Confidence with KB articles | `WindowsUpdateSearch` | High confidence (KB-based) |
| Confidence without KB articles | `WindowsRoughMatch` | Medium confidence (build-based) |

---

## Confidence Levels

The system assigns confidence scores based on detection method:

```go
if len(WindowsKBFixedIns) > 0 {
    confidence = WindowsUpdateSearch  // HIGH
    // CVE fixed by known KB article
}

for fixState in AffectedPackages:
    if fixState == "fixed" || fixState == "unfixed" {
        confidence = WindowsUpdateSearch  // HIGH
        // Build-based detection with known fix state
    } else if fixState == "unknown" {
        confidence = WindowsRoughMatch  // MEDIUM
        // Could not definitively determine fix state
    }
```

**WindowsUpdateSearch** = Highest confidence
- KB article numbers can be verified against known patches
- Build numbers can be version-compared

**WindowsRoughMatch** = Medium confidence  
- Version comparison unavailable
- Heuristic matching only

---

## Summary: The Exact Mapping Process

1. **Input:** Windows build number + list of applied/unapplied KB patches
2. **Expand:** Resolve KB aliases to canonical IDs
3. **Identify:** Determine which Windows products affect this system
4. **Filter CVEs:** Get only CVEs relevant to identified products
5. **For each CVE:**
   - For each Product in CVE:
     - For each KB requirement:
       - If KB is applied → vulnerability is FIXED
       - If KB is unapplied → vulnerability EXISTS
       - If KB is unknown → assume vulnerability is FIXED
     - If no KBs remain → product is "unfixed" or "unknown"
6. **Output:** VulnInfo with fix state, KB requirements, and confidence level

This allows Vuls to determine exactly which vulnerabilities are present, which ones can be fixed with which KBs, and which KBs are still missing on the system.
