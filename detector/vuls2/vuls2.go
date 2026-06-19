package vuls2

import (
	"cmp"
	"encoding/json"
	"errors"
	"fmt"
	"iter"
	"maps"
	"net/url"
	"path"
	"runtime"
	"slices"
	"strings"
	"time"

	"golang.org/x/xerrors"

	dataTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data"
	criteriaTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria"
	criterionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion"
	vcAffectedRangeTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/affected/range"
	vcFixStatusTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/fixstatus"
	vcPackageTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/package"
	segmentTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/segment"
	ecosystemTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/segment/ecosystem"
	severityTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/severity"
	severityVendorTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/severity/vendor"
	vulnerabilityContentTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/vulnerability/content"
	datasourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/datasource"
	sourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/source"
	"github.com/MaineK00n/vuls2/pkg/db/session"
	dbTypes "github.com/MaineK00n/vuls2/pkg/db/session/types"
	"github.com/MaineK00n/vuls2/pkg/detect/cpe"
	"github.com/MaineK00n/vuls2/pkg/detect/ospkg"
	detectTypes "github.com/MaineK00n/vuls2/pkg/detect/types"
	scanTypes "github.com/MaineK00n/vuls2/pkg/scan/types"
	"github.com/MaineK00n/vuls2/pkg/version"
	"github.com/knqyf263/go-cpe/naming"

	"github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/constant"
	"github.com/future-architect/vuls/logging"
	"github.com/future-architect/vuls/models"
)

// defaultRegistory is GitHub Container Registry for vuls2 db
const defaultRegistory = "ghcr.io/vulsio/vuls-nightly-db"

// DetectPkgs detects OS-package / Microsoft-KB vulnerabilities using the
// vuls2 database and fills ScanResult.ScannedCves. CPE-URI detection lives
// in DetectCPEs so the two paths (detector.DetectPkgCves for packages,
// detector.DetectCpeURIsCves for CPEs) can run separately without
// double-detecting packages.
func DetectPkgs(r *models.ScanResult, vuls2Conf config.Vuls2Conf, noProgress bool) error {
	return detectWith(r, preConvertPkgs(r), nil, vuls2Conf, noProgress)
}

// DetectCPEs detects vulnerabilities for the given CPE URIs (CPE 2.2 URI or
// 2.3 FS form — typically ScanResult.Config.Scan.Servers[...].CpeNames) using
// the vuls2 database. OS-package / Microsoft-KB detection is suppressed here:
// it already ran via DetectPkgs (detector.DetectPkgCves), and running it
// twice would duplicate AffectedPackages on merge.
func DetectCPEs(r *models.ScanResult, cpeURIs []string, vuls2Conf config.Vuls2Conf, noProgress bool) error {
	if len(cpeURIs) == 0 {
		return nil
	}
	vuls2Scanned, fsToOriginalCPE, err := preConvertCPEs(r, cpeURIs)
	if err != nil {
		return xerrors.Errorf("Failed to convert CPEs. err: %w", err)
	}
	return detectWith(r, vuls2Scanned, fsToOriginalCPE, vuls2Conf, noProgress)
}

func detectWith(r *models.ScanResult, vuls2Scanned scanTypes.ScanResult, fsToOriginalCPE map[string][]string, vuls2Conf config.Vuls2Conf, noProgress bool) error {
	if vuls2Conf.Repository == "" {
		sv, err := session.SchemaVersion("boltdb")
		if err != nil {
			return xerrors.Errorf("Failed to get schema version. err: %w", err)
		}

		vuls2Conf.Repository = fmt.Sprintf("%s:%d", defaultRegistory, sv)
	}
	if vuls2Conf.Path == "" {
		vuls2Conf.Path = DefaultPath
	}

	dbConfig, err := newDBConfig(vuls2Conf, noProgress)
	if err != nil {
		return xerrors.Errorf("Failed to get new db connection. err: %w", err)
	}

	sesh, err := dbConfig.New()
	if err != nil {
		return xerrors.Errorf("Failed to new db session. err: %w", err)
	}

	defer sesh.Cache().Close()

	if err := sesh.Storage().Open(); err != nil {
		return xerrors.Errorf("Failed to open db. err: %w", err)
	}
	defer sesh.Storage().Close()

	metadata, err := sesh.Storage().GetMetadata()
	if err != nil {
		return xerrors.Errorf("Failed to get metadata. err: %w", err)
	}
	config.Conf.Vuls2.Digest = metadata.Digest

	vuls2Detected, err := detect(sesh, vuls2Scanned)
	if err != nil {
		return xerrors.Errorf("Failed to detect. err: %w", err)
	}

	vulnInfos, err := postConvert(vuls2Scanned, vuls2Detected, fsToOriginalCPE)
	if err != nil {
		return xerrors.Errorf("Failed to post convert. err: %w", err)
	}

	mergeIntoScannedCves(r, vulnInfos)

	// detectWith runs once per entry point (DetectPkgs, DetectCPEs); name
	// the pass so the two log lines of one report run stay tellable apart.
	logging.Log.Infof("%s: %d CVEs are detected with vuls2 (%s)", r.FormatServerName(), len(vulnInfos), func() string {
		if len(vuls2Scanned.CPE) > 0 {
			return "cpe"
		}
		return "os packages"
	}())

	return nil
}

// mergeIntoScannedCves merges vuls2-detected VulnInfos into the scan
// result's ScannedCves. A new CVE is registered as-is; for a CVE that is
// already present (registered by the other vuls2 pass, by the
// go-cve-dictionary pass, or carried in a caller-provided result), every
// field the vuls2 postConvert produces is merged — the remaining VulnInfo
// fields are owned by enrichment / other detectors and never appear in
// vuls2 output.
//
// Not to be confused with mergeVulnInfo, which merges WITHIN one vuls2 run:
// this function merges ACROSS passes and sources, so the existing entry may
// not come from vuls2 at all. It therefore assumes nothing about
// vuls2-internal markers (no Optional["vuls2-sources"]), only dedup-appends
// (never picks a winner between conflicting contents), and also carries the
// aggregate fields mergeVulnInfo does not handle (AffectedPackages,
// CpeURIs, WindowsKBFixedIns — postConvert fills those after its own merge).
func mergeIntoScannedCves(r *models.ScanResult, vulnInfos models.VulnInfos) {
	// A caller-provided result may carry a nil ScannedCves map (e.g. a
	// zero-value ScanResult from a library consumer); initialize before
	// writing into it.
	if r.ScannedCves == nil {
		r.ScannedCves = models.VulnInfos{}
	}

	for cveID, vi := range vulnInfos {
		viBase, found := r.ScannedCves[cveID]
		if !found {
			viBase = vi
		} else {
			// Store() keeps one row per package name (last write wins), so a
			// base already carrying package statuses — a caller-provided
			// ScannedCves, or a prior detection pass — does not accumulate
			// duplicate/contradictory rows for the same package.
			for _, p := range vi.AffectedPackages {
				viBase.AffectedPackages = viBase.AffectedPackages.Store(p)
			}
			// WindowsKBFixedIns merges like the other per-path outputs: a
			// CVE first registered by the CPE pass (or already present in
			// the input ScannedCves) would otherwise lose the KB numbers
			// the package/KB pass detected.
			for _, kb := range vi.WindowsKBFixedIns {
				if !slices.Contains(viBase.WindowsKBFixedIns, kb) {
					viBase.WindowsKBFixedIns = append(viBase.WindowsKBFixedIns, kb)
				}
			}
			for _, da := range vi.DistroAdvisories {
				viBase.DistroAdvisories.AppendIfMissing(&da)
			}
			for _, c := range vi.Confidences {
				viBase.Confidences.AppendIfMissing(c)
			}
			// A pre-existing VulnInfo may carry a nil CveContents map (e.g.
			// unmarshaled from a result JSON where cveContents was omitted);
			// initialize before writing into it.
			if viBase.CveContents == nil {
				viBase.CveContents = models.CveContents{}
			}
			// A CVE can be detected by both vuls2 entry points (DetectPkgs
			// for OS packages, DetectCPEs for CPE URIs); those two passes
			// never produce the same CveContents type (distro types vs cpe
			// types), so they cannot collide with each other. A caller-provided
			// base (or the go-cve-dictionary pass) may already carry the same
			// type for this CVE, though — vuls2 now emits Nvd/Jvn contents — so
			// dedup on the (type, CVE, source link) identity before appending,
			// mirroring the key-based dedup the sibling merges above use, to
			// avoid repeating a source/link in reports. Reconciling genuinely
			// conflicting contents of one source (e.g. differing CVSS) is out
			// of scope: the existing entry is kept.
			for ccType, ccs := range vi.CveContents {
				for _, cc := range ccs {
					if slices.ContainsFunc(viBase.CveContents[ccType], func(e models.CveContent) bool {
						return e.Type == cc.Type && e.CveID == cc.CveID && e.SourceLink == cc.SourceLink
					}) {
						continue
					}
					viBase.CveContents[ccType] = append(viBase.CveContents[ccType], cc)
				}
			}
			// CpeURIs must merge too: a CVE first registered by the package
			// path would otherwise end up with an empty CpeURIs even though
			// the CPE pass matched it against the configured CPE list.
			// Dedup on append: the two vuls2 passes cannot both produce
			// CpeURIs, but the go-cve-dictionary pass may already have
			// registered the same user-supplied CPE on the same CVE (a CVE
			// covered by both NVD and a vendor advisory source).
			for _, uri := range vi.CpeURIs {
				if !slices.Contains(viBase.CpeURIs, uri) {
					viBase.CpeURIs = append(viBase.CpeURIs, uri)
				}
			}
			// Exploits / Mitigations must merge too: a CVE registered first
			// by the go-cve-dictionary non-NVD path would otherwise silently
			// drop the vuls2-derived entries.
			for _, e := range vi.Exploits {
				viBase.Exploits.AppendIfMissing(e)
			}
			for _, m := range vi.Mitigations {
				viBase.Mitigations.AppendIfMissing(m)
			}
		}
		r.ScannedCves[cveID] = viBase
	}
}

// EnrichVulnInfos enriches all ScannedCves in the ScanResult with additional vulnerability data
// (e.g., Red Hat API) from the vuls2 database.
// This should be called after all detection paths have completed.
func EnrichVulnInfos(r *models.ScanResult, vuls2Conf config.Vuls2Conf, noProgress bool) error {
	if len(r.ScannedCves) == 0 {
		return nil
	}

	if vuls2Conf.Repository == "" {
		sv, err := session.SchemaVersion("boltdb")
		if err != nil {
			return xerrors.Errorf("Failed to get schema version. err: %w", err)
		}

		vuls2Conf.Repository = fmt.Sprintf("%s:%d", defaultRegistory, sv)
	}
	if vuls2Conf.Path == "" {
		vuls2Conf.Path = DefaultPath
	}

	dbConfig, err := newDBConfig(vuls2Conf, noProgress)
	if err != nil {
		return xerrors.Errorf("Failed to get new db connection. err: %w", err)
	}

	sesh, err := dbConfig.New()
	if err != nil {
		return xerrors.Errorf("Failed to new db session. err: %w", err)
	}

	defer sesh.Cache().Close()

	if err := sesh.Storage().Open(); err != nil {
		return xerrors.Errorf("Failed to open db. err: %w", err)
	}
	defer sesh.Storage().Close()

	if err := enrich(sesh, r.ScannedCves); err != nil {
		return xerrors.Errorf("Failed to enrich vulnerability data. err: %w", err)
	}

	return nil
}

// preConvertBase builds the vuls2-shape ScanResult fields shared by both
// detection inputs (server identity, family/release mapping, kernel).
func preConvertBase(sr *models.ScanResult) scanTypes.ScanResult {
	return scanTypes.ScanResult{
		JSONVersion: 0,
		ServerName:  sr.ServerName,
		Family:      ecosystemTypes.Ecosystem(toVuls2Family(sr.Family, sr.Release)),
		Release:     toVuls2Release(sr.Family, sr.Release),

		Kernel: scanTypes.Kernel{
			Release:        sr.RunningKernel.Release,
			Version:        sr.RunningKernel.Version,
			RebootRequired: sr.RunningKernel.RebootRequired,
		},

		ScannedAt: sr.ScannedAt,
		ScannedBy: sr.ScannedBy,
	}
}

// preConvertPkgs builds the vuls2-shape ScanResult carrying the OS-package /
// Microsoft-KB inputs for DetectPkgs. The CPE list stays empty — CPE
// detection is DetectCPEs' job (see preConvertCPEs).
func preConvertPkgs(sr *models.ScanResult) scanTypes.ScanResult {
	pkgs := make(map[string]scanTypes.OSPackage)
	for _, p := range sr.SrcPackages {
		if sr.Family == constant.Raspbian && models.IsRaspbianPackage(p.Name, p.Version) {
			continue
		}
		for _, bn := range p.BinaryNames {
			pkgs[bn] = scanTypes.OSPackage{
				SrcName:    p.Name,
				SrcVersion: p.Version,
			}
		}
	}
	for _, p := range sr.Packages {
		if sr.Family == constant.Raspbian && models.IsRaspbianPackage(p.Name, p.Version) {
			continue
		}
		base := pkgs[p.Name]
		base.Name = p.Name
		base.Version = preConvertBinaryVersion(sr.Family, p.Version)
		base.Release = p.Release
		base.NewVersion = p.NewVersion
		base.NewRelease = p.NewRelease
		base.Arch = p.Arch
		base.Repository = p.Repository
		base.ModularityLabel = p.ModularityLabel
		pkgs[p.Name] = base
	}

	scanned := preConvertBase(sr)
	scanned.OSPackages = func() []scanTypes.OSPackage {
		ps := slices.Collect(maps.Values(pkgs))
		// For Windows, include the OS release as a synthetic package so that
		// kernel-version-based detection can report the correct release name.
		if sr.Family == constant.Windows && sr.RunningKernel.Version != "" {
			ps = append(ps, scanTypes.OSPackage{
				Name:    toVuls2Release(sr.Family, sr.Release),
				Version: sr.RunningKernel.Version,
			})
		}
		return ps
	}()
	if sr.WindowsKB != nil {
		scanned.MicrosoftKB = scanTypes.MicrosoftKB{
			Applied:   sr.WindowsKB.Applied,
			Unapplied: sr.WindowsKB.Unapplied,
		}
	}
	return scanned
}

// preConvertCPEs builds the vuls2-shape ScanResult carrying only the CPE
// list for DetectCPEs — the OS-package / Microsoft-KB inputs stay empty so
// detect() only exercises the CPE path; packages were already detected via
// DetectPkgs, and converting them again would duplicate AffectedPackages on
// merge.
//
// The CPE list is converted to the CPE 2.3 Formatted-String form vuls2
// requires: vuls normalises config CPEs to CPE 2.2 URI, so most inputs go
// through UnbindURI + BindToFS; entries already in FS form pass through, and
// an unparseable entry fails the conversion — config-sourced CPEs were
// already validated at config-load time, so it signals an unvalidated
// caller input. The returned reverse map
// (FS string -> user-supplied forms) is consumed by postConvert to restore
// the user's input in VulnInfo.CpeURIs rather than leaking the internal
// FS-with-wildcards representation.
func preConvertCPEs(sr *models.ScanResult, cpeURIs []string) (scanTypes.ScanResult, map[string][]string, error) {
	scanned := preConvertBase(sr)
	if len(cpeURIs) == 0 {
		return scanned, nil, nil
	}

	fsCPEs := make([]string, 0, len(cpeURIs))
	fsToOriginal := make(map[string][]string, len(cpeURIs))
	for _, u := range cpeURIs {
		var fs string
		if strings.HasPrefix(u, "cpe:2.3:") {
			// Validate FS-form inputs too (the URI branch validates via
			// UnbindURI). Config-sourced CPEs were already validated at
			// config-load time (toCpeURI), so a failure here means an
			// unvalidated input — propagate it instead of silently
			// detecting nothing for that CPE.
			if _, err := naming.UnbindFS(u); err != nil {
				return scanTypes.ScanResult{}, nil, xerrors.Errorf("Failed to unbind CPE FS %q. err: %w", u, err)
			}
			fs = u
		} else {
			wfn, err := naming.UnbindURI(u)
			if err != nil {
				return scanTypes.ScanResult{}, nil, xerrors.Errorf("Failed to unbind CPE URI %q. err: %w", u, err)
			}
			fs = naming.BindToFS(wfn)
		}
		// Dedup the DETECTION list by FS form — re-detecting the same FS
		// string would only repeat work — but keep every distinct
		// user-supplied form in the reverse map: the map exists to restore
		// the user's input in VulnInfo.CpeURIs, and a user listing the same
		// CPE in both URI and FS form expects both back (matching the
		// classic per-input go-cve-dictionary behaviour).
		if _, exists := fsToOriginal[fs]; !exists {
			fsCPEs = append(fsCPEs, fs)
		}
		if !slices.Contains(fsToOriginal[fs], u) {
			fsToOriginal[fs] = append(fsToOriginal[fs], u)
		}
	}

	scanned.CPE = fsCPEs
	return scanned, fsToOriginal, nil
}

func detect(sesh *session.Session, sr scanTypes.ScanResult) (detectTypes.DetectResult, error) {
	// The two entry points feed exclusive inputs: preConvertPkgs converts
	// OS packages / Microsoft KB only, preConvertCPEs the CPE list only.
	// Receiving both means a caller bypassed them.
	if len(sr.CPE) > 0 && (len(sr.OSPackages) > 0 || len(sr.MicrosoftKB.Applied) > 0 || len(sr.MicrosoftKB.Unapplied) > 0) {
		return detectTypes.DetectResult{}, xerrors.Errorf("ScanResult carries both CPE and OS-package / Microsoft-KB inputs; DetectPkgs and DetectCPEs feed them exclusively")
	}

	detections, err := func() (map[dataTypes.RootID]detectTypes.VulnerabilityDataDetection, error) {
		if len(sr.CPE) > 0 {
			m, err := cpe.Detect(sesh.Storage(), sr, runtime.NumCPU())
			if err != nil {
				return nil, xerrors.Errorf("Failed to detect cpe. err: %w", err)
			}
			return m, nil
		}
		// ospkg.Detect also covers Microsoft-KB detection, so gate on
		// either input being present — a Windows scan can carry KBs
		// without any OS packages.
		if len(sr.OSPackages) > 0 || len(sr.MicrosoftKB.Applied) > 0 || len(sr.MicrosoftKB.Unapplied) > 0 {
			m, err := ospkg.Detect(sesh.Storage(), sr, runtime.NumCPU())
			if err != nil {
				return nil, xerrors.Errorf("Failed to detect os packages. err: %w", err)
			}
			return m, nil
		}
		return nil, nil
	}()
	if err != nil {
		return detectTypes.DetectResult{}, xerrors.Errorf("Failed to detect. err: %w", err)
	}

	// Fetch Vulnerability/Advisory data narrowed to the detecting
	// ecosystem / datasources, as master always did: pulling other
	// ecosystems' or RootIDs' contents is EnrichVulnInfos' job, not
	// detection's.
	detected := make(map[dataTypes.RootID]detectTypes.VulnerabilityData, len(detections))
	for rootID, d := range detections {
		avs, err := sesh.GetVulnerabilityData(rootID, dbTypes.Filter{
			Contents: []dbTypes.FilterContentType{
				dbTypes.FilterContentTypeAdvisories,
				dbTypes.FilterContentTypeVulnerabilities,
			},
			RootIDs:     []dataTypes.RootID{rootID},
			Ecosystems:  []ecosystemTypes.Ecosystem{d.Ecosystem},
			DataSources: slices.Collect(maps.Keys(d.Contents)),
		})
		if err != nil {
			return detectTypes.DetectResult{}, xerrors.Errorf("Failed to get vulnerability data. RootID: %s, err: %w", rootID, err)
		}
		detected[rootID] = detectTypes.VulnerabilityData{
			ID:              rootID,
			Detections:      []detectTypes.VulnerabilityDataDetection{d},
			Advisories:      avs.Advisories,
			Vulnerabilities: avs.Vulnerabilities,
		}
	}

	var sourceIDs []sourceTypes.SourceID
	for _, data := range detected {
		for _, a := range data.Advisories {
			for sourceID := range a.Contents {
				if !slices.Contains(sourceIDs, sourceID) {
					sourceIDs = append(sourceIDs, sourceID)
				}
			}
		}
		for _, v := range data.Vulnerabilities {
			for sourceID := range v.Contents {
				if !slices.Contains(sourceIDs, sourceID) {
					sourceIDs = append(sourceIDs, sourceID)
				}
			}
		}
		for _, d := range data.Detections {
			for sourceID := range d.Contents {
				if !slices.Contains(sourceIDs, sourceID) {
					sourceIDs = append(sourceIDs, sourceID)
				}
			}
		}
	}

	datasources := make([]datasourceTypes.DataSource, 0, len(sourceIDs))
	for _, sourceID := range sourceIDs {
		s, err := sesh.Storage().GetDataSource(sourceID)
		if err != nil {
			return detectTypes.DetectResult{}, xerrors.Errorf("Failed to get datasource. sourceID: %s, err: %w", sourceID, err)
		}
		datasources = append(datasources, s)
	}

	return detectTypes.DetectResult{
		JSONVersion: 0,
		ServerUUID:  sr.ServerUUID,
		ServerName:  sr.ServerName,

		Detected:    slices.Collect(maps.Values(detected)),
		DataSources: datasources,

		DetectedAt: time.Now(),
		DetectedBy: version.String(),
	}, nil
}

type source struct {
	RootID   dataTypes.RootID     `json:"root_id,omitempty"`
	SourceID sourceTypes.SourceID `json:"source_id,omitempty"`
	Segment  segmentTypes.Segment `json:"segment,omitzero"`
}

type sourceData struct {
	// detectableCveIDs whitelists which of this source's vulninfos
	// postConvert may emit. vulninfos is content-driven — an advisory
	// RootID carries every CVE under it, detected or not — and the pack
	// aggregation picks ONE winning source per CVE/package via
	// comparePack, so only the CVEs backed by a detection signal here
	// (and, for packages, only on the winning source) are listed.
	detectableCveIDs []string
	vulninfos        models.VulnInfos
	packStatuses     []packStatus
	kbIDs            []string
	// exactCpes holds scanned CPEs the criterion accepted at Exact quality
	// (Accepts.CPE.Exact) — the version was confirmed. They are reported with
	// the high ExactVersionMatch confidence.
	exactCpes []string
	// vpCpes holds scanned CPEs the criterion accepted only at
	// VersionUnconfirmed quality (Accepts.CPE.VersionUnconfirmed) — the
	// version could not be pinned (e.g. a version=NA criterion, or a
	// version=NA query). They are reported with the low VendorProductMatch
	// confidence instead of ExactVersionMatch — the vuls2 replacement for
	// go-cve-dictionary's fuzzy CPE reporting.
	vpCpes []string
}

type rootTag struct {
	rootID dataTypes.RootID
	tag    segmentTypes.DetectionTag
}

type pack struct {
	ecosystem ecosystemTypes.Ecosystem
	sourceID  sourceTypes.SourceID
	rootTags  []rootTag

	packStatus packStatus
}

type packStatus struct {
	rangeType vcAffectedRangeTypes.RangeType
	status    models.PackageFixStatus
}

// appendMissing appends each element of src to dst, skipping values already
// present (order-preserving). The slice-wise companion to util.AppendIfMissing,
// used to accumulate scanned-CPE / KB lists across conditions and sources.
func appendMissing(dst, src []string) []string {
	for _, s := range src {
		if !slices.Contains(dst, s) {
			dst = append(dst, s)
		}
	}
	return dst
}

// postConvert assembles VulnInfos from the vuls2 detect result.
//
// fsToOriginalCPE maps each CPE 2.3 FS string in scanned.CPE back to the
// user-supplied CPE form (URI or FS). It is consulted when building
// VulnInfo.CpeURIs so the report shows the user-supplied CPE rather than
// the internal FS-with-wildcards form. Nil / missing keys fall back to
// the FS string as-is.
func postConvert(scanned scanTypes.ScanResult, detected detectTypes.DetectResult, fsToOriginalCPE map[string][]string) (models.VulnInfos, error) {
	m := make(map[source]sourceData)

	if err := walkVulnerabilityDetections(m, scanned, detected.Detected); err != nil {
		return nil, xerrors.Errorf("Failed to walk detections. err: %w", err)
	}

	if err := walkVulnerabilityDatas(m, detected.Detected); err != nil {
		return nil, xerrors.Errorf("Failed to walk vulnerability data. err: %w", err)
	}

	type affected struct {
		packm     map[string]pack
		kbIDs     []string
		exactCpes []string
		vpCpes    []string
	}

	am := make(map[string]affected)
	for src, vd := range m {
		for _, vi := range vd.vulninfos {
			base := am[vi.CveID]

			if len(vd.packStatuses) > 0 {
				if base.packm == nil {
					base.packm = make(map[string]pack)
				}
				for _, status := range vd.packStatuses {
					p, ok := base.packm[status.status.Name]
					if ok {
						result, err := comparePack(p, pack{
							ecosystem: src.Segment.Ecosystem,
							sourceID:  src.SourceID,
							rootTags: []rootTag{{
								rootID: src.RootID,
								tag:    src.Segment.Tag,
							}},
							packStatus: packStatus{
								rangeType: status.rangeType,
								status:    status.status,
							},
						})
						if err != nil {
							return nil, xerrors.Errorf("Failed to compare pack. err: %w", err)
						}
						switch result {
						case 0:
							p.rootTags = append(p.rootTags, rootTag{
								rootID: src.RootID,
								tag:    src.Segment.Tag,
							})
						case -1:
							p = pack{
								ecosystem: src.Segment.Ecosystem,
								sourceID:  src.SourceID,
								rootTags: []rootTag{{
									rootID: src.RootID,
									tag:    src.Segment.Tag,
								}},
								packStatus: packStatus{
									rangeType: status.rangeType,
									status:    status.status,
								},
							}
						default:
						}
					} else {
						p = pack{
							ecosystem: src.Segment.Ecosystem,
							sourceID:  src.SourceID,
							rootTags: []rootTag{{
								rootID: src.RootID,
								tag:    src.Segment.Tag,
							}},
							packStatus: packStatus{
								rangeType: status.rangeType,
								status:    status.status,
							},
						}
					}
					base.packm[status.status.Name] = p
				}
			}

			base.kbIDs = appendMissing(base.kbIDs, vd.kbIDs)
			base.exactCpes = appendMissing(base.exactCpes, vd.exactCpes)
			base.vpCpes = appendMissing(base.vpCpes, vd.vpCpes)

			// A KB/CPE detection signal marks this CVE emittable. packStatuses
			// are deliberately excluded — packages are gated separately through
			// comparePack's per-source winner selection.
			if len(vd.kbIDs) > 0 || len(vd.exactCpes) > 0 || len(vd.vpCpes) > 0 {
				if !slices.Contains(vd.detectableCveIDs, vi.CveID) {
					vd.detectableCveIDs = append(vd.detectableCveIDs, vi.CveID)
				}
			}

			am[vi.CveID] = base
		}

		m[src] = vd
	}
	for cveID, mm := range am {
		for _, p := range mm.packm {
			for _, tag := range p.rootTags {
				src := source{
					RootID:   tag.rootID,
					SourceID: p.sourceID,
					Segment: segmentTypes.Segment{
						Ecosystem: p.ecosystem,
						Tag:       tag.tag,
					},
				}
				base := m[src]
				if !slices.Contains(base.detectableCveIDs, cveID) {
					base.detectableCveIDs = append(base.detectableCveIDs, cveID)
				}
				m[src] = base
			}
		}
	}

	vim := make(models.VulnInfos)
	for _, vd := range m {
		for _, vi := range vd.vulninfos {
			if !slices.Contains(vd.detectableCveIDs, vi.CveID) {
				continue
			}

			base, ok := vim[vi.CveID]
			if ok {
				merged, err := mergeVulnInfo(base, vi)
				if err != nil {
					return nil, xerrors.Errorf("Failed to merge vuln info. err: %w", err)
				}
				base = merged
			} else {
				base = vi
			}
			vim[vi.CveID] = base
		}
	}
	for _, vi := range vim {
		// Keep ps nil when there are no affected packages — skip the
		// allocation and stay consistent with the in-memory convention that
		// "not detected" is nil rather than an empty slice. (JSON output is
		// unaffected either way: AffectedPackages carries omitempty.)
		var ps models.PackageFixStatuses
		if n := len(am[vi.CveID].packm); n > 0 {
			ps = make(models.PackageFixStatuses, 0, n)
			for _, p := range am[vi.CveID].packm {
				ps = append(ps, p.packStatus.status)
			}
		}
		if len(ps) > 0 {
			vi.AffectedPackages = ps
		}

		// Restore the user-supplied CPE form (URI or FS) instead of
		// leaking the matched FS-with-wildcards form. Unknown FS keys
		// pass through verbatim (defensive — should not occur because
		// walkCPECriteria sources cpes from scanned.CPE). Exact-match CPEs
		// take precedence; the version-unconfirmed CPEs only fill CpeURIs
		// when the CVE has no exact match at all.
		cpes := am[vi.CveID].exactCpes
		if len(cpes) == 0 {
			cpes = am[vi.CveID].vpCpes
		}
		if len(cpes) > 0 {
			out := make([]string, 0, len(cpes))
			for _, fs := range cpes {
				if origs, ok := fsToOriginalCPE[fs]; ok {
					out = append(out, origs...)
				} else {
					out = append(out, fs)
				}
			}
			vi.CpeURIs = out
		}

		// Populate WindowsKBFixedIns and KB-based DistroAdvisories for Microsoft detections
		if string(scanned.Family) == ecosystemTypes.EcosystemTypeMicrosoft {
			for _, kbID := range am[vi.CveID].kbIDs {
				kbWithPrefix := fmt.Sprintf("KB%s", kbID)
				if !slices.Contains(vi.WindowsKBFixedIns, kbWithPrefix) {
					vi.WindowsKBFixedIns = append(vi.WindowsKBFixedIns, kbWithPrefix)
				}
				da := models.DistroAdvisory{AdvisoryID: kbWithPrefix, Description: "Microsoft Knowledge Base"}
				vi.DistroAdvisories.AppendIfMissing(&da)
			}
		}

		vim[vi.CveID] = vi
	}

	return vim, nil
}

func walkVulnerabilityDetections(m map[source]sourceData, scanned scanTypes.ScanResult, vs []detectTypes.VulnerabilityData) error {
	for _, v := range vs {
		for _, d := range v.Detections {
			for sourceID, fconds := range d.Contents {
				for _, fcond := range fconds {
					var (
						statuses  []packStatus
						kbIDs     []string
						exactCpes []string
						vpCpes    []string
					)
					if d.Ecosystem == ecosystemTypes.EcosystemTypeCPE {
						exact, vp, err := walkCPECriteria(sourceID, fcond.Criteria, scanned)
						if err != nil {
							return xerrors.Errorf("Failed to walk cpe criteria. err: %w", err)
						}
						exactCpes, vpCpes = exact, vp
					} else {
						s, k, err := walkPkgCriteria(d.Ecosystem, sourceID, fcond.Criteria, fcond.Tag, scanned)
						if err != nil {
							return xerrors.Errorf("Failed to walk pkg criteria. err: %w", err)
						}
						statuses, kbIDs = s, k
					}

					// A condition with no detection signal is skipped
					// WITHOUT registering it in m: the downstream walk
					// treats presence in m as "this source detected
					// something", and an empty entry would emit contents
					// for an undetected CVE.
					if len(statuses) == 0 && len(kbIDs) == 0 && len(exactCpes) == 0 && len(vpCpes) == 0 {
						continue
					}

					src := source{
						RootID:   v.ID,
						SourceID: sourceID,
						Segment: segmentTypes.Segment{
							Ecosystem: d.Ecosystem,
							Tag:       fcond.Tag,
						},
					}
					base := m[src]
					// Plain appends here; postConvert owns de-duplication when
					// it accumulates these across a CVE's sources.
					base.packStatuses = append(base.packStatuses, statuses...)
					base.kbIDs = append(base.kbIDs, kbIDs...)
					base.exactCpes = append(base.exactCpes, exactCpes...)
					base.vpCpes = append(base.vpCpes, vpCpes...)
					m[src] = base
				}
			}
		}
	}
	return nil
}

// pruneCPECriteria returns the criteria tree with everything a CPE-only
// scan cannot evaluate removed: criterions other than vulnerable=true CPE
// ones (vulnerable=false environment/hardware guards, other criterion
// types) and child criterias left empty by that removal. Unlike
// prunePkgCriteria, which gates on detect-time accepts for the package/KB
// path, this prunes purely on evaluability — accepts are judged later by
// walkCPECriteria's collecting walk.
func pruneCPECriteria(c criteriaTypes.FilteredCriteria) criteriaTypes.FilteredCriteria {
	pruned := criteriaTypes.FilteredCriteria{Operator: c.Operator}
	for _, child := range c.Criterias {
		child = pruneCPECriteria(child)
		if len(child.Criterias) == 0 && len(child.Criterions) == 0 {
			continue
		}
		pruned.Criterias = append(pruned.Criterias, child)
	}
	for _, cn := range c.Criterions {
		if cn.Criterion.Type != criterionTypes.CriterionTypeCPE || cn.Criterion.CPE == nil || !cn.Criterion.CPE.Vulnerable {
			continue
		}
		pruned.Criterions = append(pruned.Criterions, cn)
	}
	return pruned
}

// walkCPECriteria projects a cpe-ecosystem condition onto vuls0's flat result.
// All CPE match semantics — WFN attribute matching, range/cpematch evaluation,
// and the exact vs version-unconfirmed quality judgement — already happened in
// vuls-data-update's cpecriterion.Match; this function only reads the resulting
// AcceptQueries.CPE indices and folds the supporting scanned CPEs (FS form) up
// the AND/OR tree into vuls0's two confidence tiers: exact and vendor:product.
//
// Anything a CPE-only scan cannot evaluate — vulnerable=false
// environment/hardware guards and other criterion types — is removed by a
// prune pass first, so it never vetoes an AND (the historical
// go-cve-dictionary behaviour existing users rely on).
//
//   - Accepts.CPE.Exact (version-confirmed match) → exact tier
//   - Accepts.CPE.VersionUnconfirmed (accepted, but no version confirmation)
//     → vendor:product tier
//
// AND nodes require every relevant child to be satisfied and demote their
// exact contributions when any leg holds only at vendor:product level (the
// conjunction as a whole is then only vendor:product-confirmed); OR nodes take
// any satisfied child as-is. Finally, a CPE source that carries no version
// data at all (JVN) is reported at vendor:product regardless of the projected
// tier — that is a source-semantics decision, kept here in vuls0.
func walkCPECriteria(sourceID sourceTypes.SourceID, ca criteriaTypes.FilteredCriteria, scanned scanTypes.ScanResult) ([]string, []string, error) {
	// Pass 1: prune everything a CPE-only scan cannot evaluate, so the
	// collecting walk below sees evaluatable criterions only and plain
	// two-valued AND/OR logic suffices (no neutrality tracking). An empty
	// result means the condition carries nothing to evaluate at all.
	ca = pruneCPECriteria(ca)
	if len(ca.Criterias) == 0 && len(ca.Criterions) == 0 {
		return nil, nil, nil
	}

	scannedCPE := func(index int) (string, error) {
		if index < 0 || len(scanned.CPE) <= index {
			return "", xerrors.Errorf("Too large CPE index. len(CPE): %d, index: %d", len(scanned.CPE), index)
		}
		return scanned.CPE[index], nil
	}

	// Pass 2: walk returns (satisfied, exact, vp) — whether the subtree
	// holds, and the supporting scanned CPEs per confidence tier.
	var walk func(c criteriaTypes.FilteredCriteria) (bool, []string, []string, error)
	walk = func(c criteriaTypes.FilteredCriteria) (bool, []string, []string, error) {
		satisfied := c.Operator != criteriaTypes.CriteriaOperatorTypeOR
		var exact, vp []string

		foldChild := func(childSatisfied bool, childExact, childVP []string) {
			switch c.Operator {
			case criteriaTypes.CriteriaOperatorTypeOR:
				if childSatisfied {
					satisfied = true
					exact = append(exact, childExact...)
					vp = append(vp, childVP...)
				}
			case criteriaTypes.CriteriaOperatorTypeAND:
				if !childSatisfied {
					satisfied = false
					return
				}
				exact = append(exact, childExact...)
				vp = append(vp, childVP...)
			default: // unreachable: criteria operators are only AND / OR
			}
		}

		for _, child := range c.Criterias {
			sat, ex, v, err := walk(child)
			if err != nil {
				return false, nil, nil, xerrors.Errorf("Failed to walk criteria. err: %w", err)
			}
			foldChild(sat, ex, v)
		}
		for _, cn := range c.Criterions {
			var exactMatched, vpMatched []string
			for _, index := range cn.Accepts.CPE.Exact {
				fs, err := scannedCPE(index)
				if err != nil {
					return false, nil, nil, err
				}
				exactMatched = append(exactMatched, fs)
			}
			for _, index := range cn.Accepts.CPE.VersionUnconfirmed {
				fs, err := scannedCPE(index)
				if err != nil {
					return false, nil, nil, err
				}
				vpMatched = append(vpMatched, fs)
			}
			foldChild(len(exactMatched) > 0 || len(vpMatched) > 0, exactMatched, vpMatched)
		}

		if !satisfied {
			return false, nil, nil, nil
		}
		if c.Operator != criteriaTypes.CriteriaOperatorTypeOR && len(vp) > 0 {
			// A conjunction with a leg confirmed only at vendor:product
			// level is only vendor:product-confirmed as a whole.
			vp = append(vp, exact...)
			exact = nil
		}
		return true, exact, vp, nil
	}

	satisfied, exact, vp, err := walk(ca)
	if err != nil {
		return nil, nil, xerrors.Errorf("Failed to walk criteria. err: %w", err)
	}
	if !satisfied {
		return nil, nil, nil
	}

	// JVN carries no version data, so even an exact-tier projection only
	// confirms the product. Demote before dedup so the tier-exclusion below
	// sees the final tiers. This is a source-semantics call, not a CPE-match
	// one, so it lives in vuls0 rather than the source-agnostic matcher.
	if isJVNCPESource(sourceID) {
		vp = append(vp, exact...)
		exact = nil
	}

	exact = appendMissing(nil, exact)
	vp = appendMissing(nil, vp)

	// The tiers are exclusive per scanned CPE: one confirmed at exact level
	// (e.g. by another OR leg) does not also report at vendor:product level.
	vp = slices.DeleteFunc(vp, func(fs string) bool { return slices.Contains(exact, fs) })
	if len(vp) == 0 {
		vp = nil
	}
	return exact, vp, nil
}

// isJVNCPESource reports whether a CPE-ecosystem detection from this source
// carries no version data and must therefore be reported at vendor:product
// regardless of the projected match quality. JVN's CPE entries are all
// version=ANY with no range; add any future JVN CPE source here.
func isJVNCPESource(sourceID sourceTypes.SourceID) bool {
	switch sourceID {
	case sourceTypes.JVNFeedRSS, sourceTypes.JVNFeedDetail:
		return true
	default:
		return false
	}
}

// prunePkgCriteria drops unaffected branches from a FilteredCriteria tree.
//
// AND parents fail (return empty) if any required child is unaffected, OR
// parents skip unaffected children. The vuls2 util.Detect step now passes
// every condition through unconditionally — this function is the actual
// AND/OR gate. cpe-ecosystem conditions never come through here; they are
// evaluated by walkCPECriteria on the raw tree instead.
func prunePkgCriteria(c criteriaTypes.FilteredCriteria) (criteriaTypes.FilteredCriteria, error) {
	pruned := criteriaTypes.FilteredCriteria{
		Operator: c.Operator,
		Criterias: func() []criteriaTypes.FilteredCriteria {
			if len(c.Criterias) > 0 {
				return make([]criteriaTypes.FilteredCriteria, 0, len(c.Criterias))
			}
			return nil
		}(),
		Criterions: func() []criterionTypes.FilteredCriterion {
			if len(c.Criterions) > 0 {
				return make([]criterionTypes.FilteredCriterion, 0, len(c.Criterions))
			}
			return nil
		}(),
	}

	for _, child := range c.Criterias {
		child, err := prunePkgCriteria(child)
		if err != nil {
			return criteriaTypes.FilteredCriteria{}, xerrors.Errorf("prune criteria: %w", err)
		}

		if len(child.Criterias) == 0 && len(child.Criterions) == 0 {
			switch c.Operator {
			case criteriaTypes.CriteriaOperatorTypeAND:
				return criteriaTypes.FilteredCriteria{}, nil
			case criteriaTypes.CriteriaOperatorTypeOR:
				continue
			default:
				return criteriaTypes.FilteredCriteria{}, xerrors.Errorf("unexpected operator. expected: %q, actual: %q", []criteriaTypes.CriteriaOperatorType{criteriaTypes.CriteriaOperatorTypeAND, criteriaTypes.CriteriaOperatorTypeOR}, c.Operator)
			}
		}

		pruned.Criterias = append(pruned.Criterias, child)
	}

	for _, cn := range c.Criterions {
		isAffected, err := cn.Affected()
		if err != nil {
			return criteriaTypes.FilteredCriteria{}, xerrors.Errorf("criterion affected: %w", err)
		}

		if !isAffected {
			switch c.Operator {
			case criteriaTypes.CriteriaOperatorTypeAND:
				return criteriaTypes.FilteredCriteria{}, nil
			case criteriaTypes.CriteriaOperatorTypeOR:
				continue
			default:
				return criteriaTypes.FilteredCriteria{}, xerrors.Errorf("unexpected operator. expected: %q, actual: %q", []criteriaTypes.CriteriaOperatorType{criteriaTypes.CriteriaOperatorTypeAND, criteriaTypes.CriteriaOperatorTypeOR}, c.Operator)
			}
		}

		pruned.Criterions = append(pruned.Criterions, cn)
	}

	return pruned, nil
}

// walkPkgCriteria evaluates a package/KB condition: prunePkgCriteria drops the
// branches whose criterions did not accept (the AND/OR gate over detect-time
// accepts), then the pruned tree is walked for package statuses and KB IDs.
// The cpe-ecosystem counterpart is walkCPECriteria, which prunes on
// evaluability instead and judges accepts during its own walk.
func walkPkgCriteria(e ecosystemTypes.Ecosystem, sourceID sourceTypes.SourceID, ca criteriaTypes.FilteredCriteria, tag segmentTypes.DetectionTag, scanned scanTypes.ScanResult) ([]packStatus, []string, error) {
	pruned, err := prunePkgCriteria(ca)
	if err != nil {
		return nil, nil, xerrors.Errorf("Failed to prune criteria. err: %w", err)
	}

	var walk func(ca criteriaTypes.FilteredCriteria) ([]packStatus, []string, bool, error)
	walk = func(ca criteriaTypes.FilteredCriteria) ([]packStatus, []string, bool, error) {
		var (
			statuses []packStatus
			kbIDs    []string
		)
		for _, child := range ca.Criterias {
			ss, ks, ignore, err := walk(child)
			if err != nil {
				return nil, nil, false, xerrors.Errorf("Failed to walk criteria. err: %w", err)
			}
			if ignore {
				switch ca.Operator {
				case criteriaTypes.CriteriaOperatorTypeAND:
					return nil, nil, ignore, nil
				case criteriaTypes.CriteriaOperatorTypeOR:
					continue
				default:
					return nil, nil, false, xerrors.Errorf("unexpected operator: %s", ca.Operator)
				}
			}
			statuses = append(statuses, ss...)
			kbIDs = append(kbIDs, ks...)
		}

		for _, cn := range ca.Criterions {
			if ignoreCriteria(e, sourceID, cn) {
				return nil, nil, true, nil
			}

			switch cn.Criterion.Type {
			case criterionTypes.CriterionTypeVersion:
				if cn.Criterion.Version == nil {
					continue
				}

				if ignoreCriterion(e, cn, tag) {
					continue
				}

				fcn, err := filterCriterion(e, scanned, cn)
				if err != nil {
					return nil, nil, false, xerrors.Errorf("Failed to filter criterion. err: %w", err)
				}

				switch fcn.Criterion.Version.Package.Type {
				case vcPackageTypes.PackageTypeBinary, vcPackageTypes.PackageTypeSource:
					if !fcn.Criterion.Version.Vulnerable {
						continue
					}

					rangeType, fixedIn := func() (vcAffectedRangeTypes.RangeType, string) {
						if fcn.Criterion.Version.Affected == nil {
							return vcAffectedRangeTypes.RangeTypeUnknown, ""
						}
						return fcn.Criterion.Version.Affected.Type, selectFixedIn(fcn.Criterion.Version.Affected.Type, fcn.Criterion.Version.Affected.Fixed)
					}()

					for _, index := range fcn.Accepts.Version {
						if len(scanned.OSPackages) <= index {
							return nil, nil, false, xerrors.Errorf("Too large OSPackage index. len(OSPackage): %d, index: %d", len(scanned.OSPackages), index)
						}
						statuses = append(statuses, packStatus{
							rangeType: rangeType,
							status: models.PackageFixStatus{
								Name: affectedPackageName(e, scanned.OSPackages[index]),
								FixState: func() string {
									if fcn.Criterion.Version.FixStatus == nil {
										return ""
									}
									return fixState(e, sourceID, fcn.Criterion.Version.FixStatus.Vendor)
								}(),
								FixedIn:     fixedIn,
								NotFixedYet: fcn.Criterion.Version.FixStatus == nil || fcn.Criterion.Version.FixStatus.Class != vcFixStatusTypes.ClassFixed,
							},
						})
					}
				default:
				}
			case criterionTypes.CriterionTypeKB:
				if cn.Criterion.KB == nil || (!cn.Accepts.KB.Covered && !cn.Accepts.KB.Unapplied) {
					continue
				}
				kbIDs = append(kbIDs, cn.Criterion.KB.KBID)
			default:
				continue
			}
		}
		return statuses, kbIDs, false, nil
	}

	statuses, kbIDs, _, err := walk(pruned)
	if err != nil {
		return nil, nil, xerrors.Errorf("Failed to walk criteria. err: %w", err)
	}
	return statuses, kbIDs, nil
}
func walkVulnerabilityDatas(m map[source]sourceData, vds []detectTypes.VulnerabilityData) error {
	for _, vd := range vds {
		am := make(map[source]models.DistroAdvisories)
		for _, vda := range vd.Advisories {
			for sid, rm := range vda.Contents {
				if rm == nil {
					return xerrors.Errorf("advisories map is nil, root id: %q -> advisories[source id: %q]", vd.ID, sid)
				}
				for _, a := range rm[vd.ID] {
					for _, segment := range a.Segments {
						src := source{
							RootID:   vd.ID,
							SourceID: sid,
							Segment:  segment,
						}

						if _, ok := m[src]; !ok {
							continue
						}

						am[src] = append(am[src], models.DistroAdvisory{
							AdvisoryID: string(a.Content.ID),
							Severity: func() string {
								for _, s := range a.Content.Severity {
									if s.Type == severityTypes.SeverityTypeVendor && s.Vendor != nil {
										return *s.Vendor
									}
								}
								return ""
							}(),
							Issued: func() time.Time {
								if a.Content.Published != nil {
									return *a.Content.Published
								}
								return time.Date(1000, time.January, 1, 0, 0, 0, 0, time.UTC)
							}(),
							Updated: func() time.Time {
								if a.Content.Modified != nil {
									return *a.Content.Modified
								}
								return time.Date(1000, time.January, 1, 0, 0, 0, 0, time.UTC)
							}(),
							Description: a.Content.Description,
						})
					}
				}
			}
		}

		srcsWithVulns := make(map[source]struct{})
		for _, vdv := range vd.Vulnerabilities {
			for sid, rm := range vdv.Contents {
				if rm == nil {
					return xerrors.Errorf("vulnerabilities map is nil, root id: %q -> vulnerabilities[source id: %q]", vd.ID, sid)
				}
				for _, v := range rm[vd.ID] {
					for _, segment := range v.Segments {
						src := source{
							RootID:   vd.ID,
							SourceID: sid,
							Segment:  segment,
						}

						sd, ok := m[src]
						if !ok {
							continue
						}

						srcsWithVulns[src] = struct{}{}

						if ignoreVulnerability(src.Segment.Ecosystem, v, am[src]) {
							continue
						}

						vinfo, err := func() (models.VulnInfo, error) {
							bs, err := json.Marshal([]source{src})
							if err != nil {
								return models.VulnInfo{}, xerrors.Errorf("Failed to marshal sources. err: %w", err)
							}

							fdas := filterDistroAdvisories(src.Segment.Ecosystem, am[src])
							cctype := toCveContentType(src.Segment.Ecosystem, sid)
							cvss2, cvss3, cvss40 := toCvss(src.Segment.Ecosystem, sid, v.Content.Severity)

							var rs models.References
							for _, r := range v.Content.References {
								rs = append(rs, toReference(r.URL))
							}
							for _, da := range fdas {
								ar, err := advisoryReference(src.Segment.Ecosystem, src.SourceID, da)
								if err != nil {
									return models.VulnInfo{}, xerrors.Errorf("Failed to get advisory reference. err: %w", err)
								}
								if !slices.ContainsFunc(rs, func(r models.Reference) bool {
									return r.Link == ar.Link && r.Source == ar.Source && r.RefID == ar.RefID && slices.Equal(r.Tags, ar.Tags)
								}) {
									rs = append(rs, ar)
								}
							}

							// Map content-level Exploit / Mitigations into the
							// vuls0 models — NVD content only. The NVD feed
							// extractor lifts detection-relevant reference tags
							// ("Exploit", "Mitigation") into these slots
							// (Exploit.Link / Remediation.Description carry the
							// reference URL), and the classic gocve path derives
							// the same entries in ConvertNvdToModel. Other
							// sources (e.g. Red Hat) also populate these slots
							// but with different semantics; mapping them here
							// would mis-label entries as ExploitTypeNVD, so they
							// are intentionally left to their own renderers.
							var (
								exploits    []models.Exploit
								mitigations []models.Mitigation
							)
							if cctype == models.Nvd {
								for _, e := range v.Content.Exploit {
									if e.Link == "" {
										continue
									}
									exploits = append(exploits, models.Exploit{
										ExploitType: models.ExploitTypeNVD,
										URL:         e.Link,
									})
								}
								for _, m := range v.Content.Mitigations {
									if m.Description == "" {
										continue
									}
									mitigations = append(mitigations, models.Mitigation{
										CveContentType: models.Nvd,
										URL:            m.Description,
									})
								}
							}

							return models.VulnInfo{
								CveID:            string(v.Content.ID),
								Confidences:      models.Confidences{toVuls0Confidence(src.Segment.Ecosystem, src.SourceID, sd)},
								DistroAdvisories: fdas,
								Exploits:         exploits,
								Mitigations:      mitigations,
								CveContents: models.NewCveContents(models.CveContent{
									Type:           cctype,
									CveID:          string(v.Content.ID),
									Title:          v.Content.Title,
									Summary:        v.Content.Description,
									Cvss2Score:     cvss2.BaseScore,
									Cvss2Vector:    cvss2.Vector,
									Cvss2Severity:  cvss2.NVDBaseSeverity,
									Cvss3Score:     cvss3.BaseScore,
									Cvss3Vector:    cvss3.Vector,
									Cvss3Severity:  cvss3.BaseSeverity,
									Cvss40Score:    cvss40.Score,
									Cvss40Vector:   cvss40.Vector,
									Cvss40Severity: cvss40.Severity,
									SourceLink:     cveContentSourceLink(cctype, v),
									References:     rs,
									CweIDs: func() []string {
										var cs []string
										for _, cwe := range v.Content.CWE {
											cs = append(cs, cwe.CWE...)
										}
										return cs
									}(),
									Published: func() time.Time {
										if v.Content.Published != nil {
											return *v.Content.Published
										}
										return time.Date(1000, time.January, 1, 0, 0, 0, 0, time.UTC)
									}(),
									LastModified: func() time.Time {
										if v.Content.Modified != nil {
											return *v.Content.Modified
										}
										return time.Date(1000, time.January, 1, 0, 0, 0, 0, time.UTC)
									}(),
									Optional: cveContentOptional(src.Segment.Ecosystem, v, string(bs)),
								}),
							}, nil
						}()
						if err != nil {
							return xerrors.Errorf("Failed to create vuln info. err: %w", err)
						}

						base := m[src]
						if base.vulninfos == nil {
							base.vulninfos = make(models.VulnInfos)
						}
						base.vulninfos[vinfo.CveID] = vinfo
						m[src] = base
					}
				}
			}
		}

		// Remove sources that had vulnerabilities from the advisory map.
		// The advisory fallback below creates VulnInfo from advisory IDs only when
		// no vulnerabilities exist for a source. Without this deletion, sources whose
		// vulnerabilities were all dropped by ignoreVulnerability would incorrectly
		// fall through to advisory-based VulnInfo creation.
		for src := range srcsWithVulns {
			delete(am, src)
		}

		for src, das := range am {
			if len(m[src].vulninfos) > 0 {
				continue
			}

			fdas := filterDistroAdvisories(src.Segment.Ecosystem, das)
			for _, da := range fdas {
				bs, err := json.Marshal([]source{src})
				if err != nil {
					return xerrors.Errorf("Failed to marshal sources. err: %w", err)
				}

				cctype := toCveContentType(src.Segment.Ecosystem, src.SourceID)

				ar, err := advisoryReference(src.Segment.Ecosystem, src.SourceID, da)
				if err != nil {
					return xerrors.Errorf("Failed to get advisory reference. err: %w", err)
				}

				vinfo := models.VulnInfo{
					CveID:            da.AdvisoryID,
					Confidences:      models.Confidences{toVuls0Confidence(src.Segment.Ecosystem, src.SourceID, m[src])},
					DistroAdvisories: models.DistroAdvisories{da},
					CveContents: models.NewCveContents(models.CveContent{
						Type:         cctype,
						CveID:        da.AdvisoryID,
						Summary:      da.Description,
						SourceLink:   ar.Link,
						References:   models.References{ar},
						Published:    da.Issued,
						LastModified: da.Updated,
						Optional:     map[string]string{"vuls2-sources": string(bs)},
					}),
				}

				base := m[src]
				if base.vulninfos == nil {
					base.vulninfos = make(models.VulnInfos)
				}
				base.vulninfos[vinfo.CveID] = vinfo
				m[src] = base
			}
		}
	}
	return nil
}

func comparePack(a, b pack) (int, error) {
	if a.ecosystem == b.ecosystem {
		if r := compareSourceID(a.ecosystem, a.sourceID, b.sourceID); r != 0 {
			return r, nil
		}

		maxTagFn := func(e ecosystemTypes.Ecosystem, s sourceTypes.SourceID, tags []rootTag) segmentTypes.DetectionTag {
			rt := slices.MaxFunc(tags, func(a, b rootTag) int {
				return compareTag(e, s, a.tag, b.tag)
			})
			return rt.tag
		}

		if r := compareTag(a.ecosystem, a.sourceID, maxTagFn(a.ecosystem, a.sourceID, a.rootTags), maxTagFn(b.ecosystem, b.sourceID, b.rootTags)); r != 0 {
			return r, nil
		}
	}

	r, err := comparePackStatus(a.packStatus, b.packStatus)
	if err != nil {
		return 0, xerrors.Errorf("Failed to compare pack status. err: %w", err)
	}

	return r, nil
}

// mergeVulnInfo merges two VulnInfos for the same CVE WITHIN one vuls2 run:
// postConvert builds one VulnInfo per detecting source segment (e.g. RHEL
// CSAF and VEX, redhat:9 and epel:9) and folds them together here.
//
// Not to be confused with mergeIntoScannedCves, which merges across passes
// and sources at the detectWith level. Both inputs here are vuls2-produced,
// so a same-type CveContents conflict is RESOLVED — the entry whose
// Optional["vuls2-sources"] ranks higher wins (and the marker is required:
// non-vuls2 input is an error). Only content-level fields are handled;
// AffectedPackages / CpeURIs / WindowsKBFixedIns are aggregated separately
// by postConvert after this merge.
func mergeVulnInfo(a, b models.VulnInfo) (models.VulnInfo, error) {
	if a.CveID != b.CveID {
		return models.VulnInfo{}, xerrors.Errorf("CVE IDs are different. a: %s, b: %s", a.CveID, b.CveID)
	}

	info := models.VulnInfo{
		CveID:       a.CveID,
		CveContents: models.CveContents{},
	}

	for _, cc := range []models.Confidences{a.Confidences, b.Confidences} {
		for _, c := range cc {
			info.Confidences.AppendIfMissing(c)
		}
	}

	for _, e := range slices.Concat(a.Exploits, b.Exploits) {
		info.Exploits.AppendIfMissing(e)
	}
	for _, m := range slices.Concat(a.Mitigations, b.Mitigations) {
		info.Mitigations.AppendIfMissing(m)
	}

	am := make(map[string]models.DistroAdvisory)
	for _, as := range []models.DistroAdvisories{a.DistroAdvisories, b.DistroAdvisories} {
		for _, a := range as {
			base, ok := am[a.AdvisoryID]
			if ok {
				if cmp.Or(
					severityVendorTypes.Compare("", base.Severity, a.Severity),
					base.Issued.Compare(a.Issued),
					base.Updated.Compare(a.Updated),
				) < 0 {
					base = a
				}
			} else {
				base = a
			}
			am[a.AdvisoryID] = base
		}
	}
	info.DistroAdvisories = slices.Collect(maps.Values(am))

	ccm := make(map[models.CveContentType]models.CveContent)
	for _, cciter := range []iter.Seq[[]models.CveContent]{maps.Values(a.CveContents), maps.Values(b.CveContents)} {
		for cc := range cciter {
			for _, c := range cc {
				base, ok := ccm[c.Type]
				if ok {
					var src1 []source
					if err := json.Unmarshal([]byte(base.Optional["vuls2-sources"]), &src1); err != nil {
						return models.VulnInfo{}, xerrors.Errorf("Failed to unmarshal sources. err: %w", err)
					}
					var src2 []source
					if err := json.Unmarshal([]byte(c.Optional["vuls2-sources"]), &src2); err != nil {
						return models.VulnInfo{}, xerrors.Errorf("Failed to unmarshal sources. err: %w", err)
					}

					merged := models.CveContent{
						Type:         base.Type,
						CveID:        base.CveID,
						Title:        base.Title,
						Summary:      base.Summary,
						SSVC:         base.SSVC,
						SourceLink:   base.SourceLink,
						Published:    base.Published,
						LastModified: base.LastModified,
						Optional:     base.Optional,
					}

					if compareSource(slices.MaxFunc(src1, compareSource), slices.MaxFunc(src2, compareSource)) < 0 {
						merged = models.CveContent{
							Type:         c.Type,
							CveID:        c.CveID,
							Title:        c.Title,
							Summary:      c.Summary,
							SSVC:         c.SSVC,
							SourceLink:   c.SourceLink,
							Published:    c.Published,
							LastModified: c.LastModified,
							Optional:     c.Optional,
						}
					}

					switch cmp.Compare(base.Cvss40Score, c.Cvss40Score) {
					case -1:
						merged.Cvss40Score = c.Cvss40Score
						merged.Cvss40Vector = c.Cvss40Vector
						merged.Cvss40Severity = c.Cvss40Severity
					default:
						merged.Cvss40Score = base.Cvss40Score
						merged.Cvss40Vector = base.Cvss40Vector
						merged.Cvss40Severity = base.Cvss40Severity
					}

					switch {
					case strings.HasPrefix(base.Cvss3Vector, "CVSS:3.0") && strings.HasPrefix(c.Cvss3Vector, "CVSS:3.1"):
						merged.Cvss3Score = c.Cvss3Score
						merged.Cvss3Vector = c.Cvss3Vector
						merged.Cvss3Severity = c.Cvss3Severity
					case strings.HasPrefix(base.Cvss3Vector, "CVSS:3.1") && strings.HasPrefix(c.Cvss3Vector, "CVSS:3.0"):
						merged.Cvss3Score = base.Cvss3Score
						merged.Cvss3Vector = base.Cvss3Vector
						merged.Cvss3Severity = base.Cvss3Severity
					default:
						switch cmp.Compare(base.Cvss3Score, c.Cvss3Score) {
						case -1:
							merged.Cvss3Score = c.Cvss3Score
							merged.Cvss3Vector = c.Cvss3Vector
							merged.Cvss3Severity = c.Cvss3Severity
						default:
							merged.Cvss3Score = base.Cvss3Score
							merged.Cvss3Vector = base.Cvss3Vector
							merged.Cvss3Severity = base.Cvss3Severity
						}
					}

					switch cmp.Compare(base.Cvss2Score, c.Cvss2Score) {
					case -1:
						merged.Cvss2Score = c.Cvss2Score
						merged.Cvss2Vector = c.Cvss2Vector
						merged.Cvss2Severity = c.Cvss2Severity
					default:
						merged.Cvss2Score = base.Cvss2Score
						merged.Cvss2Vector = base.Cvss2Vector
						merged.Cvss2Severity = base.Cvss2Severity
					}

					for _, rs := range []models.References{base.References, c.References} {
						for _, r := range rs {
							if !slices.ContainsFunc(merged.References, func(e models.Reference) bool {
								return r.Link == e.Link && r.Source == e.Source && r.RefID == e.RefID && slices.Equal(r.Tags, e.Tags)
							}) {
								merged.References = append(merged.References, r)
							}
						}
					}

					for _, cs := range [][]string{base.CweIDs, c.CweIDs} {
						for _, c := range cs {
							if !slices.Contains(merged.CweIDs, c) {
								merged.CweIDs = append(merged.CweIDs, c)
							}
						}
					}

					srcs := append(src1, src2...)
					slices.SortFunc(srcs, compareSource)
					bs, err := json.Marshal(srcs)
					if err != nil {
						return models.VulnInfo{}, xerrors.Errorf("Failed to marshal sources. err: %w", err)
					}
					merged.Optional["vuls2-sources"] = string(bs)

					base = merged
				} else {
					base = c
				}
				ccm[c.Type] = base
			}
		}
	}
	ccs := make(models.CveContents)
	for cctype, cc := range ccm {
		ccs[cctype] = []models.CveContent{cc}
	}
	info.CveContents = ccs

	return info, nil
}

func toReference(ref string) models.Reference {
	switch {
	case strings.HasPrefix(ref, "https://www.cve.org/CVERecord?id="):
		return models.Reference{
			Link:   ref,
			Source: "CVE",
			RefID:  strings.TrimPrefix(ref, "https://www.cve.org/CVERecord?id="),
		}
	case strings.HasPrefix(ref, "https://cve.mitre.org/cgi-bin/cvename.cgi?name="):
		return models.Reference{
			Link:   ref,
			Source: "MITRE",
			RefID:  strings.TrimPrefix(ref, "https://cve.mitre.org/cgi-bin/cvename.cgi?name="),
		}
	case strings.HasPrefix(ref, "https://nvd.nist.gov/vuln/detail/"):
		return models.Reference{
			Link:   ref,
			Source: "NVD",
			RefID:  strings.TrimPrefix(ref, "https://nvd.nist.gov/vuln/detail/"),
		}
	case strings.HasPrefix(ref, "https://access.redhat.com/"), strings.HasPrefix(ref, "https://bugzilla.redhat.com/"):
		switch {
		case strings.HasPrefix(ref, "https://access.redhat.com/security/cve/"):
			return models.Reference{
				Link:   ref,
				Source: "REDHAT",
				RefID:  strings.TrimPrefix(ref, "https://access.redhat.com/security/cve/"),
			}
		case strings.HasPrefix(ref, "https://access.redhat.com/errata/"):
			return models.Reference{
				Link:   ref,
				Source: "REDHAT",
				RefID:  strings.TrimPrefix(ref, "https://access.redhat.com/errata/"),
			}
		case strings.HasPrefix(ref, "https://bugzilla.redhat.com/show_bug.cgi?id="):
			return models.Reference{
				Link:   ref,
				Source: "REDHAT",
				RefID:  strings.TrimPrefix(ref, "https://bugzilla.redhat.com/show_bug.cgi?id="),
			}
		default:
			return models.Reference{
				Link:   ref,
				Source: "REDHAT",
			}
		}
	case strings.HasPrefix(ref, "https://bodhi.fedoraproject.org/"):
		switch {
		case strings.HasPrefix(ref, "https://bodhi.fedoraproject.org/updates/"):
			return models.Reference{
				Link:   ref,
				Source: "FEDORA",
				RefID:  strings.TrimPrefix(ref, "https://bodhi.fedoraproject.org/updates/"),
			}
		default:
			return models.Reference{
				Link:   ref,
				Source: "FEDORA",
			}
		}
	case strings.HasPrefix(ref, "https://errata.almalinux.org/"):
		u, err := url.Parse(ref)
		if err != nil {
			return models.Reference{
				Link:   ref,
				Source: "ALMA",
			}
		}

		ss := strings.Split(strings.TrimSuffix(path.Base(u.Path), ".html"), "-")
		if len(ss) != 3 {
			return models.Reference{
				Link:   ref,
				Source: "ALMA",
			}
		}

		return models.Reference{
			Link:   ref,
			Source: "ALMA",
			RefID:  fmt.Sprintf("%s-%s:%s", ss[0], ss[1], ss[2]),
		}
	case strings.HasPrefix(ref, "https://errata.build.resf.org/"):
		return models.Reference{
			Link:   ref,
			Source: "ROCKY",
			RefID:  strings.TrimPrefix(ref, "https://errata.build.resf.org/"),
		}
	case strings.HasPrefix(ref, "https://linux.oracle.com/"):
		switch {
		case strings.HasPrefix(ref, "https://linux.oracle.com/cve/"):
			return models.Reference{
				Link:   ref,
				Source: "ORACLE",
				RefID:  strings.TrimPrefix(strings.TrimSuffix(ref, ".html"), "https://linux.oracle.com/cve/"),
			}
		case strings.HasPrefix(ref, "https://linux.oracle.com/errata/"):
			return models.Reference{
				Link:   ref,
				Source: "ORACLE",
				RefID:  strings.TrimPrefix(strings.TrimSuffix(ref, ".html"), "https://linux.oracle.com/errata/"),
			}
		default:
			return models.Reference{
				Link:   ref,
				Source: "ORACLE",
			}
		}
	case strings.HasPrefix(ref, "https://security.alpinelinux.org/vuln/"):
		return models.Reference{
			Link:   ref,
			Source: "ALPINE",
			RefID:  strings.TrimPrefix(ref, "https://security.alpinelinux.org/vuln/"),
		}
	case strings.HasPrefix(ref, "https://ubuntu.com/security/"):
		switch {
		case strings.HasPrefix(ref, "https://ubuntu.com/security/CVE-"):
			return models.Reference{
				Link:   ref,
				Source: "UBUNTU",
				RefID:  strings.TrimPrefix(ref, "https://ubuntu.com/security/"),
			}
		case strings.HasPrefix(ref, "https://ubuntu.com/security/notices/"):
			return models.Reference{
				Link:   ref,
				Source: "UBUNTU",
				RefID:  strings.TrimPrefix(ref, "https://ubuntu.com/security/notices/"),
			}
		default:
			return models.Reference{
				Link:   ref,
				Source: "UBUNTU",
			}
		}
	default:
		return models.Reference{
			Link:   ref,
			Source: "MISC",
		}
	}
}

// enrich adds vulnerability data from specific enrichment sources (KEV, RedHat
// CVE, NVD) to the already-detected VulnInfos. This replaces gost.FillCVEsWithRedHat
// and the NVD slice of FillCvesWithGoCVEDictionary, and also provides cross-source
// enrichment (e.g., RedHat CVE / NVD data for Debian-detected CVEs).
func enrich(sesh *session.Session, vim models.VulnInfos) error {
	for cveID, vi := range vim {
		vd, err := sesh.GetVulnerabilityDataByVulnerabilityID(vulnerabilityContentTypes.VulnerabilityID(cveID), dbTypes.Filter{
			Contents: []dbTypes.FilterContentType{
				dbTypes.FilterContentTypeAdvisories,
				dbTypes.FilterContentTypeVulnerabilities,
			},
			DataSources: []sourceTypes.SourceID{
				sourceTypes.CISAKEV,
				sourceTypes.ENISAKEV,
				sourceTypes.ExploitExploitDB,
				sourceTypes.ExploitGitHub,
				sourceTypes.ExploitInTheWild,
				sourceTypes.ExploitTrickest,
				sourceTypes.Metasploit,
				sourceTypes.NVDFeedCVEv2,
				sourceTypes.NucleiRepository,
				sourceTypes.RedHatCVE,
				sourceTypes.VulnCheckKEV,
			},
		})
		if err != nil {
			if errors.Is(err, dbTypes.ErrNotFoundVulnerability) {
				continue
			}
			return xerrors.Errorf("Failed to get vulnerability. CVE-ID: %s, err: %w", cveID, err)
		}

		if vi.CveContents == nil {
			vi.CveContents = models.NewCveContents()
		}

		enrichVulnerabilities(&vi, vd.Vulnerabilities)
		enrichAdvisories(&vi, vd.Advisories)

		vim[cveID] = vi
	}
	return nil
}
