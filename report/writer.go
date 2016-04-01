/* Vuls - Vulnerability Scanner
Copyright (C) 2016  Future Architect, Inc. Japan.

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

package report

import "github.com/future-architect/vuls/models"

const (
	nvdBaseURL            = "https://web.nvd.nist.gov/view/vuln/detail"
	mitreBaseURL          = "https://cve.mitre.org/cgi-bin/cvename.cgi?name="
	cveDetailsBaseURL     = "http://www.cvedetails.com/cve"
	cvssV2CalcURLTemplate = "https://nvd.nist.gov/cvss/v2-calculator?name=%s&vector=%s"

	redhatSecurityBaseURL = "https://access.redhat.com/security/cve"
	redhatRHSABaseBaseURL = "https://rhn.redhat.com/errata/%s.html"
	amazonSecurityBaseURL = "https://alas.aws.amazon.com/%s.html"

	ubuntuSecurityBaseURL = "http://people.ubuntu.com/~ubuntu-security/cve"
	debianTrackerBaseURL  = "https://security-tracker.debian.org/tracker"
)

// ResultWriter Interface
type ResultWriter interface {
	Write([]models.ScanResult) error
}
