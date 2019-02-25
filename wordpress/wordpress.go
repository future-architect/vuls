/* Vuls - Vulnerability Scanner
Copyright (C) 2016  Future Corporation , Japan.

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

package wordpress

//WpCveInfos is for wpvulndb's json
type WpCveInfos struct {
	ReleaseDate     string      `json:"release_date"`
	ChangelogURL    string      `json:"changelog_url"`
	Status          string      `json:"status"`
	LatestVersion   string      `json:"latest_version"`
	LastUpdated     string      `json:"last_updated"`
	Popular         bool        `json:"popular"`
	Vulnerabilities []WpCveInfo `json:"vulnerabilities"`
	Error           string      `json:"error"`
}

//WpCveInfo is for wpvulndb's json
type WpCveInfo struct {
	ID            int        `json:"id"`
	Title         string     `json:"title"`
	CreatedAt     string     `json:"created_at"`
	UpdatedAt     string     `json:"updated_at"`
	PublishedDate string     `json:"published_date"`
	VulnType      string     `json:"vuln_type"`
	References    References `json:"references"`
	FixedIn       string     `json:"fixed_in"`
}

//References is for wpvulndb's json
type References struct {
	URL     []string `json:"url"`
	Cve     []string `json:"cve"`
	Secunia []string `json:"secunia"`
}
