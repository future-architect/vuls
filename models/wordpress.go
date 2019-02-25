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

package models

// WordPress has Core version, plugins and themes.
type WordPress struct {
	CoreVersion string      `json:"coreVersion,omitempty"`
	Plugins     []WpPackage `json:"plugins,omitempty"`
	Themes      []WpPackage `json:"themes,omitempty"`
}

// WpPackage has a details of plugin and theme
type WpPackage struct {
	Name    string `json:"name,omitempty"`
	Status  string `json:"status,omitempty"`
	Update  string `json:"update,omitempty"`
	Version string `json:"version,omitempty"`
}
