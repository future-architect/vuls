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

import (
	"os"

	"github.com/Sirupsen/logrus"
	"github.com/future-architect/vuls/models"
	formatter "github.com/kotakanbe/logrus-prefixed-formatter"
)

// LogrusWriter write to logfile
type LogrusWriter struct {
}

func (w LogrusWriter) Write(scanResults []models.ScanResult) error {
	path := "/var/log/vuls/report.log"
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
	if err != nil {
		return err
	}
	log := logrus.New()
	log.Formatter = &formatter.TextFormatter{}
	log.Out = f
	log.Level = logrus.InfoLevel

	for _, s := range scanResults {
		text, err := toPlainText(s)
		if err != nil {
			return err
		}
		log.Infof(text)
	}
	return nil
}
