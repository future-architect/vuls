package alert

// GenerateAlertDict returns XCERT alert slice by cveID
func GenerateAlertDict(cveID string, lang string) (alerts []Alert) {
	if lang == "ja" {
		if keys, ok := CveDictJa[cveID]; ok {
			for _, key := range keys {
				alerts = append(alerts, AlertDictJa[key])
			}
		}
		return alerts
	}

	// default language is English
	if keys, ok := CveDictEn[cveID]; ok {
		for _, key := range keys {
			alerts = append(alerts, AlertDictEn[key])
		}
	}
	return alerts
}
