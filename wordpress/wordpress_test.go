package wordpress

// func TestContentConvertVinfos(t *testing.T) {

// 	var tests = []struct {
// 		in1      string
// 		in2      models.WpPackage
// 		expected []models.VulnInfo
// 	}{
// 		{
// 			in1: `{"4.9.4":{"release_date":"2018-02-06","changelog_url":"https://codex.wordpress.org/Version_4.9.4","status":"insecure","vulnerabilities":[{"id":9021,"title":"WordPress <= 4.9.4 - Application Denial of Service (DoS) (unpatched)","created_at":"2018-02-05T16:50:40.000Z","updated_at":"2018-08-29T19:13:04.000Z","published_date":"2018-02-05T00:00:00.000Z","vuln_type":"DOS","references":{"url":["https://baraktawily.blogspot.fr/2018/02/how-to-dos-29-of-world-wide-websites.html","https://github.com/quitten/doser.py","https://thehackernews.com/2018/02/wordpress-dos-exploit.html"],"cve":["2018-6389"]},"fixed_in":null}]}}`,
// 			in2: models.WpPackage{Name: "twentyfifteen", Status: "inactive", Update: "available", Version: "1.1"},
// 			expected: []models.VulnInfo{
// 				{
// 					CveID: "CVE-2018-6389",
// 					AffectedPackages: models.PackageStatuses{
// 						models.PackageStatus{
// 							NotFixedYet: true,
// 						},
// 					},
// 					CveContents: models.NewCveContents(
// 						models.CveContent{
// 							CveID: "CVE-2018-6389",
// 							Title: "WordPress <= 4.9.4 - Application Denial of Service (DoS) (unpatched)",
// 						},
// 					),
// 				},
// 			},
// 		},
// 		{
// 			in1:      `{"4.9.4":{"release_date":"2018-02-06","changelog_url":"https://codex.wordpress.org/Version_4.9.4","status":"insecure","vulnerabilities":[{"id":9021,"title":"WordPress <= 4.9.4 - Application Denial of Service (DoS) (unpatched)","created_at":"2018-02-05T16:50:40.000Z","updated_at":"2018-08-29T19:13:04.000Z","published_date":"2018-02-05T00:00:00.000Z","vuln_type":"DOS","references":{"url":["https://baraktawily.blogspot.fr/2018/02/how-to-dos-29-of-world-wide-websites.html","https://github.com/quitten/doser.py","https://thehackernews.com/2018/02/wordpress-dos-exploit.html"],"cve":["2018-6389"]},"fixed_in":"1.0"}]}}`,
// 			in2:      models.WpPackage{Name: "twentyfifteen", Status: "inactive", Update: "available", Version: "1.1"},
// 			expected: nil,
// 		},
// 		{
// 			in1: `{"4.9.4":{"release_date":"2018-02-06","changelog_url":"https://codex.wordpress.org/Version_4.9.4","status":"insecure","vulnerabilities":[{"id":9021,"title":"WordPress <= 4.9.4 - Application Denial of Service (DoS) (unpatched)","created_at":"2018-02-05T16:50:40.000Z","updated_at":"2018-08-29T19:13:04.000Z","published_date":"2018-02-05T00:00:00.000Z","vuln_type":"DOS","references":{"url":["https://baraktawily.blogspot.fr/2018/02/how-to-dos-29-of-world-wide-websites.html","https://github.com/quitten/doser.py","https://thehackernews.com/2018/02/wordpress-dos-exploit.html"],"cve":["2018-6389"]},"fixed_in":"1.2"}]}}`,
// 			in2: models.WpPackage{Name: "twentyfifteen", Status: "inactive", Update: "available", Version: "1.1"},
// 			expected: []models.VulnInfo{
// 				{
// 					CveID: "CVE-2018-6389",
// 					AffectedPackages: models.PackageStatuses{
// 						models.PackageStatus{
// 							NotFixedYet: false,
// 						},
// 					},
// 					CveContents: models.NewCveContents(
// 						models.CveContent{
// 							CveID: "CVE-2018-6389",
// 							Title: "WordPress <= 4.9.4 - Application Denial of Service (DoS) (unpatched)",
// 						},
// 					),
// 				},
// 			},
// 		},
// 	}
// 	for _, test := range tests {
// 		actual, _ := contentConvertVinfos(test.in1, test.in2)
// 		if !reflect.DeepEqual(test.expected, actual) {
// 			h := pp.Sprint(actual)
// 			k := pp.Sprint(test.expected)
// 			t.Errorf("expected %v, actual %v", k, h)
// 		}
// 	}

// }

// func TestCoreConvertVinfos(t *testing.T) {

// 	var test = struct {
// 		in1      string
// 		expected []models.VulnInfo
// 	}{
// 		in1: `{"4.9.4":{"release_date":"2018-02-06","changelog_url":"https://codex.wordpress.org/Version_4.9.4","status":"insecure","vulnerabilities":[{"id":9021,"title":"WordPress <= 4.9.4 - Application Denial of Service (DoS) (unpatched)","created_at":"2018-02-05T16:50:40.000Z","updated_at":"2018-08-29T19:13:04.000Z","published_date":"2018-02-05T00:00:00.000Z","vuln_type":"DOS","references":{"url":["https://baraktawily.blogspot.fr/2018/02/how-to-dos-29-of-world-wide-websites.html","https://github.com/quitten/doser.py","https://thehackernews.com/2018/02/wordpress-dos-exploit.html"],"cve":["2018-6389"]},"fixed_in":null}]}}`,
// 		expected: []models.VulnInfo{
// 			{
// 				CveID: "CVE-2018-6389",
// 				AffectedPackages: models.PackageStatuses{
// 					models.PackageStatus{
// 						NotFixedYet: true,
// 					},
// 				},
// 				CveContents: models.NewCveContents(
// 					models.CveContent{
// 						CveID: "CVE-2018-6389",
// 						Title: "WordPress <= 4.9.4 - Application Denial of Service (DoS) (unpatched)",
// 					},
// 				),
// 			},
// 		},
// 	}
// 	actual, _ := coreConvertVinfos(test.in1)
// 	if !reflect.DeepEqual(test.expected, actual) {
// 		h := pp.Sprint(actual)
// 		k := pp.Sprint(test.expected)
// 		t.Errorf("expected %v, actual %v", k, h)
// 	}
// }
