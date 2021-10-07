package v2

import (
	"testing"

	"github.com/d4l3k/messagediff"

	"github.com/future-architect/vuls/models"
)

func TestParse(t *testing.T) {
	cases := map[string]struct {
		vulnJSON []byte
		expected *models.ScanResult
	}{
		"redis": {vulnJSON: redisTrivy,
			expected: redisSR,
		},
	}

	for testcase, v := range cases {
		actual, err := ParserV2{}.Parse(v.vulnJSON)
		if err != nil {
			t.Errorf("%s", err)
		}

		diff, equal := messagediff.PrettyDiff(
			v.expected,
			actual,
			messagediff.IgnoreStructField("ScannedAt"),
			messagediff.IgnoreStructField("Title"),
			messagediff.IgnoreStructField("Summary"),
			messagediff.IgnoreStructField("LastModified"),
			messagediff.IgnoreStructField("Published"),
		)
		if !equal {
			t.Errorf("test: %s, diff %s", testcase, diff)
		}
	}
}

var redisTrivy = []byte(`
{
  "SchemaVersion": 2,
  "ArtifactName": "redis",
  "ArtifactType": "container_image",
  "Metadata": {
    "OS": {
      "Family": "debian",
      "Name": "10.10"
    },
    "ImageID": "sha256:ddcca4b8a6f0367b5de2764dfe76b0a4bfa6d75237932185923705da47004347",
    "DiffIDs": [
      "sha256:f68ef921efae588b3dd5cc466a1ca9c94c24785f1fa9420bea15ecc2dedbe781",
      "sha256:b6fc243eaea74d1a41b242da4c3ec5166db80f38c4d57a10ce8860c00d902ace",
      "sha256:ec92e47b7c52dacc26df07ee13e8e81c099b5a5661ccc97b06692a9c9d01e772",
      "sha256:4be6d4460d3615186717f21ffc0023b168dce48967d01934bbe31127901d3d5c",
      "sha256:992463b683270e164936e9c48fa395d05a7b8b5cc0aa208e4fa81aa9158fcae1",
      "sha256:0083597d42d190ddb86c35587a7b196fe18d79382520544b5f715c1e4792b19a"
    ],
    "RepoTags": [
      "redis:latest"
    ],
    "RepoDigests": [
      "redis@sha256:66ce9bc742609650afc3de7009658473ed601db4e926a5b16d239303383bacad"
    ],
    "ImageConfig": {
      "architecture": "amd64",
      "container": "fa59f1c2817c9095f8f7272a4ab9b11db0332b33efb3a82c00a3d1fec8763684",
      "created": "2021-08-17T14:30:06.550779326Z",
      "docker_version": "20.10.7",
      "history": [
        {
          "created": "2021-08-17T01:24:06Z",
          "created_by": "/bin/sh -c #(nop) ADD file:87b4e60fe3af680c6815448374365a44e9ea461bc8ade2960b4639c25aed3ba9 in / "
        },
        {
          "created": "2021-08-17T14:30:06Z",
          "created_by": "/bin/sh -c #(nop)  CMD [\"redis-server\"]",
          "empty_layer": true
        }
      ],
      "os": "linux",
      "rootfs": {
        "type": "layers",
        "diff_ids": [
          "sha256:f68ef921efae588b3dd5cc466a1ca9c94c24785f1fa9420bea15ecc2dedbe781",
          "sha256:b6fc243eaea74d1a41b242da4c3ec5166db80f38c4d57a10ce8860c00d902ace",
          "sha256:ec92e47b7c52dacc26df07ee13e8e81c099b5a5661ccc97b06692a9c9d01e772",
          "sha256:4be6d4460d3615186717f21ffc0023b168dce48967d01934bbe31127901d3d5c",
          "sha256:992463b683270e164936e9c48fa395d05a7b8b5cc0aa208e4fa81aa9158fcae1",
          "sha256:0083597d42d190ddb86c35587a7b196fe18d79382520544b5f715c1e4792b19a"
        ]
      },
      "config": {
        "Cmd": [
          "redis-server"
        ],
        "Entrypoint": [
          "docker-entrypoint.sh"
        ],
        "Env": [
          "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
          "GOSU_VERSION=1.12",
          "REDIS_VERSION=6.2.5",
          "REDIS_DOWNLOAD_URL=http://download.redis.io/releases/redis-6.2.5.tar.gz",
          "REDIS_DOWNLOAD_SHA=4b9a75709a1b74b3785e20a6c158cab94cf52298aa381eea947a678a60d551ae"
        ],
        "Image": "sha256:befbd3fc62bffcd0115008969a014faaad07828b2c54b4bcfd2d9fc3aa2508cd",
        "Volumes": {
          "/data": {}
        },
        "WorkingDir": "/data"
      }
    }
  },
  "Results": [
    {
      "Target": "redis (debian 10.10)",
      "Class": "os-pkgs",
      "Type": "debian",
      "Packages": [
        {
          "Name": "adduser",
          "Version": "3.118",
          "SrcName": "adduser",
          "SrcVersion": "3.118",
          "Layer": {
            "DiffID": "sha256:f68ef921efae588b3dd5cc466a1ca9c94c24785f1fa9420bea15ecc2dedbe781"
          }
        },
        {
          "Name": "apt",
          "Version": "1.8.2.3",
          "SrcName": "apt",
          "SrcVersion": "1.8.2.3",
          "Layer": {
            "DiffID": "sha256:f68ef921efae588b3dd5cc466a1ca9c94c24785f1fa9420bea15ecc2dedbe781"
          }
        },
        {
          "Name": "bsdutils",
          "Version": "1:2.33.1-0.1",
          "SrcName": "util-linux",
          "SrcVersion": "2.33.1-0.1",
          "Layer": {
            "DiffID": "sha256:f68ef921efae588b3dd5cc466a1ca9c94c24785f1fa9420bea15ecc2dedbe781"
          }
        },
        {
          "Name": "pkgA",
          "Version": "1:2.33.1-0.1",
          "SrcName": "util-linux",
          "SrcVersion": "2.33.1-0.1",
          "Layer": {
            "DiffID": "sha256:f68ef921efae588b3dd5cc466a1ca9c94c24785f1fa9420bea15ecc2dedbe781"
          }
        }
      ],
      "Vulnerabilities": [
        {
          "VulnerabilityID": "CVE-2011-3374",
          "PkgName": "apt",
          "InstalledVersion": "1.8.2.3",
          "Layer": {
            "DiffID": "sha256:f68ef921efae588b3dd5cc466a1ca9c94c24785f1fa9420bea15ecc2dedbe781"
          },
          "SeveritySource": "debian",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2011-3374",
          "Description": "It was found that apt-key in apt, all versions, do not correctly validate gpg keys with the master keyring, leading to a potential man-in-the-middle attack.",
          "Severity": "LOW",
          "CweIDs": [
            "CWE-347"
          ],
          "CVSS": {
            "nvd": {
              "V2Vector": "AV:N/AC:M/Au:N/C:N/I:P/A:N",
              "V3Vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N",
              "V2Score": 4.3,
              "V3Score": 3.7
            }
          },
          "References": [
            "https://access.redhat.com/security/cve/cve-2011-3374"
          ],
          "PublishedDate": "2019-11-26T00:15:00Z",
          "LastModifiedDate": "2021-02-09T16:08:00Z"
        }
      ]
    }
  ]
}
`)
var redisSR = &models.ScanResult{
	JSONVersion: 4,
	ServerName:  "redis (debian 10.10)",
	Family:      "debian",
	ScannedBy:   "trivy",
	ScannedVia:  "trivy",
	ScannedCves: models.VulnInfos{
		"CVE-2011-3374": {
			CveID: "CVE-2011-3374",
			Confidences: models.Confidences{
				models.Confidence{Score: 100,
					DetectionMethod: "TrivyMatch",
				},
			},
			AffectedPackages: models.PackageFixStatuses{
				models.PackageFixStatus{
					Name:        "apt",
					NotFixedYet: true,
					FixState:    "Affected",
					FixedIn:     "",
				}},
			CveContents: models.CveContents{
				"trivy": []models.CveContent{{
					Title:         "",
					Summary:       "It was found that apt-key in apt, all versions, do not correctly validate gpg keys with the master keyring, leading to a potential man-in-the-middle attack.",
					Cvss3Severity: "LOW",
					References: models.References{
						{Source: "trivy", Link: "https://access.redhat.com/security/cve/cve-2011-3374"},
					},
				}},
			},
			LibraryFixedIns: models.LibraryFixedIns{},
		},
	},
	LibraryScanners: models.LibraryScanners{},
	Packages: models.Packages{
		"apt": models.Package{
			Name:    "apt",
			Version: "1.8.2.3",
		},
		"adduser": models.Package{
			Name:    "adduser",
			Version: "3.118",
		},
		"bsdutils": models.Package{
			Name:    "bsdutils",
			Version: "1:2.33.1-0.1",
		},
		"pkgA": models.Package{
			Name:    "pkgA",
			Version: "1:2.33.1-0.1",
		},
	},
	SrcPackages: models.SrcPackages{
		"util-linux": models.SrcPackage{
			Name:        "util-linux",
			Version:     "2.33.1-0.1",
			BinaryNames: []string{"bsdutils", "pkgA"},
		},
	},
	Optional: map[string]interface{}{
		"trivy-target": "redis (debian 10.10)",
	},
}
