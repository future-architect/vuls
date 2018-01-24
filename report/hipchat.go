package report


import (
//	"encoding/json"
//	"fmt"
//	"sort"
//	"strings"
//	"time"

//	"github.com/cenkalti/backoff"
//	"github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/models"
)

// HipChatWriter send report to HipChat
type HipChatWriter struct{}

func (w HipChatWriter) Write(rs ...models.ScanResult) (err error) {
	return
}
