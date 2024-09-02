// Package cli contains functions for running checks from command-line.
package cli

import (
	"encoding/json"
	"fmt"
	"log"
	"math"
	"net"
	"os"
	"sort"
	"sync"

	"github.com/jreisinger/checkip/check"
)

// Run runs checks concurrently against the ippaddr.
func Run(checkFuncs []check.Func, ipaddr net.IP) (Checks, []error) {
	var checksMu struct {
		sync.Mutex
		checks []check.Check
	}
	var errorsMu struct {
		sync.Mutex
		errors []error
	}

	var wg sync.WaitGroup
	for _, cf := range checkFuncs {
		wg.Add(1)
		go func(cf check.Func) {
			defer wg.Done()
			c, err := cf(ipaddr)
			if err != nil {
				errorsMu.Lock()
				errorsMu.errors = append(errorsMu.errors, err)
				errorsMu.Unlock()
				return
			}
			checksMu.Lock()
			checksMu.checks = append(checksMu.checks, c)
			checksMu.Unlock()
		}(cf)
	}
	wg.Wait()

	return checksMu.checks, errorsMu.errors
}

// Checks are generic or security information provided by a Check.
type Checks []check.Check

// PrintJSON prints all results in JSON.
func (rs Checks) PrintJSON(ipaddr net.IP) {
	// if len(rs) == 0 {
	// 	return
	// }

	_, _, prob := rs.maliciousStats()

	out := struct {
		IpAddr        net.IP `json:"ipAddr"`
		MaliciousProb string `json:"maliciousProb"`
		Checks        Checks `json:"checks"`
	}{
		ipaddr,
		fmt.Sprintf("%.2f", prob),
		rs,
	}

	enc := json.NewEncoder(os.Stdout)
	if err := enc.Encode(out); err != nil {
		log.Fatal(err)
	}
}

// SortByName sorts Results by name.
func (rs Checks) SortByName() {
	sort.Slice(rs, func(i, j int) bool {
		return rs[i].Description < rs[j].Description
	})
}

// PrintSummary prints summary results from Info and InfoSec checks.
func (rs Checks) PrintSummary() {
	for _, r := range rs {
		// To avoid "invalid memory address or nil pointer dereference"
		// runtime error and printing empty summary info.
		if r.IpAddrInfo == nil || r.IpAddrInfo.Summary() == "" {
			continue
		}

		if r.Type == check.Info || r.Type == check.InfoAndIsMalicious {
			fmt.Printf("%-15s %s\n", r.Description, r.IpAddrInfo.Summary())
		}
	}
}

// PrintMalicious prints how many of the InfoSec and Sec checks consider the IP
// address to be malicious.
func (rs Checks) PrintMalicious() {
	total, malicious, prob := rs.maliciousStats()
	msg := fmt.Sprintf("%-15s %.0f%% (%d/%d) ",
		"malicious prob.", math.Round(prob*100), malicious, total)
	switch {
	case prob >= 0.50:
		msg += `🚫`
	case prob >= 0.15:
		msg += `🤏`
	default:
		msg += `✅`
	}
	fmt.Println(msg)
}

func (rs Checks) maliciousStats() (total, malicious int, prob float64) {
	for _, r := range rs {
		// if r.Info == nil {
		// 	continue
		// }
		if r.Type == check.IsMalicious || r.Type == check.InfoAndIsMalicious {
			total++
			if r.IpAddrIsMalicious {
				malicious++
			}
		}
	}
	prob = float64(malicious) / float64(total)
	return total, malicious, prob
}
