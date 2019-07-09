package main

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"log"
	"os"
	"strings"
)

var (

	// We need to change these paths to allow portability with other OSes.

	// logFile is for any errors to report with the program.
	logFile = "testfiles/logFile"
	// outputFile is for the results from the program.
	// This will also include errors due to the remote system, but not
	// related to the program itself.
	outputFile = "testfiles/outputFile"
	// This file contains the csv of url/ip, port pairs
	inputFile = "testfiles/inputFile"
)

// Config struct for tls.Dial()
// InsecureSkipVerify: true, is required for any IP address entries in the source csv file.
var conf = &tls.Config{
	InsecureSkipVerify: true,
}

// prettyPrint ...
func prettyPrint(i interface{}) string {
	s, _ := json.MarshalIndent(i, "", "\t")
	return string(s)
}

// fileScanner ...
func fileScanner(f *os.File) (lines []string) {
	scanner := bufio.NewScanner(f)
	scanner.Split(bufio.ScanLines)

	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	return lines
}

// tlsConnection ...
func tlsConnection(s string, config *tls.Config) (*tls.Conn, error) {
	conn, err := tls.Dial("tcp", s, config)
	if err != nil {
		return nil, err
	}
	// Let's run the handshake protocol.
	err = conn.Handshake()
	if err != nil {
		return nil, err
	}

	return conn, err
}

type extCert struct {
	origHost string
	origIP   string
	cert     x509.Certificate
}

/* func (e extCert) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		extCert
		origHost string
		origIP   string
	}{
		extCert:  extCert(e),
		origHost: hostname,
		origIP:   ip,
	})
} */

// marshalJSON ...
func marshalJSON(cert x509.Certificate, origHost string, origIP string) extCert {
	var fullCert *extCert
	fullCert.origHost = origHost
	fullCert.origIP = origIP
	fullCert.cert = cert

	return *fullCert
}

func main() {
	// Logger set flags for logging errors.
	log.SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds | log.Lshortfile)

	// Let's open a file to write error logs to.
	errFile, err := os.OpenFile(logFile, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0644)
	if err != nil {
		log.Fatalf("error opening file: %v", err)
	}
	defer errFile.Close()
	log.SetOutput(errFile)

	// Let's open a file to write our certificate info to.
	outFile, err := os.OpenFile(outputFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0744)
	if err != nil {
		log.Fatal(err)
	}
	defer outFile.Close()

	// Let's open the file containing url/ip and port pairs
	// Form is: url/ip, port as: "www.trexis.com", "443"
	f, err := os.Open(inputFile)
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()

	fileLines := fileScanner(f)

	for _, line := range fileLines {
		// Let's dump the comma between the host and port and replace with a ":" as required for tls.Dial()
		line = strings.Replace(line, ",", ":", -1)
		conn, err := tlsConnection(line, conf)
		if err != nil {
			log.Println(err)
		}
		// Let's get some cert information
		if conn != nil {
			certStr := prettyPrint(conn.ConnectionState().PeerCertificates[0])
			if _, err := outFile.Write([]byte(certStr)); err != nil {
				log.Fatal(err)
			}
		}

	}
}
