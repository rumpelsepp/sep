package sephelper

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"git.sr.ht/~rumpelsepp/sep"
)

// LoadAuthorizedFingerprints loads a file and returns a map of alias to
// fingerprint. Lines starting with "#" are ignored. The file needs to have one
// fingerprint and alias per line like so:
// 	ni://<authority>/<algorithm>;<value>		<alias>
//	ni://<authority>/<algorithm>;<value>		<alias>
//	ni://<authority>/<algorithm>;<value>		<alias>
func LoadAuthorizedFingerprints(path string) (map[string]*sep.Fingerprint, error) {
	Logger.Debugf("Loading authorized fingerprints from %s", path)

	m := make(map[string]*sep.Fingerprint)

	if _, err := os.Stat(path); err != nil {
		return nil, fmt.Errorf("file does not exist: %w", err)
	}

	file, err := os.OpenFile(path, os.O_RDONLY, 0600)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		if err := scanner.Err(); err != nil {
			return nil, fmt.Errorf("read error: %w", err)
		}

		// Ignore comments
		if strings.HasPrefix(scanner.Text(), "#") {
			Logger.Debugf("Ignoring comment:\t\"%s\"", scanner.Text())
			continue
		}
		// Ignore empty lines
		fields := strings.Fields(scanner.Text())
		if len(fields) == 0 {
			continue
		}
		// Ignore invalid lines
		fingerprint, err := sep.FingerprintFromNIString(fields[0])
		if len(fields) != 2 || err != nil {
			Logger.Debugf("Could not parse:\t\"%s\"", scanner.Text())
			continue
		}

		m[fields[1]] = fingerprint
	}

	Logger.Debugln("Extracted these fingerprints:")
	for k, v := range m {
		Logger.Debugf("\t%s\t%s", v, k)
	}

	return m, nil
}

// AddAuthorizedFingerprint appends the given fingerprint and alias to the
// specified file such that LoadAuthorizedFingerprints() can understand.
func AddAuthorizedFingerprint(path string, fingerprint *sep.Fingerprint, alias string) error {
	Logger.Debugf("Trying to add fingerprint %s as %s", fingerprint.String(), alias)

	// Create conf folder if not existing
	// Load file, if it is already there.
	if _, err := os.Stat(path); err != nil {
		basePath := filepath.Dir(path)
		err = os.MkdirAll(basePath, 0700)
		if err != nil {
			return err
		}
	} else {
		// Check whether fingerprint or alias already exist
		if authorizedFingerprints, err := LoadAuthorizedFingerprints(path); err == nil {
			for k, v := range authorizedFingerprints {
				if k == alias {
					return fmt.Errorf("alias '%s' exists", alias)
				}
				if sep.FingerprintIsEqual(v, fingerprint) {
					return fmt.Errorf("fingerprint '%s' exists", fingerprint.String())
				}
			}
		}
	}

	// Append new fingerprint and alias
	file, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0600)
	if err != nil {
		return err
	}
	defer file.Close()

	// Check if the last byte is a newline.
	// If not, then add to avoid corruption…
	if fileInfo, _ := file.Stat(); fileInfo.Size() > 0 {
		if _, err := file.Seek(-1, os.SEEK_END); err != nil {
			return err
		}

		buf := make([]byte, 1)
		if _, err := file.Read(buf); err != nil {
			return err
		}

		if buf[0] != '\n' {
			file.WriteString("\n")
		}
	}

	file.WriteString(fmt.Sprintf("%s\t%s\n", fingerprint.String(), alias))

	return nil
}
