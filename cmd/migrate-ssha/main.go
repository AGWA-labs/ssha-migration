package main

import (
	"bufio"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/AGWA-labs/ssha-migration"
	"github.com/sethvargo/go-password/password"
	"golang.org/x/crypto/nacl/secretbox"
	"golang.org/x/crypto/scrypt"
)

func migrate(sshaPasswordBase64 string) (string, *sshaMigration.User, error) {
	sshaPassword, err := base64.StdEncoding.DecodeString(sshaPasswordBase64)
	if err != nil {
		return "", nil, err
	}
	sshaHash, sshaSalt := sshaPassword[:20], sshaPassword[20:]

	var scryptSalt [32]byte
	if _, err := rand.Read(scryptSalt[:]); err != nil {
		return "", nil, err
	}

	var encryptionKey [32]byte
	if p, err := scrypt.Key(sshaHash, scryptSalt[:], 32768, 8, 1, 32); err == nil {
		copy(encryptionKey[:], p)
	} else {
		return "", nil, err
	}

	newPassword, err := password.Generate(16, 4, 0, false, false)
	if err != nil {
		return "", nil, err
	}

	var nonce [24]byte // all-zero nonce OK because key is single-use and derived using random salt
	encryptedPassword := secretbox.Seal(nil, []byte(newPassword), &nonce, &encryptionKey)

	return newPassword, &sshaMigration.User{
		ScryptSalt:        scryptSalt[:],
		SSHASalt:          sshaSalt,
		EncryptedPassword: encryptedPassword,
	}, nil
}

func main() {
	chpasswdFile, err := os.OpenFile("chpasswd.input", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		log.Fatal(err)
	}
	defer chpasswdFile.Close()

	usersFile, err := os.OpenFile("ssha-users.json", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		log.Fatal(err)
	}
	defer usersFile.Close()

	users := make(map[string]*sshaMigration.User)

	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Split(line, ":")

		username := fields[0]
		password := fields[1]

		if !strings.HasPrefix(password, "{SSHA}") {
			continue
		}
		newPassword, user, err := migrate(strings.TrimPrefix(password, "{SSHA}"))
		if err != nil {
			log.Fatal("Error migrating ", username, ": ", err)
		}

		if _, err := fmt.Fprintf(chpasswdFile, "%s:%s\n", username, newPassword); err != nil {
			log.Fatal(err)
		}
		users[username] = user
	}
	if err := scanner.Err(); err != nil {
		log.Fatal(err)
	}

	usersEncoder := json.NewEncoder(usersFile)
	usersEncoder.SetIndent("", "\t")
	if err := usersEncoder.Encode(users); err != nil {
		log.Fatal(err)
	}
}
