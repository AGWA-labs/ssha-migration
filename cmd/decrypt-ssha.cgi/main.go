package main

import (
	"crypto/sha1"
	"encoding/json"
	"errors"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/cgi"
	"os"

	"github.com/AGWA-labs/ssha-migration"
	"golang.org/x/crypto/nacl/secretbox"
	"golang.org/x/crypto/scrypt"
)

func loadUsers() (map[string]*sshaMigration.User, error) {
	usersFile := os.Getenv("SSHA_USERS_FILE")
	if usersFile == "" {
		return nil, errors.New("$SSHA_USERS_FILE not set")
	}

	usersJSON, err := ioutil.ReadFile(usersFile)
	if err != nil {
		return nil, err
	}

	users := make(map[string]*sshaMigration.User)
	if err := json.Unmarshal(usersJSON, &users); err != nil {
		return nil, err
	}

	return users, err
}

func decrypt(user *sshaMigration.User, oldPassword string) (string, error) {
	sshaHash := sha1.Sum(append([]byte(oldPassword), user.SSHASalt...))

	var decryptionKey [32]byte
	if p, err := scrypt.Key(sshaHash[:], user.ScryptSalt, 32768, 8, 1, 32); err == nil {
		copy(decryptionKey[:], p)
	} else {
		return "", err
	}

	var nonce [24]byte
	newPassword, ok := secretbox.Open(nil, user.EncryptedPassword, &nonce, &decryptionKey)
	if !ok {
		return "", nil
	}
	return string(newPassword), nil
}

func handle(w http.ResponseWriter, req *http.Request) {
	username := req.FormValue("username")
	password := req.FormValue("password")

	users, err := loadUsers()
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	user := users[username]
	if user == nil {
		http.Error(w, "No such user", 404)
		return
	}
	newPassword, err := decrypt(user, password)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	if newPassword == "" {
		http.Error(w, "Password incorrect", 403)
		return
	}
	http.Error(w, newPassword, 200)
}

func main() {
	if err := cgi.Serve(http.HandlerFunc(handle)); err != nil {
		log.Fatal(err)
	}
}
