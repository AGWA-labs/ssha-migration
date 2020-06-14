package sshaMigration

type User struct {
	ScryptSalt        []byte
	SSHASalt          []byte
	EncryptedPassword []byte
}
