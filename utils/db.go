package utils

import (
	"regexp"

	_ "github.com/go-sql-driver/mysql"
	"github.com/rs/xid"
	"golang.org/x/crypto/bcrypt"

	"database/sql"
	"errors"
	"os"
	"time"
)

type User struct {
	ID   string
	Name string
	Hash string
	Auth string
}

var db *sql.DB

var regexID *regexp.Regexp

func Open(userName, password, address, databaseName string) error {
	var err error
	db, err = sql.Open("mysql", userName+":"+password+"@"+address+"/"+databaseName)
	if err != nil {
		return err
	}

	regexID = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)

	return initDB()
}

func Close() {
	db.Close()
}

func initDB() error {
	rows, err := db.Query("show tables like 'users'")
	if err != nil {
		return err
	}
	if !rows.Next() {
		_, err := db.Exec("create table users (id varchar(32) NOT NULL PRIMARY KEY, name varchar(32) NOT NULL, hash varchar(256) NOT NULL, auth varchar(20) NOT NULL)")
		if err != nil {
			rows.Close()
			return err
		}
	}
	rows.Close()

	rows, err = db.Query("show tables like 'sessions'")
	if err != nil {
		return err
	}
	if !rows.Next() {
		_, err := db.Exec("create table sessions (id varchar(32) NOT NULL, session varchar(20) NOT NULL PRIMARY KEY, expiration_date timestamp NOT NULL, index(expiration_date))")
		if err != nil {
			rows.Close()
			return err
		}
	}
	rows.Close()

	rows, err = db.Query("select id from users where id = 'root'")
	if err != nil {
		return err
	}
	defer rows.Close()
	if !rows.Next() {
		Register("root", "root", os.Getenv("DATABASE_ROOT_PASSWORD"), "admin")
	}
	return nil
}

func (user *User) insert() error {
	_, err := db.Exec("insert into users values (?, ?, ?, ?)", user.ID, user.Name, user.Hash, user.Auth)
	return err
}

func Register(ID, Name, Password, auth string) error {
	hash, err := bcrypt.GenerateFromPassword([]byte(Password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	if auth != "admin" && auth != "default" && auth != "guest" {
		return errors.New("auth = {admin, default, guest}")
	}

	if !regexID.MatchString(ID) {
		return errors.New("ID := ^[a-zA-Z0-9-_]+$")
	}

	user := User{ID, Name, string(hash), auth}

	err = user.insert()
	if err != nil {
		return err
	}
	return nil
}

func Confirm(ID, password string) bool {
	rows, err := db.Query("select hash from users where id = ?", ID)
	if err != nil || !rows.Next() {
		return false
	}
	var hash string
	rows.Scan(&hash)
	ret := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return ret == nil
}

func ChangePassword(ID, oldPass, newPass string) error {
	if !Confirm(ID, oldPass) {
		return errors.New("incorrect id or password")
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(newPass), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	_, err = db.Exec("update users set hash = ? where id = ?", hash, ID)
	return err
}

func ChangeName(ID, password, name string) error {
	if !Confirm(ID, password) {
		return errors.New("incorrect id or password")
	}
	_, err := db.Exec("update users set name = ? where id = ?", name, ID)
	return err
}

func Delete(ID string) error {
	if ID == "root" {
		return errors.New("permission denied")
	}
	_, err := db.Exec("delete from users where id = ?", ID)
	return err
}

func StartSession(ID, password string) (string, error) {
	if !Confirm(ID, password) {
		return "", errors.New("incorrect id or password")
	}
	expiration := time.Now().AddDate(0, 0, 30)
	session := xid.New()
	_, err := db.Exec("insert into sessions values(?, ?, ?)", ID, session.String(), expiration.Format("2006-01-02 15:04:05"))
	if err != nil {
		return "", err
	}
	return session.String(), nil
}

func CheckSession(session string) (string, error) {
	now := time.Now()
	rows, err := db.Query("select id from sessions where session = ? and expiration_date > ?", session, now.Format("2016-01-02 15:04:05"))
	if err != nil {
		return "", err
	}
	defer rows.Close()
	if !rows.Next() {
		return "", nil
	}
	var ID string
	rows.Scan(&ID)
	return ID, nil
}

func DiscardSession(session string) error {
	now := time.Now()
	_, err := db.Exec("delete from sessions where session = ? and expiration_date > ?", session, now.Format("2016-01-02 15:04:05"))
	return err
}

func GetNameByID(ID string) (string, error) {
	rows, err := db.Query("select name from users where id = ?", ID)
	if err != nil {
		return "", err
	}
	defer rows.Close()
	var name string
	if !rows.Next() {
		return "", errors.New("user not found")
	}
	rows.Scan(&name)
	return name, nil
}

func CheckAuth(ID string) (bool, error) {
	rows, err := db.Query("select auth from users where id = ?", ID)
	if err != nil {
		return false, err
	}
	defer rows.Close()
	var auth string
	if !rows.Next() {
		return false, errors.New("user not found")
	}
	rows.Scan(&auth)
	return auth == "admin", nil
}
