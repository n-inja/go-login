package db

import (
	"golang.org/x/crypto/bcrypt"
	_ "github.com/go-sql-driver/mysql"
	"database/sql"
	"os"
)

type User struct {
	ID string
	Name string
	Hash string
}

var db *sql.DB

func Open (userName, password, address, databaseName string) (error) {
	var err error
	db, err = sql.Open("mysql", userName + ":" + password + "@" + address + "/" + databaseName)
	if err != nil {
		return err
	}
	return initDB()
}

func Close () {
	db.Close()
}

func initDB () (error) {
	rows, err := db.Query("show tables like 'users'")
	if err != nil {
		return err
	}
	if !rows.Next() {
		_, err := db.Exec("create table users (id varchar(32) NOT NULL PRIMARY KEY, name varchar(32), hash varchar(256))")
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
		Register("root", "root", os.Getenv("DATABASE_ROOT_PASSWORD"))
	}
	return nil
}

func (user *User) insert() (error) {
	_, err := db.Exec("insert into users values (?, ?, ?)", user.ID, user.Name, user.Hash)
	return err
}

func Register (ID, Name, Password string) (error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(Password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	user := User{ID, Name, string(hash)}

	err = user.insert()
	if err != nil {
		return err
	}
	return nil
}

func Comfirm (ID, password string) (bool) {
	rows, err := db.Query("select hash from users where id = ?", ID)
	if err != nil || !rows.Next() {
		return false
	}
	var hash string
	rows.Scan(&hash)
	ret := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return ret == nil
}

func ChangePassword (ID, oldPass, newPass string) (bool) {
	if !Comfirm(ID, oldPass) {
		return false
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(newPass), bcrypt.DefaultCost)
	if err != nil {
		return false
	}
	_, err = db.Exec("update users set hash = ? where id = ?", hash, ID)
	return err == nil
}

func ChangeName (ID, password, name string) (bool) {
	if !Comfirm(ID, password) {
		return false
	}
	_, err := db.Exec("update users set name = ? where id = ?", name, ID)
	return err == nil
}

func Delete (ID string) (bool) {
	if ID == "root" {
		return false
	}
	_, err := db.Exec("delete from users where id = ?", ID)
	return err == nil
}