package views

import (
	"log"
	"time"
	"triton-cnc/core/models/client/terminal"
	"triton-cnc/core/models/util"
	database "triton-cnc/core/mysql"

	"golang.org/x/crypto/ssh"
	"golang.org/x/term"
)

func Login_NewUser(channel ssh.Channel, conn *ssh.ServerConn, User *database.User) error {
	error, _ := terminal.Banner("login-newuser", User, channel, true, false, nil)
	if error != nil {
		log.Println(error)
		return error
	}

	NewTerm := term.NewTerminal(channel, "\x1b[0m新密码>\x1b[38;5;16m")
	NewPassword, error := NewTerm.ReadLine()
	if error != nil {
		time.Sleep(5 * time.Second)
		channel.Close()
		return error
	}

	NewTermconfirm := term.NewTerminal(channel, "\x1b[0m确认您的新密码>\x1b[38;5;16m")
	NewConfirmPassword, error := NewTermconfirm.ReadLine()
	if error != nil {
		time.Sleep(5 * time.Second)
		channel.Close()
		return error
	}

	if NewPassword != NewConfirmPassword {
		channel.Write([]byte("\x1b[0m两次输入的密码不相同！\r\n"))
		time.Sleep(5 * time.Second)
		channel.Close()
		return error
	}

	if len(NewPassword) <= 5 {
		channel.Write([]byte("\x1b[0m密码需要超过5位数\r\n"))
		time.Sleep(5 * time.Second)
		channel.Close()
		return error
	}

	errors := database.EditFeild(User.Username, "password", util.HashPassword(NewPassword))
	if !errors {
		channel.Write([]byte("\x1b[0m更新密码失败！\r\n"))
		time.Sleep(5 * time.Second)
		channel.Close()
		return error
	}

	errors = database.EditFeild(User.Username, "NewUser", "0")
	if !errors {
		channel.Write([]byte("\x1b[0m更新密码失败！\r\n"))
		time.Sleep(5 * time.Second)
		channel.Close()
		return error
	}

	channel.Write([]byte("\x1b[0m更新密码成功！5秒后进入系统！\r\n"))

	time.Sleep(5 * time.Second)

	return nil

}
