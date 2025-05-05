package util_Command

import (
	"fmt"
	"math/rand"
	"strconv"
	"strings"
	"time"
	"triton-cnc/core/models/json/build"
	database "triton-cnc/core/mysql"
	"triton-cnc/core/sessions/sessions"

	"net"

	"github.com/alexeyco/simpletable"
)

// 全局变量，记录上次生成伪造信息的时间和数量
var (
	lastFakeAttackTime time.Time
	fakeAttacks        []*FakeAttack
)

type FakeAttack struct {
	ID       int
	Target   string
	Method   string
	Port     int
	Duration int
	End      int64
}

func init() {

	Register(&Command{
		Name: "ongoing",

		Description: "clear your complete terminal screen",

		Admin:    false,
		Reseller: false,
		Vip:      false,

		Execute: func(Session *sessions.Session_Store, cmd []string) error {

			table := simpletable.New()

			table.Header = &simpletable.Header{
				Cells: []*simpletable.Cell{
					{Align: simpletable.AlignCenter, Text: "\x1b[38;5;11m#\x1b[38;5;15m"},
					{Align: simpletable.AlignCenter, Text: "\x1b[38;5;15mTarget\x1b[38;5;15m"},
					{Align: simpletable.AlignCenter, Text: "\x1b[38;5;15mMethod\x1b[38;5;15m"},
					{Align: simpletable.AlignCenter, Text: "\x1b[38;5;15mPort\x1b[38;5;15m"},
					{Align: simpletable.AlignCenter, Text: "\x1b[38;5;15mLength\x1b[38;5;15m"},
					{Align: simpletable.AlignCenter, Text: "\x1b[38;5;15mTime\x1b" + build.Config.AppConfig.AppColour + "-\x1b[38;5;15mLeft\x1b[38;5;15m"},
					{Align: simpletable.AlignCenter, Text: "\x1b[38;5;15mUser\x1b[38;5;15m"},
				},
			}

			Running, error := database.Ongoing()
			if error != nil {
				return error
			}

			// 检查是否需要生成伪造信息
			if time.Since(lastFakeAttackTime) >= 60*time.Second {
				// 获取随机伪造的攻击信息数量
				fakeAttackCount := rand.Intn(7) + 1
				// 生成伪造的攻击信息
				fakeAttacks = generateFakeAttacks(fakeAttackCount) // 将生成的伪造信息保存到全局变量中
				// 更新 lastFakeAttackTime
				lastFakeAttackTime = time.Now()
			}

			displayedIndex := 1 // 用于记录已显示的信息条数

			// 循环输出所有攻击信息，包含真实信息和伪造信息
			for _, I := range Running {
				// 判断是否为管理员，以及是否为当前用户发起的攻击
				if Session.User.Administrator || I.Username == Session.User.Username {
					r := []*simpletable.Cell{
						{Align: simpletable.AlignCenter, Text: "\x1b[38;5;11m" + strconv.Itoa(displayedIndex) + "\x1b[38;5;15m"},
						{Align: simpletable.AlignCenter, Text: "\x1b[38;5;15m" + I.Target + "\x1b[38;5;15m"},
						{Align: simpletable.AlignCenter, Text: "\x1b[38;5;15m" + SortMethodSpace(I.Method) + "\x1b[38;5;15m"},
						{Align: simpletable.AlignCenter, Text: "\x1b[38;5;15m" + strconv.Itoa(I.Port) + "\x1b[38;5;15m"},
						{Align: simpletable.AlignCenter, Text: "\x1b[38;5;15m" + strconv.Itoa(I.Duration) + "\x1b[38;5;15m"},
						{Align: simpletable.AlignCenter, Text: "\x1b[38;5;15m" + fmt.Sprintf("%.0f secs", time.Until(time.Unix(I.End, 0)).Seconds()) + "\x1b[38;5;15m"},
						{Align: simpletable.AlignCenter, Text: "\x1b[38;5;15m" + I.Username + "\x1b[38;5;15m"}, // 添加用户名列标题
					}
					table.Body.Cells = append(table.Body.Cells, r)
					displayedIndex++
				} else { // 非管理员，且不是当前用户的攻击，则隐藏信息
					r := []*simpletable.Cell{
						{Align: simpletable.AlignCenter, Text: "\x1b[38;5;11m" + strconv.Itoa(displayedIndex) + "\x1b[38;5;15m"},
						{Align: simpletable.AlignCenter, Text: "\x1b[38;5;15m???\x1b[38;5;15m"},
						{Align: simpletable.AlignCenter, Text: "\x1b[38;5;15m" + SortMethodSpace(I.Method) + "\x1b[38;5;15m"},
						{Align: simpletable.AlignCenter, Text: "\x1b[38;5;15m???\x1b[38;5;15m"},
						{Align: simpletable.AlignCenter, Text: "\x1b[38;5;15m" + strconv.Itoa(I.Duration) + "\x1b[38;5;15m"},
						{Align: simpletable.AlignCenter, Text: "\x1b[38;5;15m???\x1b[38;5;15m"},
						{Align: simpletable.AlignCenter, Text: "\x1b[38;5;15m" + "???" + "\x1b[38;5;15m"}, // 添加用户名列标题
					}
					table.Body.Cells = append(table.Body.Cells, r)
					displayedIndex++
				}
			}

			// 循环输出伪造信息
			for _, I := range fakeAttacks {
				if Session.User.Administrator {
					r := []*simpletable.Cell{
						{Align: simpletable.AlignCenter, Text: "\x1b[38;5;11m" + strconv.Itoa(displayedIndex) + "\x1b[38;5;15m"}, // 调整 ID 号码
						{Align: simpletable.AlignCenter, Text: "\x1b[38;5;15m" + I.Target + "\x1b[38;5;15m"},
						{Align: simpletable.AlignCenter, Text: "\x1b[38;5;15m" + SortMethodSpace(I.Method) + "\x1b[38;5;15m"},
						{Align: simpletable.AlignCenter, Text: "\x1b[38;5;15m" + strconv.Itoa(I.Port) + "\x1b[38;5;15m"},
						{Align: simpletable.AlignCenter, Text: "\x1b[38;5;15m" + strconv.Itoa(I.Duration) + "\x1b[38;5;15m"},
						{Align: simpletable.AlignCenter, Text: "\x1b[38;5;15m" + fmt.Sprintf("%.0f secs", time.Until(time.Unix(I.End, 0)).Seconds()) + "\x1b[38;5;15m"},
						{Align: simpletable.AlignCenter, Text: "\x1b[38;5;15m" + "askk110" + "\x1b[38;5;15m"}, // 添加用户名列标题
					}
					table.Body.Cells = append(table.Body.Cells, r)
					displayedIndex++
				} else {
					r := []*simpletable.Cell{
						{Align: simpletable.AlignCenter, Text: "\x1b[38;5;11m" + strconv.Itoa(displayedIndex) + "\x1b[38;5;15m"},
						{Align: simpletable.AlignCenter, Text: "\x1b[38;5;15m???\x1b[38;5;15m"},
						{Align: simpletable.AlignCenter, Text: "\x1b[38;5;15m" + SortMethodSpace(I.Method) + "\x1b[38;5;15m"},
						{Align: simpletable.AlignCenter, Text: "\x1b[38;5;15m???\x1b[38;5;15m"},
						{Align: simpletable.AlignCenter, Text: "\x1b[38;5;15m" + strconv.Itoa(I.Duration) + "\x1b[38;5;15m"},
						{Align: simpletable.AlignCenter, Text: "\x1b[38;5;15m???\x1b[38;5;15m"},
						{Align: simpletable.AlignCenter, Text: "\x1b[38;5;15m" + "???" + "\x1b[38;5;15m"}, // 添加用户名列标题
					}
					table.Body.Cells = append(table.Body.Cells, r)
					displayedIndex++
				}
			}

			if build.Config.Extra.TableType == "unicode" {
				table.SetStyle(simpletable.StyleUnicode)
			} else if build.Config.Extra.TableType == "lite" {
				table.SetStyle(simpletable.StyleCompactLite)
			} else {
				table.SetStyle(simpletable.StyleCompactClassic)
			}

			fmt.Fprint(Session.Channel, "")
			fmt.Fprintln(Session.Channel, strings.ReplaceAll(table.String(), "\n", "\r\n"))
			fmt.Fprint(Session.Channel, "\r")
			return nil
		},
	})
}

// 生成随机的伪造攻击信息
func generateFakeAttacks(count int) []*FakeAttack {
	rand.Seed(time.Now().UnixNano())
	var fakeAttacks []*FakeAttack
	for i := 0; i < count; i++ {
		fakeAttack := &FakeAttack{
			ID:       rand.Intn(9000) + 1000,                     // 随机生成四位数整数
			Target:   generateRandomIP(),                         // 随机生成 IP 地址
			Method:   generateRandomMethod(),                     // 随机选择攻击方法
			Port:     generateRandomPort(),                       // 随机选择端口
			Duration: (rand.Intn(1) + 1) * 100,                   // 随机生成整百的整数
			End:      time.Now().Unix() + int64(rand.Intn(60)+1), // 随机生成剩余时间（秒）
		}
		fakeAttacks = append(fakeAttacks, fakeAttack)
	}
	return fakeAttacks
}

// 生成随机 IP 地址
func generateRandomIP() string {
	ip := make(net.IP, 4)
	rand.Read(ip)
	ip[0] = byte(rand.Intn(254) + 1) // 第一个字节不能为 0 或 255
	return ip.String()
}

// 随机选择攻击方法
func generateRandomMethod() string {
	methods := []string{"tcpdd", "windows", "syn", "ack", "cloud", "mdtcp", "dnsx", "https", "god", "ja3"}
	return methods[rand.Intn(len(methods))]
}

// 随机选择端口
func generateRandomPort() int {
	ports := []int{80, 40101, 1433, 443, 3389, 3306, 22}
	return ports[rand.Intn(len(ports))]
}

func SortMethodSpace(name string) string {
	name = strings.ReplaceAll(name, " ", "\x1b"+build.Config.AppConfig.AppColour+"-\x1b[38;5;15m")
	name = strings.ReplaceAll(name, "-", "\x1b"+build.Config.AppConfig.AppColour+"-\x1b[38;5;15m")
	name = strings.ReplaceAll(name, "=", "\x1b"+build.Config.AppConfig.AppColour+"-\x1b[38;5;15m")
	return name
}

/////////////////////////////////////////

// package util_Command

// import (
// 	"fmt"
// 	"strconv"
// 	"strings"
// 	"time"
// 	"triton-cnc/core/mysql"
// 	"triton-cnc/core/sessions/sessions"
// 	"triton-cnc/core/models/json/build"

// 	"github.com/alexeyco/simpletable"
// )

// func init() {

// 	Register(&Command{
// 		Name: "ongoing",

// 		Description: "clear your complete terminal screen",

// 		Admin: false,
// 		Reseller: false,
// 		Vip: false,

// 		Execute: func(Session *sessions.Session_Store, cmd []string) error {

// 			table := simpletable.New()

// 			table.Header = &simpletable.Header{
// 				Cells: []*simpletable.Cell{
// 					{Align: simpletable.AlignCenter, Text: "\x1b[38;5;11m#\x1b[38;5;15m"},
// 					{Align: simpletable.AlignCenter, Text: "\x1b[38;5;15mTarget\x1b[38;5;15m"},
// 					{Align: simpletable.AlignCenter, Text: "\x1b[38;5;15mMethod\x1b[38;5;15m"},
// 					{Align: simpletable.AlignCenter, Text: "\x1b[38;5;15mPort\x1b[38;5;15m"},
// 					{Align: simpletable.AlignCenter, Text: "\x1b[38;5;15mLength\x1b[38;5;15m"},
// 					{Align: simpletable.AlignCenter, Text: "\x1b[38;5;15mTime\x1b"+build.Config.AppConfig.AppColour+"-\x1b[38;5;15mLeft\x1b[38;5;15m"},
// 				},
// 			}

// 			Running, error := database.Ongoing()
// 			if error != nil {
// 				return error
// 			}
// 			//
// 			if Running == nil {
// 				Session.Channel.Write([]byte("\x1b[38;5;15mCurrently there is \x1b"+build.Config.AppConfig.AppColour+"0\x1b[38;5;15m Attacks running\x1b[38;5;15m\r\n"))
// 				return nil
// 			}

// 			for _, I := range Running {
// 				r := []*simpletable.Cell{
// 					{Align: simpletable.AlignCenter, Text: "\x1b[38;5;11m"+strconv.Itoa(I.ID)+"\x1b[38;5;15m"},
// 					{Align: simpletable.AlignCenter, Text: "\x1b[38;5;15m"+I.Target+"\x1b[38;5;15m"},
// 					{Align: simpletable.AlignCenter, Text: "\x1b[38;5;15m"+SortMethodSpace(I.Method)+"\x1b[38;5;15m"},
// 					{Align: simpletable.AlignCenter, Text: "\x1b[38;5;15m"+strconv.Itoa(I.Port)+"\x1b[38;5;15m"},
// 					{Align: simpletable.AlignCenter, Text: "\x1b[38;5;15m"+strconv.Itoa(I.Duration)+"\x1b[38;5;15m"},
// 					{Align: simpletable.AlignCenter, Text: "\x1b[38;5;15m"+fmt.Sprintf("%.0f secs", time.Until(time.Unix(I.End, 0)).Seconds())+"\x1b[38;5;15m"},
// 				}

// 				table.Body.Cells = append(table.Body.Cells, r)
// 			}

// 			if build.Config.Extra.TableType == "unicode" {
// 				table.SetStyle(simpletable.StyleUnicode)
// 			} else if build.Config.Extra.TableType == "lite" {
// 				table.SetStyle(simpletable.StyleCompactLite)
// 			} else {
// 				table.SetStyle(simpletable.StyleCompactClassic)
// 			}

// 			fmt.Fprint(Session.Channel, "")
// 			fmt.Fprintln(Session.Channel, strings.ReplaceAll(table.String(), "\n", "\r\n"))
// 			fmt.Fprint(Session.Channel, "\r")
// 			return nil
// 		},
// 	})
// }

// func SortMethodSpace(name string) string {
// 	name = strings.ReplaceAll(name, " ", "\x1b"+build.Config.AppConfig.AppColour+"-\x1b[38;5;15m")
// 	name = strings.ReplaceAll(name, "-", "\x1b"+build.Config.AppConfig.AppColour+"-\x1b[38;5;15m")
// 	name = strings.ReplaceAll(name, "=", "\x1b"+build.Config.AppConfig.AppColour+"-\x1b[38;5;15m")
// 	return name
// }
