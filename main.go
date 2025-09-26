package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/PuerkitoBio/goquery"
	"github.com/spf13/viper"
	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common"
	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common/errors"
	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common/profile"
	lighthouse "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/lighthouse/v20200324"
)

type Creds struct {
	SecretID    string
	SecretKey   string
	InstanceIds []string
}

type FirewallRule struct {
	Protocol                string
	Port                    string
	CidrBlock               string
	Ipv6CidrBlock           string
	Action                  string
	FirewallRuleDescription string
}

type Instance struct {
	InstanceId    string `mapstructure:"InstanceId"`
	Region        string
	FirewallRules []FirewallRule `mapstructure:"firewallRules"`
}

type DingTalkMessage struct {
	Msgtype string `json:"msgtype"`
	Text    struct {
		Content string `json:"content"`
	} `json:"text"`
}

type updateInfo struct {
	SG  string
	IPs []string
}

func currentDateTime() string {
	return time.Now().Format("2006-01-02 15:04:05")
}

func initConfig() {
	viper.SetConfigName("config")
	viper.SetConfigType("toml")
	viper.AddConfigPath(".")
	err := viper.ReadInConfig()
	if err != nil {
		panic(fmt.Errorf("fatal error config file: %w ", err))
	}
}

func sendDingTalkMessage(updates []updateInfo) {
	webhook := viper.GetString("dingtalk.webhook")
	if webhook == "" {
		fmt.Printf("%s 钉钉webhook未配置，跳过消息发送\n", currentDateTime())
		return
	}

	var content strings.Builder
	content.WriteString("IP变化汇总:\n")
	for _, u := range updates {
		content.WriteString(fmt.Sprintf("- 实例%s更新了IP: %s\n", u.SG, strings.Join(u.IPs, ", ")))
	}

	// 打印要发送的消息内容
	messageContent := content.String()
	fmt.Printf("%s 准备发送的钉钉消息内容:\n%s\n", currentDateTime(), messageContent)

	message := DingTalkMessage{
		Msgtype: "text",
		Text: struct {
			Content string `json:"content"`
		}{
			Content: messageContent,
		},
	}

	messageBytes, _ := json.Marshal(message)
	_, err := http.Post(webhook, "application/json", bytes.NewBuffer(messageBytes))
	if err != nil {
		fmt.Printf("%s 发送钉钉消息失败: %v\n", currentDateTime(), err)
	} else {
		fmt.Printf("%s 发送钉钉消息成功\n", currentDateTime())
	}
}
func getIframeURL(client *http.Client) (string, error) {
	resp, err := client.Get("http://nstool.netease.com")
	if err != nil {
		return "", fmt.Errorf("无法连接到 http://nstool.netease.com: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return "", fmt.Errorf("无法连接到 http://nstool.netease.com: %v", resp.Status)
	}

	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		return "", fmt.Errorf("读取响应失败: %v", err)
	}

	iframe := doc.Find("iframe").First()
	if iframe.Length() > 0 {
		iframeURL, exists := iframe.Attr("src")
		if exists {
			return iframeURL, nil
		}
	}

	return "", fmt.Errorf("未找到 iframe 标签")
}

func getIPFromURL(client *http.Client, url string) ([]string, error) {
	resp, err := client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("无法连接到 %s: %v", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("无法连接到 %s: %v", url, resp.Status)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("读取响应失败: %v", err)
	}

	re := regexp.MustCompile(`\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b`)
	content := string(body)
	ipAddresses := re.FindAllString(content, -1)

	dnsIndex := len(content)
	if dnsPos := regexp.MustCompile(`DNS`).FindStringIndex(content); dnsPos != nil {
		dnsIndex = dnsPos[0]
	}
	ipAddresses = re.FindAllString(content[:dnsIndex], -1)

	return ipAddresses, nil
}

func getIPFromInip(client *http.Client) (string, error) {
	resp, err := client.Get("http://inip.in/ipinfo.html")
	if err != nil {
		return "", fmt.Errorf("无法连接到 http://inip.in/ipinfo.html: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return "", fmt.Errorf("无法连接到 http://inip.in/ipinfo.html: %v", resp.Status)
	}

	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		return "", fmt.Errorf("解析HTML失败: %v", err)
	}

	ip := doc.Find("strong.your-ip").Text()
	if ip == "" {
		return "", fmt.Errorf("未找到IP地址")
	}

	ip = strings.TrimSpace(ip)
	return ip, nil
}

func getUniqueIPs(maxAttempts int, minRequiredIPs int, maxRequiredIPs int) ([]string, error) {
	var mu sync.Mutex
	var wg sync.WaitGroup

	client := &http.Client{
		Timeout: 10 * time.Second,
	}
	rnd := rand.New(rand.NewSource(time.Now().UnixNano()))
	uniqueIPs := make(map[string]bool)
	ch := make(chan struct{}, maxAttempts)

	for i := 0; i < maxAttempts; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ch <- struct{}{}
			defer func() { <-ch }()

			pause := time.Duration(rnd.Intn(11)+5) * time.Second
			time.Sleep(pause)

			iframeURL, err := getIframeURL(client)
			if err != nil {
				fmt.Println(err)
				return
			}

			ipAddresses, err := getIPFromURL(client, iframeURL)
			if err != nil {
				fmt.Println(err)
				return
			}

			mu.Lock()
			for _, ip := range ipAddresses {
				if len(uniqueIPs) >= maxRequiredIPs {
					mu.Unlock()
					return
				}
				if _, exists := uniqueIPs[ip]; !exists {
					uniqueIPs[ip] = true
					fmt.Printf("找到IP: %s\n", ip)
				}
			}
			mu.Unlock()
		}()
	}
	wg.Wait()

	var result []string
	for ip := range uniqueIPs {
		result = append(result, ip)
	}

	if len(result) < minRequiredIPs {
		return nil, fmt.Errorf("未能收集到最少的 %d 个IP地址，仅收集到 %d 个", minRequiredIPs, len(result))
	}

	if len(result) > maxRequiredIPs {
		result = result[:maxRequiredIPs]
	}

	fmt.Printf("最终找到的Unique IPs: %v\n", result)
	return result, nil
}

func readWriteIPs(filePath string, ips []string, mode string) []string {
	if mode == "r" {
		file, err := os.Open(filePath)
		if err != nil {
			fmt.Println(currentDateTime(), " Error opening file:", err)
			return []string{}
		}
		defer file.Close()

		var result []string
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			ip := strings.TrimSpace(scanner.Text())
			if ip != "" {
				result = append(result, ip)
				fmt.Printf("读取到IP: '%s'\n", ip)
			}
		}
		if err := scanner.Err(); err != nil {
			fmt.Println(currentDateTime(), " Error reading file:", err)
		}
		fmt.Printf("最终读取到的Existing IPs: %v\n", result)
		return result
	} else if mode == "w" {
		file, err := os.Create(filePath)
		if err != nil {
			fmt.Println(currentDateTime(), " Error creating file:", err)
			return nil
		}
		defer file.Close()

		for _, ip := range ips {
			_, err := file.WriteString(ip + "\n")
			if err != nil {
				fmt.Println(currentDateTime(), " Error writing to file:", err)
			}
			fmt.Printf("写入IP: '%s'\n", ip)
		}
	}
	return nil
}

// modifyFirewallRules 替换防火墙规则
func modifyFirewallRules(creds Creds, instance Instance, newIPs []string) error {
	credential := common.NewCredential(
		creds.SecretID,
		creds.SecretKey,
	)
	cpf := profile.NewClientProfile()
	cpf.HttpProfile.Endpoint = "lighthouse.tencentcloudapi.com"
	client, _ := lighthouse.NewClient(credential, instance.Region, cpf)

	var rules []*lighthouse.FirewallRule
	for _, rule := range instance.FirewallRules {
		for _, ip := range newIPs {
			newRule := &lighthouse.FirewallRule{
				Protocol:                common.StringPtr(rule.Protocol),
				Port:                    common.StringPtr(rule.Port),
				Action:                  common.StringPtr(rule.Action),
				FirewallRuleDescription: common.StringPtr(fmt.Sprintf("%s", rule.FirewallRuleDescription)),
			}
			// 判断IP地址是IPv4还是IPv6，并设置相应的CidrBlock
			if strings.Contains(ip, ".") {
				newRule.CidrBlock = common.StringPtr(ip)
			} else if strings.Contains(ip, ":") {
				newRule.Ipv6CidrBlock = common.StringPtr(ip)
			}
			rules = append(rules, newRule)
		}
	}

	request := lighthouse.NewModifyFirewallRulesRequest()
	request.InstanceId = common.StringPtr(instance.InstanceId)
	request.FirewallRules = rules

	_, err := client.ModifyFirewallRules(request)
	if err != nil {
		if _, ok := err.(*errors.TencentCloudSDKError); ok {
			return fmt.Errorf("API error: %s", err)
		}
		return err
	}

	fmt.Printf("%s Instance %s firewall rules updated successfully.\n", currentDateTime(), instance.InstanceId)
	return nil
}

func compareIPLists(list1, list2 []string) bool {
	if len(list1) != len(list2) {
		return false
	}

	// 将两个列表转换为map进行比较
	map1 := make(map[string]bool)
	map2 := make(map[string]bool)

	for _, ip := range list1 {
		map1[ip] = true
	}

	for _, ip := range list2 {
		map2[ip] = true
	}

	// 比较两个map是否相同
	for ip := range map1 {
		if !map2[ip] {
			return false
		}
	}

	for ip := range map2 {
		if !map1[ip] {
			return false
		}
	}

	return true
}

var (
	ipFilePath     string
	maxAttempts    int
	minRequiredIPs int
	maxRequiredIPs int
)

func init() {
	flag.StringVar(&ipFilePath, "ip", "", "Path to the file containing IP addresses")
	flag.IntVar(&maxAttempts, "maxAttempts", 30, "Maximum number of attempts")
	flag.IntVar(&minRequiredIPs, "minRequiredIPs", 1, "Number of min required unique IPs")
	flag.IntVar(&maxRequiredIPs, "maxRequiredIPs", 5, "Number of max required unique IPs")
	initConfig()
}

func main() {
	flag.Parse()

	var updates []updateInfo
	var creds []Creds
	err := viper.UnmarshalKey("creds", &creds)
	if err != nil {
		fmt.Println(currentDateTime(), " Unable to decode into struct", err)
		return
	}

	if len(creds) == 0 {
		fmt.Println(currentDateTime(), " No credentials found in config.toml")
		return
	}

	var instances []Instance
	err = viper.UnmarshalKey("instances", &instances)
	if err != nil {
		fmt.Println(currentDateTime(), " Unable to decode into struct", err)
		return
	}

	var uniqueIPs []string
	if ipFilePath != "" {
		uniqueIPs = readWriteIPs(ipFilePath, nil, "r")
	} else {
		uniqueIPs, err = getUniqueIPs(maxAttempts, minRequiredIPs, maxRequiredIPs)
		if err != nil {
			// 处理错误，例如打印日志或退出程序
			log.Fatal(err)
		}
	}

	// 确保IP数量符合要求
	if len(uniqueIPs) > maxRequiredIPs {
		uniqueIPs = uniqueIPs[:maxRequiredIPs]
	}

	fmt.Printf("当前获取到的IPs: %v\n", uniqueIPs)

	existingIPs := readWriteIPs("./ips.txt", nil, "r")
	fmt.Printf("从ips.txt读取的历史IPs: %v\n", existingIPs)

	// 比较IP列表是否有变化
	hasChanges := !compareIPLists(uniqueIPs, existingIPs)

	if !hasChanges {
		fmt.Printf("%s IP列表无变化，跳过更新\n", currentDateTime())
		return
	}

	fmt.Printf("%s IP列表有变化，开始更新防火墙\n", currentDateTime())

	// 更新每个实例的防火墙规则
	for _, instance := range instances {
		fmt.Printf("%s 开始更新实例 %s 的防火墙规则\n", currentDateTime(), instance.InstanceId)

		err := modifyFirewallRules(creds[0], instance, uniqueIPs)
		if err != nil {
			fmt.Printf("%s 更新实例 %s 防火墙失败: %v\n", currentDateTime(), instance.InstanceId, err)
			continue
		}

		// 记录成功更新的信息
		updates = append(updates, updateInfo{
			SG:  instance.InstanceId,
			IPs: uniqueIPs,
		})

		fmt.Printf("%s 实例 %s 防火墙更新完成\n", currentDateTime(), instance.InstanceId)

		// 添加短暂延迟，避免API调用过于频繁
		time.Sleep(100 * time.Millisecond)
	}

	// 保存新的IP列表到文件
	readWriteIPs("ips.txt", uniqueIPs, "w")
	fmt.Printf("已将新的IP列表写入文件: %v\n", uniqueIPs)

	// 发送钉钉通知
	if len(updates) > 0 {
		sendDingTalkMessage(updates)
	}
}
