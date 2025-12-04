// Copyright (c) 2015-2021 MinIO, Inc.
//
// This file is part of MinIO Object Storage stack
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package cmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"math/rand"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"slices"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/coreos/go-systemd/v22/daemon"
	"github.com/minio/cli"
	"github.com/minio/minio/internal/color"
	"github.com/minio/minio/internal/config"
	xhttp "github.com/minio/minio/internal/http"
	"github.com/minio/minio/internal/logger"
	"github.com/minio/pkg/v3/certs"
	"github.com/minio/pkg/v3/console"
	"github.com/minio/pkg/v3/env"
	"github.com/minio/pkg/v3/trie"
	"github.com/minio/pkg/v3/words"
)

// GlobalFlags - global flags for minio.
var GlobalFlags = []cli.Flag{
	// Deprecated flag, so its hidden now - existing deployments will keep working.
	cli.StringFlag{
		Name:   "config-dir, C",
		Value:  defaultConfigDir.Get(),
		Usage:  "[DEPRECATED] path to legacy configuration directory",
		Hidden: true,
	},
	cli.StringFlag{
		Name:  "certs-dir, S",
		Value: defaultCertsDir.Get(),
		Usage: "path to certs directory",
	},
	cli.BoolFlag{
		Name:  "quiet",
		Usage: "disable startup and info messages",
	},
	cli.BoolFlag{
		Name:  "anonymous",
		Usage: "hide sensitive information from logging",
	},
	cli.BoolFlag{
		Name:  "json",
		Usage: "output logs in JSON format",
	},
	// Deprecated flag, so its hidden now, existing deployments will keep working.
	cli.BoolFlag{
		Name:   "compat",
		Usage:  "enable strict S3 compatibility by turning off certain performance optimizations",
		Hidden: true,
	},
	// This flag is hidden and to be used only during certain performance testing.
	cli.BoolFlag{
		Name:   "no-compat",
		Usage:  "disable strict S3 compatibility by turning on certain performance optimizations",
		Hidden: true,
	},
}

// Help template for minio.
var minioHelpTemplate = `NAME:
  {{.Name}} - {{.Usage}}

DESCRIPTION:
  {{.Description}}

USAGE:
  {{.HelpName}} {{if .VisibleFlags}}[FLAGS] {{end}}COMMAND{{if .VisibleFlags}}{{end}} [ARGS...]

COMMANDS:
  {{range .VisibleCommands}}{{join .Names ", "}}{{ "\t" }}{{.Usage}}
  {{end}}{{if .VisibleFlags}}
FLAGS:
  {{range .VisibleFlags}}{{.}}
  {{end}}{{end}}
VERSION:
  {{.Version}}
`

func newApp(name string) *cli.App {
	// Collection of minio commands currently supported are.
	commands := []cli.Command{}

	// Collection of minio commands currently supported in a trie tree.
	commandsTree := trie.NewTrie()

	// registerCommand registers a cli command.
	registerCommand := func(command cli.Command) {
		// avoid registering commands which are not being built (via
		// go:build tags)
		if command.Name == "" {
			return
		}
		commands = append(commands, command)
		commandsTree.Insert(command.Name)
	}

	findClosestCommands := func(command string) []string {
		var closestCommands []string
		closestCommands = append(closestCommands, commandsTree.PrefixMatch(command)...)

		sort.Strings(closestCommands)
		// Suggest other close commands - allow missed, wrongly added and
		// even transposed characters
		for _, value := range commandsTree.Walk(commandsTree.Root()) {
			if sort.SearchStrings(closestCommands, value) < len(closestCommands) {
				continue
			}
			// 2 is arbitrary and represents the max
			// allowed number of typed errors
			if words.DamerauLevenshteinDistance(command, value) < 2 {
				closestCommands = append(closestCommands, value)
			}
		}

		return closestCommands
	}

	// Register all commands.
	registerCommand(serverCmd)
	registerCommand(fmtGenCmd)

	// Set up app.
	cli.HelpFlag = cli.BoolFlag{
		Name:  "help, h",
		Usage: "show help",
	}
	cli.VersionPrinter = printMinIOVersion

	app := cli.NewApp()
	app.Name = name
	app.Author = "MinIO, Inc."
	app.Version = ReleaseTag
	app.Usage = "High Performance Object Storage"
	app.Description = `Build high performance data infrastructure for machine learning, analytics and application data workloads with MinIO`
	app.Flags = GlobalFlags
	app.HideHelpCommand = true // Hide `help, h` command, we already have `minio --help`.
	app.Commands = commands
	app.CustomAppHelpTemplate = minioHelpTemplate
	app.CommandNotFound = func(ctx *cli.Context, command string) {
		console.Printf("‘%s’ is not a minio sub-command. See ‘minio --help’.\n", command)
		closestCommands := findClosestCommands(command)
		if len(closestCommands) > 0 {
			console.Println()
			console.Println("Did you mean one of these?")
			for _, cmd := range closestCommands {
				console.Printf("\t‘%s’\n", cmd)
			}
		}

		os.Exit(1)
	}

	return app
}

func startupBanner(banner io.Writer) {
	CopyrightYear = strconv.Itoa(time.Now().Year())
	fmt.Fprintln(banner, color.Blue("Copyright:")+color.Bold(" 2015-%s MinIO, Inc.", CopyrightYear))
	fmt.Fprintln(banner, color.Blue("License:")+color.Bold(" "+MinioLicense))
	fmt.Fprintln(banner, color.Blue("Version:")+color.Bold(" %s (%s %s/%s)", ReleaseTag, runtime.Version(), runtime.GOOS, runtime.GOARCH))
}

func versionBanner(c *cli.Context) io.Reader {
	banner := &strings.Builder{}
	fmt.Fprintln(banner, color.Bold("%s version %s (commit-id=%s)", c.App.Name, c.App.Version, CommitID))
	fmt.Fprintln(banner, color.Blue("Runtime:")+color.Bold(" %s %s/%s", runtime.Version(), runtime.GOOS, runtime.GOARCH))
	fmt.Fprintln(banner, color.Blue("License:")+color.Bold(" GNU AGPLv3 - https://www.gnu.org/licenses/agpl-3.0.html"))
	fmt.Fprintln(banner, color.Blue("Copyright:")+color.Bold(" 2015-%s MinIO, Inc.", CopyrightYear))
	return strings.NewReader(banner.String())
}

func printMinIOVersion(c *cli.Context) {
	io.Copy(c.App.Writer, versionBanner(c))
}

var debugNoExit = env.Get("_MINIO_DEBUG_NO_EXIT", "") != ""

// Main main for minio server.
func Main(args []string) {
	// Set the minio app name.
	appName := filepath.Base(args[0])

	if debugNoExit {
		freeze := func(_ int) {
			// Infinite blocking op
			<-make(chan struct{})
		}

		// Override the logger os.Exit()
		logger.ExitFunc = freeze

		defer func() {
			if err := recover(); err != nil {
				fmt.Println("panic:", err)
				fmt.Println("")
				fmt.Println(string(debug.Stack()))
			}
			freeze(-1)
		}()
	}

	// Run the app - exit on error.
	if err := newApp(appName).Run(args); err != nil {
		os.Exit(1) //nolint:gocritic
	}
}

// OnlyAPI 仅保留 S3 API 部分
// 强制单盘模式，移除分布式锁与网络调用
func OnlyAPI(ctx *cli.Context) {
	// fmt.Printf("%#v", *ctx)
	// var lgDir string
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	var warnings []string

	// 基础信号与环境设置
	signal.Notify(globalOSSignalCh, os.Interrupt, syscall.SIGTERM, syscall.SIGQUIT)
	go handleSignals()
	setDefaultProfilerRates()
	// 日志系统初始化
	bootstrapTrace("newConsoleLogger", func() {
		// output, err := initializeLogRotateWithDp(lgDir)
		output, err := initializeLogRotate(ctx)
		if err == nil {
			logger.Output = output
			globalConsoleSys = NewConsoleLogger(GlobalContext, output)
			globalLoggerOutput = output
		} else {
			logger.Output = os.Stderr
			globalConsoleSys = NewConsoleLogger(GlobalContext, os.Stderr)
		}
		logger.AddSystemTarget(GlobalContext, globalConsoleSys)
	})

	// 构建服务上下文（解析参数，端口，磁盘布局）
	bootstrapTrace("serverHandleCmdArgs", func() {
		err := buildServerCtxt(ctx, &globalServerCtxt)
		logger.FatalIf(err, "Unable to prepare the list of endpoints")

		serverHandleCmdArgs(globalServerCtxt)
	})

	bootstrapTrace("initHelp", initHelp)

	bootstrapTrace("initCoreSubsystems", func() {
		// (A) 事件通知器 (Bucket 操作会触发，必须有，否则空指针)
		globalEventNotifier = NewEventNotifier(GlobalContext)
		// (B) 桶元数据系统 (必须有，否则无法识别 Bucket)
		globalBucketMetadataSys = NewBucketMetadataSys()
		// (C) 配置系统
		globalConfigSys = NewConfigSys()
		globalBucketTargetSys = NewBucketTargetSys(GlobalContext)
	})

	var getCert certs.GetCertificateFunc
	if globalTLSCerts != nil {
		getCert = globalTLSCerts.GetCertificate
	}
	// Set system resources to maximum.
	bootstrapTrace("setMaxResources", func() {
		_ = setMaxResources(globalServerCtxt)
	})
	// Verify kernel release and version.
	if oldLinux() {
		warnings = append(warnings, color.YellowBold("Detected Linux kernel version older than 4.0 release, there are some known potential performance problems with this kernel version. MinIO recommends a minimum of 4.x linux kernel version for best performance"))
	}
	maxProcs := runtime.GOMAXPROCS(0)
	cpuProcs := runtime.NumCPU()
	if maxProcs < cpuProcs {
		warnings = append(warnings, color.YellowBold("Detected GOMAXPROCS(%d) < NumCPU(%d), please make sure to provide all PROCS to MinIO for optimal performance",
			maxProcs, cpuProcs))
	}

	// Configure server.
	bootstrapTrace("configureServer", func() {
		// 仅注册 data api 和健康检查
		handler, err := configureDataHandler()
		if err != nil {
			logger.Fatal(config.ErrUnexpectedError(err), "Unable to configure one of server's RPC services")
		}

		httpServer := xhttp.NewServer(getServerListenAddrs()).
			UseHandler(setCriticalErrorHandler(corsHandler(handler))).
			UseTLSConfig(newTLSConfig(getCert)).
			UseIdleTimeout(globalServerCtxt.IdleTimeout).
			UseReadTimeout(globalServerCtxt.IdleTimeout).
			UseWriteTimeout(globalServerCtxt.IdleTimeout).
			UseReadHeaderTimeout(globalServerCtxt.ReadHeaderTimeout).
			UseBaseContext(GlobalContext).
			UseCustomLogger(log.New(io.Discard, "", 0)). // Turn-off random logging by Go stdlib
			UseTCPOptions(globalTCPOptions)

		httpServer.TCPOptions.Trace = bootstrapTraceMsg
		go func() {
			serveFn, err := httpServer.Init(GlobalContext, func(listenAddr string, err error) {
				bootLogIf(GlobalContext, fmt.Errorf("Unable to listen on `%s`: %v", listenAddr, err))
			})
			if err != nil {
				globalHTTPServerErrorCh <- err
				return
			}
			globalHTTPServerErrorCh <- serveFn()
		}()

		setHTTPServer(httpServer)
	})
	// 对象层初始化
	var newObject ObjectLayer
	bootstrapTrace("newObjectLayer", func() {
		var err error
		newObject, err = newObjectLayer(GlobalContext, globalEndpoints)
		if err != nil {
			logFatalErrs(err, Endpoint{}, true)
		}
	})

	var err error
	bootstrapTrace("initServerConfig", func() {
		if err = initServerConfig(GlobalContext, newObject); err != nil {
			var cerr config.Err
			// For any config error, we don't need to drop into safe-mode
			// instead its a user error and should be fixed by user.
			if errors.As(err, &cerr) {
				logger.FatalIf(err, "Unable to initialize the server")
			}

			// If context was canceled
			if errors.Is(err, context.Canceled) {
				logger.FatalIf(err, "Server startup canceled upon user request")
			}

			bootLogIf(GlobalContext, err)
		}

		if !globalServerCtxt.StrictS3Compat {
			warnings = append(warnings, color.YellowBold("Strict AWS S3 compatible incoming PUT, POST content payload validation is turned off, caution is advised do not use in production"))
		}
	})

	go func() {
		// Initialize bucket notification system.
		bootstrapTrace("initBucketTargets", func() {
			bootLogIf(GlobalContext, globalEventNotifier.InitBucketTargets(GlobalContext, newObject))
		})

		var buckets []string
		// List buckets to initialize bucket metadata sub-sys.
		bootstrapTrace("listBuckets", func() {
			for {
				bucketsList, err := newObject.ListBuckets(GlobalContext, BucketOptions{NoMetadata: true})
				if err != nil {
					if configRetriableErrors(err) {
						logger.Info("Waiting for list buckets to succeed to initialize buckets.. possible cause (%v)", err)
						time.Sleep(time.Duration(r.Float64() * float64(time.Second)))
						continue
					}
					bootLogIf(GlobalContext, fmt.Errorf("Unable to list buckets to initialize bucket metadata sub-system: %w", err))
				}

				buckets = make([]string, len(bucketsList))
				for i := range bucketsList {
					buckets[i] = bucketsList[i].Name
				}
				break
			}
		})

		// 检查并创建默认 Bucket (例如 "default-bucket")
		defaultBucketName := "default" // 你可以将其改为配置或环境变量
		if !slices.Contains(buckets, defaultBucketName) {
			// Bucket 不存在，创建它
			err := newObject.MakeBucket(GlobalContext, defaultBucketName, MakeBucketOptions{})
			if err != nil {
				// 记录错误但不中断启动，除非这是致命的
				logger.LogIf(GlobalContext, "", fmt.Errorf("Unable to create default bucket %s: %w", defaultBucketName, err))
			} else {
				logger.Info("Created default bucket: %s", defaultBucketName)
				// 将新创建的 Bucket 添加到列表中，以便 Metadata 系统初始化它
				buckets = append(buckets, defaultBucketName)
			}
		}

		// Initialize bucket metadata sub-system.
		bootstrapTrace("globalBucketMetadataSys.Init", func() {
			globalBucketMetadataSys.Init(GlobalContext, buckets, newObject)
		})

		// Prints the formatted startup message, if err is not nil then it prints additional information as well.
		printStartupMessage(getAPIEndpoints(), err)

		for _, warn := range warnings {
			logger.Warning(warn)
		}
	}()

	daemon.SdNotify(false, daemon.SdNotifyReady)

	<-globalOSSignalCh
}
