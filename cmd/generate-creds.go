//go:build ignore

package main

import (
	"fmt"
	"os"

	"github.com/minio/minio/internal/auth"
)

func main() {
	// 方式 A: 生成随机凭证
	accessKey, secretKey, err := auth.GenerateCredentials()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error generating credentials: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("=== 自动生成的凭证 ===")
	fmt.Printf("AccessKey: %s\n", accessKey)
	fmt.Printf("SecretKey: %s\n", secretKey)
	fmt.Println()

	// 方式 B: 生成指定长度的凭证
	accessKey20, err := auth.GenerateAccessKey(20, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	secretKey40, err := auth.GenerateSecretKey(40, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("=== 指定长度的凭证 ===")
	fmt.Printf("AccessKey (20字符): %s\n", accessKey20)
	fmt.Printf("SecretKey (40字符): %s\n", secretKey40)
	fmt.Println()

	// 方式 C: 创建 Credentials 对象
	cred, err := auth.CreateCredentials(accessKey, secretKey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating credentials: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("=== Credentials 对象 ===")
	fmt.Printf("AccessKey: %s\n", cred.AccessKey)
	fmt.Printf("SecretKey: %s\n", cred.SecretKey)
	fmt.Printf("Status: %s\n", cred.Status)
	fmt.Printf("IsValid: %v\n", cred.IsValid())
	fmt.Println()

	// 输出环境变量格式
	fmt.Println("=== 复制以下内容到环境变量 ===")
	fmt.Printf("export MINIO_ROOT_USER=\"%s\"\n", accessKey)
	fmt.Printf("export MINIO_ROOT_PASSWORD=\"%s\"\n", secretKey)
}
