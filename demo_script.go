package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

const baseURL = "http://localhost:8081/api"

func RunDemo() {
	fmt.Println("🚀 Стартиране на демострация на KSMS...")

	// 1. Регистрация на нов администратор
	adminEmail := "admin@ksms.io"
	adminPass := "admin123"
	registerPayload := map[string]string{
		"email":      adminEmail,
		"password":   adminPass,
		"first_name": "Админ",
		"last_name":  "KSMS",
		"role":       "Administrator",
	}

	fmt.Println("\n1. Регистрация на администратор...")
	resp, err := postJSON(baseURL+"/register", registerPayload, "")
	if err != nil {
		fmt.Printf("⚠️ Статус при регистрация: %v (Може вече да съществува)\n", err)
	} else {
		fmt.Printf("✅ Регистрация успешна (Status: %d)\n", resp.StatusCode)
	}

	// 2. Вход (Login)
	fmt.Println("\n2. Вход в системата...")
	loginPayload := map[string]string{
		"email":    adminEmail,
		"password": adminPass,
	}
	loginResp, err := postJSON(baseURL+"/login", loginPayload, "")
	if err != nil {
		fmt.Printf("❌ Грешка при вход: %v\n", err)
		return
	}

	var loginData map[string]string
	json.NewDecoder(loginResp.Body).Decode(&loginData)
	token := loginData["token"]
	if token == "" {
		fmt.Println("❌ Неуспешно получаване на JWT токен")
		return
	}
	fmt.Println("✅ Вход успешен. Получен JWT токен.")

	// 3. Създаване на политика за сигурност
	fmt.Println("\n3. Създаване на нова политика за сигурност...")
	policyPayload := map[string]interface{}{
		"name":        "No Privileged Pods",
		"description": "Забранява стартирането на привилегировани контейнери",
		"rules":       []string{"disallow_privileged"},
		"namespace":   "default",
	}
	resp, err = postJSON(baseURL+"/policies", policyPayload, token)
	if err != nil {
		fmt.Printf("❌ Грешка при създаване на политика: %v\n", err)
	} else {
		fmt.Printf("✅ Политика създадена успешно (Status: %d)\n", resp.StatusCode)
	}

	// 4. Извличане на списък с потребители (Админ само)
	fmt.Println("\n4. Тест на RBAC: Извличане на списък с потребители...")
	req, _ := http.NewRequest("GET", baseURL+"/users", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	client := &http.Client{}
	resp, err = client.Do(req)
	if err != nil {
		fmt.Printf("❌ Грешка при заявка: %v\n", err)
	} else {
		fmt.Printf("✅ Списъкът с потребители е достъпен (Status: %d)\n", resp.StatusCode)
	}

	// 5. Проверка на SSE Алеърти (кратък тест)
	fmt.Println("\n5. Проверка на SSE потока за алеърти (за 3 секунди)...")
	go func() {
		req, _ := http.NewRequest("GET", baseURL+"/tests", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		resp, err := client.Do(req)
		if err != nil {
			return
		}
		defer resp.Body.Close()

		buf := make([]byte, 1024)
		for {
			n, err := resp.Body.Read(buf)
			if n > 0 {
				fmt.Printf("🔔 Получен алерт през SSE: %s\n", string(buf[:n]))
			}
			if err != nil {
				break
			}
		}
	}()
	time.Sleep(3 * time.Second)

	fmt.Println("\n✨ Демонстрацията приключи успешно!")
	fmt.Println("👉 Вече можете да влезете в интерфейса на http://localhost:8081 с:")
	fmt.Printf("   User: %s\n", adminEmail)
	fmt.Printf("   Pass: %s\n", adminPass)
}

func postJSON(url string, data interface{}, token string) (*http.Response, error) {
	jsonData, _ := json.Marshal(data)
	req, _ := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 400 && resp.StatusCode != 409 {
		body, _ := io.ReadAll(resp.Body)
		return resp, fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(body))
	}
	return resp, nil
}
