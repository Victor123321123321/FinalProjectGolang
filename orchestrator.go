package main

import (
	"context"
	"database/sql"
	_ "database/sql"
	"encoding/json"
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	_ "github.com/mattn/go-sqlite3"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Expression2 struct {
	ID          string    `json:"id"`
	Expression  string    `json:"expression"`
	Status      string    `json:"status"`
	Result      int       `json:"result"`
	Date_start  time.Time `json:"date_start"`
	Date_finish time.Time `json:"date_finish"`
}

type Task struct {
	ID      string
	Expr    string
	Result  int
	IsReady bool
}

type Time struct {
	time_plus     int
	time_minus    int
	time_divide   int
	time_multiply int
	time_limit    int
}

var (
	db          *sql.DB
	expressions = make(map[string]*Expression2)
	tasks       = make(map[string]*Task)
	mu          sync.RWMutex
	times       = Time{
		time_plus:     10,
		time_minus:    10,
		time_divide:   10,
		time_multiply: 10,
		time_limit:    50,
	}
)

func isOperator(c byte) bool {
	return c == '+' || c == '-' || c == '*' || c == '/'
}

func precedence(op byte) int {
	switch op {
	case '+', '-':
		return 1
	case '*', '/':
		return 2
	}
	return 0
}

func infixToPostfix(expression string) []string {
	var stack []byte
	var result []string

	for i := 0; i < len(expression); i++ {
		if expression[i] == ' ' {
			expression = string(expression[:i]) + "+" + string(expression[i+1:])
		}
	}

	for i := 0; i < len(expression); i++ {
		if expression[i] == ' ' {
			continue
		} else if expression[i] == '(' {
			stack = append(stack, expression[i])
		} else if expression[i] == ')' {
			for len(stack) > 0 && stack[len(stack)-1] != '(' {
				result = append(result, string(stack[len(stack)-1]))
				stack = stack[:len(stack)-1]
			}
			stack = stack[:len(stack)-1]
		} else if isOperator(expression[i]) {
			for len(stack) > 0 && precedence(stack[len(stack)-1]) >= precedence(expression[i]) {
				result = append(result, string(stack[len(stack)-1]))
				stack = stack[:len(stack)-1]
			}
			stack = append(stack, expression[i])
		} else {
			var operand strings.Builder
			for i < len(expression) && (expression[i] >= '0' && expression[i] <= '9') {
				operand.WriteByte(expression[i])
				i++
			}
			i--
			result = append(result, operand.String())
		}
	}

	for len(stack) > 0 {
		result = append(result, string(stack[len(stack)-1]))
		stack = stack[:len(stack)-1]
	}

	return result
}

func addExampleToDB(expression string, tokenUser string, db *sql.DB) error {
	ctx := context.TODO()
	_, err := db.ExecContext(ctx, "INSERT INTO examples (expression, token_user, result, isReady) VALUES (?, ?)", expression, tokenUser, 0, false)
	return err
}

func addExpressionHandler(w http.ResponseWriter, r *http.Request) {
	//Получаем токен из заголовка Authorization
	expression := r.FormValue("expression")
	tokenString := r.FormValue("token")
	tokenFromString, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			panic(fmt.Errorf("unexpected signing method: %v", token.Header["alg"]))
		}

		return []byte("super_secret_signature"), nil
	})
	if err != nil {
		log.Fatal(err)
	}
	var username interface{}
	if claims, ok := tokenFromString.Claims.(jwt.MapClaims); ok {
		fmt.Println("username: ", claims["username"])
		username = claims["username"]
	} else {
		panic(err)
	}
	db, err := sql.Open("sqlite3", "DataBase.db")
	if err != nil {
		log.Fatal(err)
	}
	var exists bool
	err = db.QueryRowContext(context.TODO(), "SELECT EXISTS (SELECT 1 FROM users WHERE username = ?)", username).Scan(&exists)
	if err != nil {
		http.Error(w, "invalid token2", http.StatusBadRequest)
		return
	}
	if exists {
		err = addExampleToDB(expression, tokenString, db)
		if err != nil {
			http.Error(w, "Failed to add expression to database", http.StatusInternalServerError)
			return
		}
		fmt.Fprintf(w, "Expression added by user: %s", tokenString)
	} else {
		http.Error(w, "Failed to add expression to database", http.StatusInternalServerError)
		return
	}
	id := fmt.Sprintf("%d", time.Now().UnixNano())
	task := &Task{
		ID:      id,
		Expr:    expression,
		Result:  0,
		IsReady: false,
	}
	mu.Lock()
	tasks[id] = task
	expressions[id] = &Expression2{
		ID:         id,
		Expression: expression,
		Status:     "waiting",
		Result:     0,
		Date_start: time.Now(),
	}
	mu.Unlock()

	go calculateExpression(task, id)

	fmt.Fprint(w, id)
}

func calculateExpression(task *Task, id string) {
	expression := infixToPostfix(task.Expr)
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(times.time_limit)*time.Second)
	defer cancel()
	ch_res := make(chan Result)
	go main2(expression, ch_res)
	select {
	case result := <-ch_res:
		if result.Err != nil {
			task.IsReady = true
			expressions[id].Result = 0
			expressions[id].Status = "invalid operation"
			expressions[id].Date_finish = time.Now()
		} else {
			task.Result = int(result.Value)
			task.IsReady = true
			expressions[id].Result = task.Result
			expressions[id].Status = "Ready"
		}
		expressions[id].Date_finish = time.Now()
	case <-ctx.Done():
		task.Result = 0
		task.IsReady = true
		expressions[id].Result = 0
		expressions[id].Status = "The operation has expired or been canceled."
		expressions[id].Date_finish = time.Now()
	}

}

func listExpressionsHandler(w http.ResponseWriter, r *http.Request) {
	tokenString := r.FormValue("token")
	db, err := sql.Open("sqlite3", "DataBase.db")

	var expressions []Task
	var q = "SELECT id, expression, result, isReady FROM examples WHERE token = $1)"
	rows, err := db.QueryContext(context.TODO(), q, tokenString)
	if err != nil {
		return
	}
	defer rows.Close()
	for rows.Next() {
		u := Task{}
		err := rows.Scan(&u.ID, &u.Expr, &u.Result, &u.IsReady)
		if err != nil {
			return
		}
		expressions = append(expressions, u)
	}

	mu.RLock()
	defer mu.RUnlock()
	expressionList := make([]*Task, 0, len(expressions))
	for _, expr := range expressions {
		expr.Expr = strings.Replace(expr.Expr, " ", "+", -1)
		expressionList = append(expressionList, &expr)
		fmt.Fprintln(w, expr.ID, expr.Expr, expr.IsReady, expr.Result)
	}

	json.NewEncoder(w).Encode(expressionList)
}

func settime(w http.ResponseWriter, r *http.Request) {
	time_pl, _ := strconv.Atoi(r.URL.Query().Get("time "))
	time_mi, _ := strconv.Atoi(r.URL.Query().Get("time-"))
	time_de, _ := strconv.Atoi(r.URL.Query().Get("time/"))
	time_mul, _ := strconv.Atoi(r.URL.Query().Get("time*"))
	time_li, _ := strconv.Atoi(r.URL.Query().Get("time_limit"))
	times = Time{
		time_plus:     time_pl,
		time_minus:    time_mi,
		time_divide:   time_de,
		time_multiply: time_mul,
		time_limit:    time_li,
	}
}

func createTables(ctx context.Context, db *sql.DB) error {
	const (
		usersTable = `
	CREATE TABLE IF NOT EXISTS users(
		id INTEGER PRIMARY KEY AUTOINCREMENT, 
		username TEXT,
		password TEXT
	);`
		expressionsTable = `
	CREATE TABLE IF NOT EXISTS examples (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    expression TEXT NOT NULL,
    token_user TEXT,
    result 		 string,
    isReady		 bool
	);`
	)
	fmt.Println("_+_+_+_+_+_+_+_+_+_+_+_+_")
	if _, err := db.ExecContext(ctx, usersTable); err != nil {
		return err
	}
	fmt.Println("_+_+_+_+_+_+_+_+_+_+_+_+_")
	if _, err := db.ExecContext(ctx, expressionsTable); err != nil {
		return err
	}
	fmt.Println("_+_+_+_+_+_+_+_+_+_+_+_+_")
	return nil
}

func createDB() (*sql.DB, error) {
	ctx := context.TODO()
	db, err := sql.Open("sqlite3", "DataBase.db")
	if err != nil {
		return nil, err
	}
	fmt.Println("_+_+_+_+_+_+_+_+_+_+_+_+_")
	err = db.PingContext(ctx)
	fmt.Println("_+_+_+_+_+_+_+_+_+_+_+_+_")
	if err != nil {
		return nil, err
	}
	fmt.Println("_+_+_+_+_+_+_+_+_+_+_+_+_")
	if err = createTables(ctx, db); err != nil {
		return nil, err
	}
	fmt.Println("_+_+_+_+_+_+_+_+_+_+_+_+_")

	return db, nil
}

func insertUser(ctx context.Context, db *sql.DB, user *User) (int64, error) { // Добавлен параметр db
	var q = `
	INSERT INTO users (username, password) values ($1, $2)
	`
	result, err := db.ExecContext(ctx, q, user.Username, user.Password) // Исправлен запрос
	if err != nil {
		return 0, err
	}
	id, err := result.LastInsertId()
	if err != nil {
		return 0, err
	}
	return id, nil
}

type User struct {
	ID       int
	Username string
	Password string
}

type ExpressionDB struct {
	expression string
	token_user string
}

func isUserExists(ctx context.Context, db *sql.DB, username string) (bool, error) {
	var exists bool
	db, err := sql.Open("sqlite3", "DataBase.db")
	err = db.QueryRowContext(ctx, "SELECT EXISTS (SELECT 1 FROM users WHERE username = ?)", username).Scan(&exists)
	if err != nil {
		return false, err
	}
	return exists, nil
}

// Обработчик регистрации нового пользователя
func registerUserHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Println("=======================")
	r.ParseForm() // Добавлен вызов ParseForm для обработки POST данных
	fmt.Println("=======================")
	username := r.FormValue("username") // Исправлено использование FormValue для получения данных
	password := r.FormValue("password") // Исправлено использование FormValue для получения данных
	if username == "" || password == "" {
		http.Error(w, "Username and password are required", http.StatusBadRequest)
		return
	}
	fmt.Println("=======================")
	fmt.Println("=======================")
	const hmacSampleSecret = "super_secret_signature"
	now := time.Now()
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"name":     username,
		"password": password,
		"nbf":      now.Unix(),
		"exp":      now.Add(5 * time.Minute).Unix(),
		"iat":      now.Unix(),
	})
	fmt.Println("=======================")
	tokenString, err := token.SignedString([]byte(hmacSampleSecret))
	if err != nil {
		panic(err)
	}
	fmt.Println("=======================")
	fmt.Println(tokenString)
	user := &User{
		Username: username,
		Password: password,
	}
	fmt.Println("=======================")
	db, err := createDB()
	exists, err := isUserExists(context.TODO(), db, username)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	fmt.Println("=======================")
	if exists {
		http.Error(w, "Такой пользователь уже существует", http.StatusBadRequest)
		return
	}
	fmt.Println("=======================")
	// Создание базы данных для добавления пользователя
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	fmt.Println("=======================")
	db, err = sql.Open("sqlite3", "DataBase.db")
	_, err = insertUser(context.TODO(), db, user) // Исправлен вызов insertUser
	defer db.Close()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	fmt.Println("=======================")
	// Отправляем ответ клиенту
	w.WriteHeader(http.StatusCreated)
	fmt.Fprintln(w, "Регистрация прошла успешно")
}

// Функция для поиска пользователя в базе данных по имени и паролю
func findUser(w http.ResponseWriter, ctx context.Context, db *sql.DB, username, password string) (*User, error) {
	db, err := sql.Open("sqlite3", "DataBase.db")
	var user User
	fmt.Println(username, password)
	err = db.QueryRowContext(ctx, "SELECT id FROM users WHERE username = $1 AND password = $2", username, password).Scan(&user.ID)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil // Пользователь не найден
		}
		return nil, err // Возникла ошибка при выполнении запроса
	}

	var users []User
	var q = "SELECT id, username FROM users"
	rows, err := db.QueryContext(ctx, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		u := User{}
		err := rows.Scan(&u.ID, &u.Username)
		if err != nil {
			return nil, err
		}
		users = append(users, u)
	}
	now := time.Now()
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"username": username,
		"nbf":      now.Unix(),
		"exp":      now.Add(5 * time.Minute).Unix(),
		"iat":      now.Unix(),
	})
	// Подписываем токен с секретным ключом
	tokenString, err := token.SignedString([]byte("super_secret_signature"))
	if err != nil {
		//http.Error(w, err.Error(), http.StatusInternalServerError)
		return nil, fmt.Errorf(strconv.Itoa(http.StatusInternalServerError))
	}
	// Отправляем токен в ответе
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"token": tokenString})

	user.Username = username
	user.Password = password

	return &user, nil // Пользователь найден
}

// Обработчик входа в аккаунт
func loginHandler(w http.ResponseWriter, r *http.Request) {
	// Получаем имя пользователя и пароль из запроса
	username := r.FormValue("username")
	password := r.FormValue("password")
	// Проверяем ваших пользователей в базе данных
	user, err := findUser(w, context.TODO(), db, username, password)
	if err != nil {
		http.Error(w, "Error finding user", http.StatusInternalServerError)
		return
	}
	if user == nil {
		// Пользователь не найден
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}
	// Пользователь найден, создаем токен доступа
	//token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
	//	"username": user.Username,
	//	"exp":      time.Now().Add(time.Hour * 24).Unix(),
	//})
	//// Подписываем токен с секретным ключом
	//tokenString, err := token.SignedString([]byte("super_secret_signature"))
	//if err != nil {
	//	http.Error(w, err.Error(), http.StatusInternalServerError)
	//	return
	//}
	//// Отправляем токен в ответе
	//w.Header().Set("Content-Type", "application/json")
	//json.NewEncoder(w).Encode(map[string]string{"token": tokenString})
	//
	//var q = "UPDATE users SET balance = balance+$1 WHERE id = $2"
	//_, err = db.ExecContext(ctx, q, diff, id)
	//if err != nil {
	//	return err
	//}

}

func admin(w http.ResponseWriter, r *http.Request) {
	db, err := sql.Open("sqlite3", "DataBase.db")
	if err != nil {
		return
	}
	var users []User
	var q = "SELECT id, Username, Password FROM users"
	rows, err := db.QueryContext(context.TODO(), q)
	if err != nil {
		return
	}
	defer rows.Close()
	for rows.Next() {
		u := User{}
		err := rows.Scan(&u.ID, &u.Username, &u.Password)
		if err != nil {
			return
		}
		users = append(users, u)
	}
	for i := 0; i < len(users); i++ {
		fmt.Fprintln(w, users[i].ID, users[i].Username, users[i].Password)
	}
	fmt.Fprintln(w, "\n================================================\n")
	var expressionDB []ExpressionDB
	var qq = "SELECT expression, token_user FROM examples"
	rows, err = db.QueryContext(context.TODO(), qq)
	if err != nil {
		return
	}
	defer rows.Close()
	for rows.Next() {
		u := ExpressionDB{}
		err := rows.Scan(&u.expression, &u.token_user)
		if err != nil {
			return
		}
		expressionDB = append(expressionDB, u)
	}
	for i := 0; i < len(expressionDB); i++ {
		fmt.Fprintln(w, expressionDB[i].expression, expressionDB[i].token_user)
		fmt.Fprintln(w, "________________________________")
	}
	fmt.Println("------------------------------------")
	return
}

func main() {
	http.HandleFunc("/add", addExpressionHandler)
	http.HandleFunc("/list", listExpressionsHandler)
	http.HandleFunc("/settime", settime)
	http.HandleFunc("/register", registerUserHandler)
	http.HandleFunc("/login", loginHandler)

	http.HandleFunc("/admin", admin)

	fmt.Println("Server is running on port 8080")
	if err := http.ListenAndServe(":8080", nil); err != nil {
		fmt.Printf("Error starting server: %s\n", err)
	}
}

type Expression struct {
	Operation string
	Operand1  float64
	Operand2  float64
}

type Result struct {
	Value float64
	Err   error
}

func calculate_plus(expression Expression) Result {
	time.Sleep(time.Duration(times.time_plus) * time.Second)
	return Result{Value: expression.Operand1 + expression.Operand2}
}

func calculate_minus(expression Expression) Result {
	time.Sleep(time.Duration(times.time_minus) * time.Second)
	return Result{Value: expression.Operand1 - expression.Operand2}
}

func calculate_multiply(expression Expression) Result {
	time.Sleep(time.Duration(times.time_multiply) * time.Second)
	return Result{Value: expression.Operand1 * expression.Operand2}
}

func calculate_division(expression Expression) Result {
	time.Sleep(time.Duration(times.time_divide) * time.Second)
	if expression.Operand2 == 0 {
		return Result{Err: fmt.Errorf("division by zero")}
	}
	return Result{Value: expression.Operand1 / expression.Operand2}
}

func remove(slice []string, s int) []string {
	return append(slice[:s], slice[s+1:]...)
}

func main2(expression []string, ch_res chan Result) {
	for h := 0; h < len(expression); h++ {
		if expression[h] != "0" && expression[h] != "1" && expression[h] != "2" && expression[h] != "3" && expression[h] != "4" && expression[h] != "5" && expression[h] != "6" && expression[h] != "7" && expression[h] != "8" && expression[h] != "9" && expression[h] != "+" && expression[h] != "-" && expression[h] != "*" && expression[h] != "/" {
			ch_res <- Result{
				Value: 0,
				Err:   fmt.Errorf("invalid operation"),
			}
			break
		}
	}
	for {
		jj := 0
		for j := 0; j < len(expression); j++ {
			if expression[j] == "+" || expression[j] == "-" || expression[j] == "*" || expression[j] == "/" {
				jj = j
				break
			}
		}
		a, err := strconv.ParseFloat(expression[jj-2], 64)
		if err != nil {
			ch_res <- Result{
				Value: 0,
				Err:   fmt.Errorf("invalid operation"),
			}
			break
		}
		b, err := strconv.ParseFloat(expression[jj-1], 64)
		if err != nil {
			ch_res <- Result{
				Value: 0,
				Err:   fmt.Errorf("invalid operation"),
			}
			break
		}
		result := Result{
			Value: 0,
			Err:   nil,
		}
		if expression[jj] == "+" {
			result = calculate_plus(Expression{expression[jj], a, b})
		} else if expression[jj] == "-" {
			result = calculate_minus(Expression{expression[jj], a, b})
		} else if expression[jj] == "*" {
			result = calculate_multiply(Expression{expression[jj], a, b})
		} else if expression[jj] == "/" {
			result = calculate_division(Expression{expression[jj], a, b})
		} else {
			result = Result{
				Value: 0,
				Err:   fmt.Errorf("invalid operation"),
			}
		}

		if result.Err != nil {
			fmt.Println("sfdgbhjbhuklsfdbvlkjsvdflkjnfzvdsl;kjvdfa")
			ch_res <- result
		}
		expression = remove(expression, jj-2)
		expression = remove(expression, jj-2)
		expression = remove(expression, jj-2)
		t := strconv.Itoa(int(result.Value))
		expression2 := []string{}
		if len(expression) == 1 {
			ch_res <- result
			break
		}
		if len(expression) == 0 {
			ch_res <- result
			fmt.Println(result.Value)
			break
		}
		for j := 0; j < len(expression); j++ {
			if len(expression2) == jj-2 {
				expression2 = append(expression2, t)
			}
			expression2 = append(expression2, expression[j])
		}
		expression = expression2
	}

	numOfGoroutinesStr := os.Getenv("NUMOF_GOROUTINES")
	numOfGoroutines, err := strconv.Atoi(numOfGoroutinesStr)
	if err != nil || numOfGoroutines <= 0 {
		numOfGoroutines = 5
	}
}
