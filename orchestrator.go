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
	Result      string    `json:"result"`
	Date_start  time.Time `json:"date_start"`
	Date_finish time.Time `json:"date_finish"`
}

type Task struct {
	ID      string
	Expr    string
	Result  string
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

func addExampleToDB(expression string, tokenUser string, db *sql.DB) (int, error) {
	ctx := context.TODO()
	result, err := db.ExecContext(ctx, "INSERT INTO examples (expression, token_user, result, isReady) VALUES (?, ?, ?, ?)", expression, tokenUser, 0, false)
	id, err := result.LastInsertId()
	if err != nil {
		return 0, err
	}
	return int(id), err
}

func addExpressionHandler(w http.ResponseWriter, r *http.Request) {
	//Получаем токен из заголовка Authorization
	expression := r.FormValue("expression")
	tokenString := r.FormValue("token")
	tokenFromString, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			fmt.Fprintf(w, "Время действия токена истекло")
			return nil, nil
		}

		return []byte("super_secret_signature"), nil
	})
	if err != nil {
		fmt.Fprintf(w, "Время действия токена истекло")
		return
	}
	var username interface{}
	if claims, ok := tokenFromString.Claims.(jwt.MapClaims); ok {
		username = claims["username"]
	} else {
		panic(err)
	}
	db, err := sql.Open("sqlite3", "DataBase.db")
	if err != nil {
		fmt.Fprintf(w, "Кажется что то пошло не так")
	}
	var exists bool
	err = db.QueryRowContext(context.TODO(), "SELECT EXISTS (SELECT 1 FROM users WHERE username = ?)", username).Scan(&exists)
	if err != nil {
		http.Error(w, "invalid token", http.StatusBadRequest)
		return
	}
	var id_ex int
	if exists {
		id_ex, err = addExampleToDB(expression, tokenString, db)
		if err != nil {
			http.Error(w, "Failed to add expression to database", http.StatusInternalServerError)
			return
		}
		fmt.Fprintf(w, "Expression added by user")
	} else {
		http.Error(w, "Failed to add expression to database", http.StatusInternalServerError)
		return
	}
	id := fmt.Sprintf("%d", time.Now().UnixNano())
	task := &Task{
		ID:      id,
		Expr:    expression,
		Result:  "0",
		IsReady: false,
	}
	mu.Lock()
	tasks[id] = task
	expressions[id] = &Expression2{
		ID:         id,
		Expression: expression,
		Status:     "waiting",
		Result:     "0",
		Date_start: time.Now(),
	}
	mu.Unlock()

	go calculateExpression(task, id, *r, id_ex, db)

	fmt.Fprint(w, id)
}

func calculateExpression(task *Task, id string, r http.Request, id_ex int, db *sql.DB) {
	expression := infixToPostfix(task.Expr)
	tokenString := r.FormValue("token")
	var aaa []int
	tokenFromString, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			task.IsReady = true
			task.Result = "0"
			return nil, nil
			panic(fmt.Errorf("unexpected signing method: %v", token.Header["alg"]))
		}
		return []byte("super_secret_signature"), nil
	})
	if err != nil {
		task.IsReady = true
		task.Result = "The token has expired"
		var q = "UPDATE examples SET result = $1, isReady = $2 WHERE id = $3"
		_, err = db.ExecContext(context.TODO(), q, task.Result, true, id_ex)
		if err != nil {
			fmt.Println(err)
			return
		}
		return
		fmt.Println("Кажется что то пошло не так")
	}
	var username interface{}
	if claims, ok := tokenFromString.Claims.(jwt.MapClaims); ok {
		username = claims["username"]
	} else {
		panic(err)
	}
	var q = "SELECT time_limit FROM users WHERE username = $1"
	rows, err := db.QueryContext(context.TODO(), q, username)
	if err != nil {
		fmt.Println(err)
		return
	}
	defer rows.Close()
	for rows.Next() {
		var u int
		err := rows.Scan(&u)
		if err != nil {
			return
		}
		aaa = append(aaa, u)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(aaa[0])*time.Second)
	defer cancel()
	ch_res := make(chan Result)
	go main2(expression, ch_res, r, id_ex, db)
	select {
	case result := <-ch_res:
		if result.Err != nil {
			task.Result = "division by zero"
			task.IsReady = true
			expressions[id].Result = "division by zero"
			expressions[id].Status = "invalid operation"
		} else {
			task.Result = fmt.Sprintf("%v", result.Value)
			task.IsReady = true
			expressions[id].Result = task.Result
			expressions[id].Status = "Ready"
		}
		expressions[id].Date_finish = time.Now()
	case <-ctx.Done():
		task.Result = "0"
		task.IsReady = true
		expressions[id].Result = "0"
		expressions[id].Status = "The operation has expired or been canceled."
		expressions[id].Date_finish = time.Now()
		var q = "UPDATE examples SET result = $1, isReady = $2 WHERE id = $3"
		_, err = db.ExecContext(context.TODO(), q, "The operation has expired or been canceled", true, id_ex)
		if err != nil {
			fmt.Println(err)
			return
		}
		break
	}

}

func listExpressionsHandler(w http.ResponseWriter, r *http.Request) {
	tokenString := r.FormValue("token")
	db, err := sql.Open("sqlite3", "DataBase.db")
	var expressions []Task
	var q = "SELECT id, expression, result, isReady FROM examples WHERE token_user = $1"
	rows, err := db.QueryContext(context.TODO(), q, tokenString)
	if err != nil {
		fmt.Println(err)
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
		fmt.Fprintln(w, "ID: "+expr.ID, "| expression: "+expr.Expr, "| status:", expr.IsReady, "| result:", expr.Result)
	}
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
	tokenString := r.FormValue("token")

	tokenFromString, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			fmt.Fprintf(w, "Кажется что то пошло не так")
		}

		return []byte("super_secret_signature"), nil
	})
	if err != nil {
		fmt.Fprintf(w, "Кажется что то пошло не так")
	}
	var username interface{}
	if claims, ok := tokenFromString.Claims.(jwt.MapClaims); ok {
		username = claims["username"]
	} else {
		panic(err)
	}

	db, err := sql.Open("sqlite3", "DataBase.db")
	var q = "UPDATE users SET time_plus = $1 WHERE username = $2"
	_, err = db.ExecContext(context.TODO(), q, time_pl, username)
	if err != nil {
		return
	}

	var qq = "UPDATE users SET time_minus = $1 WHERE username = $2"
	_, err = db.ExecContext(context.TODO(), qq, time_mi, username)
	if err != nil {
		return
	}

	var qqq = "UPDATE users SET time_divide = $1 WHERE username = $2"
	_, err = db.ExecContext(context.TODO(), qqq, time_de, username)
	if err != nil {
		return
	}

	var qqqq = "UPDATE users SET time_multiply = $1 WHERE username = $2"
	_, err = db.ExecContext(context.TODO(), qqqq, time_mul, username)
	if err != nil {
		return
	}

	var qqqqq = "UPDATE users SET time_limit = $1 WHERE username = $2"
	_, err = db.ExecContext(context.TODO(), qqqqq, time_li, username)
	if err != nil {
		return
	}
}

func createTables(ctx context.Context, db *sql.DB) error {
	const (
		usersTable = `
	CREATE TABLE IF NOT EXISTS users(
		id INTEGER PRIMARY KEY AUTOINCREMENT, 
		username TEXT,
		password TEXT,
		time_plus INTEGER,
	    time_minus INTEGER,
	    time_divide INTEGER,
	    time_multiply INTEGER,
	    time_limit INTEGER
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
	if _, err := db.ExecContext(ctx, usersTable); err != nil {
		return err
	}
	if _, err := db.ExecContext(ctx, expressionsTable); err != nil {
		return err
	}
	return nil
}

func createDB() (*sql.DB, error) {
	ctx := context.TODO()
	db, err := sql.Open("sqlite3", "DataBase.db")
	if err != nil {
		return nil, err
	}
	err = db.PingContext(ctx)
	if err != nil {
		return nil, err
	}
	if err = createTables(ctx, db); err != nil {
		return nil, err
	}

	return db, nil
}

func insertUser(ctx context.Context, db *sql.DB, user *User) (int64, error) { // Добавлен параметр db
	var q = `
	INSERT INTO users (username, password, time_plus, time_minus, time_divide, time_multiply, time_limit) values ($1, $2, $3, $4, $5, $6, $7)
	`
	result, err := db.ExecContext(ctx, q, user.Username, user.Password, 10, 10, 10, 10, 50) // Исправлен запрос
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
	r.ParseForm()                       // Добавлен вызов ParseForm для обработки POST данных
	username := r.FormValue("username") // Исправлено использование FormValue для получения данных
	password := r.FormValue("password") // Исправлено использование FormValue для получения данных
	if username == "" || password == "" {
		http.Error(w, "Username and password are required", http.StatusBadRequest)
		return
	}
	const hmacSampleSecret = "super_secret_signature"
	now := time.Now()
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"name":     username,
		"password": password,
		"nbf":      now.Unix(),
		"exp":      now.Add(15 * time.Minute).Unix(),
		"iat":      now.Unix(),
	})
	_, err := token.SignedString([]byte(hmacSampleSecret))
	if err != nil {
		panic(err)
	}
	user := &User{
		Username: username,
		Password: password,
	}
	db, err := createDB()
	exists, err := isUserExists(context.TODO(), db, username)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if exists {
		http.Error(w, "Такой пользователь уже существует", http.StatusBadRequest)
		return
	}
	// Создание базы данных для добавления пользователя
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	db, err = sql.Open("sqlite3", "DataBase.db")
	_, err = insertUser(context.TODO(), db, user) // Исправлен вызов insertUser
	defer db.Close()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	// Отправляем ответ клиенту
	w.WriteHeader(http.StatusCreated)
	fmt.Fprintln(w, "Регистрация прошла успешно")
}

// Функция для поиска пользователя в базе данных по имени и паролю
func findUser(w http.ResponseWriter, ctx context.Context, db *sql.DB, username, password string) (*User, error) {
	db, err := sql.Open("sqlite3", "DataBase.db")
	var user User
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
		"exp":      now.Add(3 * time.Minute).Unix(),
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
}

func main() {
	http.HandleFunc("/add", addExpressionHandler)
	http.HandleFunc("/list", listExpressionsHandler)
	http.HandleFunc("/settime", settime)
	http.HandleFunc("/register", registerUserHandler)
	http.HandleFunc("/login", loginHandler)

	fmt.Println("Server is running on port 8080")
	restartPendingTasks()
	if err := http.ListenAndServe(":8080", nil); err != nil {
		fmt.Printf("Error starting server: %s\n", err)
	}

}

func restartPendingTasks() {
	db, err := sql.Open("sqlite3", "DataBase.db")
	// Запрос к базе данных для поиска невыполненных задач
	rows, err := db.QueryContext(context.TODO(), "SELECT id, expression, token_user FROM examples WHERE isReady = false")
	if err != nil {
		fmt.Println("Error querying database for pending tasks:", err)
		return
	}
	defer rows.Close()

	// Обработка результатов запроса
	for rows.Next() {
		var id int
		var expression string
		var token_user string
		if err := rows.Scan(&id, &expression, &token_user); err != nil {
			log.Println("Error scanning rows for pending tasks:", err)
			continue
		}
		// Добавление задачи в очередь на выполнение
		idStr := strconv.Itoa(id)
		task := &Task{
			ID:      idStr,
			Expr:    expression,
			Result:  "0",
			IsReady: false,
		}
		mu.Lock()
		tasks[idStr] = task
		expressions[idStr] = &Expression2{
			ID:         idStr,
			Expression: expression,
			Status:     "waiting",
			Result:     "0",
			Date_start: time.Now(),
		}
		mu.Unlock()

		// Запуск горутины для выполнения задачи
		r, err := http.NewRequest("GET", "http://127.0.0.1:8080/add?expression="+expression+"&token="+token_user, nil)
		if err != nil {
			// handle error
			fmt.Println("Кажется что то пошло не так")
		}
		go calculateExpression(task, idStr, *r, id, db)
	}
	if err := rows.Err(); err != nil {
		log.Println("Error iterating over pending tasks:", err)
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

func calculate_plus(expression Expression, r http.Request) Result {
	tokenString := r.FormValue("token")
	db, err := sql.Open("sqlite3", "DataBase.db")
	var expressions []int
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
		username = claims["username"]
	} else {
		panic(err)
	}
	var q = "SELECT time_plus FROM users WHERE username = $1"
	rows, err := db.QueryContext(context.TODO(), q, username)
	if err != nil {
		fmt.Println(err)
		return Result{
			Value: 0,
			Err:   err,
		}
	}
	defer rows.Close()
	for rows.Next() {
		var u int
		err := rows.Scan(&u)
		if err != nil {
			return Result{
				Value: 0,
				Err:   err,
			}
		}
		expressions = append(expressions, u)
	}

	time.Sleep(time.Duration(expressions[0]) * time.Second)
	return Result{Value: expression.Operand1 + expression.Operand2}
}

func calculate_minus(expression Expression, r http.Request) Result {
	tokenString := r.FormValue("token")
	db, err := sql.Open("sqlite3", "DataBase.db")
	var expressions []int
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
		username = claims["username"]
	} else {
		panic(err)
	}
	var q = "SELECT time_minus FROM users WHERE username = $1"
	rows, err := db.QueryContext(context.TODO(), q, username)
	if err != nil {
		fmt.Println(err)
		return Result{
			Value: 0,
			Err:   err,
		}
	}
	defer rows.Close()
	for rows.Next() {
		var u int
		err := rows.Scan(&u)
		if err != nil {
			return Result{
				Value: 0,
				Err:   err,
			}
		}
		expressions = append(expressions, u)
	}

	time.Sleep(time.Duration(expressions[0]) * time.Second)
	return Result{Value: expression.Operand1 - expression.Operand2}
}

func calculate_multiply(expression Expression, r http.Request) Result {
	tokenString := r.FormValue("token")
	db, err := sql.Open("sqlite3", "DataBase.db")
	var expressions []int
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
		username = claims["username"]
	} else {
		panic(err)
	}
	var q = "SELECT time_multiply FROM users WHERE username = $1"
	rows, err := db.QueryContext(context.TODO(), q, username)
	if err != nil {
		fmt.Println(err)
		return Result{
			Value: 0,
			Err:   err,
		}
	}
	defer rows.Close()
	for rows.Next() {
		var u int
		err := rows.Scan(&u)
		if err != nil {
			return Result{
				Value: 0,
				Err:   err,
			}
		}
		expressions = append(expressions, u)
	}
	time.Sleep(time.Duration(expressions[0]) * time.Second)
	return Result{Value: expression.Operand1 * expression.Operand2}
}

func calculate_division(expression Expression, r http.Request) Result {
	tokenString := r.FormValue("token")
	db, err := sql.Open("sqlite3", "DataBase.db")
	var expressions []int
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
		username = claims["username"]
	} else {
		panic(err)
	}
	var q = "SELECT time_divide FROM users WHERE username = $1"
	rows, err := db.QueryContext(context.TODO(), q, username)
	if err != nil {
		fmt.Println(err)
		return Result{
			Value: 0,
			Err:   err,
		}
	}
	defer rows.Close()
	for rows.Next() {
		var u int
		err := rows.Scan(&u)
		if err != nil {
			return Result{
				Value: 0,
				Err:   err,
			}
		}
		expressions = append(expressions, u)
	}
	time.Sleep(time.Duration(expressions[0]) * time.Second)
	if expression.Operand2 == 0 {
		return Result{Err: fmt.Errorf("division by zero")}
	}
	return Result{Value: expression.Operand1 / expression.Operand2}
}

func remove(slice []string, s int) []string {
	return append(slice[:s], slice[s+1:]...)
}

func main2(expression []string, ch_res chan Result, r http.Request, id_ex int, db *sql.DB) {
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
			result = calculate_plus(Expression{expression[jj], a, b}, r)
		} else if expression[jj] == "-" {
			result = calculate_minus(Expression{expression[jj], a, b}, r)
		} else if expression[jj] == "*" {
			result = calculate_multiply(Expression{expression[jj], a, b}, r)
		} else if expression[jj] == "/" {
			result = calculate_division(Expression{expression[jj], a, b}, r)
		} else {
			result = Result{
				Value: 0,
				Err:   fmt.Errorf("invalid operation"),
			}
		}

		if result.Err != nil {
			ch_res <- result
			var q = "UPDATE examples SET result = $1, isReady = $2 WHERE id = $3"
			_, err = db.ExecContext(context.TODO(), q, "invalid operation", true, id_ex)
			if err != nil {
				fmt.Println(err)
				return
			}
			break
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
			var q = "UPDATE examples SET result = $1, isReady = $2 WHERE id = $3"
			_, err = db.ExecContext(context.TODO(), q, result.Value, true, id_ex)
			if err != nil {
				fmt.Println(err)
				return
			}
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
