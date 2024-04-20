package main

import (
	"bytes"
	"context"
	_ "context"
	"database/sql"
	_ "database/sql"
	"github.com/golang-jwt/jwt/v5"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"testing"
	"time"
)

func TestInfixToPostfix(t *testing.T) {
	tests := []struct {
		name       string
		expression string
		expected   []string
	}{
		{"Simple Addition", "2+3", []string{"2", "3", "+"}},
		{"Simple Subtraction", "5-4", []string{"5", "4", "-"}},
		{"Simple Multiplication", "2*3", []string{"2", "3", "*"}},
		{"Simple Division", "6/2", []string{"6", "2", "/"}},
		{"Complex Expression", "2+3*4", []string{"2", "3", "4", "*", "+"}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := infixToPostfix(tc.expression)
			if !reflect.DeepEqual(result, tc.expected) {
				t.Errorf("Expected %v, but got %v", tc.expected, result)
			}
		})
	}
}

func TestIsOperator(t *testing.T) {
	tests := []struct {
		char     byte
		expected bool
	}{
		{'+', true},
		{'-', true},
		{'*', true},
		{'/', true},
		{'a', false},
		{'1', false},
		{'(', false},
		{')', false},
	}

	for _, tc := range tests {
		t.Run(string(tc.char), func(t *testing.T) {
			result := isOperator(tc.char)
			if result != tc.expected {
				t.Errorf("For %c, expected %v, got %v", tc.char, tc.expected, result)
			}
		})
	}
}

func TestPrecedence(t *testing.T) {
	tests := []struct {
		op       byte
		expected int
	}{
		{'+', 1},
		{'-', 1},
		{'*', 2},
		{'/', 2},
		{'a', 0}, // некорректный символ
	}

	for _, tc := range tests {
		t.Run(string(tc.op), func(t *testing.T) {
			result := precedence(tc.op)
			if result != tc.expected {
				t.Errorf("For %c, expected %v, got %v", tc.op, tc.expected, result)
			}
		})
	}
}

func setupTestDB(t *testing.T) *sql.DB {
	// Open a test database connection
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("error opening test database: %v", err)
	}

	// Create necessary tables for testing
	if err := createTables(context.Background(), db); err != nil {
		t.Fatalf("error creating tables: %v", err)
	}

	return db
}

func TestAddExampleToDB(t *testing.T) {
	// Setup test environment
	db := setupTestDB(t)
	defer db.Close()

	// Mock data
	expression := "2 + 2"
	tokenUser := "test_token"

	// Call the function
	id, err := addExampleToDB(expression, tokenUser, db)
	if err != nil {
		t.Fatalf("error adding example to DB: %v", err)
	}

	// Check if ID is not 0
	if id == 0 {
		t.Fatalf("expected non-zero ID, got 0")
	}

	// Optionally, you can check if the example exists in the database using db.QueryRowContext and checking if the returned ID matches the expected one.
}

func TestMain(m *testing.M) {
	// setup code here

	// Run tests
	exitCode := m.Run()

	// teardown code here

	// Exit with the status code from tests
	os.Exit(exitCode)
}

func TestCreateTables(t *testing.T) {
	// Создание временной базы данных SQLite в памяти
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("Failed to open database: %v", err)
	}
	defer db.Close()

	// Вызов функции для создания таблиц
	err = createTables(context.Background(), db)
	if err != nil {
		t.Fatalf("createTables() returned an error: %v", err)
	}

	// Проверка наличия таблицы пользователей
	rows, err := db.QueryContext(context.Background(), "SELECT name FROM sqlite_master WHERE type='table' AND name='users';")
	if err != nil {
		t.Fatalf("Error querying database: %v", err)
	}
	defer rows.Close()
	if !rows.Next() {
		t.Error("Table 'users' was not created")
	}
}

func TestCreateTables2(t *testing.T) {
	// Создание временной базы данных SQLite в памяти
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("Failed to open database: %v", err)
	}
	defer db.Close()

	// Вызов функции для создания таблиц
	err = createTables(context.Background(), db)
	if err != nil {
		t.Fatalf("createTables() returned an error: %v", err)
	}

	// Проверка наличия таблицы пользователей
	rows, err := db.QueryContext(context.Background(), "SELECT name FROM sqlite_master WHERE type='table' AND name='examples';")
	if err != nil {
		t.Fatalf("Error querying database: %v", err)
	}
	defer rows.Close()
	if !rows.Next() {
		t.Error("Table 'examples' was not created")
	}
}

func TestCreateDB(t *testing.T) {
	// Создаем временный файл базы данных для тестов

	// Вызываем функцию createDB
	db, err := createDB()
	if err != nil {
		t.Fatalf("createDB returned an error: %v", err)
	}
	defer db.Close()

	// Проверяем, что база данных создана
	if err := checkTableExists(db, "users"); err != nil {
		t.Fatalf("table 'users' was not created: %v", err)
	}

	if err := checkTableExists(db, "examples"); err != nil {
		t.Fatalf("table 'examples' was not created: %v", err)
	}
}

func checkTableExists(db *sql.DB, tableName string) error {
	rows, err := db.Query("SELECT name FROM sqlite_master WHERE type='table' AND name=?", tableName)
	if err != nil {
		return err
	}
	defer rows.Close()

	if !rows.Next() {
		return sql.ErrNoRows
	}
	return nil
}

func TestInsertUser(t *testing.T) {
	// Создаем временный файл базы данных для тестов
	tmpDBPath := "test_db.db"
	defer os.Remove(tmpDBPath)

	// Открываем соединение с временной базой данных
	db, err := sql.Open("sqlite3", tmpDBPath)
	if err != nil {
		t.Fatalf("failed to open database: %v", err)
	}
	defer db.Close()

	// Создаем таблицы
	if err := createTables(context.Background(), db); err != nil {
		t.Fatalf("failed to create tables: %v", err)
	}

	// Создаем тестового пользователя
	user := &User{
		Username: "test_user",
		Password: "test_password",
	}

	// Вставляем пользователя в базу данных
	id, err := insertUser(context.Background(), db, user)
	if err != nil {
		t.Fatalf("failed to insert user: %v", err)
	}

	// Проверяем, что ID пользователя больше 0
	if id <= 0 {
		t.Fatalf("invalid user ID: %d", id)
	}

	// Проверяем, что пользователь успешно добавлен в базу данных
	if err := checkUserExists(db, user.Username); err != nil {
		t.Fatalf("user not found in database: %v", err)
	}
}

func checkUserExists(db *sql.DB, username string) error {
	var count int
	row := db.QueryRow("SELECT COUNT(*) FROM users WHERE username = ?", username)
	if err := row.Scan(&count); err != nil {
		return err
	}
	if count != 1 {
		return sql.ErrNoRows
	}
	return nil
}

func TestIsUserExists(t *testing.T) {
	// Открываем соединение с временной базой данных
	db, err := sql.Open("sqlite3", "DataBase.db")
	if err != nil {
		t.Fatalf("failed to open database: %v", err)
	}
	defer db.Close()

	// Создаем таблицы
	if err := createTables(context.Background(), db); err != nil {
		t.Fatalf("failed to create tables: %v", err)
	}

	// Вставляем тестового пользователя в базу данных
	if _, err := insertTestUser(db); err != nil {
		t.Fatalf("failed to insert test user: %v", err)
	}

	// Проверяем, что пользователь существует
	exists, err := isUserExists(context.Background(), db, "qwe")
	if err != nil {
		t.Fatalf("failed to check if user exists: %v", err)
	}

	// Проверяем, что результат проверки верен
	if !exists {
		t.Fatalf("user 'qwe' should exist, but got false")
	}

	// Проверяем, что несуществующий пользователь не существует
	exists, err = isUserExists(context.Background(), db, "non_existing_user")
	if err != nil {
		t.Fatalf("failed to check if user exists: %v", err)
	}

	// Проверяем, что результат проверки верен
	if exists {
		t.Fatalf("user 'non_existing_user' should not exist, but got true")
	}
}

func insertTestUser(db *sql.DB) (int64, error) {
	user := &User{
		Username: "qwe",
		Password: "qwe",
	}

	return insertUser(context.Background(), db, user)
}

func TestRegisterUserHandler(t *testing.T) {
	// Создаем запрос POST для регистрации пользователя
	req, err := http.NewRequest("POST", "/register?username=tesвtu1rп1tf1se6r&password=teвs11tfpatsrswo1rdыавп", bytes.NewBufferString(""))
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}

	// Создаем ResponseRecorder для записи ответа
	rr := httptest.NewRecorder()

	// Обрабатываем запрос с помощью регистрационного обработчика
	registerUserHandler(rr, req)

	// Проверяем тело ответа
	expected := "Регистрация прошла успешно\n"
	if rr.Body.String() != expected {
		t.Errorf("handler returned unexpected body: got %v want %v",
			rr.Body.String(), expected)
	}
}

func TestRegisterUserHandler_InvalidData(t *testing.T) {
	// Создаем запрос POST для регистрации пользователя без указания имени пользователя и пароля
	req, err := http.NewRequest("POST", "/register", nil)
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}

	// Создаем ResponseRecorder для записи ответа
	rr := httptest.NewRecorder()

	// Обрабатываем запрос с помощью регистрационного обработчика
	registerUserHandler(rr, req)

	// Проверяем код статуса ответа
	if status := rr.Code; status != http.StatusBadRequest {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusBadRequest)
	}

	// Проверяем тело ответа
	expected := "Username and password are required\n"
	if rr.Body.String() != expected {
		t.Errorf("handler returned unexpected body: got %v want %v",
			rr.Body.String(), expected)
	}
}

func TestFindUser(t *testing.T) {
	// Set up a test database
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("error opening database: %v", err)
	}
	defer db.Close()

	// Initialize the database schema
	if err := createTables(context.Background(), db); err != nil {
		t.Fatalf("error creating tables: %v", err)
	}

	// Populate the test database with test data
	if _, err := insertUser(context.Background(), db, &User{Username: "test_user", Password: "password123"}); err != nil {
		t.Fatalf("error inserting user: %v", err)
	}

	// Create a new HTTP request
	req, err := http.NewRequest("GET", "/login?username=test_user&password=password123", nil)
	if err != nil {
		t.Fatalf("error creating request: %v", err)
	}

	// Create a ResponseRecorder to record the response
	rr := httptest.NewRecorder()

	// Call the loginHandler function with the created request and recorder
	loginHandler(rr, req)
}

func TestLoginHandler_ValidCredentials(t *testing.T) {
	// Mock the database
	// Mock JWT token generation

	// Create a request with valid username and password
	req, err := http.NewRequest("POST", "/login?username=vk&password=vk", nil)
	if err != nil {
		t.Fatal(err)
	}
	q := req.URL.Query()
	req.URL.RawQuery = q.Encode()

	// Create a ResponseRecorder to record the response
	rr := httptest.NewRecorder()

	// Call the loginHandler function
	loginHandler(rr, req)

	// Check the status code
	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusOK)
	}

	// Check the response body or JWT token
	// Assert that the response contains a valid JWT token
}

func TestCalculatePlus(t *testing.T) {
	now := time.Now()
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"username": "qwe",
		"nbf":      now.Unix(),
		"exp":      now.Add(1 * time.Second).Unix(),
		"iat":      now.Unix(),
	})
	// Подписываем токен с секретным ключом
	tokenString, _ := token.SignedString([]byte("super_secret_signature"))
	expression := Expression{Operation: "+", Operand1: 5, Operand2: 3}
	req, _ := http.NewRequest("GET", "/add?expression=(1+3)*5-2*7&token="+tokenString, nil) // You might need to adjust this according to your actual request
	result := calculate_plus(expression, *req)
	expected := 8.0 // Expected result for 5 + 3
	if result.Value != expected {
		t.Errorf("calculate_plus(%v) = %f; want %f", expression, result.Value, expected)
	}
}

func TestCalculateMinus(t *testing.T) {
	now := time.Now()
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"username": "qwe",
		"nbf":      now.Unix(),
		"exp":      now.Add(1 * time.Second).Unix(),
		"iat":      now.Unix(),
	})
	// Подписываем токен с секретным ключом
	tokenString, _ := token.SignedString([]byte("super_secret_signature"))
	expression := Expression{Operation: "-", Operand1: 5, Operand2: 3}
	req, _ := http.NewRequest("GET", "/add?expression=(1+3)*5-2*7&token="+tokenString, nil) // You might need to adjust this according to your actual request
	result := calculate_minus(expression, *req)
	expected := 2.0 // Expected result for 5 - 3
	if result.Value != expected {
		t.Errorf("calculate_minus(%v) = %f; want %f", expression, result.Value, expected)
	}
}

func TestCalculateMultiply(t *testing.T) {
	now := time.Now()
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"username": "qwe",
		"nbf":      now.Unix(),
		"exp":      now.Add(1 * time.Second).Unix(),
		"iat":      now.Unix(),
	})
	// Подписываем токен с секретным ключом
	tokenString, _ := token.SignedString([]byte("super_secret_signature"))
	expression := Expression{Operation: "*", Operand1: 5, Operand2: 3}
	req, _ := http.NewRequest("GET", "/add?expression=(1+3)*5-2*7&token="+tokenString, nil) // You might need to adjust this according to your actual request
	result := calculate_multiply(expression, *req)
	expected := 15.0 // Expected result for 5 * 3
	if result.Value != expected {
		t.Errorf("calculate_multiply(%v) = %f; want %f", expression, result.Value, expected)
	}
}

func TestCalculateDivision(t *testing.T) {
	now := time.Now()
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"username": "qwe",
		"nbf":      now.Unix(),
		"exp":      now.Add(1 * time.Second).Unix(),
		"iat":      now.Unix(),
	})
	// Подписываем токен с секретным ключом
	tokenString, _ := token.SignedString([]byte("super_secret_signature"))
	expression := Expression{Operation: "/", Operand1: 6, Operand2: 3}
	req, _ := http.NewRequest("GET", "/add?expression=(1+3)*5-2*7&token="+tokenString, nil) // You might need to adjust this according to your actual request
	result := calculate_division(expression, *req)
	expected := 2.0 // Expected result for 6 / 3
	if result.Value != expected {
		t.Errorf("calculate_division(%v) = %f; want %f", expression, result.Value, expected)
	}
}

func TestRemove(t *testing.T) {
	testCases := []struct {
		inputSlice []string
		index      int
		expected   []string
	}{
		{[]string{"a", "b", "c", "d"}, 2, []string{"a", "b", "d"}},
		{[]string{"1", "2", "3", "4", "5"}, 0, []string{"2", "3", "4", "5"}},
		{[]string{"x", "y", "z"}, 1, []string{"x", "z"}},
	}

	for _, tc := range testCases {
		t.Run("", func(t *testing.T) {
			actual := remove(tc.inputSlice, tc.index)
			if !reflect.DeepEqual(actual, tc.expected) {
				t.Errorf("Expected %v, but got %v", tc.expected, actual)
			}
			if len(actual) != len(tc.inputSlice)-1 {
				t.Errorf("Expected length %d, but got %d", len(tc.inputSlice)-1, len(actual))
			}
		})
	}
}

func TestMain2_ValidExpression(t *testing.T) {
	expression := []string{"2", "3", "+"}
	ch := make(chan Result)
	now := time.Now()
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"username": "qwe",
		"nbf":      now.Unix(),
		"exp":      now.Add(1 * time.Second).Unix(),
		"iat":      now.Unix(),
	})
	// Подписываем токен с секретным ключом
	tokenString, _ := token.SignedString([]byte("super_secret_signature"))
	db, _ := sql.Open("sqlite3", "DataBase.db")
	req, _ := http.NewRequest("GET", "/add?expression=2+3&token="+tokenString, nil)
	go main2(expression, ch, *req, 1, db)
	result := <-ch
	if result.Err != nil {
		t.Errorf("Expected no error, got %v", result.Err)
	}
	if result.Value != 5 {
		t.Errorf("Expected result to be 5, got %f", result.Value)
	}
}

//func TestMain2_InvalidExpression(t *testing.T) {
//	expression := []string{"2", "+", "3"} // Invalid expression
//	ch := make(chan Result)
//	now := time.Now()
//	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
//		"username": "qwe",
//		"nbf":      now.Unix(),
//		"exp":      now.Add(1 * time.Second).Unix(),
//		"iat":      now.Unix(),
//	})
//	// Подписываем токен с секретным ключом
//	tokenString, _ := token.SignedString([]byte("super_secret_signature"))
//	req, _ := http.NewRequest("GET", "/add?expression=2+3"+tokenString, nil)
//	db, _ := sql.Open("sqlite3", "DataBase.db")
//	go main2(expression, ch, *req, 0, db)
//	result := <-ch
//	if result.Err == nil {
//		t.Error("Expected an error, got nil")
//	}
//}
//
//func TestMain2_DivisionByZero(t *testing.T) {
//	expression := []string{"2", "0", "/"} // Division by zero
//	ch := make(chan Result)
//	now := time.Now()
//	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
//		"username": "qwe",
//		"nbf":      now.Unix(),
//		"exp":      now.Add(1 * time.Second).Unix(),
//		"iat":      now.Unix(),
//	})
//	// Подписываем токен с секретным ключом
//	tokenString, _ := token.SignedString([]byte("super_secret_signature"))
//	req, _ := http.NewRequest("GET", "/add?expression=2/0&token="+tokenString, nil)
//	db, _ := sql.Open("sqlite3", "DataBase.db")
//	go main2(expression, ch, *req, 0, db)
//	result := <-ch
//	if result.Err == nil {
//		t.Error("Expected division by zero error, got nil")
//	}
//}
