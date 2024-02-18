package main

import (
	"context"
	"encoding/json"
	"fmt"
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

func addExpressionHandler(w http.ResponseWriter, r *http.Request) {
	expr := r.URL.Query().Get("expression")
	if expr == "" {
		http.Error(w, "Empty expression is not allowed", http.StatusBadRequest)
		return
	}
	fmt.Fprint(w, "id примера:")
	id := fmt.Sprintf("%d", time.Now().UnixNano())
	task := &Task{
		ID:      id,
		Expr:    expr,
		Result:  0,
		IsReady: false,
	}

	mu.Lock()
	tasks[id] = task
	expressions[id] = &Expression2{
		ID:         id,
		Expression: expr,
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
	mu.RLock()
	defer mu.RUnlock()
	expressionList := make([]*Expression2, 0, len(expressions))
	for _, expr := range expressions {
		expr.Expression = strings.Replace(expr.Expression, " ", "+", -1)
		expressionList = append(expressionList, expr)
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

func main() {
	http.HandleFunc("/add", addExpressionHandler)
	http.HandleFunc("/list", listExpressionsHandler)
	http.HandleFunc("/settime", settime)

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
		if expression[h] != "0" && expression[h] != "0" && expression[h] != "1" && expression[h] != "2" && expression[h] != "3" && expression[h] != "4" && expression[h] != "5" && expression[h] != "6" && expression[h] != "7" && expression[h] != "8" && expression[h] != "9" && expression[h] != "+" && expression[h] != "-" && expression[h] != "*" && expression[h] != "/" {
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
