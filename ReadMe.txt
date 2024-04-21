Урок Спринт «Финальный проект»


Распределённый калькулятор. Часть 2

Автор: Виктор Копытов
t.me/VictorKopytov


В проекте реализовано:

1. Добавлена регистрация пользователя. Добавлен вход (Реализована авторизация). Весь реализованный ранее функционал работает как раньше, только в контексте конкретного пользователя.
2. Хранение выражений перенесено из памяти в SQLite. Теперь система способна переживать перезагрузку.
3. Реализовано покрытие проекта модульными тестами.
4. Реализовано покрытие проекта интеграционными тестами.


Инструкция по эксплуатации:

1. Открыть файл orchestrator.go в среде разработки Visual Studio Code.
2. Запустить файл orchestrator.go в Терминале Visual Studio Code командой: go run orchestrator.go.
3. Для регистрации пользователя на сайте в адресной строке браузера необходимо ввести ссылку в формате: http://127.0.0.1:8080/register?username=VictorKopytov&password=qwerty123,
где параметр username отвечает за имя пользователя, параметр password – пароль.
4. Для авторизации пользователя на сайте в адресной строке браузера необходимо ввести ссылку в формате:
http://127.0.0.1:8080/login?username=VictorKopytov&password=qwerty123,
где параметр username отвечает за имя пользователя, параметр password – пароль.
После авторизации в окне браузера отобразится токен (Образец: {"token":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3MTM2OTc4NTcsImlhdCI6MTcxMzY5NzY3NywibmJmIjoxNzEzNjk3Njc3LCJ1c2VybmFtZSI6IjUifQ.DhT7MBRs0axGCELC2SdWKXCP7EL8ZeUH-WifXfN6sls"}), который необходимо сохранить для дальнейшего взаимодействия с сайтом.
5. Для настройки времени выполнения арифметических операций, в адресной строке браузера необходимо ввести ссылку в формате: 
127.0.0.1:8080/settime?time+=10&time-=10&time*=10&time/=10&time_limit=60&token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3MTM2OTc4NTcsImlhdCI6MTcxMzY5NzY3NywibmJmIjoxNzEzNjk3Njc3LCJ1c2VybmFtZSI6IjUifQ.DhT7MBRs0axGCELC2SdWKXCP7EL8ZeUH-WifXfN6sls
где параметр time+ отвечает за время выполнения операции сложения;
параметр time- отвечает за время выполнения операции вычитания;
параметр time* отвечает за время выполнения операции умножения;
параметр time/ отвечает за время выполнения операции деления;
параметр time_limit отвечает за лимит времени на выполнение всего арифметического выражения. Единица измерения всех параметров – 1 сек;
параметр token  - ранее сохраненный токен.
6. Для отправки арифметического выражения в адресной строке браузера необходимо ввести ссылку в формате:
127.0.0.1:8080/add?expression=(1+3)*5-2*7&token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3MTM2OTc4NTcsImlhdCI6MTcxMzY5NzY3NywibmJmIjoxNzEzNjk3Njc3LCJ1c2VybmFtZSI6IjUifQ.DhT7MBRs0axGCELC2SdWKXCP7EL8ZeUH-WifXfN6sls
где параметр expression отвечает за содержание арифметического выражения
ВНИМАНИЕ! Ввод параметра expression осуществляется, строго, без пробелов;
параметр token  - ранее сохраненный токен.
На открывшейся странице отобразится сообщениие: «Expression added by user» означающее, что выражение отправлено на вычисление.
7. Для просмотра страницы со списком выражений в виде списка с выражениями, в адресной строке браузера необходимо ввести ссылку в формате:
127.0.0.1:8080/list?token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3MTM2OTc4NTcsImlhdCI6MTcxMzY5NzY3NywibmJmIjoxNzEzNjk3Njc3LCJ1c2VybmFtZSI6IjUifQ.DhT7MBRs0axGCELC2SdWKXCP7EL8ZeUH-WifXfN6sls,
где параметр token  - ранее сохраненный токен.


В файле LookMe.mkv находится видеоинструкция.
