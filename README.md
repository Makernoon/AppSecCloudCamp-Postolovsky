# Тестовое задание на стажировку AppSecCloudCamp
 
**Контактные данные** 
 - Постоловский Михаил
 - +7 928 766 31 65
 - mihailpostolovskij@gmail.com
 - @makernoon

## 1. Вопросы для разогрева

1. Расскажите, с какими задачами в направлении безопасной разработки вы сталкивались? 
2. Если вам приходилось проводить security code review или моделирование угроз, расскажите, как это было? 
3. Если у вас был опыт поиска уязвимостей, расскажите, как это было? 
4. Почему вы хотите участвовать в стажировке?
   

---

## 2. Security code review

### Часть 1. Security code review: GO

Требуется провести анализ кода на GO с точки зрения безопасности и подготовить отчет по следующим пунктам:
 - Какие уязвимости присутствуют в этом фрагменте кода?
   
   - SQL-инъекции

   
 - Указать строки, в которых присутствуют уязвимости.

   
     **Потенциальная SQL-инъекция**
     ```
     query := fmt.Sprintf("SELECT * FROM products WHERE name LIKE '%%%s%%'", searchQuery)
     ```

     
 - К каким последствиям может привести эксплуатация найденных уязвимостей злоумышленником?
   - Злоумышленник таким образом может получить несанкционированный доступ к конфиденциальным данным, которые хранятся в базе данных. Например, данные пользователей. Ему нужно лишь в ввод поиска добавить подобные данные
     ```
     a;SELECT * FROM users;
     ```
   - Это обернется в такой SQL-запрос:
     ```
      SELECT * FROM products WHERE name --LIKE '%a%'; SELECT * FROM users;
     ```
 - Описать способы исправления уязвимостей.
   - Валидировать и фильтровать входные данные. Подаваемые данные на вход должны соответствовать входному типу.
   - Экранирование. Добавлять / перед спецсимволами. Это укажет, что символ является продолжением строки, а значит это не повлияет на логику работы сервиса.
   - Использовать параметризованные запросы. Сначала СУБД анализирует и подготавливает сам запрос, формируя шаблон, и лишь только затем подставляет входные данные.  
 - Если уязвимость можно исправить несколькими способами, необходимо перечислить их, выбрать лучший по вашему мнению и аргументировать свой выбор.
   - Я выбираю параметризованные запросы. Из-за соотношения затраченного времени и результата. Достаточно добавлять в запросах символ ? для входных данных. Данный способ не только защищает от SQL инъекций, но и повышает эффективность выполнения запроса в случае, если он будет многократным.
     ```
     query := fmt.Sprintf("SELECT * FROM products WHERE name LIKE ? ", searchQuery)
     ```

```
package main

import (
    "database/sql"
    "fmt"
    "log"
    "net/http"
    "github.com/go-sql-driver/mysql"
)

var db *sql.DB
var err error

func initDB() {
    db, err = sql.Open("mysql", "user:password@/dbname")
    if err != nil {
        log.Fatal(err)
    }

err = db.Ping()
if err != nil {
    log.Fatal(err)
    }
}

func searchHandler(w http.ResponseWriter, r *http.Request) {
    if r.Method != "GET" {
        http.Error(w, "Method is not supported.", http.StatusNotFound)
        return
    }

searchQuery := r.URL.Query().Get("query")
if searchQuery == "" {
    http.Error(w, "Query parameter is missing", http.StatusBadRequest)
    return
}

query := fmt.Sprintf("SELECT * FROM products WHERE name LIKE '%%%s%%'", searchQuery)
rows, err := db.Query(query)
if err != nil {
    http.Error(w, "Query failed", http.StatusInternalServerError)
    log.Println(err)
    return
}
defer rows.Close()

var products []string
for rows.Next() {
    var name string
    err := rows.Scan(&name)
    if err != nil {
        log.Fatal(err)
    }
    products = append(products, name)
}

fmt.Fprintf(w, "Found products: %v\n", products)
}

func main() {
    initDB()
    defer db.Close()

http.HandleFunc("/search", searchHandler)
fmt.Println("Server is running")
log.Fatal(http.ListenAndServe(":8080", nil))
}
```

### Часть 2: Security code review: Python

Требуется определить тип уязвимости в примерах кода на Python и ответить на следующие вопросы:
 - Указать строки, в которых присутствуют уязвимости.
   
    **XSS уязвимость**
   
    **Пример №2.1**
     ```
     @app.route("/page")
    def page():
    name = request.values.get('name')
    age = request.values.get('age', 'unknown')
    output = Template('Hello ' + name + '! Your age is ' + age + '.').render()
    return output
     ```

    **Внедрение команд ОС**

    **Пример №2.2**
     ```
    @app.route("/dns")
    def dns_lookup():
    hostname = request.values.get('hostname')
    cmd = 'nslookup ' + hostname
    output = subprocess.check_output(cmd, shell=True, text=True)
    return output
     ```
 - К каким последствиям может привести эксплуатация данных уязвимостей злоумышленником?
   
   **Пример №2.1**
    - Злоумышленник может украсть конфиденциальные данные, перехватить куки или токены состояния, нарушить логику работы веб-приложения. Это достигается благодаря встраиванию скриптов в пользовательский ввод.
      
   **Пример №2.2**
    - Злоумышленник может все так же украсть конфиденциальные данные, узнать скрытые сведения о системе, нарушить работу ОС, что напрямую повлияет на веб-приложение. Происходит так из-за встраивания команд ОС в пользовательский ввод. 
 - Описать способы исправления уязвимостей.

    **Пример №2.1**
   - Использовать политику CSP. Это функция браузера, которая помогает обнаружить и предотвратить определенные типы атак, включая XSS и атаки с внедрением данных
   - Валидировать и фильтровать входные данные. Проверять допустимость вводимых данных, этого можно достигнуть при помощи черных и белых списков, где бы хранились допустимые значение.
  
    **Пример №2.2**
   - WAF
   - CSP
 - Если уязвимость можно исправить несколькими способами, необходимо перечислить их, выбрать лучший по вашему мнению и аргументировать свой выбор.

**Пример №2.1**
```
from flask import Flask, request
from jinja2 import Template

app = Flask(name)

@app.route("/page")
def page():
    name = request.values.get('name')
    age = request.values.get('age', 'unknown')
    output = Template('Hello ' + name + '! Your age is ' + age + '.').render()
return output

if name == "main":
    app.run(debug=True)
```

**Пример №2.2**
```
from flask import Flask, request
import subprocess

app = Flask(name)

@app.route("/dns")
def dns_lookup():
    hostname = request.values.get('hostname')
    cmd = 'nslookup ' + hostname
    output = subprocess.check_output(cmd, shell=True, text=True)
return output
if name == "main":
    app.run(debug=True)
```

## 3. Моделировани угроз

Изучите диаграмму потоков данных (Data Flow Diagram, DFD) сервиса, обеспечивающего отправку информации в Telegram и Slack:

![DFD](https://github.com/appseccloudcamp/test-assignment/blob/main/test-dfd.png)

Краткое описание компонентов сервиса:
 - **User** - авторизованный пользователь системы. Может настраивать отправку уведомлений и загружать изображения для дальнейшего использования при отправке уведомлений;
 - **Microfront** - микрофронт, которые позволяет взаимодействовать с сервисом отправки информации;
 - **Backend application** - набор микросервисов реализующих бизнес-логику приложения и обеспечивающих взаимодействие со всеми внешними сервисами;
 - **Auth** - сервис отвечающий за аутентификацию и авторизацию клиентов сервиса отправки информации;
 - **S3** - объектное хранилище, предназначенное для хранения статического контента сервиса отправки информации;
 - **PostgreSQL** - база данных, предназначенная для хранения пользовательских конфигураций сервиса отправки информации.    

Проанализируйте диаграмму потоков данных приложения и ответьте на следующий вопросы:
 - Расскажите, какие потенциальные проблемы безопасности существуют для данного сервиса?
 - Расскажите, к каким последствиям может привести эксплуатация проблем, найденных вами?
 - Расскажите, какие способы исправления уязвимостей и смягчения рисков вы можете предложить по отмеченным вами проблемам безопасности?
 - Напишите список уточняющих вопросов, которые вы бы задали разработчикам данного сервиса?
