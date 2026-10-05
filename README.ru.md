# ycauth

[Английская версия](./README.md)

`ycauth` — набор небольших Go-модулей для приложений с короткоживущими
IAM-токенами Yandex Cloud. В него входят источники токенов, потокобезопасный
кэш, временные учётные данные для Object Storage через AWS SDK v2 и
IAM-аутентификация новых соединений pgx v5.

Подключайте только нужные модули:

- `github.com/skarm/ycauth` — источники IAM-токенов и `Cache`;
- `github.com/skarm/ycauth/s3iam` — временные учётные данные Object Storage для
  AWS SDK for Go v2;
- `github.com/skarm/ycauth/pgxiam` — IAM-аутентификация новых физических
  соединений pgx.

Для всех модулей нужен Go 1.25 или новее. Добавьте опубликованную версию
нужного модуля в `go.mod`:

```bash
go get github.com/skarm/ycauth@<version>
go get github.com/skarm/ycauth/s3iam@<version> # только Object Storage
go get github.com/skarm/ycauth/pgxiam@<version> # только PostgreSQL
```

## Архитектура

```text
imds.Source или authzkey.Source
                │
                ▼
            ycauth.Cache ──── TokenProvider ──── s3iam или pgxiam
```

`TokenSource` получает свежий токен. `Cache` превращает его в потокобезопасный
`TokenProvider` для горячего пути запроса или создания соединения. `s3iam` и
`pgxiam` используют этот поставщик токенов, но сами не хранят долгоживущий
IAM-токен.

Исходящие запросы по умолчанию содержат `User-Agent: ycauth`. Если приложению
нужно представиться, задайте свой заголовок через `imds.WithUserAgent`,
`authzkey.WithUserAgent` или `s3iam.Config.UserAgent`.

## Источник и кэш IAM-токена

Создайте один `Cache` для каждой независимой учётной записи и конфигурации,
затем используйте его во всех клиентах. Он безопасен для конкурентного
использования.

### Виртуальная машина Compute Cloud: сервис метаданных экземпляра

На виртуальной машине Compute Cloud с прикреплённым сервисным аккаунтом
используйте `imds`. Аббревиатура IMDS означает *instance metadata service* —
сервис метаданных экземпляра виртуальной машины. Источник получает IAM-токен
прикреплённого сервисного аккаунта без файла ключа авторизации.

```go
source, err := imds.New()
if err != nil {
	return err
}

tokens, err := ycauth.NewCache(source, ycauth.CacheConfig{})
if err != nil {
	return err
}
```

Стандартный адрес сервиса метаданных является локальным для канала связи
(link-local) и намеренно использует HTTP. Он доступен только из виртуальной
машины; стандартный клиент отключает прокси и переходы
по перенаправлениям. Вне Compute Cloud этот адрес обычно недоступен.

### Другие окружения: ключ сервисного аккаунта

Если сервис метаданных экземпляра недоступен, используйте ключ сервисного
аккаунта:

```go
source, err := authzkey.NewFile("authorized-key.json")
if err != nil {
	return err
}

tokens, err := ycauth.NewCache(source, ycauth.CacheConfig{})
if err != nil {
	return err
}
```

`authzkey` проверяет JSON-документ и RSA-ключ, затем обменивает
короткоживущий подписанный JWT на IAM-токен. Права доступа к файлу он не
проверяет: безопасное хранение закрытого ключа и выдача доступа к нему — задача
приложения.

Пользовательские адреса API учётных данных должны использовать HTTPS. HTTP
разрешён только для loopback — так работают локальные эмуляторы и тесты, не
выпуская учётные данные в сеть; для адреса службы метаданных дополнительно
разрешён link-local, где она и отвечает. Клиенты API учётных данных, включая
переданный вами, имеют ограниченное время ожидания и не переходят по
перенаправлениям.

### Поведение кэша

При `CacheConfig{}` `Cache` запускает фоновое обновление за пять минут до
истечения токена, ограничивает одно обновление десятью секундами и не обновляет
валидный токен чаще раза в пять секунд — если только токен не истекает раньше.

- При попадании в кэш `Cache` читает атомарный снимок и часы один раз, без
  мьютекса. Монотонная составляющая планирует обновление, а календарная
  проверяет абсолютный срок действия токена.
- В окне обновления вызывающий сразу получает валидный токен, пока одно общее
  обновление выполняется в фоне.
- Когда кэш пуст или токен истёк, вызывающие ждут то же общее обновление.
  Отмена одного контекста отменяет только его ожидание, но не общее обновление.
- При ошибке обновления предыдущий токен может быть возвращён только до его
  фактического истечения. Следующие попытки ограничиваются экспоненциальной
  задержкой.
- Паника из `TokenSource` становится ошибкой обновления, а не завершает процесс.

Меняйте `CacheConfig`, только если значения по умолчанию не подходят нагрузке.
Каждое нулевое поле сохраняет значение по умолчанию, включая поля
`BackoffConfig`:

```go
tokens, err := ycauth.NewCache(source, ycauth.CacheConfig{
	RefreshBefore: 2 * time.Minute,
	RefreshTimeout: 5 * time.Second,
	Backoff: ycauth.BackoffConfig{
		Initial:    time.Second,
		Max:        30 * time.Second,
		Multiplier: 2,
		Jitter:     0.2,
	},
})
```

`RefreshEvent` и `Observer` дают данные для наблюдаемости обновлений, не
раскрывая токен. Наблюдатель должен быстро завершаться; его паника
перехватывается.

### Ошибки и принудительное обновление

Когда механизм задержек подавляет новое получение токена, это можно отличить через
`errors.Is`:

```go
token, err := tokens.Token(ctx)
if errors.Is(err, ycauth.ErrBackoff) {
	// Предыдущее обновление завершилось ошибкой; повтор пока ограничен.
}
```

Вызывайте `tokens.Invalidate()` только когда невалиден сам IAM-токен. Например,
если новое PostgreSQL-соединение не прошло из-за устаревших IAM-учётных данных,
инвалидируйте кэш и повторите создание соединения. Неверного пользователя БД,
роли или адреса службы новый токен не исправит.

`*ycauth.APIError` содержит статус HTTP, идентификатор запроса, ограниченный
фрагмент тела ответа и `Retry-After`. Подсказка `Retry-After` соблюдается как
есть, но ограничена несколькими минутами: один ответ не может приостановить
обновления на произвольно долгий срок. Тело ответа недоверенное и может быть
чувствительным, поэтому не логируйте его без необходимости.

Постоянные ошибки аутентификации, например HTTP 401/403 после отзыва ключа,
не прекращают повторные попытки: последующие вызовы `Token` могут запускать
новые попытки после экспоненциального backoff с ограниченной максимальной
задержкой, без ограничения числа попыток. Используйте
`var apiErr *ycauth.APIError`, `errors.As(err, &apiErr)` и
`apiErr.Temporary()`, чтобы решить, должно ли приложение прекратить повторы.

## Yandex Object Storage с AWS SDK v2

`s3iam.New` запрашивает эфемерные AWS-совместимые учётные данные для Yandex
Object Storage и возвращает
`*aws.CredentialsCache`. Присвойте его напрямую в `aws.Config`:

```go
policy, err := s3iam.PrefixPolicy(
	"my-bucket",
	"tenant/42",
	s3iam.PermissionReadObject |
		s3iam.PermissionListObjects |
		s3iam.PermissionWriteObject |
		s3iam.PermissionMultipartUpload,
)
if err != nil {
	return err
}

credentials, err := s3iam.New(tokens, s3iam.Config{
	SessionName:   "orders-api",
	Duration:      time.Hour,
	SessionPolicy: policy,
})
if err != nil {
	return err
}

awsConfig.Credentials = credentials
```

Обязательно только поле `SessionName`. `SessionPolicy` опционально: без него
временные учётные данные получают все права Object Storage, уже выданные
субъекту. `Duration` — целое число секунд от 15 минут до 12 часов; ноль означает
один час. `RefreshTimeout` ограничивает всё обновление, включая получение
IAM-токена; значение по умолчанию — десять секунд.

Кэш AWS обновляет учётные данные заранее. Yandex Cloud может ограничить время
жизни эфемерного ключа оставшимся временем IAM-токена, поэтому `s3iam`
ограничивает окно раннего обновления фактическим временем жизни учётных данных.
Скорректированное время кэша AWS не считается фактическим временем истечения
ключа.

### Политика с минимальными правами

`PrefixPolicy` строит компактную встроенную политику для одного бакета и
префикса объектов. Имя бакета проверяется по правилам Yandex Object Storage. Префикс
используется ровно в переданном виде: он не может начинаться или заканчиваться
`/` и не может содержать метасимволы политики (`*`, `?`, `$`) либо управляющие
символы.

- `PermissionReadObject` — скачивание;
- `PermissionListObjects` — список объектов под выбранным префиксом;
- `PermissionWriteObject` — загрузка;
- `PermissionDeleteObject` — удаление;
- `PermissionMultipartUpload` — операции составной загрузки (multipart) над выбранными объектами; включает то же право `s3:PutObject`, что и `PermissionWriteObject`;
- `PermissionBucketLocation` — чтение расположения бакета.

Пустой префикс намеренно означает весь бакет, поэтому передавайте его только
осознанно: незаполненная переменная расширит политику, а не вызовет ошибку.

`PermissionMultipartUpload` не выдаёт `s3:ListBucketMultipartUploads`: эта
операция показывает незавершённые загрузки всего бакета. Используйте `RawPolicy`,
только если типизированная политика не выражает нужное право. Она проверяет
синтаксис JSON и уплотняет документ, но не может доказать безопасность
произвольной политики. Компактный документ должен укладываться в лимит Yandex
Cloud в 2048 символов.

Для нескольких бакетов или префиксов одного бакета используйте `PrefixPolicies`:

```go
policy, err := s3iam.PrefixPolicies(
	s3iam.PrefixGrant{
		Bucket:      "source-bucket",
		Prefix:      "incoming",
		Permissions: s3iam.PermissionReadObject | s3iam.PermissionListObjects,
	},
	s3iam.PrefixGrant{
		Bucket:      "target-bucket",
		Prefix:      "processed",
		Permissions: s3iam.PermissionWriteObject,
	},
)
if err != nil {
	log.Fatal(err)
}
credentials, err := s3iam.New(tokens, s3iam.Config{
	SessionName:   "copy-objects",
	SessionPolicy: policy,
})
if err != nil {
	log.Fatal(err)
}
```

Один провайдер учётных данных можно использовать для всех перечисленных бакетов.
Каждый `PrefixGrant` сохраняет собственные права и условия листинга. Права
складываются: более узкое правило не ограничивает более широкое. Пустой список
правил и любое невалидное правило вызывают ошибку; лимит 2048 символов применяется
ко всему документу. `PrefixPolicy` остаётся сокращённой формой для одного правила.

### Обновление отклонённых S3-учётных данных

При `ExpiredToken`, `InvalidToken` или `TokenRefreshRequired` от Object Storage
инвалидируйте кэш учётных данных AWS, а не кэш IAM-токенов:

```go
credentials.Invalidate()
```

Эти ошибки используют HTTP 400. Невалидный ключ доступа, данные безопасности
или подпись могут дать HTTP 403. См. официальный [список кодов ответа Object
Storage](https://yandex.cloud/ru/docs/storage/s3/api-ref/response-codes).

## Подготовка сервисного аккаунта для PostgreSQL

Перед использованием `pgxiam` настройте сервисный аккаунт и кластер:

- В качестве имени пользователя PostgreSQL используйте ID сервисного аккаунта
  вида `aje...`. Имя сервисного аккаунта, например `my-service-account`, в DSN
  не подходит.
- IAM-токен должен принадлежать тому же сервисному аккаунту, чей ID указан как
  пользователь. Передайте `TokenProvider`, получающий токен из контекста или
  метаданных среды выполнения. На виртуальной машине Compute Cloud используйте
  `imds`, а при отсутствии метаданных — авторизованный ключ через `authzkey`.
- Назначьте подключающемуся сервисному аккаунту роль
  `iam.serviceAccounts.user` на этот же сервисный аккаунт как на ресурс или на
  содержащий его каталог. Роль нужна Odyssey для чтения информации об
  аккаунте. Более широкая роль, например примитивная `auditor`, также подходит,
  но для минимальных привилегий используйте `iam.serviceAccounts.user`.
- Отдельно назначьте сервисному аккаунту на целевой кластер роль
  `managed-postgresql.clusters.connector`. Создайте в кластере пользователя с
  именем, равным ID сервисного аккаунта, методом аутентификации IAM и доступом
  к нужной базе данных. Эти ресурсы `pgxiam` не создаёт.

Минимальную роль можно назначить непосредственно на сервисный аккаунт:

```bash
yc iam service-account add-access-binding <service-account-id> \
  --role iam.serviceAccounts.user \
  --subject serviceAccount:<service-account-id>
```

Или назначить её на каталог, от которого сервисный аккаунт унаследует права:

```bash
yc resource-manager folder add-access-binding <folder-id> \
  --role iam.serviceAccounts.user \
  --subject serviceAccount:<service-account-id>
```

Настройте доступ к кластеру и создайте пользователя БД следующими командами:

```bash
yc managed-postgresql cluster add-access-binding \
  --id <cluster-id> \
  --role managed-postgresql.clusters.connector \
  --service-account-id <service-account-id>

yc managed-postgresql user create <service-account-id> \
  --cluster-id <cluster-id> \
  --auth-method auth-method-iam \
  --permissions <database-name>
```

Проверьте, что ID в DSN, субъект этих назначений и владелец IAM-токена — один
и тот же сервисный аккаунт. Подробности см. в документации по
[правам на сервисный аккаунт](https://yandex.cloud/ru/docs/iam/operations/sa/set-access-bindings),
[назначению ролей](https://yandex.cloud/ru/docs/iam/operations/roles/grant) и
[подключению к PostgreSQL через IAM](https://yandex.cloud/ru/docs/managed-postgresql/operations/connect/clients).

## PostgreSQL с pgxpool

IAM-токен передаётся как пароль подключения. В качестве логина в DSN укажите
ID сервисного аккаунта вида `aje...`, а не его имя. DSN также обязан
устанавливать TLS: используйте `sslmode=verify-full` с CA Yandex Cloud.
Значение по умолчанию в pgx — `sslmode=prefer` — молча откатывается на
незашифрованное соединение, и `pgxiam` этого не увидит: он настраивает
подключения, а не согласовывает их.

Настройте IAM-аутентификацию до открытия пула:

```go
poolConfig, err := pgxpool.ParseConfig(databaseURL)
if err != nil {
	return err
}

if authMode == "iam" {
	pgxiam.ConfigurePool(poolConfig, tokens)
}

pool, err := pgxpool.NewWithConfig(ctx, poolConfig)
if err != nil {
	return err
}
defer pool.Close()

if err := pool.Ping(ctx); err != nil {
	return err
}
```

`ConfigurePool` сохраняет `BeforeConnect` и запускает его первым. Перед каждым
физическим соединением IAM-токен записывается в локальную для соединения копию
конфигурации pgx, поэтому базовая конфигурация пула не хранит токен. Не храните
постоянный пароль в IAM DSN: IAM-учётные данные записываются последними и
заменяют его.

Уже аутентифицированные соединения не нужно закрывать из-за истечения
IAM-токена. Он нужен при создании нового физического соединения, а не для
каждого SQL-запроса.

## PostgreSQL с database/sql

Используйте стандартный коннектор pgx вместо `sql.Open("pgx", dsn)`: у него
статичный DSN и он не умеет менять IAM-токен.

```go
connectionConfig, err := pgx.ParseConfig(databaseURL)
if err != nil {
	return err
}

db := stdlib.OpenDB(*connectionConfig, pgxiam.StdlibOption(tokens))
defer db.Close()

db.SetMaxOpenConns(20)
db.SetMaxIdleConns(10)
db.SetConnMaxLifetime(time.Hour)

if err := db.PingContext(ctx); err != nil {
	return err
}
```

Адрес подключения должен быть настроен для IAM-аутентификации. Библиотека не
создаёт облачные ресурсы и не ищет адреса базы данных.

## Безопасность и эксплуатация

- IAM-токены, закрытые ключи, ключи доступа, секретные ключи и сеансовые токены
  являются секретами. `Token` скрывает значение в JSON, `%s`, `%#v` и `slog`,
  но прямое чтение `Token.Value` остаётся чувствительным.
- HTTP-ответы, файлы ключей и документы политик валидируются. Отсутствующий
  (`nil`) `TokenProvider` или `TokenSource` отклоняется там, где он передаётся:
  конструкторы возвращают ошибку, а построители хуков `pgxiam` вызывают панику.
  `Cache.Token` возвращает ошибку при `nil`-контексте независимо от наличия
  токена в кэше.
- В Compute Cloud предпочитайте `imds`: тогда закрытый ключ сервисного
  аккаунта не нужно распространять в приложение.
- Используйте один `Cache` и один кэш учётных данных AWS на учётную запись и
  конфигурацию; создание их на каждый запрос отменяет объединение обновлений.

## Разработка и релизы

Модули версионируются независимо. `go.work` намеренно игнорируется, поэтому CI
тестирует каждый модуль вне рабочей области.

```bash
go test -race ./...
go vet ./...
golangci-lint run ./...
```

При изменении API корневого модуля для `s3iam` или `pgxiam` добавляйте в
подмодуль локальную некоммитимую директиву
`replace github.com/skarm/ycauth => ..`.
Сначала выпустите корневой модуль, обновите зависимость подмодуля на опубликованную версию, затем
запустите `go mod tidy -diff`, `go build ./...`, `go vet ./...` и
`go test -race ./...` с `GOWORK=off` и без директивы replace перед тегированием
подмодуля.

## Сообщение об уязвимостях

Сообщайте об уязвимостях приватно через GitHub Security Advisories репозитория,
а не через публичную задачу.

## Лицензия

[MIT](./LICENSE).
