# cveBot

cronとdockerを使ってcveを通知するbot

## bot

NVDからCVEのJSONとってきて、新着エントリをSlackにだすbot。  
cronにいいかんじに置けばいい。

(20分に1回動かす例)

```txt
$crontab -e
(snip)
cveBotUrl='[slack webhook url]'
*/20 * * * * /path/to/github/cveBot/bot/bot
```

## db

cve管理用のdb

```txt
$ sudo docker-compose up -d
Creating network "db_default" with the default driver
Creating db_db_1 ... done
Attaching to db_db_1
(snip)
```
