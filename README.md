# cveBot

cronとdockerを使ってcveを通知するbot

## bot

NVDからCVEのJSONとってきて、新着エントリをSlackにだすbot。  
cronにいいかんじに置けばいい。

(20分に1回動かす例)

```txt
$crontab -e
(snip)
cveBotUrl='[slack bot api url]'
*/20 * * * * /path/to/github/cveBot/bot/bot
```

## db

cve管理用のdb
