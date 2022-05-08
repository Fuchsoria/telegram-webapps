
# Telegram WebApps
Tools for telegram web apps: https://core.telegram.org/bots/webapps

## Quick start:
**Install Package:**
`go get github.com/Fuchsoria/telegram-webapps`

**Add Imports:**
```
import (
	"fmt"
	"log"
	webapps "github.com/Fuchsoria/telegram-webapps"
)
```

**Use!:**
```
func  main() {
	token  :=  "BOT_TOKEN"
	data  :=  "WebAppInitData_from_TG"

	err, user  := webapps.VerifyWebAppData(data, token)
	if err !=  nil {
		log.Fatal(err)
	}

	fmt.Println(user)
}
```
