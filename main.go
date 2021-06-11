package main

import (
  "github.com/dgrijalva/jwt-go"
  "github.com/gin-gonic/gin"
  "log"
  "net/http"
  "time"

  "fmt"
  "strings"

  "database/sql"
  _ "github.com/go-sql-driver/mysql"

  "golang.org/x/crypto/bcrypt"
)

var (
  router = gin.Default()
  db, _ = sql.Open("mysql", "root:@tcp(127.0.0.1:3306)/golang")
)

func main() {
  router.POST("/login", Login)
  router.POST("/register", Register)
  router.POST("/upload-picture", UploadPicture)
  router.GET("/images", GetPictures)
  log.Fatal(router.Run(":8080"))
}


type User struct {
  Id uint64 `json:"id"`
  Username string `json:"username"`
  PasswordHash string `json:"password_hash"`
}

type Image struct {
  UserId string `json:"user_id"`
  ImagePath string `json:"image_path"`
}

func Login(c *gin.Context) {

  var u User
  if err := c.ShouldBindJSON(&u); err != nil {
     c.JSON(http.StatusUnprocessableEntity, "Помилка формату")
     return
  }

  res, err := db.Query("SELECT * FROM `users`")
  if err != nil { panic(err) }

  for res.Next() {

    var user User
    err = res.Scan(&user.Id, &user.Username, &user.PasswordHash)
    if err != nil { panic(err) }

    compare := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(u.PasswordHash))

    if user.Username != u.Username || compare != nil {
      if user.Username == u.Username {
        compare := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(u.PasswordHash))

        fmt.Println(u.PasswordHash, user.PasswordHash)

        if compare != nil {
          c.JSON(http.StatusUnauthorized, gin.H{ "error": "Пароль неправильний", })
          return
        }
      }

    } else {
      token, err := CreateToken(user.Id)

      if err != nil {
         c.JSON(http.StatusUnprocessableEntity, gin.H{ "error": err.Error(), })
         return
      }

      c.JSON(http.StatusOK, gin.H{ "token": string(token), })

      return
    }

  }

  c.JSON(http.StatusUnauthorized, gin.H{ "error": "Логін неправильний", })
  return

}

func Register(c *gin.Context) {
  var u User
  if err := c.ShouldBindJSON(&u); err != nil {
     c.JSON(http.StatusUnauthorized, gin.H{ "error": "Помилка формату", })
     return
  }

  fmt.Println(u.Username, u.PasswordHash)

  password := []byte(u.PasswordHash)

  hashedPassword, err := bcrypt.GenerateFromPassword(password, bcrypt.DefaultCost)
  if err != nil {
      panic(err)
  }


  insert, err := db.Query("INSERT INTO `users` (`username`, `password_hash`) VALUES(?, ?)", u.Username, hashedPassword)
  if err != nil { c.JSON(http.StatusUnprocessableEntity, gin.H{ "error": err.Error(), })
  return }
  defer insert.Close()

  c.JSON(http.StatusOK, gin.H{ "response": "Реєстрація успішна", })
  return

}

func CreateToken(userId uint64) (string, error) {
  var err error

  atClaims := jwt.MapClaims{}
  atClaims["authorized"] = true
  atClaims["user_id"] = userId
  atClaims["exp"] = time.Now().Add(time.Hour * 12).Unix()
  at := jwt.NewWithClaims(jwt.SigningMethodHS256, atClaims)
  token, err := at.SignedString([]byte("1234567890"))
  if err != nil {
     return "", err
  }
  return token, nil
}



func GetPictures(c *gin.Context) {
  header := c.GetHeader("Authorization")

  if header == "" {
    c.JSON(http.StatusUnprocessableEntity, gin.H{ "error": "Пустий хеадер", })
    return
  }

  headerParts := strings.Split(header, " ")

  if len(headerParts) != 2 {
    c.JSON(http.StatusUnprocessableEntity, gin.H{ "error": "Неправильний формат хеадеру", })
    return
  }

  claims := jwt.MapClaims{}
  _, err := jwt.ParseWithClaims(headerParts[1], &claims, func(token *jwt.Token) (interface{}, error) {
      return []byte("1234567890"), nil
  })

  if err != nil{
    c.JSON(http.StatusUnauthorized, gin.H{ "error": "Токен не валідний", })
    return
  }

  user_id := claims["user_id"].(float64)
  fmt.Println(user_id)

  res, err := db.Query("SELECT `user_id`, `image_path` FROM `images`")
  if err != nil { panic(err) }

  var arrayImages []string

  for res.Next() {
    var img Image
    err = res.Scan(&img.UserId, &img.ImagePath)
    if err != nil {
        panic(err)
    }
    if fmt.Sprint(user_id) == img.UserId{
      arrayImages = append(arrayImages, img.ImagePath)
    }

  }

  c.JSON(http.StatusOK, gin.H{"images": arrayImages})


}

func UploadPicture(c *gin.Context) {

  header := c.GetHeader("Authorization")

  if header == "" {
    c.JSON(http.StatusUnprocessableEntity, gin.H{ "error": "Пустий хеадер", })
    return
  }

  headerParts := strings.Split(header, " ")

  if len(headerParts) != 2 {
    c.JSON(http.StatusUnprocessableEntity, gin.H{ "error": "Неправильний формат хеадеру", })
    return
  }

  claims := jwt.MapClaims{}
  _, err := jwt.ParseWithClaims(headerParts[1], &claims, func(token *jwt.Token) (interface{}, error) {
      return []byte("1234567890"), nil
  })

  if err != nil{
    c.JSON(http.StatusUnauthorized, gin.H{ "error": "Токен не валідний", })
    return
  }

  //for key, val := range claims {
      //c.JSON(http.StatusUnauthorized, gin.H{ key: val, })
  //}

  user_id := claims["user_id"].(float64)
  fmt.Println(user_id)


  file, err := c.FormFile("image")
	if err != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{ "error": "Завантажити фото не вдалося", })
    return
	}

  fileName := setPathName(file.Filename)

  err = c.SaveUploadedFile(file, fileName)
	if err != nil {
    c.JSON(http.StatusUnprocessableEntity, gin.H{ "error": "Зберегти фото не вдалося", })
    return
	}

  insert, err := db.Query("INSERT INTO `images` (`user_id`, `image_path`) VALUES(?, ?)", user_id, fileName)
  if err != nil {
    c.JSON(http.StatusUnprocessableEntity, gin.H{ "error": err.Error(), })
    return
  }
  defer insert.Close()

  c.JSON(http.StatusUnprocessableEntity, gin.H{ "response": "Фото успішно збережено", })


}

func setPathName(name string) string{
  filePathNameNow := time.Now().String()
  filePathNameSplit := strings.Split(filePathNameNow, " ")
  str := filePathNameSplit[0] + filePathNameSplit[1]
  filePathName := "images/"+strings.ReplaceAll(strings.ReplaceAll(strings.ReplaceAll(strings.ReplaceAll(str, "/", ""), ":", ""), ".", ""), "-", "")+name

  return filePathName
}
