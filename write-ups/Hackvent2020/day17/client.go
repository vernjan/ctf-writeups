package main

import "fmt"
import "io/ioutil"
import "net/http"
import "github.com/CUCyber/ja3transport"
//import "strings"

func main() {
  client, _ := ja3transport.NewWithString("771,49162-49161-52393-49200-49199-49172-49171-52392,0-13-5-11-43-10,23-24,0")

  // Get homepage
  req, _ := http.NewRequest("GET", "https://876cfcc0-1928-4a71-a63e-29334ca287a0.rdocker.vuln.land/", nil)
  req.Header.Set("Cookie", "session=eyJraWQiOiIxZDIxYTlmOTQ1IiwiYWxnIjoiSFM1MTIifQ.eyJzdWIiOiJzYW50YTEzMzciLCJpYXQiOjE2MDgyMjgzNDQsImV4cCI6MTYwODMxNDc0NH0.ly4-lXnExyYE4bm2n42shPxK-XXHNaVLVcTMkeo13Q1DUYhalUViA3ereutshmHTNtL3tdrnZAxlGQSkkAM1FQ")
  resp, _ := client.Do(req)

  // Send login
  // req, _ := http.NewRequest("POST", "https://876cfcc0-1928-4a71-a63e-29334ca287a0.rdocker.vuln.land/login", strings.NewReader("username=admin&password=admin"))
  // req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
  // resp, _ := client.Do(req)

  // Get key
  //req, _ := http.NewRequest("GET", "https://876cfcc0-1928-4a71-a63e-29334ca287a0.rdocker.vuln.land/keys/1d21a9f945", nil)
  //resp, _ := client.Do(req)

  // Print response headers
  for k, v := range resp.Header {
    fmt.Print(k)
    fmt.Print(" : ")
    fmt.Println(v)
  }

  // Print response body
  defer resp.Body.Close()
  bodyBytes, _ := ioutil.ReadAll(resp.Body)
  bodyString := string(bodyBytes)
  fmt.Print(bodyString)
}
