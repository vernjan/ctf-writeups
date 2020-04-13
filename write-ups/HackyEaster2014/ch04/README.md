# 04 - Nothing to see here

_There's nothing to see here. Go back. Please follow the order. Go back._

![](nothingtoseehere.jpg)

---

I couldn't find anything hidden in the picture so the next step was to inspect the HTTP traffic:
```
GET https://he-archive.sieber.space/api/v1/challenges/4

{
  "data": {
    "files": [],
    "description": "There's nothing to see here. Go back. Please follow the order. Go back.\r\n\r\n<img src=\"/files/f99ad0ad2359ea5768fd616e07b66a6e/nothingtoseehere.jpg\" style=\"width: 360px\">\r\n\r\n<div style=\"display:none\">\r\n/files/d87e91870d8f6df1d4c7bc515ca21557/nothingtoseehere.txt\r\n</div>",
    "tags": [
      "author: PS"
    ],
    "id": 4,
    "type_data": {
      "templates": {
        "create": "/plugins/challenges/assets/create.html",
        "update": "/plugins/challenges/assets/update.html",
        "view": "/plugins/challenges/assets/view.html"
      },
      "scripts": {
        "create": "/plugins/challenges/assets/create.js",
        "update": "/plugins/challenges/assets/update.js",
        "view": "/plugins/challenges/assets/view.js"
      },
      "id": "standard",
      "name": "standard"
    },
    "hints": [],
    "category": "he2014",
    "name": "Nothing to see here",
    "solves": null,
    "value": 1,
    "state": "visible",
    "type": "standard",
    "max_attempts": 0
  },
  "success": true
}
```

Look what `description` key contains:
```html
There's nothing to see here. Go back. Please follow the order. Go back.\r\n\r\n<img src=\"/files/f99ad0ad2359ea5768fd616e07b66a6e/nothingtoseehere.jpg\" style=\"width: 360px\">\r\n\r\n<div style=\"display:none\">\r\n/files/d87e91870d8f6df1d4c7bc515ca21557/nothingtoseehere.txt\r\n</div>
```

A hidden block!
```
<div style=\"display:none\">\r\n/files/d87e91870d8f6df1d4c7bc515ca21557/nothingtoseehere.txt\r\n</div>
```

Download the file [nothingtoseehere.txt](nothingtoseehere.txt) and decode the egg:
```
$ cat nothingtoseehere.txt | sed '1d;$d' | tr -d '\n' | base64 -d > egg04.png
```

![](egg04.png)