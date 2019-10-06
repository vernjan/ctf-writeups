# 26 - Hidden Egg 2
*A stylish blue egg is hidden somewhere here on the web server. Go catch it!*

---

I didn't get it immediately but then it struck me as a lightning. A **stylish** blue egg!
It's an obvious hint to search in *stylesheets*. The egg is hidden in 
https://hackyeaster.hacking-lab.com/hackyeaster/css/source-sans-pro.css. 

```css
@font-face {
    font-family: 'Egg26';
    font-weight: 400;
    font-style: normal;
    font-stretch: normal;
    src: local('Egg26'),
    local('Egg26'),
    url('../fonts/TTF/Egg26.ttf') format('truetype');
}
```

Just download it at `fonts/TTF/Egg26.ttf` and rename to `Egg26.png`.

![](Egg26.png)
