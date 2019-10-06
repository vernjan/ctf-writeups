# 16 - Every-Thing

After the brilliant idea from [here]().

The data model is stable and you can really store **Every-Thing**.

[EveryThing.zip](EveryThing.zip)

---

The first step was to import the database dump into MySQL for easier analysis. The model is funny -
every thing is indeed in one table. 

```sql
CREATE TABLE `Thing` (
  `id` binary(16) NOT NULL,
  `ord` int(11) NOT NULL,
  `type` varchar(255) NOT NULL,
  `value` varchar(1024) DEFAULT NULL,
  `pid` binary(16) DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `FKfaem61vklu1cjw9ckunvpicgi` (`pid`),
  CONSTRAINT `FKfaem61vklu1cjw9ckunvpicgi` FOREIGN KEY (`pid`) REFERENCES `Thing` (`id`)
)
```
 
Here is the data overview. Basically, we have 3 domains (addresses, books and gallery):

```sql
SELECT type, count(*) FROM Thing GROUP BY type

'address','16674'
'address.about','16674'
'address.address','16674'
'address.age','16674'
'address.company','16674'
'address.email','16674'
'address.eyeColor','16674'
'address.favoriteFruit','16674'
'address.gender','16674'
'address.greeting','16674'
'address.guid','16674'
'address.name','16674'
'address.phone','16674'
'address.picture','16674'
'address.registered','16674'
'addressbook','1'
'book','10000'
'book.author','10000'
'book.isbn','10000'
'book.language','10000'
'book.title','10000'
'book.url','10000'
'book.year','10000'
'bookshelf','1'
'galery','1'
'png','11'
'png.bkgd','11'
'png.chrm','1'
'png.gama','1'
'png.head','11'
'png.idat','928'
'png.iend','11'
'png.ihdr','11'
'png.phys','11'
'png.text','3'
'png.time','11'
'ROOT','1'
'shelf','58'
```

The `png` type looks interesting .. Let's join parents (`id`) and children (`pid`) together:

```sql
SELECT t1.type, t1.ord, t1.value AS picName, t2.type, t2.ord, t2.value, t3.type, t3.ord, t3.value
FROM Thing AS t1
LEFT JOIN Thing AS t2 ON t2.pid = t1.id
LEFT JOIN Thing AS t3 ON t3.pid = t2.id
WHERE t1.type = 'png'
ORDER BY t1.ord, t2.ord, t3.ord

'png','0','At the beach','png.head','0','iVBORw0KGgo=',NULL,NULL,NULL
'png','0','At the beach','png.ihdr','1','AAAADUlIRFIAAAHgAAAB4AgGAAAAfdS+lQ==',NULL,NULL,NULL
'png','0','At the beach','png.bkgd','2','AAAABmJLR0QA/wD/AP+gvaeT',NULL,NULL,NULL
'png','0','At the beach','png.phys','3','AAAACXBIWXMAADRjAAA0YwFVm585',NULL,NULL,NULL
'png','0','At the beach','png.time','4','AAAAB3RJTUUH4wESECkqGK+AZQ==',NULL,NULL,NULL
'png','0','At the beach','png.idat','5','11','png.idat','0','AAAgAElEQV'
'png','0','At the beach','png.idat','5','11','png.idat','1','+vo3EDGMMX'
'png','0','At the beach','png.idat','5','11','png.idat','2','/vInjEQiRW'
'png','0','At the beach','png.idat','5','11','png.idat','3','CjHybQ3ex6'
'png','0','At the beach','png.idat','5','11','png.idat','4','jt3noqu/jY'
'png','0','At the beach','png.idat','5','11','png.idat','5','GnFF9x62vL'
'png','0','At the beach','png.idat','5','11','png.idat','6','qwFEjsQcbF'
...

```

We have 11 `PNG` pictures split into [chunks](https://en.wikipedia.org/wiki/Portable_Network_Graphics#%22Chunks%22_within_the_file)
(according to the model design).
I wrote this [simple program](../../../src/main/kotlin/cz/vernjan/ctf/he19/ch16/EveryThing.kt) to join them back together. One of the pictures is our egg:

![](pictures/A%20strange%20car.png)