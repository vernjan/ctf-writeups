# Blog site

Hi, packet inspector,

a simple blog webpage was created where all employees can write their suggestions for improvements. It is one part of
the optimization plan designed by our allmighty AI.

Examine the web http://blog.mysterious-delivery.tcc:20000/ and find any interesting information.

May the Packet be with you!

---

- users can be enumerated on login page

dirb http://blog.mysterious-delivery.tcc:20000/

-----------------
DIRB v2.22
By The Dark Raver
-----------------

START_TIME: Fri Oct 28 01:24:34 2022
URL_BASE: http://blog.mysterious-delivery.tcc:20000/
WORDLIST_FILES: /usr/share/dirb/wordlists/common.txt

-----------------

GENERATED WORDS: 4612

---- Scanning URL: http://blog.mysterious-delivery.tcc:20000/ ----
+ http://blog.mysterious-delivery.tcc:20000/.git/HEAD (CODE:200|SIZE:23)
+ http://blog.mysterious-delivery.tcc:20000/create (CODE:302|SIZE:209)
+ http://blog.mysterious-delivery.tcc:20000/hello (CODE:200|SIZE:13)
  ==> DIRECTORY: http://blog.mysterious-delivery.tcc:20000/javascript/
  ==> DIRECTORY: http://blog.mysterious-delivery.tcc:20000/phpmyadmin/
+ http://blog.mysterious-delivery.tcc:20000/server-status (CODE:403|SIZE:296)
+ http://blog.mysterious-delivery.tcc:20000/settings (CODE:302|SIZE:209)

---- Entering directory: http://blog.mysterious-delivery.tcc:20000/javascript/ ----
==> DIRECTORY: http://blog.mysterious-delivery.tcc:20000/javascript/jquery/

---- Entering directory: http://blog.mysterious-delivery.tcc:20000/phpmyadmin/ ----
==> DIRECTORY: http://blog.mysterious-delivery.tcc:20000/phpmyadmin/doc/
+ http://blog.mysterious-delivery.tcc:20000/phpmyadmin/favicon.ico (CODE:200|SIZE:22486)
+ http://blog.mysterious-delivery.tcc:20000/phpmyadmin/index.php (CODE:200|SIZE:16077)
  ==> DIRECTORY: http://blog.mysterious-delivery.tcc:20000/phpmyadmin/js/
+ http://blog.mysterious-delivery.tcc:20000/phpmyadmin/libraries (CODE:403|SIZE:296)
  ==> DIRECTORY: http://blog.mysterious-delivery.tcc:20000/phpmyadmin/locale/
+ http://blog.mysterious-delivery.tcc:20000/phpmyadmin/phpinfo.php (CODE:200|SIZE:16079)
+ http://blog.mysterious-delivery.tcc:20000/phpmyadmin/robots.txt (CODE:200|SIZE:26)
  ==> DIRECTORY: http://blog.mysterious-delivery.tcc:20000/phpmyadmin/sql/
+ http://blog.mysterious-delivery.tcc:20000/phpmyadmin/templates (CODE:403|SIZE:296)
  ==> DIRECTORY: http://blog.mysterious-delivery.tcc:20000/phpmyadmin/themes/

---- Entering directory: http://blog.mysterious-delivery.tcc:20000/javascript/jquery/ ----
+ http://blog.mysterious-delivery.tcc:20000/javascript/jquery/jquery (CODE:200|SIZE:287600)

TODO - not finished!!!


GIT DUMPER