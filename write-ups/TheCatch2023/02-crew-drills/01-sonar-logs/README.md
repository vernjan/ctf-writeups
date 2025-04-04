# Sonar logs

Ahoy, officer,

each crew member must be able to operate the sonar and understand its logs. Your task is to analyze the given log file, and check out what the sonar has seen.

May you have fair winds and following seas!

Download the [logs](sonar.log).

--- 

The log contains hex encoded characters:
```
$ grep -oE '0x.{2}' sonar.log | xargs
0x41 0x72 0x47 0x62 0x6a 0x46 0x7b 0x77 0x6d 0x32 0x57 0x4c 0x59 0x57 0x4c 0x33 0x5a 0x7d 0x2d 0x6f 0x2d 0x41 0x2d 0x4b 0x47
```

They decode into:
`ArGbjF{wm2WLYWL3Z}-o-A-KG`

That looks like a transposed flag. `F` should be on the first position. The log line with F (`0x46`) is:
```
2023-10-02 03:35:00 America/St_Barthelemy - Object detected in depth 70 (0x46)
```

Most likely we need to sort the log by time in a single timezone. Could have been doen by hand but that's no fun:

```java
package cz.vernjan.ctf.catch23;


import com.google.common.base.Joiner;
import cz.vernjan.ctf.Resources;
import org.jetbrains.annotations.NotNull;

import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class SonarParser {

    private static final Pattern HEX_PATTERN = Pattern.compile("(0x.{2})");
    private static final DateTimeFormatter DATE_TIME_FORMATTER = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    public static void main(String[] args) {
        Map<ZonedDateTime, Character> flag = new TreeMap<>(); // tree map is naturally sorted
        for (String line : Resources.INSTANCE.asLines("catch23/sonar.log")) {
            Matcher matcher = HEX_PATTERN.matcher(line);
            if (matcher.find()) {
                String flagCharHex = matcher.group().substring(2);
                char flagChar = (char) Integer.parseInt(flagCharHex, 16);
                String timezone = parseTimezone(line);
                ZoneId zoneId = TimeZone.getTimeZone(timezone).toZoneId();
                ZonedDateTime datetime = LocalDateTime.parse(line.substring(0, 19), DATE_TIME_FORMATTER).atZone(zoneId);
                flag.put(datetime, flagChar);
            }
        }
        System.out.println(Joiner.on("").join(flag.values()));
    }

    @NotNull
    private static String parseTimezone(String line) {
        int tzStart = 20;
        int tzEnd = line.indexOf('-', tzStart) - 1;
        return line.substring(tzStart, tzEnd);
    }
}
```

The flag is `FLAG{3YAG-2rbj-KWoZ-LwWm}`