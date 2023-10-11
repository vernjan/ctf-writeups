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
