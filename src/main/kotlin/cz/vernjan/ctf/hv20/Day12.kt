package cz.vernjan.ctf.hv20

import cz.vernjan.ctf.base64ToHex

fun main() {

    val nHex = "dbn25TSjDhUge4L68AYooIqwo0HC2mIYxK/ICnc+8/0fZi1CHo/QwiPCcHM94jYdfj3PIQFTri9j/za3oO+3gVK39bj2O9OekGPG2M1GtN0Sp+ltellLl1oV+TBpgGyDt8vcCAR1B6shOJbjPAFqL8iTaW1C4KyGDVQhQrfkXtAdYv3ZaHcV8tC4ztgA4euP9o1q+kZux0fTv31kJSE7K1iJDpGfy1HiJ5gOX5T9fEyzSR0kA3sk3a35qTuUU1OWkH5MqysLVKZXiGcStNErlaggvJb6oKkx1dr9nYbqFxaQHev0EFX4EVfPqQzEzesa9ZAZTtxbwgcV9ZmTp25MZg==".base64ToHex()
    println(nHex.chunked(2).map { "0x$it" }.joinToString(","))

    val eHex = "4BFD0ECF3CC345DB29B3E23CE6D362E1DD62DDDD04BBCA6299C3F94816AA4DE0737000EDBAB0D81E4D50BA8A9D4EDC17F576355A28BA027C92A4443D7941044D84244D1A6AF6B060808926B859CBCA0BA3153F9223767E1CB0DF316941C5A3D6DC4C68E58AAAAF3771E19CDED5DA85342E63251544241C9DEDCEBEC2A8939D2E1D47BEE69C568F1EDFFD22E3218A0562B29B713CB27E83D417E19257F2E714E863D2573CD39B094322369E9E1ECBD1B0B552AFDEB930D4263CCD5A73291CB1E74B3DAF8312E0E19B708BDD5D3A93BB2A3BDD650EFEFA7947444EB394C1D3B273C54B02F01B56719C655D167B8C8C46CF03775C4DEE782F13926F672F64A0D9A8"
    println(eHex.chunked(2).map { "0x$it" }.joinToString(","))

    println("fJdSIoC9qz27pWVpkXTIdJPuR9Fidfkq1IJPRQdnTM2XmhrcZToycoEoqJy91BxikRXQtioFKbS7Eun7oVS0yw==".base64ToHex())
    println("vzwheJ3akhr1LJTFzmFxdhBgViykRpUldFyU6qTu5cjxd1fOM3xkn49GYEM+2cUVk22Tu5IsYDbzJ4/zSDfzKA==".base64ToHex())
    println("fRYUyYEINA5i/hCsEtKkaCn2HsCp98+ksi/8lw1HNTP+KFyjwh2gZH+nkzLwI+fdJFbCN5iwFFXo+OzgcEMFqw==".base64ToHex())
    println("+y2fMsE0u2F6bp2VP27EaLN68uj2CXm9J1WVFyLgqeQryh5jMyryLwuJNo/pz4tXzRqV4a8gM0JGdjvF84mf+w==".base64ToHex())
}