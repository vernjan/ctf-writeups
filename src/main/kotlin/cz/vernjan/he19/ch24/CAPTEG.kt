package cz.vernjan.he19.ch24

import okhttp3.*
import org.json.simple.JSONArray
import org.json.simple.JSONObject
import org.json.simple.parser.JSONParser
import java.nio.file.Files
import java.nio.file.Path
import java.time.Duration
import java.util.ArrayList

private const val CAPTEG_URL = "http://whale.hacking-lab.com:3555"

fun main() {
    val downloadPath: Path = Files.createTempDirectory("capteg")
    println("New directory for cards CAPTEG pictures: $downloadPath")

    val nanosetsClient = NanosetsClient()
    val captegClient = CAPTEGClient()

    captegClient.obtainSession()

    println("Let's get started!")

    for (i in (1..42)) {
        println("Round $i:")

        val picturePath = downloadPath.resolve("picture$i.jpg")
        captegClient.downloadPicture(picturePath)

        val numberOfEggs = nanosetsClient.countEggs(picturePath)

        val verified = captegClient.verify(numberOfEggs)
        if (!verified) System.exit(1)
    }
}

class CAPTEGClient {

    private val client = OkHttpClient.Builder()
        .cookieJar(MyCookieJar())
        .build()

    fun obtainSession() {
        val request = Request.Builder()
            .url(CAPTEG_URL)
            .get()
            .build()

        val response = client.newCall(request).execute()
        println("Obtaining session: ${response.code()}")
    }

    fun downloadPicture(downloadPath: Path) {
        val request = Request.Builder()
            .url("$CAPTEG_URL/picture")
            .get()
            .build()

        val response = client.newCall(request).execute()
        println("Downloading /picture: ${response.code()}")

        val pictureBytes = response.body()!!.bytes()
        Files.write(downloadPath, pictureBytes)
    }

    fun verify(numberOfEggs: Int): Boolean {
        val formBody = FormBody.Builder()
            .add("s", numberOfEggs.toString())
            .build()

        val request = Request.Builder()
            .url("$CAPTEG_URL/verify")
            .post(formBody)
            .build()

        val response = client.newCall(request).execute()
        val responseBody = response.body()!!.string()

        println("Verify guess $numberOfEggs: ${response.code()} $responseBody")

        return response.code() != 400 && !responseBody.startsWith("Wrong solution")
    }
}

class NanosetsClient {

    private val modelId = "645aeb7d-27d3-480c-bab6-718a293cba83"

    private val jsonParser = JSONParser()

    private val client = OkHttpClient.Builder()
        .connectTimeout(Duration.ofSeconds(5 ))
        .readTimeout(Duration.ofSeconds(30))
        .build()

    fun countEggs(picturePath: Path): Int {
        println("Counting eggs for picture $picturePath")
        val start = System.currentTimeMillis()

        val requestBody = MultipartBody.Builder()
                .setType(MultipartBody.FORM)
                .addFormDataPart(
                    "file",
                    picturePath.fileName.toString(),
                    RequestBody.create(MediaType.parse("image/jpeg"), picturePath.toFile()))
                .build()

        val request = Request.Builder()
                .url("https://app.nanonets.com/api/v2/ObjectDetection/Model/$modelId/LabelFile/")
                .post(requestBody)
                .addHeader("Authorization", Credentials.basic("MY_SECRET_KEY", ""))
                .build()

        val response = client.newCall(request).execute()
        val responseBody = response.body()!!.string()

        val responseJson: JSONObject = jsonParser.parse(responseBody) as JSONObject
        val result: JSONObject = (responseJson.getValue("result") as JSONArray)[0] as JSONObject
        val predictions = result["prediction"] as JSONArray

        val count =  predictions.filter { ((it as JSONObject)["score"] as Double) > 0.52 }.count()
        println("${response.code()}: Counted $count eggs (done in ${System.currentTimeMillis() - start})")

        return count
    }
}

class MyCookieJar : CookieJar {

    private var cookies: List<Cookie>? = ArrayList()

    override fun saveFromResponse(url: HttpUrl, cookies: List<Cookie>) {
        this.cookies = cookies
    }

    override fun loadForRequest(url: HttpUrl): List<Cookie> {
        return cookies!!
    }
}
