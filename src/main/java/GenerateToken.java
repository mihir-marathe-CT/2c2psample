import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTCreationException;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.JWTVerifier;
import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.InputStreamReader;
import java.net.URL;
import java.util.HashMap;
import java.util.Map;
import javax.net.ssl.HttpsURLConnection;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;

public class GenerateToken {

    public static void main(String[] args) {

        String token="";
        String secretKey = "33949FCDF8791E4DC33E186BA30C93232870F093CCC2D4CCC4CE215B819B6550";

        HashMap<String, Object> payload = new HashMap<>();

        payload.put("backendReturnUrl","https://a1798905-7eb8-4794-8934-b1b7630097cf.mock.pstmn.io/cp");
        payload.put("merchantID","702702000001875");
        payload.put("invoiceNo","1750951463355AAF0KUVW");
        payload.put("description","monday");
        payload.put("amount",1.00);
        payload.put("currencyCode","SGD");
//        payload.put("paymentExpiry","2022-04-28 12:00:00");
//        payload.put("immediatePayment",false);
        //payload.put("tokenizeOnly",true);


        try {
            Algorithm algorithm = Algorithm.HMAC256(secretKey);

            token = JWT.create()
                .withPayload(payload).sign(algorithm);

        } catch (JWTCreationException | IllegalArgumentException e){
            //Invalid Signing configuration / Couldn't convert Claims.
            e.printStackTrace();
        }

        JSONObject requestData = new JSONObject();
        requestData.put("payload", token);

        try
        {
            String endpoint = "https://sandbox-pgw.2c2p.com/payment/4.1/PaymentToken";
            URL obj = new URL(endpoint);
            HttpsURLConnection con = (HttpsURLConnection) obj.openConnection();

            con.setRequestMethod("POST");
            con.setRequestProperty("Content-Type", "application/*+json");
            con.setRequestProperty("Accept", "text/plain");

            con.setDoOutput(true);
            DataOutputStream wr = new DataOutputStream(con.getOutputStream());
            wr.writeBytes(requestData.toString());
            wr.flush();
            wr.close();


            BufferedReader in = new BufferedReader(new InputStreamReader(con.getInputStream()));
            String inputLine;
            StringBuffer response = new StringBuffer();

            while ((inputLine = in.readLine()) != null) {
                response.append(inputLine);
            }
            in.close();

            JSONParser parser = new JSONParser();
            JSONObject responseJSON = (JSONObject) parser.parse(response.toString());
            String responseToken = responseJSON.get("payload").toString();

            Algorithm algorithm = Algorithm.HMAC256(secretKey);

            JWTVerifier verifier = JWT.require(algorithm).build();
            verifier.verify(responseToken);   //verify signature
            DecodedJWT jwt = JWT.decode(responseToken); //decode encoded payload
            Map<String, Claim> responseData = jwt.getClaims();
            String paymentToken = responseData.get("paymentToken").asString();

            //paymentToken -> {JsonNodeClaim@3050} ""kSAops9Zwhos8hSTSeLTUZBQPG0it8C9onkziF7YwrTaN6Ojrs3Bq86PDH0CvKY4j+pF55ffrKl8IKpWqpx923Rqgmpa1b5zaSsrS3qvJfpPA8iEhgZVthsmiSw+Y9uv""

            HashMap<String, Object> capture = new HashMap<>();

            capture.put("paymentToken",paymentToken);

        }catch(Exception e){
            e.printStackTrace();
        }
    }
}
