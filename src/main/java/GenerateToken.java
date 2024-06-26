import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTCreationException;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.JWTVerifier;
import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.InputStreamReader;
import java.math.BigDecimal;
import java.net.URL;
import java.text.DecimalFormat;
import java.util.HashMap;
import java.util.Map;
import javax.net.ssl.HttpsURLConnection;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;

public class GenerateToken {

    public static void main(String[] args) {


        String token="";
        String secretKey = "499191E0E41AFECEC26DE59A0EF6DECE57687EAA10F292A5206452B2204ED1E5";

        HashMap<String, Object> payload = new HashMap<>();

        double d = 1.00;
        DecimalFormat df = new DecimalFormat("#.00");
        System.out.print(df.format(d));

        String[] tokens = new String[1];
        tokens[0] = "04062415512440757977";
        payload.put("backendReturnUrl","https://a1798905-7eb8-4794-8934-b1b7630097cf.mock.pstmn.io/cp");
        payload.put("merchantID","458458000002539");
        payload.put("invoiceNo","8953951463355AAF0KUVWG");
        payload.put("description","monday");
        payload.put("amount", 1.09);
        payload.put("currencyCode","MYR");
        payload.put("cardTokens",tokens);
        payload.put("request3DS","N");

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

            JSONObject requestDataDoPaymentNestedData = new JSONObject();
            JSONObject requestDataDoPaymentNestedCode = new JSONObject();
            requestDataDoPaymentNestedCode.put("channelCode","CC");

//            requestDataDoPaymentNestedData.put("name","test");
//            requestDataDoPaymentNestedData.put("email","test@shell.com");
            requestDataDoPaymentNestedData.put("token","04062415512440757977");

            JSONObject requestDataDoPaymentNested = new JSONObject();
            requestDataDoPaymentNested.put("code",requestDataDoPaymentNestedCode);
            requestDataDoPaymentNested.put("data",requestDataDoPaymentNestedData);

            JSONObject requestDataDoPayment = new JSONObject();
            requestDataDoPayment.put("paymentToken", paymentToken);
            requestDataDoPayment.put("payment",requestDataDoPaymentNested);

            String endpointDoPaY = "https://sandbox-pgw.2c2p.com/payment/4.1/payment";
            URL objdOpAY = new URL(endpointDoPaY);
            HttpsURLConnection conDoPay = (HttpsURLConnection) objdOpAY.openConnection();
            conDoPay.setRequestMethod("POST");
            conDoPay.setRequestProperty("Content-Type", "application/*+json");
            conDoPay.setRequestProperty("Accept", "text/plain");
            conDoPay.setDoOutput(true);
            DataOutputStream wrDoPay = new DataOutputStream(conDoPay.getOutputStream());
            wrDoPay.writeBytes(requestDataDoPayment.toString());
            wrDoPay.flush();
            wrDoPay.close();

            BufferedReader inDoPy = new BufferedReader(new InputStreamReader(conDoPay.getInputStream()));
            String inputLineDoPy;
            StringBuffer responseDoPy = new StringBuffer();

            while ((inputLineDoPy = inDoPy.readLine()) != null) {
                responseDoPy.append(inputLineDoPy);
            }
            inDoPy.close();

        }catch(Exception e){
            e.printStackTrace();
        }
    }
}
