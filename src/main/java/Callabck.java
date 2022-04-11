import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.JWTVerifier;
import java.util.Map;

public class Callabck {

    public static void main(String[] args) {

        String secretKey = "33949FCDF8791E4DC33E186BA30C93232870F093CCC2D4CCC4CE215B819B6550";
        Algorithm algorithm = Algorithm.HMAC256(secretKey);

        String responseToken = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJjYXJkTm8iOiI0MTExMTFYWFhYWFgxMTExIiwiY2FyZFRva2VuIjoiIiwibG95YWx0eVBvaW50cyI6bnVsbCwibWVyY2hhbnRJRCI6IjcwMjcwMjAwMDAwMTg3NSIsImludm9pY2VObyI6InBheTYiLCJhbW91bnQiOjEwLjAsIm1vbnRobHlQYXltZW50IjpudWxsLCJ1c2VyRGVmaW5lZDEiOiIiLCJ1c2VyRGVmaW5lZDIiOiIiLCJ1c2VyRGVmaW5lZDMiOiIiLCJ1c2VyRGVmaW5lZDQiOiIiLCJ1c2VyRGVmaW5lZDUiOiIiLCJjdXJyZW5jeUNvZGUiOiJTR0QiLCJyZWN1cnJpbmdVbmlxdWVJRCI6IiIsInRyYW5SZWYiOiI0ODE0NzE4IiwicmVmZXJlbmNlTm8iOiI0NDY4MDM3IiwiYXBwcm92YWxDb2RlIjoiMzIwNzU2IiwiZWNpIjoiMDUiLCJ0cmFuc2FjdGlvbkRhdGVUaW1lIjoiMjAyMjA0MTExNDU5NDkiLCJhZ2VudENvZGUiOiJUQkFOSyIsImNoYW5uZWxDb2RlIjoiVkkiLCJpc3N1ZXJDb3VudHJ5IjoiVVMiLCJpc3N1ZXJCYW5rIjoiQkFOSyIsImluc3RhbGxtZW50TWVyY2hhbnRBYnNvcmJSYXRlIjpudWxsLCJjYXJkVHlwZSI6IkNSRURJVCIsImlkZW1wb3RlbmN5SUQiOiIiLCJwYXltZW50U2NoZW1lIjoiVkkiLCJyZXNwQ29kZSI6IjAwMDAiLCJyZXNwRGVzYyI6IlN1Y2Nlc3MifQ.LsyO1q4n9dV7N7w7uAfEAg4GkkbEH3vnRdF-yOyVfEY";


            JWTVerifier verifier = JWT.require(algorithm).build();
        verifier.verify(responseToken);   //verify signature
        DecodedJWT jwt = JWT.decode(responseToken); //decode encoded payload
        Map<String, Claim> responseData = jwt.getClaims();
        String paymentToken = responseData.get("paymentToken").asString();
    }
}
