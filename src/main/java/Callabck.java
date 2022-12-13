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

        String responseToken = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJjYXJkTm8iOiI0MTExMTFYWFhYWFgxMTExIiwiY2FyZFRva2VuIjoiIiwibG95YWx0eVBvaW50cyI6bnVsbCwibWVyY2hhbnRJRCI6IjcwMjcwMjAwMDAwMTg3NSIsImludm9pY2VObyI6IjE4NTA5NTE0NjMzNTVBQUYwS1VWVyIsImFtb3VudCI6MTUwLjAsIm1vbnRobHlQYXltZW50IjpudWxsLCJ1c2VyRGVmaW5lZDEiOiIiLCJ1c2VyRGVmaW5lZDIiOiIiLCJ1c2VyRGVmaW5lZDMiOiIiLCJ1c2VyRGVmaW5lZDQiOiIiLCJ1c2VyRGVmaW5lZDUiOiIiLCJjdXJyZW5jeUNvZGUiOiJTR0QiLCJyZWN1cnJpbmdVbmlxdWVJRCI6IiIsInRyYW5SZWYiOiI1NzgyNzg0IiwicmVmZXJlbmNlTm8iOiI1MjU2NzM3IiwiYXBwcm92YWxDb2RlIjoiNDM0MjAwIiwiZWNpIjoiMDUiLCJ0cmFuc2FjdGlvbkRhdGVUaW1lIjoiMjAyMjEyMTIyMTQzMjIiLCJhZ2VudENvZGUiOiJCQkwiLCJjaGFubmVsQ29kZSI6IlZJIiwiaXNzdWVyQ291bnRyeSI6IlVTIiwiaXNzdWVyQmFuayI6IkJBTksiLCJpbnN0YWxsbWVudE1lcmNoYW50QWJzb3JiUmF0ZSI6bnVsbCwiY2FyZFR5cGUiOiJDUkVESVQiLCJpZGVtcG90ZW5jeUlEIjoiIiwicGF5bWVudFNjaGVtZSI6IlZJIiwicmVzcENvZGUiOiIwMDAwIiwicmVzcERlc2MiOiJTdWNjZXNzIn0.ah9xR1npM9mRyMi974tk8rp3JJl9icJPMVNONkTHR0c";


            JWTVerifier verifier = JWT.require(algorithm).build();
        verifier.verify(responseToken);   //verify signature
        DecodedJWT jwt = JWT.decode(responseToken); //decode encoded payload
        Map<String, Claim> responseData = jwt.getClaims();
        String paymentToken = responseData.get("paymentToken").asString();
    }
}
