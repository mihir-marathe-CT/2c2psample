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

        String responseToken = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJjYXJkTm8iOiI0MTExMTFYWFhYWFgxMTExIiwiY2FyZFRva2VuIjoiIiwibG95YWx0eVBvaW50cyI6bnVsbCwibWVyY2hhbnRJRCI6IjcwMjcwMjAwMDAwMTg3NSIsImludm9pY2VObyI6InBheTExNCIsImFtb3VudCI6NTUuMCwibW9udGhseVBheW1lbnQiOm51bGwsInVzZXJEZWZpbmVkMSI6IiIsInVzZXJEZWZpbmVkMiI6IiIsInVzZXJEZWZpbmVkMyI6IiIsInVzZXJEZWZpbmVkNCI6IiIsInVzZXJEZWZpbmVkNSI6IiIsImN1cnJlbmN5Q29kZSI6IlNHRCIsInJlY3VycmluZ1VuaXF1ZUlEIjoiIiwidHJhblJlZiI6IjQ4MTc4ODkiLCJyZWZlcmVuY2VObyI6IjQ0NzA3NjMiLCJhcHByb3ZhbENvZGUiOiI1OTMzMzciLCJlY2kiOiIwNSIsInRyYW5zYWN0aW9uRGF0ZVRpbWUiOiIyMDIyMDQxMjEzMDMwMiIsImFnZW50Q29kZSI6IkJCTCIsImNoYW5uZWxDb2RlIjoiVkkiLCJpc3N1ZXJDb3VudHJ5IjoiVVMiLCJpc3N1ZXJCYW5rIjoiQkFOSyIsImluc3RhbGxtZW50TWVyY2hhbnRBYnNvcmJSYXRlIjpudWxsLCJjYXJkVHlwZSI6IkNSRURJVCIsImlkZW1wb3RlbmN5SUQiOiIiLCJwYXltZW50U2NoZW1lIjoiVkkiLCJyZXNwQ29kZSI6IjAwMDAiLCJyZXNwRGVzYyI6IlN1Y2Nlc3MifQ.ka98KShceI_xha9j8dT0fH3VFU8iFJFS_WWb30wOlGk";


            JWTVerifier verifier = JWT.require(algorithm).build();
        verifier.verify(responseToken);   //verify signature
        DecodedJWT jwt = JWT.decode(responseToken); //decode encoded payload
        Map<String, Claim> responseData = jwt.getClaims();
        String paymentToken = responseData.get("paymentToken").asString();
    }
}
