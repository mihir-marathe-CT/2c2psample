import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.JWTVerifier;
import java.util.Map;

public class Callabck {

    public static void main(String[] args) {

        String secretKey = "E99BEB729C9517141266E246910C9BA7071F8976B543C266F601BED7056CB611";
        Algorithm algorithm = Algorithm.HMAC256(secretKey);

        String responseToken = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJjYXJkTm8iOiI1MTI5NzJYWFhYWFgwMjIzIiwiY2FyZFRva2VuIjoiMDUxMjIzMTU0ODU5NTI0NzEyOTEiLCJsb3lhbHR5UG9pbnRzIjpudWxsLCJtZXJjaGFudElEIjoiNzAyNzAyMDAwMDAyOTUwIiwiaW52b2ljZU5vIjoiMTcxODU1Nzc2NTI3MkNSUFVJTEciLCJhbW91bnQiOjcwLjAsIm1vbnRobHlQYXltZW50IjpudWxsLCJ1c2VyRGVmaW5lZDEiOiIxMTI2MzE0NCIsInVzZXJEZWZpbmVkMiI6IiIsInVzZXJEZWZpbmVkMyI6IiIsInVzZXJEZWZpbmVkNCI6IiIsInVzZXJEZWZpbmVkNSI6IiIsImN1cnJlbmN5Q29kZSI6IlNHRCIsInJlY3VycmluZ1VuaXF1ZUlEIjoiIiwidHJhblJlZiI6IjQ4MDc3OTYxNCIsInJlZmVyZW5jZU5vIjoiZDQ4ZjFjZTctMThmMi00YWE0LTkxMTQtOTE5NzY0ODMxYzg5IiwiYXBwcm92YWxDb2RlIjpudWxsLCJlY2kiOiIwMiIsInRyYW5zYWN0aW9uRGF0ZVRpbWUiOiIyMDI0MDYxNzAxMTIxMiIsImFnZW50Q29kZSI6IlVPQlMiLCJjaGFubmVsQ29kZSI6Ik1BIiwiaXNzdWVyQ291bnRyeSI6IlNHIiwiaXNzdWVyQmFuayI6IlVOSVRFRCBPVkVSU0VBUyBCQU5LICxMVEQuIiwiaW5zdGFsbG1lbnRNZXJjaGFudEFic29yYlJhdGUiOm51bGwsImNhcmRUeXBlIjoiREVCSVQiLCJpZGVtcG90ZW5jeUlEIjoiIiwicGF5bWVudFNjaGVtZSI6Ik1BIiwiY3VzdG9tRGVmaW5lZDEiOiI1OSIsImN1c3RvbURlZmluZWQyIjoiVU9CIFNHIFBlcnNvbmFsIERlYml0IENhcmQiLCJjdXN0b21EZWZpbmVkMyI6IiIsImN1c3RvbURlZmluZWQ0IjoiIiwiY3VzdG9tRGVmaW5lZDUiOiIiLCJkaXNwbGF5UHJvY2Vzc2luZ0Ftb3VudCI6ZmFsc2UsInJlc3BDb2RlIjoiNDAwNSIsInJlc3BEZXNjIjoiRG8gbm90IGhvbm9yIn0.T1enGYvc5D9lqxwWqbcRsZkcgkRdDSdz0quH64KBlkM";


            JWTVerifier verifier = JWT.require(algorithm).build();
        verifier.verify(responseToken);   //verify signature
        DecodedJWT jwt = JWT.decode(responseToken); //decode encoded payload
        Map<String, Claim> responseData = jwt.getClaims();
        String paymentToken = responseData.get("paymentToken").asString();
    }
}
