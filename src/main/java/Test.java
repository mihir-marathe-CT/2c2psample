import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.crypto.bc.BouncyCastleProviderSingleton;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.shaded.json.JSONObject;
import com.nimbusds.jwt.EncryptedJWT;
import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.URL;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.text.ParseException;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.net.ssl.HttpsURLConnection;
import org.bouncycastle.util.encoders.Base64;

public class Test {

    public static void main(String[] args)
        throws IOException, JOSEException, NoSuchAlgorithmException, InvalidKeySpecException, CertificateException, ParseException {

        Security.addProvider(BouncyCastleProviderSingleton.getInstance());
        Security.setProperty("crypto.policy", "unlimited");

        String paymentRequest =
            "<PaymentProcessRequest><version>3.8</version><merchantID>702702000001875</merchantID>"
                + "<processType>S</processType><invoiceNo>pay5</invoiceNo></PaymentProcessRequest>";

        JWEAlgorithm alg = JWEAlgorithm.RSA_OAEP;
        EncryptionMethod enc = EncryptionMethod.A256GCM;

        RSAPublicKey jweRsaPubKey = getRsaPublicKey();

        RSAPrivateKey jwsPrivateKey = getRsaPrivateKey();

        String jwePayload = getJwePayload(paymentRequest, alg, enc, jweRsaPubKey);

        String jwsPayload = getJwsPayload(jwsPrivateKey, jwePayload);


            RSAPublicKey jweRsaPubKeyRes = getRsaPublicKey();

            boolean verified = true;
                isVerified(new StringBuffer(jwsPayload), jweRsaPubKeyRes);

            if(verified) {
                String responsePayload = decryptJwe(jwsPrivateKey, new StringBuffer(jwsPayload));
                System.out.println(responsePayload);
            }else{
                System.out.println("panic");
            }
    
    }

    private static String decryptJwe(RSAPrivateKey jwsPrivateKey, StringBuffer response)
        throws ParseException, JOSEException {
        JWSObject jwsObjectRes = JWSObject.parse(response.toString());
        JWEObject jweRes = EncryptedJWT.parse(jwsObjectRes.getPayload().toString());
        jweRes.decrypt(new RSADecrypter(jwsPrivateKey));
        String responsePayload = jweRes.getPayload().toString();
        return responsePayload;
    }

    private static boolean isVerified(StringBuffer response, RSAPublicKey jweRsaPubKeyRes)
        throws JOSEException, ParseException {
        JWSObject jwsObjectRes = JWSObject.parse(response.toString());
        boolean verified = jwsObjectRes.verify(new RSASSAVerifier(jweRsaPubKeyRes));
        return verified;
    }

    private static RSAPrivateKey getRsaPrivateKey()
        throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        File file = new File("/Users/mihirvmarathe/IdeaProjects/2c2p/self/script/p.key");

        String key = "-----BEGIN RSA PRIVATE KEY-----\n"
            + "MIIEowIBAAKCAQEArykQ8vS+zUwN0z0NeiMklkcb1rn/kvO4549pWgzjmD3Zpifm\n"
            + "E4zllOiXWFg56a8ZGxFpBuK9ux58k1MjVEwxgxP5xsLa/XI4APbaDE2ASJje6dHV\n"
            + "ovAeJqkrSMjkuQNiQ50TAmFbEJC+UwvBFZ0zH6itHhSUQD79E7q59zfm4C7I6m7T\n"
            + "Uf8LNS5mura9pSte+7bdtxQsQD0Yy48IpoH2C8XSdm7aojcHHd3Bt+GBFz6gasV3\n"
            + "X9LjJGD+oa64aCDKY/+7PIqBI6ouJ60+mJSv6/anVgUGobMTj+cAS7HCuVG+2VL8\n"
            + "MxM49kqLxDUzyPjKdFz3Ax3q7ro3v61UReqzkwIDAQABAoIBADqT1Dw8Bzcm8RSs\n"
            + "vT4UVJ8BJtk3mLXvVe3ysvvPhambPZdojnQJUZnr8vkzgCKbUR0RRHtuBp92QZkP\n"
            + "W6hMVt6MJqMG9S9/LCV+aEtm+7jLjvjJGNYF0T+CoZwUuxD4hbsw43OPVWID1fJ1\n"
            + "4tu0l61FvqdpoG6f4gjgEGMRyd88mFBxiknANXYV/tSMWvcQygacUFKPR9l0cT/K\n"
            + "IEHupZu+FcPx7NINPEhYO723eMDCFZNZryr7LkfBfmqFCMAAqqm/1epXOWgEwQfY\n"
            + "QCWRIZ1mQkRxryWvIiR6jDNnKZ5wzdHBvT22vdcyF6OIogZMVnrdJhOI4mme66HR\n"
            + "/VqIw0kCgYEA38+cM3QU/OebUA3s5AumQtLER1kSYWSSmuqnSTDsZb5Bj6lqqFGp\n"
            + "/yKZzz6d+hIMZsKvAfd50PBPBuo6luEhpmGnJqXwnye/WQocMCN2BhMir8yG3NHK\n"
            + "hJfzi3JNvWUifVymGMzlk1tXSHQZhzZlMbYPRoxYTL78xn3Vpz1w1F8CgYEAyFo2\n"
            + "0oV/0eNt3TBvur8rOl9f28wTirlSdbMUHA+jeADBpbjZED48PtN203xwORL4JW7E\n"
            + "0WsTu6bzKhIfoa9BFKIC/Xn7f8Kua7RMnvVPK5BLQ1i3RhMRUELHirExsIiW+Zle\n"
            + "HY/4mX5PhFSgELWvBl+gUT+v/4B+n0H8sG0ODU0CgYEAuovQFS7/Q2FEmjBRMC7p\n"
            + "kK8efJ2obVcnv0owzxehIpi3CqhaRxtyRz8u1ofJoyMiBRDmUAxXE6kJJalb1mCl\n"
            + "7Ileih8r9Wxq2CtOHW2hNSUD92XRTwLp+ySwEZ3fYCqI2da8dtVp0S4EDVb/5CyZ\n"
            + "ohquls3p12YlSMifqXrTrZ8CgYBZXixQEW5ngAv0evOLmFQ+8GYA0/HvkiSfDact\n"
            + "sSgYkjXOpzpjjW8wEwFQ6pPgUX7Qq60tQJcHwDt9C6KCa3sbKf0tdajiX0OQFVeM\n"
            + "HB4Zb36y5rKxljXF2FPLoKhqdzLo2SlrBFo+lWIAxAK2EWSl8ie/tinaTUWt4jBF\n"
            + "vg9jjQKBgAK4vyfBeg7kYzkKaUsWNTai38CmxgdRFC44D7vo5ruzvXWDEvvt6eRK\n"
            + "lmkpC1A2h1nvgh0fS9GNRMj0aUNwu50FFcVMUzqeyO+9JDDY8HZU6m18DyrX+paB\n"
            + "efxZ9KlRbUISY1MzMUFYeSzS2v6ElV+8AWNErl+IT1GuVU4MJFcF\n"
            + "-----END RSA PRIVATE KEY-----";

        String privateKeyPEM = key
            .replace("-----BEGIN RSA PRIVATE KEY-----", "")
            .replaceAll(System.lineSeparator(), "")
            .replace("-----END RSA PRIVATE KEY-----", "");

        byte[] encoded = Base64.decode(privateKeyPEM);

        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(encoded);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        RSAPrivateKey jwsPrivateKey = (RSAPrivateKey) kf
            .generatePrivate(spec);
        return jwsPrivateKey;
    }

    private static RSAPublicKey getRsaPublicKey() throws CertificateException, JOSEException {
        String pub = "-----BEGIN CERTIFICATE-----\n"
            + "MIIDAjCCAeoCCQCYGWg48diGHTANBgkqhkiG9w0BAQUFADBDMQswCQYDVQQGEwJJ\n"
            + "TjELMAkGA1UECAwCTUgxCzAJBgNVBAcMAk1VMQwwCgYDVQQKDANDQVAxDDAKBgNV\n"
            + "BAsMA0RFVjAeFw0yMjA0MDYwNjA1MTBaFw0zMjA0MDMwNjA1MTBaMEMxCzAJBgNV\n"
            + "BAYTAklOMQswCQYDVQQIDAJNSDELMAkGA1UEBwwCTVUxDDAKBgNVBAoMA0NBUDEM\n"
            + "MAoGA1UECwwDREVWMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArykQ\n"
            + "8vS+zUwN0z0NeiMklkcb1rn/kvO4549pWgzjmD3ZpifmE4zllOiXWFg56a8ZGxFp\n"
            + "BuK9ux58k1MjVEwxgxP5xsLa/XI4APbaDE2ASJje6dHVovAeJqkrSMjkuQNiQ50T\n"
            + "AmFbEJC+UwvBFZ0zH6itHhSUQD79E7q59zfm4C7I6m7TUf8LNS5mura9pSte+7bd\n"
            + "txQsQD0Yy48IpoH2C8XSdm7aojcHHd3Bt+GBFz6gasV3X9LjJGD+oa64aCDKY/+7\n"
            + "PIqBI6ouJ60+mJSv6/anVgUGobMTj+cAS7HCuVG+2VL8MxM49kqLxDUzyPjKdFz3\n"
            + "Ax3q7ro3v61UReqzkwIDAQABMA0GCSqGSIb3DQEBBQUAA4IBAQACrCEsqMIGzixA\n"
            + "CTPR7iDIUY2AL4OZVAKkWHZUnslnrKb+5LXjHgQlLc8PLbSo1TcuqcN9u7+LYaiD\n"
            + "Iv9vyspxukK9AV+VoveGRNo8wxA1HQT6nCoKgqQa+yR9HvReu210GDblMpVjA3IX\n"
            + "TCyWtUn4OYRgb/eaueUHryZknctQeKl2im5Z4LLfnm9p04tILe5QcbfDgNM7uRjQ\n"
            + "JkQC6nG+tXK4IqOA3gRHBQ6kXPR10DTD5aY1wDAZHf3vRmLvEjTgmOPo6p4gJqnK\n"
            + "p0yB1YBQIWZkggOZ3S7HgAqJ0Gj89LYLKmYpFMM+5uUngbgVLoHvBgqRgZ83u1/Y\n"
            + "pmPHwF39\n"
            + "-----END CERTIFICATE-----";
        InputStream targetStream = new ByteArrayInputStream(pub.getBytes());
        CertificateFactory certFactory = CertificateFactory.getInstance("X509");
        X509Certificate jwePubKey = (X509Certificate) certFactory.generateCertificate(targetStream);

        RSAKey rsaJWE = RSAKey.parse(jwePubKey);
        RSAPublicKey jweRsaPubKey = rsaJWE.toRSAPublicKey();
        return jweRsaPubKey;
    }

    private static String getJwsPayload(RSAPrivateKey jwsPrivateKey, String jwePayload)
        throws JOSEException {
        RSASSASigner signer = new RSASSASigner(jwsPrivateKey);
        JWSHeader headerc = new JWSHeader(JWSAlgorithm.PS256);
        JWSObject jwsObject = new JWSObject(headerc, new Payload(jwePayload));
        jwsObject.sign(signer);
        String jwsPayload = jwsObject.serialize();
        return jwsPayload;
    }

    private static String getJwePayload(String paymentRequest, JWEAlgorithm alg, EncryptionMethod enc,
        RSAPublicKey jweRsaPubKey) throws NoSuchAlgorithmException, JOSEException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(enc.cekBitLength());
        SecretKey cek = keyGenerator.generateKey();

        JWEObject jwe = new JWEObject(new JWEHeader(alg, enc), new Payload(paymentRequest));
        jwe.encrypt(new RSAEncrypter(jweRsaPubKey, cek));
        String jwePayload = jwe.serialize();
        return jwePayload;
    }
}
