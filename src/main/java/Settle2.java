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
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.URL;
import java.nio.charset.Charset;
import java.nio.file.Files;
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

public class Settle2 {

    public static void main(String[] args)
        throws IOException, JOSEException, NoSuchAlgorithmException, InvalidKeySpecException, CertificateException, ParseException {

        Security.addProvider(BouncyCastleProviderSingleton.getInstance());
        Security.setProperty("crypto.policy", "unlimited");

        String paymentRequest =
            "<PaymentProcessRequest><version>3.8</version><merchantID>702702000001875</merchantID>"
                + "<processType>S</processType><invoiceNo>pay5</invoiceNo></PaymentProcessRequest>";

        FileInputStream is = new FileInputStream(
            "/Users/mihirvmarathe/IdeaProjects/2c2p/2c2p/jwt.cer"); ////2c2p public cert key


        JWEAlgorithm alg = JWEAlgorithm.RSA_OAEP;
        EncryptionMethod enc = EncryptionMethod.A256GCM;

        String pub = "-----BEGIN CERTIFICATE-----\n"
            + "MIIDLjCCAhYCCQCYGrdwIYmDtzANBgkqhkiG9w0BAQsFADBZMQswCQYDVQQGEwJT\n"
            + "RzELMAkGA1UECAwCU0cxCzAJBgNVBAcMAlNHMRIwEAYDVQQKDAkyQzJQIERlbW8x\n"
            + "DTALBgNVBAsMBDJjMnAxDTALBgNVBAMMBDJjMnAwHhcNMjAxMDI5MDYyNDAzWhcN\n"
            + "MzAxMDI3MDYyNDAzWjBZMQswCQYDVQQGEwJTRzELMAkGA1UECAwCU0cxCzAJBgNV\n"
            + "BAcMAlNHMRIwEAYDVQQKDAkyQzJQIERlbW8xDTALBgNVBAsMBDJjMnAxDTALBgNV\n"
            + "BAMMBDJjMnAwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDJuLHNVQSV\n"
            + "L6eZUDR+5D9z0t/gd8fiLKcoNDmPfFS3d1p1KH1VcttTM4KxqC0/jiDs3BqBjUuO\n"
            + "6QQB+vbmV3dQZ/RO3iKgfE3fALBCiDjU6zVp9ZbWQHubyHPLMuHCBS+8EFKgBqCw\n"
            + "I1CTE5x26tskibJYOsExeYornSwGEJkXnXodDsca6sgkcnm8jVNyOYL5HG3KtuFp\n"
            + "AqU9bCfn7QLdCWbJa19exaq1o32UYPSla1Rm15xoByVlP7CxRnReSXCZDF54dUq/\n"
            + "6hw3Jdf1+rIn3rJqkHWXPdX0HMFklieeVXN/GM+8xbkvp9GEXDpvOuO/jgCKZ03z\n"
            + "TKXXpaAumHPVAgMBAAEwDQYJKoZIhvcNAQELBQADggEBAMUh53pskCrDgHVUwgQd\n"
            + "SRr25+o0XPJWW+LmpW68PwFLIrQhgQqys3RHZLPeTpCBQPCd6dClhR41kp7l/uFO\n"
            + "UjhvNcrVhqsEUEClFRu5Fos7votayJgKnvlXnJ+cI3a9cp4Z0W0tLMKus13cb6+h\n"
            + "4kXJ/wCy0IfvUlEXtFOQM+ftjgfbhIopoxvzEzvEulYOhGI/1HKXJ5nRdJRT2unV\n"
            + "oui9OKP1sUHiGqo73EEg5JZeRen/DJvaN8uhwayhyWSC5+NDGK6UKPFIpWKdg+rs\n"
            + "tWK6Vty9jVevX3Y4aNrxiD/IgPYtljGbefEKRAeqEkxc+lWBF70JjpyAobG1Oxaj\n"
            + "jPM=\n"
            + "-----END CERTIFICATE-----";
        InputStream targetStream = new ByteArrayInputStream(pub.getBytes());
        CertificateFactory certFactory = CertificateFactory.getInstance("X509");
        X509Certificate jwePubKey = (X509Certificate) certFactory.generateCertificate(targetStream);

        RSAKey rsaJWE = RSAKey.parse(jwePubKey);
        RSAPublicKey jweRsaPubKey = rsaJWE.toRSAPublicKey();

        File file = new File("/Users/mihirvmarathe/IdeaProjects/2c2p/self/script/p.key");

        String key = Files.readString(file.toPath(), Charset.defaultCharset());

        String privateKeyPEM = key
            .replace("-----BEGIN RSA PRIVATE KEY-----", "")
            .replaceAll(System.lineSeparator(), "")
            .replace("-----END RSA PRIVATE KEY-----", "");

        byte[] encoded = Base64.decode(privateKeyPEM);

        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(encoded);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        RSAPrivateKey jwsPrivateKey = (RSAPrivateKey) kf
            .generatePrivate(spec);

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(enc.cekBitLength());
        SecretKey cek = keyGenerator.generateKey();

        JWEObject jwe = new JWEObject(new JWEHeader(alg, enc), new Payload(paymentRequest));
        jwe.encrypt(new RSAEncrypter(jweRsaPubKey, cek));
        String jwePayload = jwe.serialize();

        RSASSASigner signer = new RSASSASigner(jwsPrivateKey);
        JWSHeader headerc = new JWSHeader(JWSAlgorithm.PS256);
        JWSObject jwsObject = new JWSObject(headerc, new Payload(jwePayload));
        jwsObject.sign(signer);
        String jwsPayload = jwsObject.serialize();

        JSONObject requestData = new JSONObject();
        requestData.put("payload", jwsPayload);

        try {
            String endpoint = "https://demo2.2c2p.com/2C2PFrontend/PaymentAction/2.0/action";
            URL obj = new URL(endpoint);
            HttpsURLConnection con = (HttpsURLConnection) obj.openConnection();

            con.setRequestMethod("POST");
            con.setRequestProperty("Content-Type", "application/*+json");
            con.setRequestProperty("Accept", "text/plain");

            con.setDoOutput(true);
            DataOutputStream wr = new DataOutputStream(con.getOutputStream());
            wr.writeBytes(jwsPayload);
            wr.flush();
            wr.close();
            System.out.println(requestData.toJSONString());

            BufferedReader in = new BufferedReader(new InputStreamReader(con.getInputStream()));
            String inputLine;
            StringBuffer response = new StringBuffer();

            while ((inputLine = in.readLine()) != null) {
                response.append(inputLine);
            }
            in.close();
            System.out.println(response);
            JWSObject jwsObjectRes = JWSObject.parse(response.toString());

            RSAKey rsaJWERes = RSAKey.parse(jwePubKey);
            RSAPublicKey jweRsaPubKeyRes = rsaJWERes.toRSAPublicKey();

            boolean verified = jwsObjectRes.verify(new RSASSAVerifier(jweRsaPubKeyRes));

            if(verified) {
                JWEObject jweRes = EncryptedJWT.parse(jwsObjectRes.getPayload().toString());
                jweRes.decrypt(new RSADecrypter(jwsPrivateKey));
                String responsePayload = jweRes.getPayload().toString();
                System.out.println(responsePayload);
            }else{
                System.out.println("panic");
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
