package java_auth;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.spec.ECGenParameterSpec;
import java.security.InvalidAlgorithmParameterException;

import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;

import java.time.Instant;
import java.util.Date;
import java.util.Map;
import java.util.UUID;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTCreator.Builder;
import com.auth0.jwt.algorithms.Algorithm;

public class JwtGenerator {
    
    private KeyPairGenerator keyPairGenerator;
    private KeyPair keyPair;

    public JwtGenerator() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        keyPairGenerator = KeyPairGenerator.getInstance("EC");
        keyPairGenerator.initialize(new ECGenParameterSpec("secp521r1"));
        keyPair = keyPairGenerator.generateKeyPair();
    }

    public String generateJwt(Map<String, String> payload) throws Exception {

        Builder tokenBuilder = JWT.create();

        payload.entrySet().forEach(action -> tokenBuilder.withClaim(action.getKey(), action.getValue()));

        return  tokenBuilder.sign(Algorithm.ECDSA512(((ECPublicKey) keyPair.getPublic()), ((ECPrivateKey) keyPair.getPrivate())));

    }

}