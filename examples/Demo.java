/*
 * Copyright 2020 Azul Systems, Inc.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

import org.openeddsa.java.security.interfaces.EdECPublicKey;
import org.openeddsa.java.security.interfaces.EdECPrivateKey;
import org.openeddsa.java.security.spec.EdECPoint;
import org.openeddsa.java.security.spec.EdECPrivateKeySpec;
import org.openeddsa.java.security.spec.EdECPublicKeySpec;
import org.openeddsa.java.security.spec.NamedParameterSpec;

import java.security.*;
import java.security.spec.InvalidKeySpecException;

/*
 * Application below uses OpenEdDSA provider to demonstrate EdDSA API usage
 */
public class Demo {

    public static void main(String[] args) {
        String alg = null;
        String plain = null;
        if (args.length == 0) {
            alg = "Ed25519";
            plain = "test";
        } else if (args.length != 2) {
            System.out.println("Use: Demo alg_name plain_text");
            return;
        } else {
            alg = args[0];
            plain = args[1];
        }
        KeyPair kp = null;
        try {
            // Example of nonspecific security API
            // example: generate a key pair and sign
            KeyPairGenerator kpg = KeyPairGenerator.getInstance(alg);
            kp = kpg.generateKeyPair();
            boolean res = signAndVerify(alg, plain, kp.getPrivate(), kp.getPublic());
            System.out.println(res?"Signature verified":"Signature verification fails");
        } catch (NoSuchAlgorithmException nsae) {
            System.out.println("Unsupported algorithm : " + alg);
        }

        // example: use KeyFactory to contruct a public and private key
        try {
            KeyFactory kf = KeyFactory.getInstance("EdDSA");
            EdECPublicKey edPubKey = (EdECPublicKey)(kp.getPublic());
            EdECPoint point = edPubKey.getPoint();
            EdECPrivateKey edPrKey = (EdECPrivateKey)(kp.getPrivate());
            byte[] edPrBytes = edPrKey.getBytes().orElseThrow(
                    () -> new InvalidKeyException("No private key value"));

            NamedParameterSpec paramSpec = new NamedParameterSpec(alg);
            EdECPublicKeySpec pubSpec = new EdECPublicKeySpec(paramSpec, point);
            EdECPrivateKeySpec prSpec = new EdECPrivateKeySpec(paramSpec, edPrBytes);
            boolean res = signAndVerify(alg, plain, kf.generatePrivate(prSpec), kf.generatePublic(pubSpec));
            System.out.println(res?"Signature verified":"Signature verification fails");
        } catch (NoSuchAlgorithmException nsae) {
            System.out.println("OpenEdDSA provider is not installed");
        } catch (InvalidKeySpecException | InvalidKeyException e) {
            System.out.println("Exception : " + e);
        }
    }

    static boolean signAndVerify(String alg, String plain, PrivateKey prKey, PublicKey pubKey) {
        try {
            Signature sig = Signature.getInstance(alg);
            sig.initSign(prKey);
            sig.update(plain.getBytes());
            byte[] s = sig.sign();
            Signature verify = Signature.getInstance(alg);
            verify.initVerify(pubKey);
            verify.update(plain.getBytes());
            return verify.verify(s);
        } catch (NoSuchAlgorithmException nsae) {
            System.out.println("OpenEdDSA provider is not installed");
        } catch (InvalidKeyException | SignatureException e) {
            System.out.println("Exception : " + e);
        }
        return false;
    }
}
