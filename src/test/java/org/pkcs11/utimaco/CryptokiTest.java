/*
 * Copyright 2022 - based on existing tests in CriptokiTest.java. All rights reserved.
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

package org.pkcs11.utimaco;

import junit.framework.TestCase;
import net.i2p.crypto.eddsa.EdDSAEngine;
import net.i2p.crypto.eddsa.EdDSAPublicKey;
import net.i2p.crypto.eddsa.spec.EdDSANamedCurveTable;
import net.i2p.crypto.eddsa.spec.EdDSAParameterSpec;
import net.i2p.crypto.eddsa.spec.EdDSAPublicKeySpec;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.edec.EdECObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.openssl.PEMWriter;
import org.bouncycastle.util.encoders.Base64;
import org.pkcs11.jacknji11.*;

import java.io.*;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.util.Calendar;
import java.util.Date;


/**
 * JUnit tests for jacknji11.
 * Test Edward curves in Utimaco HSM (Cryptoserver v. 4.31)
 * 
 * Based on existing tests in CriptokiTest.java
 */
public class CryptokiTest extends TestCase {
    private byte[] SO_PIN = "sopin".getBytes();
    private byte[] USER_PIN = "userpin".getBytes();
    private long TESTSLOT = 0;
    private long INITSLOT = 1;

    public void setUp() {
        String testSlotEnv = System.getenv("JACKNJI11_TEST_TESTSLOT");
        if (testSlotEnv != null && testSlotEnv.length() > 0) {
            TESTSLOT = Long.parseLong(testSlotEnv);
        }
        String initSlotEnv = System.getenv("JACKNJI11_TEST_INITSLOT");
        if (initSlotEnv != null && initSlotEnv.length() > 0) {
            INITSLOT = Long.parseLong(initSlotEnv);
        }
        String soPinEnv = System.getenv("JACKNJI11_TEST_SO_PIN");
        if (soPinEnv != null && soPinEnv.length() > 0) {
            SO_PIN = soPinEnv.getBytes();
        }
        String userPinEnv = System.getenv("JACKNJI11_TEST_USER_PIN");
        if (userPinEnv != null && userPinEnv.length() > 0) {
            USER_PIN = userPinEnv.getBytes();
        }
        // Library path can be set with JACKNJI11_PKCS11_LIB_PATH, or done in code such
        // as:
        // C.NATIVE = new
        // org.pkcs11.jacknji11.jna.JNA("/usr/lib/softhsm/libsofthsm2.so");
        // Or JFFI can be used rather than JNA:
        // C.NATIVE = new org.pkcs11.jacknji11.jffi.JFFI();
        CE.Initialize();
    }

    public void tearDown() {
        CE.Finalize();
    }

    /**
     * Test Ed25519 signature and verification using the HSM
     */
    public void testSignVerifyEd25519() {
        long session = loginSession(TESTSLOT, USER_PIN,
                CK_SESSION_INFO.CKF_RW_SESSION | CK_SESSION_INFO.CKF_SERIAL_SESSION, null, null);

        // Generate Ed25519 key pair
        LongRef pubKey = new LongRef();
        LongRef privKey = new LongRef();
        generateKeyPairEd25519(session, pubKey, privKey);

        // Direct sign, PKCS#11 "2.3.6 ECDSA without hashing"
        byte[] data = "Message to be signed!!".getBytes();
        CE.SignInit(session, new CKM(CKM.ECDSA), privKey.value());
        byte[] sig1 = CE.Sign(session, data);
        assertEquals(64, sig1.length);

        System.out.println(
                "testSignVerifyEd25519: Signature generated with length == 64? " + String.valueOf(64 == sig1.length));

        // Verify valid signature
        CE.VerifyInit(session, new CKM(CKM.ECDSA), pubKey.value());
        try {
            CE.Verify(session, data, sig1);
            System.out.println("testSignVerifyEd25519: Valid Signature verified");
        } catch (CKRException e) {
            assertNull("Valid signature verification failed", e.getCKR());
        }

        // Verify if two signatures of the same data are the same signature
        CE.SignInit(session, new CKM(CKM.ECDSA), privKey.value());
        byte[] sig3 = CE.Sign(session, data);

        System.out.println("testSignVerifyEd25519: Signatures are the same: sig1 = " + Hex.b2s(sig1) + " - sig3 = "
                        + Hex.b2s(sig3));
        assertEquals("Signatures are not the same.", true, Hex.b2s(sig1).equals(Hex.b2s(sig3)));

        byte[] data1 = new byte[256];
        CE.SignInit(session, new CKM(CKM.ECDSA), privKey.value());
        byte[] sig2 = CE.Sign(session, data1);

        // Verify invalid signature
        CE.VerifyInit(session, new CKM(CKM.ECDSA), pubKey.value());
        try {
            CE.Verify(session, data, sig2);
            fail("CE Verify with no real signature should throw exception");
        } catch (CKRException e) {
            System.out.println(
                    "testSignVerifyEd25519: Verifying invalid signature. Exception expected " + CKR.SIGNATURE_INVALID
                            + " : " + CKR.L2S(CKR.SIGNATURE_INVALID) + " - Actual exception: "
                            + e.getCKR() + " : " + CKR.L2S(e.getCKR()));
            assertEquals("Failure with invalid signature data should be CKR.SIGNATURE_INVALID", CKR.SIGNATURE_INVALID,
                    e.getCKR());
        }
    }

    /**
     * Test Slot access and info obtained
     */
    public void testGetSlotInfo() {
        long session = loginSession(TESTSLOT, USER_PIN,
                CK_SESSION_INFO.CKF_RW_SESSION | CK_SESSION_INFO.CKF_SERIAL_SESSION, null, null);

        // Generate Ed25519 key pair
        LongRef pubKey = new LongRef();
        LongRef privKey = new LongRef();
        generateKeyPairEd25519(session, pubKey, privKey);

        // Get slot info
        CK_SLOT_INFO info = new CK_SLOT_INFO();
        CE.GetSlotInfo(TESTSLOT, info);
        System.out.println("testGetSlotInfo - Testslot info: " + TESTSLOT);
        System.out.println(info);

        // Get token info
        CK_TOKEN_INFO tinfo = new CK_TOKEN_INFO();
        CE.GetTokenInfo(TESTSLOT, tinfo);
        System.out.println("testGetSlotInfo - Token info: ");
        System.out.println(tinfo);
    }

    /**
     * Test Ed25519 key pair genertion
     */
    public void testKeyPairEd25519() {
        long session = loginSession(TESTSLOT, USER_PIN,
                CK_SESSION_INFO.CKF_RW_SESSION | CK_SESSION_INFO.CKF_SERIAL_SESSION, null, null);

        // Generate Ed25519 key pair
        LongRef pubKey = new LongRef();
        LongRef privKey = new LongRef();
        generateKeyPairEd25519(session, pubKey, privKey);

        System.out.println("testKeyPairEd25519: edwards25519 keypair generated. PublicKey handle: " + pubKey.value()
                + ", PrivKey handle: " + privKey.value());

        // GET public key value (CKA.VALUE)
        byte[] publicKey = CE.GetAttributeValue(session, pubKey.value(), CKA.VALUE).getValue();
        assertEquals(32, publicKey.length);
        System.out.println(
                "testKeyPairEd25519: public key size (should be 32 bytes) = " + publicKey.length + " - value = "
                + Hex.b2s(publicKey));

        // Get public key EC point (CKA.EC_POINT)
        byte[] ecPoint = CE.GetAttributeValue(session, pubKey.value(), CKA.EC_POINT).getValue();
        System.out.println("testKeyPairEd25519: EC_POINT length = " + ecPoint.length + " - value = "
                + Hex.b2s(ecPoint));
        // Get public key EC params (CKA.EC_PARAMS)
        byte[] ecParams = CE.GetAttributeValue(session, pubKey.value(), CKA.EC_PARAMS).getValue();
        System.out.println("testKeyPairEd25519: EC_PARAMS length = " + ecParams.length + " - value = "
                + Hex.b2s(ecParams));

        // CKA.EC_POINT is the public key - EC points - (CKA.VALUE) in an OCTET string.
        // The ASN.1 tag for OCTET STRING is 0x04, and the length of that string is 32
        // bytes (0x20 in hex). So, CKA.EC_POINT == 0420 + CKA.VALUE.
        // EC points - pairs of integer coordinates {x, y}, laying on the curve.

        assertEquals(Hex.b2s(publicKey), Hex.b2s(ecPoint).substring(4));

        // Get private key
        try {
            final byte[] privateKey = CE.GetAttributeValue(session, privKey.value(), CKA.VALUE).getValue();
            fail("testKeyPairEd25519: Obtaining private key value should throw exception");
        } catch (CKRException e) {
            assertEquals("testKeyPairEd25519: Failure obtaining private key, should be CKR.ATTRIBUTE_SENSITIVE.",
                    CKR.ATTRIBUTE_SENSITIVE,
                    e.getCKR());
            System.out
                    .println("testKeyPairEd25519: Failure obtaining private key, as expected:  " + CKR.L2S(e.getCKR()));
        }
    }

    /**
     * Test Ed25519 public key export
     */
    public void testExportPublicKey() {
        long session = loginSession(TESTSLOT, USER_PIN,
                CK_SESSION_INFO.CKF_RW_SESSION | CK_SESSION_INFO.CKF_SERIAL_SESSION, null, null);

        // Generate Ed25519 key pair
        LongRef pubKey = new LongRef();
        LongRef privKey = new LongRef();
        generateKeyPairEd25519(session, pubKey, privKey);

        // Public key information for ed255619 is stored in CKA.VALUE
        CKA ec_point = CE.GetAttributeValue(session, pubKey.value(), CKA.VALUE);

        // Create EdDSA spec and PublicKey using net.i2p.crypto library
        EdDSAParameterSpec spec = EdDSANamedCurveTable.getByName("ed25519");
        EdDSAPublicKeySpec pubKeySpec = new EdDSAPublicKeySpec(ec_point.getValue(), spec);
        PublicKey pubKey2 = new EdDSAPublicKey(pubKeySpec);
        System.out.println("testExportPublicKey: PublicKey: " + Hex.b2s(pubKey2.getEncoded()));
        System.out.println("testExportPublicKey: PublicKey Format: " + pubKey2.getFormat());

        // Encode as PEM for export
        byte[] data = pubKey2.getEncoded();
        String base64encoded = new String(Base64.encode(data));
        String pemFormat = "-----BEGIN PUBLIC KEY-----\n" + base64encoded + "\n-----END PUBLIC KEY-----";
        System.out.println("testExportPublicKey: \n" + pemFormat);

        try {
            FileWriter myWriter = new FileWriter("pubkey.pem");
            myWriter.write(pemFormat);
            myWriter.close();
            System.out.println("testExportPublicKey: Successfully wrote to the file.");
        } catch (IOException e) {
            System.out.println("An error occurred.");
            e.printStackTrace();
        }
    }

    /**
     * Test Ed25519 signature verification using java (external to the HSM)
     * 
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     * @throws InvalidParameterSpecException
     * @throws InvalidKeyException
     * @throws SignatureException
     * @throws NoSuchProviderException
     * @throws IOException
     */
    public void testSoftVerifyEd25519()
            throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidParameterSpecException,
            InvalidKeyException, SignatureException, NoSuchProviderException, IOException {
        long session = loginSession(TESTSLOT, USER_PIN,
                CK_SESSION_INFO.CKF_RW_SESSION | CK_SESSION_INFO.CKF_SERIAL_SESSION, null, null);

        // Generate Ed25519 key pair
        LongRef pubKey = new LongRef();
        LongRef privKey = new LongRef();
        generateKeyPairEd25519(session, pubKey, privKey);

        // Direct sign, PKCS#11 "2.3.6 ECDSA without hashing"
        byte[] msg = "Message to be signed!!".getBytes("UTF-8");
        CE.SignInit(session, new CKM(CKM.ECDSA), privKey.value());
        byte[] sig1 = CE.Sign(session, msg);

        // Public key information for ed255619 is stored in CKA.VALUE
        CKA ec_point = CE.GetAttributeValue(session, pubKey.value(), CKA.VALUE);

        // Create EdDSA spec and PublicKey using net.i2p.crypto library
        EdDSAParameterSpec spec = EdDSANamedCurveTable.getByName("ed25519");
        EdDSAPublicKeySpec pubKeySpec = new EdDSAPublicKeySpec(ec_point.getValue(), spec);
        PublicKey pubKey2 = new EdDSAPublicKey(pubKeySpec);

        System.out.println("testSoftVerifyEd25519: message: " + Hex.b2s(msg));
        System.out.println("testSoftVerifyEd25519: sigString " + Hex.b2s(sig1));
        System.out.println("testSoftVerifyEd25519: pubkey " + Hex.b2s(pubKey2.getEncoded()));

        // Verify HSM signature, using extracted public key
        EdDSAEngine mEdDSAEngine = new EdDSAEngine();
        mEdDSAEngine.initVerify(pubKey2);
        mEdDSAEngine.update(msg);
        boolean validSig = mEdDSAEngine.verify(sig1);

        assertEquals(true, validSig);
        System.out.println("testSoftVerifyEd25519: Signature software verification : " + validSig);
    }

    public void testCertificateEd25519() throws IOException, CertificateException, NoSuchAlgorithmException, SignatureException, InvalidKeyException, NoSuchProviderException {
        long session = loginSession(TESTSLOT, USER_PIN,
                CK_SESSION_INFO.CKF_RW_SESSION | CK_SESSION_INFO.CKF_SERIAL_SESSION, null, null);

        // Generate Ed25519 key pair
        LongRef pubKey = new LongRef();
        LongRef privKey = new LongRef();
        generateKeyPairEd25519(session, pubKey, privKey);

        // Public key information for ed255619 is stored in CKA.VALUE
        CKA ec_point = CE.GetAttributeValue(session, pubKey.value(), CKA.VALUE);

        // Create EdDSA spec and PublicKey using net.i2p.crypto library
        EdDSAParameterSpec spec = EdDSANamedCurveTable.getByName("ed25519");
        EdDSAPublicKeySpec pubKeySpec = new EdDSAPublicKeySpec(ec_point.getValue(), spec);
        PublicKey pubKey2 = new EdDSAPublicKey(pubKeySpec);


        Calendar expiry = Calendar.getInstance();
        expiry.add(Calendar.DAY_OF_YEAR, 100);

        V3TBSCertificateGenerator certGen = new V3TBSCertificateGenerator();
        certGen.setSerialNumber(new ASN1Integer(BigInteger.valueOf(System.currentTimeMillis())));
        certGen.setIssuer(new X500Name("CN=localhost"));
        certGen.setSubject(new X500Name("CN=localhost"));
        certGen.setStartDate(new Time(new Date(System.currentTimeMillis())));
        certGen.setEndDate(new Time(expiry.getTime()));
        certGen.setSubjectPublicKeyInfo(SubjectPublicKeyInfo.getInstance(pubKey2.getEncoded()));
        certGen.setSignature(new AlgorithmIdentifier(EdECObjectIdentifiers.id_Ed25519));
        TBSCertificate tbsCert = certGen.generateTBSCertificate();

        System.out.println("Certificate:\n" + Hex.b2s(tbsCert.getEncoded()));

        SHA1Digest digester = new SHA1Digest();
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        ASN1OutputStream dOut = ASN1OutputStream.create(bOut);
        dOut.writeObject(tbsCert);

        byte[] certBlock = bOut.toByteArray();
        // first create digest
        digester.update(certBlock, 0, certBlock.length);
        byte[] hash = new byte[digester.getDigestSize()];
        digester.doFinal(hash, 0);

        CE.SignInit(session, new CKM(CKM.ECDSA), privKey.value());
        byte[] signature = CE.Sign(session, hash);

        ASN1EncodableVector  v = new ASN1EncodableVector();
        v.add(tbsCert);
        v.add(new AlgorithmIdentifier(EdECObjectIdentifiers.id_Ed25519));
        v.add(new DERBitString(signature));

        DERSequence der = new DERSequence(v);
        ByteArrayInputStream baos = new ByteArrayInputStream(der.getEncoded());
        X509Certificate cert = (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(baos);

        //cert.verify(pubKey2);

        StringWriter sw = new StringWriter();
        try (PEMWriter pw = new PEMWriter(sw)) {
            pw.writeObject(cert);
        }

        try {
            FileWriter myWriter = new FileWriter("cert.pem");
            myWriter.write(sw.toString());
            myWriter.close();
            System.out.println("testExportPublicKey: Successfully wrote to the file.");
        } catch (IOException e) {
            System.out.println("An error occurred.");
            e.printStackTrace();
        }





    }

    /**
     * Login to slotID and returns the session handle.
     * 
     * @param slotID      the slot's ID
     * @param userPIN     the normal user's PIN
     * @param flags       from CK_SESSION_INFO
     * @param application passed to callback (ok to leave it null)
     * @param notify      callback function (ok to leave it null)
     * @return session handle
     */
    public long loginSession(long slotID, byte[] userPIN, long flags, NativePointer application,
            CK_NOTIFY notify) {
        long session = CE.OpenSession(slotID, flags, application, notify);
        CE.LoginUser(session, userPIN);
        return session;
    }

    /**
     * Generates a public-key / private-key Ed25519 pair, create new key objects.
     * 
     * @param session    the session's handle
     * @param publicKey  gets handle of new public key
     * @param privateKey gets handle of new private key
     */
    public void generateKeyPairEd25519(long session, LongRef publicKey, LongRef privateKey) {
        // Attributes from PKCS #11 Cryptographic Token Interface Current Mechanisms
        // Specification Version 2.40 section 2.3.3 - ECDSA public key objects
        /*
         * DER-encoding of an ANSI X9.62 Parameters, also known as
         * "EC domain parameters".
         */
        // We use a Ed25519 key, the oid 1.3.101.112 has DER encoding in Hex 06032b6570
        // In Utimaco, EC_PARAMS needs to have the value "edwards25519"

        CKA[] pubTempl = new CKA[] {
                new CKA(CKA.EC_PARAMS, "edwards25519"),
                new CKA(CKA.WRAP, false),
                new CKA(CKA.ENCRYPT, false),
                new CKA(CKA.VERIFY, true),
                new CKA(CKA.VERIFY_RECOVER, false),
                new CKA(CKA.TOKEN, true),
                new CKA(CKA.LABEL, "edwards-public"),
                new CKA(CKA.ID, "labelec"),
        };
        CKA[] privTempl = new CKA[] {
                new CKA(CKA.TOKEN, true),
                new CKA(CKA.PRIVATE, true),
                new CKA(CKA.SENSITIVE, true),
                new CKA(CKA.SIGN, true),
                new CKA(CKA.SIGN_RECOVER, false),
                new CKA(CKA.DECRYPT, false),
                new CKA(CKA.UNWRAP, false),
                new CKA(CKA.EXTRACTABLE, false),
                new CKA(CKA.LABEL, "edwards-private"),
                new CKA(CKA.ID, "labelec"),
        };
        CE.GenerateKeyPair(session, new CKM(CKM.ECDSA_KEY_PAIR_GEN), pubTempl, privTempl, publicKey, privateKey);
    }

}
