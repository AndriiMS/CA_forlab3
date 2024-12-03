﻿using System;
using System.IO;
using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;

class Program
{
    static void Main()
    {
        //Генерація приватного ключа та самопідписаного сертифіката CA
        var caKeyPair = GenerateRsaKeyPair(4096);
        var caCertificate = GenerateSelfSignedCertificate(caKeyPair, "CN=MyRootCA, O=group1, C=UA", 3650);

        Console.WriteLine("CA сертифікат згенеровано");

        //Збереження приватного ключа та сертифіката CA
        SaveToPem("ca_private.key", caKeyPair.Private);
        SaveToPem("ca_certificate.pem", caCertificate);

        //Генерація приватного ключа сервера та CSR
        var serverKeyPair = GenerateEcKeyPair();
        var serverCsr = GenerateCertificateRequest(serverKeyPair, "CN=ELK, O=group1, C=UA");
        SaveToPem("server_private.key", serverKeyPair.Private);
        SaveToPem("server.csr", serverCsr);

        Console.WriteLine("Серверний CSR згенеровано");

        //Підписання CSR сервера сертифікатом CA
        var serverCertificate = SignCertificateRequest(serverCsr, caCertificate, caKeyPair.Private, 365);
        SaveToPem("server_certificate.pem", serverCertificate);

        Console.WriteLine("Серверний сертифікат підписаний CA");

        //Генерація приватного ключа клієнта та CSR
        var clientKeyPair = GenerateEcKeyPair();
        var clientCsr = GenerateCertificateRequest(clientKeyPair, "CN=andrii, O=group1, C=UA");
        SaveToPem("client_private.key", clientKeyPair.Private);
        SaveToPem("client.csr", clientCsr);

        Console.WriteLine("Клієнтський CSR згенеровано");

        //Підписання CSR клієнта сертифікатом CA
        var clientCertificate = SignCertificateRequest(clientCsr, caCertificate, caKeyPair.Private, 365);
        SaveToPem("client_certificate.pem", clientCertificate);

        Console.WriteLine("Клієнтський сертифікат підписаний CA.");
    }
    // Генерація RSA ключової пари
    static AsymmetricCipherKeyPair GenerateRsaKeyPair(int keySize)
    {
        var generator = new RsaKeyPairGenerator();
        generator.Init(new KeyGenerationParameters(new SecureRandom(), keySize));
        return generator.GenerateKeyPair();
    }
    // Генерація ключової пари на основі еліптичних кривих
    static AsymmetricCipherKeyPair GenerateEcKeyPair()
    {
        var generator = new ECKeyPairGenerator();
        generator.Init(new ECKeyGenerationParameters(SecObjectIdentifiers.SecP256r1, new SecureRandom()));
        return generator.GenerateKeyPair();
    }
    // Генерація самопідписаного сертифіката
    static X509Certificate GenerateSelfSignedCertificate(AsymmetricCipherKeyPair keyPair, string subjectName, int validityDays)
    {
        var certGen = new X509V3CertificateGenerator();
        var subjectDN = new X509Name(subjectName);
        var serialNumber = BigInteger.ProbablePrime(160, new Random());
        var notBefore = DateTime.UtcNow;
        var notAfter = notBefore.AddDays(validityDays);

        certGen.SetSerialNumber(serialNumber);
        certGen.SetIssuerDN(subjectDN);
        certGen.SetSubjectDN(subjectDN);
        certGen.SetNotBefore(notBefore);
        certGen.SetNotAfter(notAfter);
        certGen.SetPublicKey(keyPair.Public);

        var signatureFactory = new Asn1SignatureFactory("SHA256WithRSA", keyPair.Private);
        return certGen.Generate(signatureFactory);
    }
    // Генерація запиту на сертифікат (CSR)
    static Pkcs10CertificationRequest GenerateCertificateRequest(AsymmetricCipherKeyPair keyPair, string subjectName)
    {
        var subjectDN = new X509Name(subjectName);
        var signatureFactory = new Asn1SignatureFactory("SHA256WithECDSA", keyPair.Private, new SecureRandom());
        return new Pkcs10CertificationRequest("SHA256WithECDSA", subjectDN, keyPair.Public, null, keyPair.Private);
    }
    // Підписання CSR для створення сертифіката
    static X509Certificate SignCertificateRequest(Pkcs10CertificationRequest csr, X509Certificate caCertificate, AsymmetricKeyParameter caPrivateKey, int validityDays)
    {
        var certGen = new X509V3CertificateGenerator();
        var serialNumber = BigInteger.ProbablePrime(160, new Random());
        var notBefore = DateTime.UtcNow;
        var notAfter = notBefore.AddDays(validityDays);

        certGen.SetSerialNumber(serialNumber);
        certGen.SetIssuerDN(caCertificate.SubjectDN);
        certGen.SetSubjectDN(csr.GetCertificationRequestInfo().Subject);
        certGen.SetNotBefore(notBefore);
        certGen.SetNotAfter(notAfter);
        certGen.SetPublicKey(csr.GetPublicKey());

        var signatureFactory = new Asn1SignatureFactory("SHA256WithRSA", caPrivateKey);
        return certGen.Generate(signatureFactory);
    }
    // Збереження даних у PEM-форматі
    static void SaveToPem(string filePath, object data)
    {
        using var writer = new StreamWriter(filePath);
        var pemWriter = new Org.BouncyCastle.OpenSsl.PemWriter(writer);
        pemWriter.WriteObject(data);
    }
}
