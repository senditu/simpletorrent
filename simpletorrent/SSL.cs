//
//  SSL.cs
//
//  Copyright (C) 2014  senditu <https://github.com/senditu/simpletorrent>
//
//  This program is free software: you can redistribute it and/or modify
//  it under the terms of the GNU Affero General Public License as
//  published by the Free Software Foundation, either version 3 of the
//  License, or (at your option) any later version.
//
//  This program is distributed in the hope that it will be useful,
//  but WITHOUT ANY WARRANTY; without even the implied warranty of
//  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//  GNU Affero General Public License for more details.
//
//  You should have received a copy of the GNU Affero General Public License
//  along with this program.  If not, see <http://www.gnu.org/licenses/>.
//
//  Original Code: http://blog.differentpla.net/post/53


using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Prng;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.X509;
using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace simpletorrent
{
    internal static class SSLSelfSigned
    {
        public static X509Certificate2 GetCertOrGenerate(string path, bool generateWithECDSA)
        {
            try
            {
                Console.WriteLine("simpletorrent: Loading SSL cert...");
                X509Certificate2 x = new X509Certificate2(path, "password");
                Console.WriteLine("simpletorrent: SSL cert loaded succesfully.");
                return x;
            }
            catch
            {
                Console.WriteLine("simpletorrent: Unable to load SSL cert. Generating a new one...");
                X509Certificate2 x;

                if (generateWithECDSA)
                    x = GenerateSelfSignedCertEcdsa();
                else
                    x = GenerateSelfSignedCert();
                
                File.WriteAllBytes(path, x.Export(X509ContentType.Pfx, "password"));
                Console.WriteLine("simpletorrent: SSL cert generated succesfully.");
                return x;
            }
        }

        public static X509Certificate2 GenerateSelfSignedCert()
        {
            var randomGenerator = new CryptoApiRandomGenerator();
            var random = new SecureRandom(randomGenerator);
            var certificateGenerator = new X509V3CertificateGenerator();
            var serialNumber =
            BigIntegers.CreateRandomInRange(
                BigInteger.One, BigInteger.ValueOf(Int64.MaxValue), random);
            certificateGenerator.SetSerialNumber(serialNumber);
            const string signatureAlgorithm = "SHA1WithRSA";
            certificateGenerator.SetSignatureAlgorithm(signatureAlgorithm);
            var subjectDN = new X509Name("CN=simpletorrent");
            var issuerDN = subjectDN;
            certificateGenerator.SetIssuerDN(issuerDN);
            certificateGenerator.SetSubjectDN(subjectDN);
            var notBefore = DateTime.UtcNow.Date.AddHours(-24);
            var notAfter = notBefore.AddYears(1000);
            certificateGenerator.SetNotBefore(notBefore);
            certificateGenerator.SetNotAfter(notAfter);
            const int strength = 4096;
            var keyGenerationParameters = new KeyGenerationParameters(random, strength);

            var keyPairGenerator = new RsaKeyPairGenerator();
            keyPairGenerator.Init(keyGenerationParameters);
            var subjectKeyPair = keyPairGenerator.GenerateKeyPair();

            certificateGenerator.SetPublicKey(subjectKeyPair.Public);

            var issuerKeyPair = subjectKeyPair;
            var certificate = certificateGenerator.Generate(issuerKeyPair.Private, random);

            var store = new Pkcs12Store();
            string friendlyName = certificate.SubjectDN.ToString();
            var certificateEntry = new X509CertificateEntry(certificate);
            store.SetCertificateEntry(friendlyName, certificateEntry);

            store.SetKeyEntry(friendlyName, new AsymmetricKeyEntry(subjectKeyPair.Private), new[] { certificateEntry });

           string password = "password";

            var stream = new MemoryStream();
            store.Save(stream, password.ToCharArray(), random);

            //mono bug #1660 fix -> convert to definite-length encoding
            byte[] pfx = Pkcs12Utilities.ConvertToDefiniteLength(stream.ToArray(), password.ToCharArray());

            var convertedCertificate =
                new X509Certificate2(
                    pfx, password,
                    X509KeyStorageFlags.PersistKeySet | X509KeyStorageFlags.Exportable);

            return convertedCertificate;
        }

        public static X509Certificate2 GenerateSelfSignedCertEcdsa()
        {
            var randomGenerator = new CryptoApiRandomGenerator();
            var random = new SecureRandom(randomGenerator);
            var certificateGenerator = new X509V3CertificateGenerator();
            var serialNumber =
            BigIntegers.CreateRandomInRange(
                BigInteger.One, BigInteger.ValueOf(Int64.MaxValue), random);
            certificateGenerator.SetSerialNumber(serialNumber);
            const string signatureAlgorithm = "SHA256withECDSA";
            certificateGenerator.SetSignatureAlgorithm(signatureAlgorithm);
            var subjectDN = new X509Name("CN=simpletorrent");
            var issuerDN = subjectDN;
            certificateGenerator.SetIssuerDN(issuerDN);
            certificateGenerator.SetSubjectDN(subjectDN);
            var notBefore = DateTime.UtcNow.Date.AddHours(-24);
            var notAfter = notBefore.AddYears(1000);
            certificateGenerator.SetNotBefore(notBefore);
            certificateGenerator.SetNotAfter(notAfter);
            ECKeyGenerationParameters genParam 
                = new ECKeyGenerationParameters(X962NamedCurves.GetOid("prime256v1"), random);

            var keyPairGenerator = new ECKeyPairGenerator();
            keyPairGenerator.Init(genParam);
            var subjectKeyPair = keyPairGenerator.GenerateKeyPair();

            certificateGenerator.SetPublicKey(subjectKeyPair.Public);

            var issuerKeyPair = subjectKeyPair;
            var certificate = certificateGenerator.Generate(issuerKeyPair.Private, random);

            var store = new Pkcs12Store();
            string friendlyName = certificate.SubjectDN.ToString();
            var certificateEntry = new X509CertificateEntry(certificate);
            store.SetCertificateEntry(friendlyName, certificateEntry);

            store.SetKeyEntry(friendlyName, new AsymmetricKeyEntry(subjectKeyPair.Private), new[] { certificateEntry });

            string password = "password";

            var stream = new MemoryStream();
            store.Save(stream, password.ToCharArray(), random);

            //mono bug #1660 fix -> convert to definite-length encoding
            byte[] pfx = Pkcs12Utilities.ConvertToDefiniteLength(stream.ToArray(), password.ToCharArray());

            var convertedCertificate =
                new X509Certificate2(
                    pfx, password,
                    X509KeyStorageFlags.PersistKeySet | X509KeyStorageFlags.Exportable);

            return convertedCertificate;
        }
    }
}
