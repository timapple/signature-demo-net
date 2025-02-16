﻿using System;
using System.Collections.Generic;
using System.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
//using CryptoPro.Sharpei;
//using CryptoPro.Sharpei.Xml;
using Microsoft.Xades;
using Org.BouncyCastle.X509;
using Xades.Abstractions;
using Xades.Helpers;
using Xades.Models;

namespace Xades.Implementations
{
    public class GostCryptoProvider : ICryptoProvider
    {
        private Dictionary<string, string> HashAlgorithmMap { get; set; } 
        
        public GostCryptoProvider()
        {
            HashAlgorithmMap = new Dictionary<string, string>
            {
                //{ "http://www.w3.org/2001/04/xmldsig-more#gostr3411", "GOST3411" }
                { "urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34102012-gostr34112012-256" , "GOST3411_2012_256" }
            };
        }

        public HashAlgorithm GetHashAlgorithm(string algorithm)
        {
            string algorithmName;
            var algorithmUrl = algorithm;
            if (!HashAlgorithmMap.TryGetValue(algorithmUrl, out algorithmName))
            {
                return null;
            }
            var pkHash = HashAlgorithm.Create(algorithmName);
            return pkHash;
        }

        private int _referenceIndex;

        public string SignatureMethod
        {
            get
            {
                //return CPSignedXml.XmlDsigGost3410UrlObsolete;
                return CryptoPro.Sharpei.Xml.CPSignedXml.XmlDsigGost3410_2012_256Url;
            }
        } 

        public string DigestMethod
        {
            get
            {
                //return CPSignedXml.XmlDsigGost3411UrlObsolete;
                return CryptoPro.Sharpei.Xml.CPSignedXml.XmlDsigGost3411_2012_256Url;
            }
        }

        public AsymmetricAlgorithm GetAsymmetricAlgorithm(X509Certificate2 certificate, string privateKeyPassword)
        {
            //var provider = (CryptoPro.Sharpei.Gost3410CryptoServiceProvider)certificate.PrivateKey;
            var provider = (CryptoPro.Sharpei.Gost3410_2012_256CryptoServiceProvider)certificate.PrivateKey;

            if (!string.IsNullOrEmpty(privateKeyPassword))
            {
                var secureString = new SecureString();
                foreach (var chr in privateKeyPassword)
                    secureString.AppendChar(chr);

                provider.SetContainerPassword(secureString);
            }

            return provider;
        }

        public Reference GetReference(string signedElementId, string signatureId)
        {
            var reference = new Reference
            {
                Uri = string.Format("#{0}",signedElementId),
                DigestMethod = DigestMethod,
                Id = string.Format("{0}-ref{1}", signatureId, _referenceIndex)
            };
            reference.AddTransform(new XmlDsigEnvelopedSignatureTransform());
            reference.AddTransform(new XmlDsigExcC14NTransform());

            _referenceIndex++;

            return reference;
        }

        public AsymmetricSignatureFormatter GetSignatureFormatter(X509Certificate2 certificate)
        {
            //if (certificate.PrivateKey is CryptoPro.Sharpei.Gost3410CryptoServiceProvider)
            if (certificate.PrivateKey is CryptoPro.Sharpei.Gost3410_2012_256CryptoServiceProvider)
            {
#pragma warning disable 612
                //var signatureDescription = (SignatureDescription)CryptoConfig.CreateFromName(CPSignedXml.XmlDsigGost3410UrlObsolete);
                var signatureDescription = (SignatureDescription)CryptoConfig.CreateFromName(CryptoPro.Sharpei.Xml.CPSignedXml.XmlDsigGost3410_2012_256Url);
#pragma warning restore 612
                return signatureDescription.CreateFormatter(certificate.PrivateKey);
            }

            throw new NotSupportedException("Неизвестный тип закрытого ключа");
        }

        public XadesObject GetXadesObject(XadesInfo xadesInfo, string signatureId)
        {
            var xadesObject = new XadesObject
            {
                QualifyingProperties = new QualifyingProperties
                {
                    Target = string.Format("#{0}",signatureId),
                    SignedProperties = new SignedProperties { Id = string.Format("{0}-signedprops", signatureId) }
                }
            };

            var hashAlgorithm = GetHashAlgorithm();
            var hashValue = hashAlgorithm.ComputeHash(xadesInfo.RawCertData);

            var x509CertificateParser = new X509CertificateParser();
            var bouncyCert = x509CertificateParser.ReadCertificate(xadesInfo.RawCertData);

            var cert = new Cert
            {
                IssuerSerial = new IssuerSerial
                {
                    X509IssuerName = bouncyCert.IssuerDN.ToX509IssuerName(),
                    X509SerialNumber = bouncyCert.SerialNumber.ToString()
                },
                CertDigest =
                {
                    DigestValue = hashValue,
                    DigestMethod = new DigestMethod { Algorithm = DigestMethod }
                }
            };

            var signedSignatureProperties = xadesObject.QualifyingProperties.SignedProperties.SignedSignatureProperties;
            signedSignatureProperties.SigningCertificate.CertCollection.Add(cert);
            signedSignatureProperties.SigningTime = xadesInfo.SigningDateTimeUtc.ToDateTimeOffset(xadesInfo.TimeZoneOffsetMinutes);

            return xadesObject;
        }

        private static HashAlgorithm GetHashAlgorithm()
        {
            //return HashAlgorithm.Create("GOST3411");
            return HashAlgorithm.Create("GOST3411_2012_256");
        }
    }
}
