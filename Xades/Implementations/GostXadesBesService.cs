using System;
using System.Security.Cryptography.X509Certificates;
using Xades.Abstractions;
using Xades.Helpers;

namespace Xades.Implementations
{
    public class GostXadesBesService : IXadesService
    {
        private X509Certificate2 CachedCert = null;
        private string CachedCertKey = string.Empty;

        public GostXadesBesService()
        {

        }

        public GostXadesBesService(string certificateThumbprint, string certificatePassword)
        {
            CacheCertificate(certificateThumbprint, certificatePassword);
        }

        public void ValidateSignature(string xmlData, string elementId)
        {
            if (string.IsNullOrEmpty(xmlData))
            {
                throw new ArgumentNullException("xmlData");
            }
            if (string.IsNullOrWhiteSpace(elementId))
            {
                throw new ArgumentNullException("elementId");
            }


            var document = XmlDocumentHelper.Create(xmlData);
            var signedXml = new XadesBesSignedXml(document, elementId)
            {
                CertificateMatcher = new CertificateMatcher(new GostCryptoProvider())
            };
            using (new AdditionalXmlDsigC14NTransformOperation(document))
            {
                signedXml.Validate();
            }
        }

        public string Sign(string xmlData, string elementId, string certificateThumbprint, string certificatePassword)
        {
            if (string.IsNullOrEmpty(xmlData))
            {
                throw new ArgumentNullException("xmlData");
            }
            if (string.IsNullOrEmpty(elementId))
            {
                throw new ArgumentNullException("elementId");
            }
            if (string.IsNullOrEmpty(certificateThumbprint))
            {
                throw new ArgumentNullException("certificateThumbprint");
            }

            var originalDoc = XmlDocumentHelper.Create(xmlData);
            var certificate = CertificateHelper.GetCertificateByThumbprint(certificateThumbprint);

            var xadesSignedXml = new XadesBesSignedXml(originalDoc)
            {
                SignedElementId = elementId,
                CryptoProvider = new GostCryptoProvider()
            };

            var element = xadesSignedXml.FindElement(elementId, originalDoc);
            if (element == null)
            {
                throw new InvalidOperationException(string.Format("Не удалось найти узел c Id {0}", elementId));
            }

            xadesSignedXml.ComputeSignature(certificate, certificatePassword);
            xadesSignedXml.InjectSignatureTo(originalDoc);

            return originalDoc.OuterXml;
        }

        public string SignWithCachedCert(string xmlData, string elementId)
        {
            if (string.IsNullOrEmpty(xmlData))
            {
                throw new ArgumentNullException("xmlData");
            }
            if (string.IsNullOrEmpty(elementId))
            {
                throw new ArgumentNullException("elementId");
            }
            if (CachedCert is null)
            {
                throw new ArgumentNullException("Call CacheCertificate before!");
            }

            var originalDoc = XmlDocumentHelper.Create(xmlData);

            var xadesSignedXml = new XadesBesSignedXml(originalDoc)
            {
                SignedElementId = elementId,
                CryptoProvider = new GostCryptoProvider()
            };

            var element = xadesSignedXml.FindElement(elementId, originalDoc);
            if (element == null)
            {
                throw new InvalidOperationException(string.Format("Не удалось найти узел c Id {0}", elementId));
            }

            xadesSignedXml.ComputeSignature(CachedCert, CachedCertKey);
            xadesSignedXml.InjectSignatureTo(originalDoc);

            return originalDoc.OuterXml;
        }

        public void CacheCertificate(string certificateThumbprint, string certificatePassword)
        {
            if (string.IsNullOrEmpty(certificateThumbprint))
            {
                throw new ArgumentNullException("certificateThumbprint");
            }

            CachedCert = CertificateHelper.GetCertificateByThumbprint(certificateThumbprint);
            CachedCertKey = certificatePassword;
        }
    }
}